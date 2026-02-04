"""OXO Nessus Agent - Main agent implementation.

Processes v3.asset (ip, domain_name, link) and reports v3.report.vulnerability
via Nessus API (pyTenable). See OXO docs: https://oxo.ostorlab.co/docs
"""

import sys
from types import ModuleType


def _make_exporter_stub(module_name: str, exporter_class_name: str = "SpanExporter"):
    stub = ModuleType(module_name)
    class NoOpExporter:
        def __init__(self, *args, **kwargs): pass
        def export(self, *args, **kwargs): pass
        def shutdown(self, *args, **kwargs): pass
        def force_flush(self, *args, **kwargs): return True
    setattr(stub, exporter_class_name, NoOpExporter)
    return stub

_otel_exporter = __import__("opentelemetry.exporter", fromlist=[])
_stub_names = [
    ("cloud_trace", "CloudTraceSpanExporter"),
    ("zipkin", "ZipkinSpanExporter"),
    ("otlp", "OTLPSpanExporter"),
]
for name, class_name in _stub_names:
    full_name = f"opentelemetry.exporter.{name}"
    stub = _make_exporter_stub(full_name, class_name)
    sys.modules[full_name] = stub
    setattr(_otel_exporter, name, stub)

def _ensure_jaeger_thrift():
    try:
        from opentelemetry.exporter.jaeger import thrift as _
        return
    except ImportError:
        pass
    jaeger_stub = ModuleType("opentelemetry.exporter.jaeger.thrift")
    class _JaegerExporterStub:
        def __init__(self, agent_name=None, host_name="localhost", port=6831, **kwargs):
            pass
        def export(self, span_data): return
        def shutdown(self): pass
        def force_flush(self, timeout_millis=None): return True
    jaeger_stub.JaegerExporter = _JaegerExporterStub
    sys.modules["opentelemetry.exporter.jaeger.thrift"] = jaeger_stub
    parent = sys.modules.get("opentelemetry.exporter.jaeger", None)
    if parent is None:
        parent = ModuleType("opentelemetry.exporter.jaeger")
        sys.modules["opentelemetry.exporter.jaeger"] = parent
    setattr(parent, "thrift", jaeger_stub)
_ensure_jaeger_thrift()

import logging
import time
from typing import Optional
from urllib.parse import urlparse

from ostorlab.agent import agent
from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.agent.message import message as msg
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.agent.kb import kb
from ostorlab.assets import domain_name as asset_domain_name
from ostorlab.assets import ipv4 as asset_ipv4
from ostorlab.assets import ipv6 as asset_ipv6
from ostorlab.assets import link as asset_link

from agent.nessus_client import (
    NessusClient,
    NessusClientError,
    ScanStatus,
    Severity,
    Vulnerability,
)

logger = logging.getLogger(__name__)

# OXO asset selectors (oxo.yaml in_selectors)
SELECTOR_DOMAIN_NAME = "v3.asset.domain_name"
SELECTOR_IP_V4 = "v3.asset.ip.v4"
SELECTOR_IP_V6 = "v3.asset.ip.v6"
SELECTOR_LINK = "v3.asset.link"
DEFAULT_SCAN_TEMPLATE = "basic"
DEFAULT_MIN_SEVERITY = "info"


NESSUS_KB_ENTRY = kb.Entry(
    title="Nessus Vulnerability Scan Finding",
    short_description="Vulnerability discovered by Tenable Nessus scanner",
    description="""
    This vulnerability was discovered during an automated Nessus vulnerability scan.
    Nessus is a comprehensive vulnerability scanner that checks for security issues,
    misconfigurations, missing patches, and other potential risks.
    """,
    recommendation="Review the technical details and apply the recommended solution.",
    references={"Tenable Nessus": "https://www.tenable.com/products/nessus"},
    security_issue=True,
    privacy_issue=False,
    has_public_exploit=False,
    targeted_by_malware=False,
    targeted_by_ransomware=False,
    targeted_by_nation_state=False,
    risk_rating=agent_report_vulnerability_mixin.RiskRating.INFO,
)


class NessusAgent(agent.Agent, agent_report_vulnerability_mixin.AgentReportVulnMixin):
    """OXO Agent for Tenable Nessus vulnerability scanner."""

    def __init__(
        self,
        agent_definition: agent_definitions.AgentDefinition,
        agent_settings: runtime_definitions.AgentSettings,
    ) -> None:
        """Initialize the Nessus agent."""
        super().__init__(agent_definition, agent_settings)
        self._client: Optional[NessusClient] = None
        self._scanned_targets: set = set()

    @property
    def nessus_url(self) -> str:
        """Get Nessus URL from arguments."""
        return self.args.get("nessus_url", "https://localhost:8834")

    @property
    def access_key(self) -> str:
        """Get Nessus access key from arguments."""
        return self.args.get("access_key", "")

    @property
    def secret_key(self) -> str:
        """Get Nessus secret key from arguments."""
        return self.args.get("secret_key", "")

    @property
    def verify_ssl(self) -> bool:
        """Get SSL verification setting."""
        return self.args.get("verify_ssl", False)

    @property
    def scan_policy_id(self) -> int:
        """Get scan policy ID (0 = use template, not policy)."""
        raw = self.args.get("scan_policy_id", 0)
        if raw is None:
            return 0
        try:
            return int(raw)
        except (TypeError, ValueError):
            return 0

    @property
    def scan_template(self) -> str:
        """Get scan template name (used when scan_policy_id is 0)."""
        return self.args.get("scan_template", DEFAULT_SCAN_TEMPLATE)

    @property
    def wait_for_completion(self) -> bool:
        """Whether to wait for scan completion."""
        return self.args.get("wait_for_completion", True)

    @property
    def timeout(self) -> int:
        """Get scan timeout in seconds."""
        return self.args.get("timeout", 3600)

    @property
    def min_severity(self) -> Severity:
        """Get minimum severity level for reported vulnerabilities."""
        severity_str = self.args.get("min_severity", DEFAULT_MIN_SEVERITY)
        return Severity.from_string(severity_str)

    def _get_client(self) -> NessusClient:
        """Get or create Nessus client."""
        if self._client is None:
            if not self.access_key or not self.secret_key:
                raise NessusClientError(
                    "Nessus credentials not configured. "
                    "Please provide access_key and secret_key arguments."
                )

            self._client = NessusClient(
                url=self.nessus_url,
                access_key=self.access_key,
                secret_key=self.secret_key,
                verify_ssl=self.verify_ssl,
                timeout=self.timeout,
            )
            self._client.connect()

        return self._client

    def _extract_target(self, message: msg.Message) -> Optional[str]:
        """Extract target (IP or hostname) from message based on selector."""
        selector = message.selector
        data = message.data or {}
        if selector == SELECTOR_IP_V4 or selector == SELECTOR_IP_V6:
            return data.get("host")
        if selector == SELECTOR_DOMAIN_NAME:
            return data.get("name")
        if selector == SELECTOR_LINK:
            url = data.get("url")
            if url:
                parsed = urlparse(url)
                return parsed.hostname
        return None

    def _severity_to_risk_rating(
        self, severity: Severity
    ) -> agent_report_vulnerability_mixin.RiskRating:
        """Convert Nessus severity to OXO risk rating.
        
        Args:
            severity: Nessus severity level
            
        Returns:
            OXO risk rating
        """
        mapping = {
            Severity.CRITICAL: agent_report_vulnerability_mixin.RiskRating.CRITICAL,
            Severity.HIGH: agent_report_vulnerability_mixin.RiskRating.HIGH,
            Severity.MEDIUM: agent_report_vulnerability_mixin.RiskRating.MEDIUM,
            Severity.LOW: agent_report_vulnerability_mixin.RiskRating.LOW,
            Severity.INFO: agent_report_vulnerability_mixin.RiskRating.INFO,
        }
        return mapping.get(severity, agent_report_vulnerability_mixin.RiskRating.INFO)

    def _create_kb_entry(self, vuln: Vulnerability) -> kb.Entry:
        """Create a KB entry for a vulnerability.
        
        Args:
            vuln: Vulnerability object
            
        Returns:
            KB entry
        """
        references = {}
        if vuln.cve:
            for cve in vuln.cve:
                references[cve] = f"https://nvd.nist.gov/vuln/detail/{cve}"

        if vuln.references:
            for ref in vuln.references[:5]:
                if isinstance(ref, dict):
                    ref_type = ref.get("type", "Reference")
                    ref_id = ref.get("id", "")
                    references[f"{ref_type}: {ref_id}"] = ""
                elif isinstance(ref, str):
                    references[ref] = ""

        risk_rating = self._severity_to_risk_rating(vuln.severity)
        return kb.Entry(
            title=vuln.plugin_name or "Nessus Finding",
            short_description=vuln.synopsis or "Vulnerability detected by Nessus",
            description=vuln.description or "No description available",
            recommendation=vuln.solution or "Review and remediate as appropriate",
            references=references,
            security_issue=vuln.severity.value >= Severity.LOW.value,
            privacy_issue=False,
            has_public_exploit=False,
            targeted_by_malware=False,
            targeted_by_ransomware=False,
            targeted_by_nation_state=False,
            risk_rating=risk_rating,
        )

    def _build_technical_detail(self, vuln: Vulnerability) -> str:
        """Build technical detail string for vulnerability report.
        
        Args:
            vuln: Vulnerability object
            
        Returns:
            Technical detail string
        """
        details = []
        
        details.append(f"**Host:** {vuln.host}")
        details.append(f"**Port:** {vuln.port}/{vuln.protocol}")
        details.append(f"**Plugin ID:** {vuln.plugin_id}")
        details.append(f"**Plugin Family:** {vuln.plugin_family}")
        
        if vuln.cvss_base_score:
            details.append(f"**CVSS Base Score:** {vuln.cvss_base_score}")
        if vuln.cvss3_base_score:
            details.append(f"**CVSS3 Base Score:** {vuln.cvss3_base_score}")
            
        if vuln.cve:
            details.append(f"**CVE:** {', '.join(vuln.cve)}")
            
        if vuln.plugin_output:
            details.append(f"\n**Plugin Output:**\n```\n{vuln.plugin_output[:2000]}\n```")

        return "\n".join(details)

    def _build_vulnerability_location(
        self, message: msg.Message, vuln: Vulnerability
    ) -> Optional[agent_report_vulnerability_mixin.VulnerabilityLocation]:
        """Build vulnerability location so OXO links the finding to the scanned asset."""
        mixin = agent_report_vulnerability_mixin
        data = message.data or {}
        selector = message.selector
        asset = None
        if selector == SELECTOR_DOMAIN_NAME and data.get("name"):
            asset = asset_domain_name.DomainName(name=data["name"])
        elif selector == SELECTOR_IP_V4 and data.get("host"):
            asset = asset_ipv4.IPv4(host=data["host"])
        elif selector == SELECTOR_IP_V6 and data.get("host"):
            asset = asset_ipv6.IPv6(host=data["host"])
        elif selector == SELECTOR_LINK and data.get("url"):
            asset = asset_link.Link(url=data["url"])
        if asset is None:
            return None
        meta = [
            mixin.VulnerabilityLocationMetadata(
                metadata_type=mixin.MetadataType.PORT, value=str(vuln.port)
            ),
        ]
        return mixin.VulnerabilityLocation(metadata=meta, asset=asset)

    def _report_vulnerability(
        self, vuln: Vulnerability, message: msg.Message
    ) -> None:
        """Report a vulnerability finding with location and stable dna for OXO."""
        target = self._extract_target(message) or "unknown"
        kb_entry = self._create_kb_entry(vuln)
        risk_rating = self._severity_to_risk_rating(vuln.severity)
        technical_detail = self._build_technical_detail(vuln)
        vulnerability_location = self._build_vulnerability_location(message, vuln)
        dna = f"nessus:{target}:{vuln.host}:{vuln.port}:{vuln.plugin_id}"

        self.report_vulnerability(
            entry=kb_entry,
            technical_detail=technical_detail,
            risk_rating=risk_rating,
            dna=dna,
            vulnerability_location=vulnerability_location,
        )
        logger.debug(
            "Reported vuln to OXO: %s (%s)", vuln.plugin_name, dna
        )

    def process(self, message: msg.Message) -> None:
        """Process incoming message and perform Nessus scan.
        
        Args:
            message: Input message with target information
        """
        target = self._extract_target(message)

        if not target:
            logger.warning("Could not extract target from message: %s", message.selector)
            return

        if target in self._scanned_targets:
            logger.info("Target %s already scanned, skipping", target)
            return

        self._scanned_targets.add(target)
        logger.info("Processing target: %s", target)

        try:
            client = self._get_client()

            policy_id = self.scan_policy_id if self.scan_policy_id > 0 else None
            template_uuid = None
            if not policy_id and self.scan_template:
                template_uuid = client.get_template_uuid(self.scan_template)
                if not template_uuid:
                    logger.warning(
                        "Template '%s' not found, using default", self.scan_template
                    )
            if policy_id:
                logger.info("Using Nessus policy_id=%s for scan", policy_id)
            else:
                logger.info("Using template for scan (template_uuid=%s)", template_uuid or "basic fallback")

            scan_name = f"OXO Scan - {target}"
            scan_id = client.create_scan(
                name=scan_name,
                targets=[target],
                template_uuid=template_uuid,
                policy_id=policy_id,
                description=f"Automated scan created by OXO Nessus Agent for target: {target}",
            )

            client.launch_scan(scan_id)
            logger.info("Launched scan %s for target %s", scan_id, target)

            reported_keys: set = set()
            poll_interval = 30

            if self.wait_for_completion:
                logger.info(
                    "Waiting for scan %s to complete (reporting vulns as they appear)...",
                    scan_id,
                )
                start_time = time.time()
                while True:
                    status = client.get_scan_status(scan_id)
                    vulns = client.get_vulnerabilities(
                        scan_id, min_severity=self.min_severity
                    )
                    if vulns and len(reported_keys) == 0:
                        logger.info(
                            "Scan %s: Nessus returned %d vulnerability findings",
                            scan_id,
                            len(vulns),
                        )
                    new_count = 0
                    for vuln in vulns:
                        key = (vuln.host, vuln.port, vuln.plugin_id)
                        if key not in reported_keys:
                            reported_keys.add(key)
                            self._report_vulnerability(vuln, message)
                            new_count += 1
                    if new_count:
                        logger.info(
                            "Scan %s: reported %d new vulnerabilities (%d total so far)",
                            scan_id,
                            new_count,
                            len(reported_keys),
                        )
                    if status in (ScanStatus.COMPLETED, ScanStatus.CANCELED):
                        logger.info(
                            "Scan %s finished with status: %s", scan_id, status.value
                        )
                        break
                    if self.timeout > 0 and (
                        time.time() - start_time
                    ) >= self.timeout:
                        logger.warning(
                            "Scan %s timed out after %s seconds", scan_id, self.timeout
                        )
                        break
                    time.sleep(poll_interval)
            else:
                vulns = client.get_vulnerabilities(
                    scan_id, min_severity=self.min_severity
                )
                for vuln in vulns:
                    self._report_vulnerability(vuln, message)

            total = len(reported_keys) if self.wait_for_completion else len(vulns)
            logger.info(
                "Found %d vulnerabilities for target %s", total, target
            )

        except NessusClientError as e:
            logger.error("Nessus client error: %s", str(e))
            raise

        except Exception as e:
            logger.error("Unexpected error processing target %s: %s", target, str(e))
            raise


if __name__ == "__main__":
    logger.info("Starting OXO Nessus Agent")
    NessusAgent.main()
