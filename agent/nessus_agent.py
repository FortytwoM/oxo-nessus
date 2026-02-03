"""OXO Nessus Agent - Main agent implementation."""

import logging
from typing import Optional
from urllib.parse import urlparse

from ostorlab.agent import agent
from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent.message import message as msg
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.agent.kb import kb

from agent.nessus_client import (
    NessusClient,
    NessusClientError,
    Severity,
    Vulnerability,
)

logger = logging.getLogger(__name__)


# Custom KB entry for Nessus findings
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
)


class NessusAgent(agent.Agent, agent_report_vulnerability_mixin.AgentReportVulnMixin):
    """OXO Agent for Tenable Nessus vulnerability scanner."""

    def __init__(
        self,
        agent_definition: agent_definitions.AgentDefinition,
        agent_settings: agent_definitions.AgentSettings,
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
        """Get scan policy ID."""
        return self.args.get("scan_policy_id", 0)

    @property
    def scan_template(self) -> str:
        """Get scan template name."""
        return self.args.get("scan_template", "basic")

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
        """Get minimum severity level."""
        severity_str = self.args.get("min_severity", "info")
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
        """Extract target from message based on selector type.
        
        Args:
            message: Input message
            
        Returns:
            Target string (IP or hostname) or None
        """
        selector = message.selector

        if selector == "v3.asset.ip.v4":
            host = message.data.get("host")
            return host

        elif selector == "v3.asset.ip.v6":
            host = message.data.get("host")
            return host

        elif selector == "v3.asset.domain_name":
            name = message.data.get("name")
            return name

        elif selector == "v3.asset.link":
            url = message.data.get("url")
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
            for ref in vuln.references[:5]:  # Limit references
                if isinstance(ref, dict):
                    ref_type = ref.get("type", "Reference")
                    ref_id = ref.get("id", "")
                    references[f"{ref_type}: {ref_id}"] = ""
                elif isinstance(ref, str):
                    references[ref] = ""

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

    def _report_vulnerability(self, vuln: Vulnerability) -> None:
        """Report a vulnerability finding.
        
        Args:
            vuln: Vulnerability object
        """
        kb_entry = self._create_kb_entry(vuln)
        risk_rating = self._severity_to_risk_rating(vuln.severity)
        technical_detail = self._build_technical_detail(vuln)

        self.report_vulnerability(
            entry=kb_entry,
            technical_detail=technical_detail,
            risk_rating=risk_rating,
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

        # Avoid scanning the same target multiple times
        if target in self._scanned_targets:
            logger.info("Target %s already scanned, skipping", target)
            return

        self._scanned_targets.add(target)
        logger.info("Processing target: %s", target)

        try:
            client = self._get_client()

            # Get template UUID
            template_uuid = None
            if self.scan_template:
                template_uuid = client.get_template_uuid(self.scan_template)
                if not template_uuid:
                    logger.warning(
                        "Template '%s' not found, using default", self.scan_template
                    )

            # Create scan
            scan_name = f"OXO Scan - {target}"
            policy_id = self.scan_policy_id if self.scan_policy_id > 0 else None

            scan_id = client.create_scan(
                name=scan_name,
                targets=[target],
                template_uuid=template_uuid,
                policy_id=policy_id,
                description=f"Automated scan created by OXO Nessus Agent for target: {target}",
            )

            # Launch scan
            client.launch_scan(scan_id)
            logger.info("Launched scan %s for target %s", scan_id, target)

            # Wait for completion if configured
            if self.wait_for_completion:
                logger.info("Waiting for scan %s to complete...", scan_id)
                status = client.wait_for_scan(
                    scan_id,
                    timeout=self.timeout,
                    poll_interval=30,
                )
                logger.info("Scan %s finished with status: %s", scan_id, status.value)

            # Extract and report vulnerabilities
            vulnerabilities = client.get_vulnerabilities(
                scan_id,
                min_severity=self.min_severity,
            )

            logger.info(
                "Found %d vulnerabilities for target %s", len(vulnerabilities), target
            )

            for vuln in vulnerabilities:
                self._report_vulnerability(vuln)

        except NessusClientError as e:
            logger.error("Nessus client error: %s", str(e))
            raise

        except Exception as e:
            logger.error("Unexpected error processing target %s: %s", target, str(e))
            raise


if __name__ == "__main__":
    logger.info("Starting OXO Nessus Agent")
    NessusAgent.main()
