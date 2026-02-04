"""Nessus API client wrapper using pyTenable library.

Uses pyTenable Nessus API: scans, policies, editor (templates).
See: https://pytenable.readthedocs.io/en/stable/api/nessus/
"""

import logging
import time
from typing import Any, Dict, List, Optional
from dataclasses import dataclass
from enum import Enum

from tenable.nessus import Nessus

logger = logging.getLogger(__name__)

DEFAULT_TEMPLATE = "basic"
LAUNCH_RETRIES = 3
LAUNCH_RETRY_BACKOFF_SEC = 2


class ScanStatus(Enum):
    """Nessus scan status enum."""
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELED = "canceled"
    PAUSED = "paused"
    PENDING = "pending"
    EMPTY = "empty"


class Severity(Enum):
    """Vulnerability severity levels."""
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        """Convert string to Severity enum."""
        mapping = {
            "info": cls.INFO,
            "low": cls.LOW,
            "medium": cls.MEDIUM,
            "high": cls.HIGH,
            "critical": cls.CRITICAL,
        }
        return mapping.get(value.lower(), cls.INFO)

    @classmethod
    def from_int(cls, value: int) -> "Severity":
        """Convert integer to Severity enum."""
        for member in cls:
            if member.value == value:
                return member
        return cls.INFO


@dataclass
class Vulnerability:
    """Represents a discovered vulnerability."""
    plugin_id: int
    plugin_name: str
    plugin_family: str
    severity: Severity
    host: str
    port: int
    protocol: str
    description: str
    solution: str
    synopsis: str
    risk_factor: str
    cvss_base_score: Optional[float] = None
    cvss3_base_score: Optional[float] = None
    cve: Optional[List[str]] = None
    references: Optional[List[str]] = None
    plugin_output: Optional[str] = None


class NessusClientError(Exception):
    """Base exception for Nessus client errors."""
    pass


class NessusAuthError(NessusClientError):
    """Authentication error."""
    pass


class NessusScanError(NessusClientError):
    """Scan-related error."""
    pass


class NessusClient:
    """Client for interacting with Nessus API.

    Scan management:
        create_scan()      — create scan
        launch_scan()      — launch scan
        list_scans()       — list scans (by folder/date)
        get_scan_status()  — scan status
        wait_for_scan()    — wait for completion
        pause_scan()       — pause
        resume_scan()      — resume
        stop_scan()        — stop
        delete_scan()      — delete
        get_scan_results() / get_vulnerabilities() — results
    """

    def __init__(
        self,
        url: str,
        access_key: str,
        secret_key: str,
        verify_ssl: bool = False,
        timeout: int = 300,
    ):
        """Initialize Nessus client.
        
        Args:
            url: Nessus server URL
            access_key: API access key
            secret_key: API secret key
            verify_ssl: Whether to verify SSL certificates
            timeout: API request timeout in seconds
        """
        self.url = url.rstrip("/")
        self.access_key = access_key
        self.secret_key = secret_key
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self._client: Optional[Nessus] = None

    def connect(self) -> None:
        """Establish connection to Nessus server."""
        try:
            self._client = Nessus(
                url=self.url,
                access_key=self.access_key,
                secret_key=self.secret_key,
                ssl_verify=self.verify_ssl,
            )
            self._client.server.properties()
            logger.info("Successfully connected to Nessus server at %s", self.url)
        except Exception as e:
            logger.error("Failed to connect to Nessus: %s", str(e))
            raise NessusAuthError(f"Failed to connect to Nessus: {e}") from e

    @property
    def client(self) -> Nessus:
        """Get the Nessus client instance."""
        if self._client is None:
            raise NessusClientError("Client not connected. Call connect() first.")
        return self._client

    def get_templates(self) -> List[Dict[str, Any]]:
        """Get available scan templates.
        
        Returns:
            List of scan template dictionaries
        """
        try:
            templates = list(self.client.editor.template_list("scan"))
            return templates
        except Exception as e:
            logger.error("Failed to get templates: %s", str(e))
            raise NessusClientError(f"Failed to get templates: {e}") from e

    def get_template_uuid(self, template_name: str) -> Optional[str]:
        """Get template UUID by name.
        
        Args:
            template_name: Template name (e.g., 'basic', 'discovery')
            
        Returns:
            Template UUID or None if not found
        """
        templates = self.get_templates()
        for template in templates:
            if template.get("name", "").lower() == template_name.lower():
                return template.get("uuid")
            if template.get("title", "").lower() == template_name.lower():
                return template.get("uuid")
        return None

    def get_policies(self) -> List[Dict[str, Any]]:
        """Get available scan policies.
        
        Returns:
            List of policy dictionaries
        """
        try:
            policies = list(self.client.policies.list())
            return policies
        except Exception as e:
            logger.error("Failed to get policies: %s", str(e))
            raise NessusClientError(f"Failed to get policies: {e}") from e

    def get_policy_uuid(self, policy_id: int) -> str:
        """Get template UUID from a policy (for use in scan create).

        Nessus API: GET /policies/{id}. Policy must exist; 404 if not found.
        """
        try:
            policy = self.client.policies.details(policy_id)
            uuid_val = (
                policy.get("template_uuid")
                or policy.get("uuid")
                or policy.get("template")
            )
            if not uuid_val:
                raise NessusScanError(f"Policy {policy_id} has no template UUID")
            return uuid_val
        except NessusClientError:
            raise
        except Exception as e:
            logger.error("Failed to get policy UUID: %s", str(e))
            raise NessusClientError(f"Failed to get policy UUID: {e}") from e

    def create_scan(
        self,
        name: str,
        targets: List[str],
        template_uuid: Optional[str] = None,
        policy_id: Optional[int] = None,
        folder_id: Optional[int] = None,
        description: str = "",
    ) -> int:
        """Create a new scan.
        
        Args:
            name: Scan name
            targets: List of target IP addresses or hostnames
            template_uuid: Scan template UUID
            policy_id: Policy ID to use
            folder_id: Folder ID to store scan
            description: Scan description
            
        Returns:
            Scan ID
        """
        try:
            targets_str = ", ".join(targets) if isinstance(targets, list) else targets
            uuid_to_use = template_uuid
            policy_id_to_use: Optional[int] = None
            if not uuid_to_use and policy_id:
                try:
                    uuid_to_use = self.get_policy_uuid(policy_id)
                    policy_id_to_use = policy_id
                except NessusClientError as e:
                    err_msg = str(e).lower()
                    if "404" in err_msg or "not found" in err_msg:
                        logger.warning(
                            "Policy %s not found on Nessus server (404), using template 'basic' instead. "
                            "Check policy ID in Nessus UI (Policies) or omit scan_policy_id.",
                            policy_id,
                        )
                        uuid_to_use = self.get_template_uuid(DEFAULT_TEMPLATE)
                    else:
                        raise
            if not uuid_to_use:
                basic_uuid = self.get_template_uuid(DEFAULT_TEMPLATE)
                if basic_uuid:
                    uuid_to_use = basic_uuid
                else:
                    raise NessusScanError(
                        f"UUID template is required (template_uuid or policy_id or '{DEFAULT_TEMPLATE}' template)"
                    )

            settings: Dict[str, Any] = {
                "name": name,
                "enabled": False,
                "text_targets": targets_str,
            }
            if description:
                settings["description"] = description
            if folder_id is not None:
                settings["folder_id"] = folder_id
            if policy_id_to_use is not None:
                settings["policy_id"] = int(policy_id_to_use)

            create_kwargs: Dict[str, Any] = {"uuid": uuid_to_use, "settings": settings}
            scan = self.client.scans.create(**create_kwargs)
            scan_obj = scan.get("scan") if isinstance(scan.get("scan"), dict) else scan
            scan_id = scan_obj.get("id")
            if scan_id is None:
                raise NessusScanError(f"Create scan response has no id: {list(scan.keys())}")
            scan_id = int(scan_id)
            logger.info(
                "Created scan in Nessus: name='%s', id=%s (check Nessus UI: Scans)", name, scan_id
            )
            return scan_id
            
        except NessusScanError:
            raise
        except NessusClientError:
            raise
        except Exception as e:
            logger.error("Failed to create scan: %s", str(e))
            raise NessusScanError(f"Failed to create scan: {e}") from e

    def launch_scan(self, scan_id: int) -> str:
        """Launch a scan.
        
        Args:
            scan_id: Scan ID to launch
            
        Returns:
            Scan UUID
        """
        scan_id = int(scan_id)
        last_error: Optional[Exception] = None
        for attempt in range(LAUNCH_RETRIES):
            try:
                result = self.client.scans.launch(scan_id)
                scan_uuid = (
                    result
                    if isinstance(result, str)
                    else (result.get("scan_uuid") or "")
                )
                logger.info("Launched scan %s, UUID: %s", scan_id, scan_uuid)
                return scan_uuid
            except Exception as e:
                last_error = e
                is_conn = (
                    "Connection" in type(e).__name__
                    or "RemoteDisconnected" in str(e)
                )
                if is_conn and attempt < LAUNCH_RETRIES - 1:
                    wait = LAUNCH_RETRY_BACKOFF_SEC * (attempt + 1)
                    logger.warning(
                        "Launch scan %s attempt %s failed (connection): %s; retry in %ss",
                        scan_id,
                        attempt + 1,
                        str(e),
                        wait,
                    )
                    time.sleep(wait)
                    continue
                logger.error("Failed to launch scan %s: %s", scan_id, str(e))
                msg = str(e)
                if is_conn:
                    msg = (
                        f"{msg}. Check Nessus URL reachability, "
                        "verify_ssl, and firewall."
                    )
                raise NessusScanError(f"Failed to launch scan: {msg}") from e
        raise NessusScanError(
            f"Failed to launch scan: {last_error}"
        ) from last_error

    def get_scan_status(self, scan_id: int) -> ScanStatus:
        """Get scan status.
        
        Args:
            scan_id: Scan ID
            
        Returns:
            Scan status
        """
        try:
            scan = self.client.scans.details(scan_id)
            status = scan.get("info", {}).get("status", "unknown")
            return ScanStatus(status) if status in [s.value for s in ScanStatus] else ScanStatus.PENDING
        except Exception as e:
            logger.error("Failed to get scan status: %s", str(e))
            raise NessusScanError(f"Failed to get scan status: {e}") from e

    def wait_for_scan(
        self,
        scan_id: int,
        timeout: int = 3600,
        poll_interval: int = 30,
    ) -> ScanStatus:
        """Wait for scan to complete.
        
        Args:
            scan_id: Scan ID
            timeout: Maximum wait time in seconds
            poll_interval: Time between status checks
            
        Returns:
            Final scan status
        """
        start_time = time.time()
        
        while True:
            status = self.get_scan_status(scan_id)
            logger.info("Scan %s status: %s", scan_id, status.value)
            
            if status in (ScanStatus.COMPLETED, ScanStatus.CANCELED):
                return status
                
            if timeout > 0 and (time.time() - start_time) > timeout:
                logger.warning("Scan %s timed out after %s seconds", scan_id, timeout)
                return status
                
            time.sleep(poll_interval)

    def get_scan_results(self, scan_id: int) -> Dict[str, Any]:
        """Get scan results.
        
        Args:
            scan_id: Scan ID
            
        Returns:
            Scan results dictionary
        """
        try:
            return self.client.scans.details(scan_id)
        except Exception as e:
            logger.error("Failed to get scan results: %s", str(e))
            raise NessusScanError(f"Failed to get scan results: {e}") from e

    def get_vulnerabilities(
        self,
        scan_id: int,
        min_severity: Severity = Severity.INFO,
    ) -> List[Vulnerability]:
        """Extract vulnerabilities from scan results.
        
        Args:
            scan_id: Scan ID
            min_severity: Minimum severity to include
            
        Returns:
            List of Vulnerability objects
        """
        vulnerabilities = []
        
        try:
            results = self.get_scan_results(scan_id)
            hosts = results.get("hosts", [])
            
            for host in hosts:
                host_id = host.get("host_id")
                host_name = host.get("hostname", "unknown")
                
                try:
                    host_details = self.client.scans.host_details(scan_id, host_id)
                except Exception as e:
                    logger.warning("Failed to get details for host %s: %s", host_name, e)
                    continue
                
                for vuln in host_details.get("vulnerabilities", []):
                    severity = Severity.from_int(vuln.get("severity", 0))
                    
                    if severity.value < min_severity.value:
                        continue
                    
                    plugin_id = vuln.get("plugin_id")
                    
                    plugin_output_data: Optional[str] = None
                    plugin_attrs: Dict[str, Any] = {}
                    try:
                        po_resp = self.client.scans.plugin_output(
                            scan_id, host_id, plugin_id
                        )
                        plugin_info = (po_resp or {}).get("info", {}).get(
                            "plugindescription", {}
                        )
                        plugin_attrs = plugin_info.get("pluginattributes", {})
                        plugin_output_data = (po_resp or {}).get("output")
                    except Exception as e:
                        logger.debug(
                            "Plugin output for %s/%s/%s: %s",
                            scan_id,
                            host_id,
                            plugin_id,
                            e,
                        )

                    risk_info = plugin_attrs.get("risk_information", {})
                    ref_info = plugin_attrs.get("ref_information", {})
                    vulnerability = Vulnerability(
                        plugin_id=plugin_id,
                        plugin_name=vuln.get("plugin_name", ""),
                        plugin_family=vuln.get("plugin_family", ""),
                        severity=severity,
                        host=host_name,
                        port=vuln.get("port", 0),
                        protocol=vuln.get("protocol", "tcp"),
                        description=plugin_attrs.get("description", ""),
                        solution=plugin_attrs.get("solution", ""),
                        synopsis=plugin_attrs.get("synopsis", ""),
                        risk_factor=risk_info.get("risk_factor", ""),
                        cvss_base_score=risk_info.get("cvss_base_score"),
                        cvss3_base_score=risk_info.get("cvss3_base_score"),
                        cve=ref_info.get("cve", []),
                        references=ref_info.get("xref", []),
                        plugin_output=plugin_output_data,
                    )
                    vulnerabilities.append(vulnerability)
                    
        except Exception as e:
            logger.error("Failed to extract vulnerabilities: %s", str(e))
            raise NessusScanError(f"Failed to extract vulnerabilities: {e}") from e
            
        return vulnerabilities

    def list_scans(
        self,
        folder_id: Optional[int] = None,
        last_modification_date: Optional[int] = None,
    ) -> Dict[str, Any]:
        """List scans.
        
        Args:
            folder_id: Filter by folder ID
            last_modification_date: Only scans modified after this Unix timestamp
            
        Returns:
            API response with 'scans' list
        """
        try:
            result = self.client.scans.list(
                folder_id=folder_id,
                last_modification_date=last_modification_date,
            )
            return result if isinstance(result, dict) else {"scans": list(result)}
        except Exception as e:
            logger.error("Failed to list scans: %s", str(e))
            raise NessusScanError(f"Failed to list scans: {e}") from e

    def pause_scan(self, scan_id: int) -> None:
        """Pause a running scan.
        
        Args:
            scan_id: Scan ID to pause
        """
        try:
            self.client.scans.pause(scan_id)
            logger.info("Paused scan %s", scan_id)
        except Exception as e:
            logger.error("Failed to pause scan %s: %s", scan_id, str(e))
            raise NessusScanError(f"Failed to pause scan: {e}") from e

    def resume_scan(self, scan_id: int) -> None:
        """Resume a paused scan.
        
        Args:
            scan_id: Scan ID to resume
        """
        try:
            self.client.scans.resume(scan_id)
            logger.info("Resumed scan %s", scan_id)
        except Exception as e:
            logger.error("Failed to resume scan %s: %s", scan_id, str(e))
            raise NessusScanError(f"Failed to resume scan: {e}") from e

    def delete_scan(self, scan_id: int) -> None:
        """Delete a scan.
        
        Args:
            scan_id: Scan ID to delete
        """
        try:
            self.client.scans.delete(scan_id)
            logger.info("Deleted scan %s", scan_id)
        except Exception as e:
            logger.error("Failed to delete scan %s: %s", scan_id, str(e))
            raise NessusScanError(f"Failed to delete scan: {e}") from e

    def stop_scan(self, scan_id: int) -> None:
        """Stop a running scan.
        
        Args:
            scan_id: Scan ID to stop
        """
        try:
            self.client.scans.stop(scan_id)
            logger.info("Stopped scan %s", scan_id)
        except Exception as e:
            logger.error("Failed to stop scan %s: %s", scan_id, str(e))
            raise NessusScanError(f"Failed to stop scan: {e}") from e
