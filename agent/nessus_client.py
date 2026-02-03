"""Nessus API client wrapper using pyTenable library."""

import logging
import time
from typing import Any, Dict, List, Optional
from dataclasses import dataclass
from enum import Enum

from tenable.nessus import Nessus

logger = logging.getLogger(__name__)


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
    """Client for interacting with Nessus API."""

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
            # Test connection by getting server info
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
            targets_str = ",".join(targets)
            
            scan_params = {
                "name": name,
                "text_targets": targets_str,
            }
            
            if template_uuid:
                scan_params["uuid"] = template_uuid
            elif policy_id:
                scan_params["policy_id"] = policy_id
            else:
                # Use basic network scan template by default
                basic_uuid = self.get_template_uuid("basic")
                if basic_uuid:
                    scan_params["uuid"] = basic_uuid
                else:
                    raise NessusScanError("No template or policy specified and default template not found")
            
            if folder_id:
                scan_params["folder_id"] = folder_id
                
            if description:
                scan_params["description"] = description
                
            scan = self.client.scans.create(**scan_params)
            scan_id = scan.get("id")
            logger.info("Created scan '%s' with ID %s", name, scan_id)
            return scan_id
            
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
        try:
            result = self.client.scans.launch(scan_id)
            scan_uuid = result.get("scan_uuid")
            logger.info("Launched scan %s, UUID: %s", scan_id, scan_uuid)
            return scan_uuid
        except Exception as e:
            logger.error("Failed to launch scan %s: %s", scan_id, str(e))
            raise NessusScanError(f"Failed to launch scan: {e}") from e

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
                
                # Get host details with vulnerabilities
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
                    
                    # Get detailed plugin information
                    try:
                        plugin_output = self.client.scans.plugin_output(
                            scan_id, host_id, plugin_id
                        )
                        plugin_info = plugin_output.get("info", {}).get("plugindescription", {})
                        plugin_attrs = plugin_info.get("pluginattributes", {})
                    except Exception:
                        plugin_info = {}
                        plugin_attrs = {}
                    
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
                        risk_factor=plugin_attrs.get("risk_information", {}).get("risk_factor", ""),
                        cvss_base_score=plugin_attrs.get("risk_information", {}).get("cvss_base_score"),
                        cvss3_base_score=plugin_attrs.get("risk_information", {}).get("cvss3_base_score"),
                        cve=plugin_attrs.get("ref_information", {}).get("cve", []),
                        references=plugin_attrs.get("ref_information", {}).get("xref", []),
                        plugin_output=plugin_output.get("output"),
                    )
                    vulnerabilities.append(vulnerability)
                    
        except Exception as e:
            logger.error("Failed to extract vulnerabilities: %s", str(e))
            raise NessusScanError(f"Failed to extract vulnerabilities: {e}") from e
            
        return vulnerabilities

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
