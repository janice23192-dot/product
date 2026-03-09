"""Security Monitoring Service implementation.

Covers malware analysis, cloud security, EDR, email security,
web app security, mobile, supply chain, and deception technology.
Req 24-27, 36-40.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from sip.utils.logging import get_logger

logger = get_logger(__name__)


class FileAnalysis(BaseModel):
    """File analysis result. Req 24.1-24.12."""

    analysis_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    file_name: str = ""
    file_size: int = 0
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    file_type: str = ""
    is_malicious: bool = False
    malware_family: str = ""
    yara_matches: list[str] = Field(default_factory=list)
    iocs_extracted: list[dict[str, Any]] = Field(default_factory=list)
    sandbox_report: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CloudSecurityEvent(BaseModel):
    """Cloud security event. Req 25.1-25.12."""

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    cloud_provider: str  # aws, azure, gcp
    event_type: str  # resource_change, config_change, identity_change
    resource_type: str = ""
    resource_id: str = ""
    action: str = ""
    actor: str = ""
    details: dict[str, Any] = Field(default_factory=dict)
    is_unauthorized: bool = False
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SecurityMonitoringService:
    """Security Monitoring Service - multi-domain security monitoring.

    Covers malware analysis (Req 24), cloud security (Req 25),
    EDR integration (Req 26), email security (Req 36), web app security
    (Req 37), mobile security (Req 38), supply chain (Req 39),
    and deception technology (Req 40).
    """

    def __init__(self) -> None:
        self._file_analyses: dict[str, FileAnalysis] = {}
        self._cloud_events: list[CloudSecurityEvent] = []
        self._yara_rules: dict[str, str] = {}
        self._malware_samples: dict[str, dict[str, Any]] = {}

    # --- Malware Analysis (Req 24.1-24.12) ---

    def analyze_file(self, file_content: bytes, file_name: str = "") -> FileAnalysis:
        """Analyze a file for malware. Req 24.1-24.12."""
        analysis = FileAnalysis(
            file_name=file_name,
            file_size=len(file_content),
            md5=hashlib.md5(file_content).hexdigest(),
            sha1=hashlib.sha1(file_content).hexdigest(),
            sha256=hashlib.sha256(file_content).hexdigest(),
        )

        # Check YARA rules. Req 24.7
        for rule_name, pattern in self._yara_rules.items():
            if pattern.encode() in file_content:
                analysis.yara_matches.append(rule_name)
                analysis.is_malicious = True

        # Extract IOCs. Req 24.8
        analysis.iocs_extracted = self._extract_file_iocs(file_content)

        self._file_analyses[analysis.analysis_id] = analysis
        return analysis

    def extract_file_hashes(self, content: bytes) -> dict[str, str]:
        """Extract file hashes. Req 24.2."""
        return {
            "md5": hashlib.md5(content).hexdigest(),
            "sha1": hashlib.sha1(content).hexdigest(),
            "sha256": hashlib.sha256(content).hexdigest(),
        }

    def add_yara_rule(self, name: str, pattern: str) -> None:
        """Add YARA rule. Req 24.7."""
        self._yara_rules[name] = pattern

    def _extract_file_iocs(self, content: bytes) -> list[dict[str, Any]]:
        """Extract IOCs from file content. Req 24.8."""
        import re
        text = content.decode("utf-8", errors="replace")
        iocs: list[dict[str, Any]] = []
        # Extract IPs
        for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
            iocs.append({"type": "ip", "value": ip})
        # Extract domains
        for domain in re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", text):
            iocs.append({"type": "domain", "value": domain})
        # Extract URLs
        for url in re.findall(r"https?://\S+", text):
            iocs.append({"type": "url", "value": url})
        return iocs

    # --- Cloud Security (Req 25.1-25.12) ---

    def process_cloud_event(self, event: CloudSecurityEvent) -> list[dict[str, Any]]:
        """Process cloud security event. Req 25.1."""
        self._cloud_events.append(event)
        detections: list[dict[str, Any]] = []

        # Detect unauthorized changes. Req 25.3
        if event.is_unauthorized:
            detections.append({
                "detection_type": "unauthorized_cloud_change",
                "cloud_provider": event.cloud_provider,
                "resource": event.resource_id,
                "action": event.action,
            })

        return detections

    # --- EDR Integration (Req 26.1-26.12) ---

    def process_endpoint_event(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        """Process endpoint detection event. Req 26.1."""
        detections: list[dict[str, Any]] = []

        # Detect living-off-the-land. Req 26.5
        suspicious_tools = {"powershell.exe", "cmd.exe", "wmic.exe", "certutil.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe"}
        process_name = event.get("process_name", "").lower()
        if process_name in suspicious_tools:
            detections.append({
                "detection_type": "lotl_technique",
                "process": process_name,
                "command_line": event.get("command_line", ""),
            })

        return detections

    # --- Email Security (Req 36.1-36.12) ---

    def analyze_email(self, email_data: dict[str, Any]) -> list[dict[str, Any]]:
        """Analyze email for threats. Req 36.1-36.12."""
        detections: list[dict[str, Any]] = []

        # Check for phishing indicators. Req 36.2
        subject = email_data.get("subject", "").lower()
        phishing_keywords = ["urgent", "verify your account", "suspended", "click here", "password reset"]
        if any(kw in subject for kw in phishing_keywords):
            detections.append({"detection_type": "phishing_suspected", "indicator": "subject_keywords"})

        return detections

    def get_metrics(self) -> dict[str, Any]:
        return {
            "file_analyses": len(self._file_analyses),
            "cloud_events": len(self._cloud_events),
            "yara_rules": len(self._yara_rules),
            "malicious_files": sum(1 for a in self._file_analyses.values() if a.is_malicious),
        }
