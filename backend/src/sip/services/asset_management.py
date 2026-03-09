"""Asset and Vulnerability Management Service implementation.

Manages asset discovery, inventory, risk scoring, and vulnerability tracking.
Req 34.1-34.12, 35.1-35.12.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from sip.utils.logging import get_logger

logger = get_logger(__name__)


class Asset(BaseModel):
    """Asset record. Req 34.1-34.12."""

    asset_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    hostname: str = ""
    ip_addresses: list[str] = Field(default_factory=list)
    mac_addresses: list[str] = Field(default_factory=list)
    os_type: str = ""
    os_version: str = ""
    asset_type: str = "unknown"  # server, workstation, network_device, cloud_resource
    owner: str = ""
    business_unit: str = ""
    criticality: str = "medium"  # low, medium, high, critical
    classification: str = "unclassified"
    tags: list[str] = Field(default_factory=list)
    software_inventory: list[dict[str, Any]] = Field(default_factory=list)
    vulnerabilities: list[dict[str, Any]] = Field(default_factory=list)
    risk_score: float = 0.0
    status: str = "active"
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Vulnerability(BaseModel):
    """Vulnerability record. Req 35.1-35.12."""

    vuln_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    cve_id: str = ""
    title: str = ""
    description: str = ""
    severity: str = "medium"
    cvss_score: float = 0.0
    affected_assets: list[str] = Field(default_factory=list)
    status: str = "open"  # open, patched, mitigated, accepted
    remediation_status: str = ""
    first_detected: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AssetManagementService:
    """Asset Management Service - discovery, inventory, and risk scoring.

    Discovers assets (Req 34.1), tracks inventory (Req 34.2),
    calculates risk scores (Req 34.7), and manages vulnerabilities (Req 35.1-35.12).
    """

    def __init__(self) -> None:
        self._assets: dict[str, Asset] = {}
        self._vulnerabilities: dict[str, Vulnerability] = {}
        self._ip_to_asset: dict[str, str] = {}

    def register_asset(self, asset: Asset) -> str:
        """Register or update an asset. Req 34.1."""
        self._assets[asset.asset_id] = asset
        for ip in asset.ip_addresses:
            self._ip_to_asset[ip] = asset.asset_id
        return asset.asset_id

    def discover_asset_from_event(self, ip: str, hostname: str = "") -> Asset:
        """Discover asset from event data. Req 34.1."""
        if ip in self._ip_to_asset:
            asset = self._assets[self._ip_to_asset[ip]]
            asset.last_seen = datetime.now(timezone.utc)
            return asset

        asset = Asset(ip_addresses=[ip], hostname=hostname)
        self.register_asset(asset)
        return asset

    def add_vulnerability(self, vuln: Vulnerability) -> str:
        """Add vulnerability. Req 35.1."""
        self._vulnerabilities[vuln.vuln_id] = vuln
        return vuln.vuln_id

    def calculate_asset_risk(self, asset_id: str) -> float:
        """Calculate asset risk score. Req 34.7."""
        asset = self._assets.get(asset_id)
        if not asset:
            return 0.0

        score = 0.0
        criticality_map = {"low": 10, "medium": 25, "high": 50, "critical": 75}
        score += criticality_map.get(asset.criticality, 25)

        vuln_score = sum(v.cvss_score for v in self._vulnerabilities.values() if asset_id in v.affected_assets)
        score += min(25.0, vuln_score)

        asset.risk_score = min(100.0, score)
        return asset.risk_score

    def get_asset(self, asset_id: str) -> Asset | None:
        return self._assets.get(asset_id)

    def get_asset_by_ip(self, ip: str) -> Asset | None:
        asset_id = self._ip_to_asset.get(ip)
        return self._assets.get(asset_id) if asset_id else None

    def get_metrics(self) -> dict[str, Any]:
        return {
            "total_assets": len(self._assets),
            "total_vulnerabilities": len(self._vulnerabilities),
            "open_vulnerabilities": sum(1 for v in self._vulnerabilities.values() if v.status == "open"),
        }
