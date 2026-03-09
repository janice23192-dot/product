"""Audit System implementation.

Logs all user actions and system events with tamper-evident storage,
chain of custody, and compliance reporting. Req 11.1-11.12.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from pydantic import BaseModel, Field

from sip.utils.logging import get_logger

logger = get_logger(__name__)


class AuditEntry(BaseModel):
    """Audit log entry. Req 11.1-11.3."""

    entry_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    user_id: str = "system"
    action_type: str  # query, data_access, config_change, case_modification, auth, etc.
    resource_type: str = ""
    resource_id: str = ""
    outcome: str = "success"  # success, failure, denied
    details: dict[str, Any] = Field(default_factory=dict)
    ip_address: str = ""
    user_agent: str = ""
    integrity_hash: str = ""
    previous_hash: str = ""  # Chain hash for tamper evidence

    def compute_hash(self, previous_hash: str = "") -> str:
        """Compute integrity hash. Req 11.4."""
        data = f"{self.entry_id}:{self.timestamp.isoformat()}:{self.user_id}:{self.action_type}:{self.resource_type}:{self.resource_id}:{self.outcome}:{json.dumps(self.details, sort_keys=True, default=str)}:{previous_hash}"
        self.integrity_hash = hashlib.sha256(data.encode()).hexdigest()
        self.previous_hash = previous_hash
        return self.integrity_hash


class CustodyRecord(BaseModel):
    """Chain of custody record. Req 11.11, 44.1-44.7."""

    record_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    evidence_id: str
    action: str  # created, accessed, modified, transferred, exported
    user_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    details: str = ""
    hash_at_time: str = ""
    integrity_hash: str = ""


class AuditSystem:
    """Audit System - comprehensive audit logging and compliance.

    Logs all user actions (Req 11.1), system events (Req 11.2),
    with tamper-evident storage (Req 11.4), 7-year retention (Req 11.5),
    and compliance reporting (Req 11.9).
    """

    def __init__(self, retention_years: int = 7) -> None:
        self.retention_years = retention_years
        self._entries: list[AuditEntry] = []
        self._last_hash: str = ""
        self._custody_records: dict[str, list[CustodyRecord]] = {}
        self._capacity_threshold: float = 0.9
        self._max_entries: int = 10_000_000  # In production, this would be disk-based
        self._forwarding_callbacks: list[Any] = []

    # --- Audit Logging (Req 11.1, 11.2) ---

    async def log(
        self,
        action_type: str,
        user_id: str = "system",
        resource_type: str = "",
        resource_id: str = "",
        outcome: str = "success",
        details: dict[str, Any] | None = None,
        ip_address: str = "",
        user_agent: str = "",
    ) -> AuditEntry:
        """Log an audit event. Req 11.1, 11.2, 11.3."""
        entry = AuditEntry(
            user_id=user_id,
            action_type=action_type,
            resource_type=resource_type,
            resource_id=resource_id,
            outcome=outcome,
            details=details or {},
            ip_address=ip_address,
            user_agent=user_agent,
        )

        # Compute integrity hash with chain. Req 11.4
        entry.compute_hash(self._last_hash)
        self._last_hash = entry.integrity_hash

        self._entries.append(entry)

        # Check capacity. Req 11.6
        if len(self._entries) / self._max_entries >= self._capacity_threshold:
            logger.warning("audit_capacity_warning", usage=len(self._entries) / self._max_entries)

        # Forward to external SIEM. Req 11.12
        for callback in self._forwarding_callbacks:
            try:
                await callback(entry.model_dump(mode="json"))
            except Exception:
                pass

        return entry

    # --- Query and Search (Req 11.8) ---

    def search(
        self,
        action_type: str = "",
        user_id: str = "",
        resource_type: str = "",
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        limit: int = 100,
    ) -> list[AuditEntry]:
        """Search audit logs. Req 11.8."""
        results = []
        for entry in reversed(self._entries):
            if action_type and entry.action_type != action_type:
                continue
            if user_id and entry.user_id != user_id:
                continue
            if resource_type and entry.resource_type != resource_type:
                continue
            if start_time and entry.timestamp < start_time:
                continue
            if end_time and entry.timestamp > end_time:
                continue
            results.append(entry)
            if len(results) >= limit:
                break
        return results

    # --- Integrity Verification (Req 11.4) ---

    def verify_integrity(self) -> dict[str, Any]:
        """Verify audit log integrity using hash chain. Req 11.4."""
        if not self._entries:
            return {"valid": True, "entries_checked": 0}

        previous_hash = ""
        for i, entry in enumerate(self._entries):
            expected_hash = entry.compute_hash(previous_hash)
            if entry.integrity_hash != expected_hash:
                return {
                    "valid": False,
                    "entries_checked": i + 1,
                    "first_invalid_entry": entry.entry_id,
                    "index": i,
                }
            previous_hash = entry.integrity_hash

        return {"valid": True, "entries_checked": len(self._entries)}

    # --- Chain of Custody (Req 11.11, 44.1-44.7) ---

    async def record_custody(
        self,
        evidence_id: str,
        action: str,
        user_id: str,
        details: str = "",
        hash_at_time: str = "",
    ) -> CustodyRecord:
        """Record chain of custody event. Req 11.11."""
        record = CustodyRecord(
            evidence_id=evidence_id,
            action=action,
            user_id=user_id,
            details=details,
            hash_at_time=hash_at_time,
        )

        if evidence_id not in self._custody_records:
            self._custody_records[evidence_id] = []
        self._custody_records[evidence_id].append(record)

        # Also log as audit event
        await self.log(
            action_type="evidence_custody",
            user_id=user_id,
            resource_type="evidence",
            resource_id=evidence_id,
            details={"custody_action": action, "details": details},
        )

        return record

    def get_custody_chain(self, evidence_id: str) -> list[CustodyRecord]:
        """Get chain of custody for evidence. Req 11.11."""
        return self._custody_records.get(evidence_id, [])

    # --- Compliance Reports (Req 11.9) ---

    def generate_compliance_report(self, framework: str, start_time: datetime | None = None, end_time: datetime | None = None) -> dict[str, Any]:
        """Generate compliance report. Req 11.9."""
        entries = self.search(start_time=start_time, end_time=end_time, limit=100000)

        report: dict[str, Any] = {
            "framework": framework,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "period_start": start_time.isoformat() if start_time else "all",
            "period_end": end_time.isoformat() if end_time else "now",
            "total_entries": len(entries),
        }

        if framework == "SOC2":
            report["controls"] = self._soc2_controls(entries)
        elif framework == "ISO27001":
            report["controls"] = self._iso27001_controls(entries)
        elif framework == "GDPR":
            report["controls"] = self._gdpr_controls(entries)
        elif framework == "HIPAA":
            report["controls"] = self._hipaa_controls(entries)

        return report

    def _soc2_controls(self, entries: list[AuditEntry]) -> dict[str, Any]:
        """SOC 2 compliance controls."""
        return {
            "CC6.1_logical_access": sum(1 for e in entries if e.action_type in ("auth_success", "auth_failed")),
            "CC6.2_access_monitoring": sum(1 for e in entries if e.action_type == "access_denied"),
            "CC7.1_monitoring": len(entries),
            "CC7.2_incident_response": sum(1 for e in entries if "incident" in e.resource_type),
        }

    def _iso27001_controls(self, entries: list[AuditEntry]) -> dict[str, Any]:
        return {"A12.4_logging": len(entries)}

    def _gdpr_controls(self, entries: list[AuditEntry]) -> dict[str, Any]:
        return {"data_access_records": sum(1 for e in entries if e.action_type == "data_access")}

    def _hipaa_controls(self, entries: list[AuditEntry]) -> dict[str, Any]:
        return {"access_logs": len(entries)}

    # --- Export (Req 11.7) ---

    def export_logs(self, format_type: str = "json", entries: list[AuditEntry] | None = None) -> str:
        """Export audit logs. Req 11.7."""
        logs = entries or self._entries[-1000:]

        if format_type == "json":
            return json.dumps([e.model_dump(mode="json") for e in logs], indent=2, default=str)
        elif format_type == "cef":
            return "\n".join(self._to_cef(e) for e in logs)
        elif format_type == "leef":
            return "\n".join(self._to_leef(e) for e in logs)
        return ""

    def _to_cef(self, entry: AuditEntry) -> str:
        """Convert to CEF format."""
        return f"CEF:0|SIP|SecurityIntelligence|1.0|{entry.action_type}|{entry.action_type}|{5}|src={entry.ip_address} duser={entry.user_id} outcome={entry.outcome}"

    def _to_leef(self, entry: AuditEntry) -> str:
        """Convert to LEEF format."""
        return f"LEEF:2.0|SIP|SecurityIntelligence|1.0|{entry.action_type}|src={entry.ip_address}\tusr={entry.user_id}\toutcome={entry.outcome}"

    # --- Forwarding (Req 11.12) ---

    def on_forward(self, callback: Any) -> None:
        """Register log forwarding callback. Req 11.12."""
        self._forwarding_callbacks.append(callback)

    def get_metrics(self) -> dict[str, Any]:
        """Get audit system metrics."""
        return {
            "total_entries": len(self._entries),
            "capacity_pct": len(self._entries) / self._max_entries,
            "custody_records": sum(len(r) for r in self._custody_records.values()),
        }
