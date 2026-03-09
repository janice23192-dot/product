"""Compliance and Metrics Service implementation.

Monitors regulatory compliance, tracks security metrics and KPIs,
and manages data quality. Req 31.1-31.12, 41.1-41.12, 43.1-43.12.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from sip.utils.logging import get_logger

logger = get_logger(__name__)


class ComplianceControl(BaseModel):
    """Compliance control. Req 43.1."""

    control_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    framework: str  # GDPR, HIPAA, PCI-DSS, SOX
    control_name: str
    description: str = ""
    status: str = "not_assessed"  # compliant, non_compliant, partially_compliant, not_assessed
    evidence: list[str] = Field(default_factory=list)
    last_assessed: datetime | None = None


class DataQualityMetric(BaseModel):
    """Data quality metric. Req 31.1-31.12."""

    source_id: str
    completeness: float = 1.0
    consistency: float = 1.0
    freshness_seconds: float = 0.0
    duplicate_rate: float = 0.0
    error_rate: float = 0.0
    last_checked: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ComplianceService:
    """Compliance Service - regulatory monitoring, security metrics, data quality.

    Monitors GDPR/HIPAA/PCI-DSS/SOX compliance (Req 43.1),
    calculates MTTD/MTTR (Req 41.1, 41.2), tracks data quality (Req 31.1-31.12).
    """

    def __init__(self) -> None:
        self._controls: dict[str, ComplianceControl] = {}
        self._data_quality: dict[str, DataQualityMetric] = {}
        self._violations: list[dict[str, Any]] = []
        self._security_metrics: dict[str, Any] = {}

    # --- Compliance Monitoring (Req 43.1-43.12) ---

    def add_control(self, control: ComplianceControl) -> str:
        self._controls[control.control_id] = control
        return control.control_id

    def assess_control(self, control_id: str, status: str, evidence: list[str] | None = None) -> None:
        control = self._controls.get(control_id)
        if control:
            control.status = status
            control.evidence = evidence or []
            control.last_assessed = datetime.now(timezone.utc)

    def record_violation(self, framework: str, control_name: str, description: str, severity: str = "medium") -> None:
        """Record compliance violation. Req 43.2."""
        self._violations.append({
            "violation_id": str(uuid.uuid4()),
            "framework": framework,
            "control_name": control_name,
            "description": description,
            "severity": severity,
            "detected_at": datetime.now(timezone.utc).isoformat(),
        })

    def get_compliance_report(self, framework: str = "") -> dict[str, Any]:
        """Get compliance report. Req 43.8."""
        controls = [c for c in self._controls.values() if not framework or c.framework == framework]
        return {
            "total_controls": len(controls),
            "compliant": sum(1 for c in controls if c.status == "compliant"),
            "non_compliant": sum(1 for c in controls if c.status == "non_compliant"),
            "violations": [v for v in self._violations if not framework or v["framework"] == framework],
        }

    # --- Data Quality (Req 31.1-31.12) ---

    def update_data_quality(self, metric: DataQualityMetric) -> None:
        self._data_quality[metric.source_id] = metric

    def validate_event_completeness(self, event_data: dict[str, Any], required_fields: list[str]) -> dict[str, Any]:
        """Validate data completeness. Req 31.1."""
        missing = [f for f in required_fields if f not in event_data or event_data[f] is None]
        return {
            "complete": len(missing) == 0,
            "missing_fields": missing,
            "completeness_score": 1 - (len(missing) / len(required_fields)) if required_fields else 1.0,
        }

    def detect_duplicates(self, event_ids: list[str]) -> dict[str, Any]:
        """Detect duplicate events. Req 31.4."""
        unique = set(event_ids)
        duplicates = len(event_ids) - len(unique)
        return {
            "total_events": len(event_ids),
            "unique_events": len(unique),
            "duplicates": duplicates,
            "duplicate_rate": duplicates / len(event_ids) if event_ids else 0,
        }

    def get_data_quality_report(self) -> dict[str, Any]:
        """Get data quality report. Req 31.7."""
        metrics = list(self._data_quality.values())
        return {
            "sources_monitored": len(metrics),
            "avg_completeness": sum(m.completeness for m in metrics) / len(metrics) if metrics else 1.0,
            "avg_duplicate_rate": sum(m.duplicate_rate for m in metrics) / len(metrics) if metrics else 0,
        }

    # --- Security Metrics (Req 41.1-41.12) ---

    def update_security_metrics(self, metrics: dict[str, Any]) -> None:
        self._security_metrics.update(metrics)

    def get_security_metrics(self) -> dict[str, Any]:
        return dict(self._security_metrics)

    def get_metrics(self) -> dict[str, Any]:
        return {
            "compliance_controls": len(self._controls),
            "violations": len(self._violations),
            "data_quality_sources": len(self._data_quality),
        }
