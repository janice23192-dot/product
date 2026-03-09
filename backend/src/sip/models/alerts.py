"""Alert and incident data models.

Implements Alert, Incident, DetectionResult and supporting types.
Req 2.1-2.10, 17.1-17.12, 32.1-32.12.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class AlertStatus(str, Enum):
    """Alert lifecycle states. Req 17.7."""

    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    SUPPRESSED = "suppressed"


class IncidentStatus(str, Enum):
    """Incident lifecycle states. Req 32.1."""

    DETECTED = "detected"
    TRIAGED = "triaged"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    ERADICATED = "eradicated"
    RECOVERED = "recovered"
    CLOSED = "closed"


class DetectionResult(BaseModel):
    """Result from the threat detection engine. Req 2.1-2.10."""

    detection_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    rule_id: str
    rule_name: str = ""
    event_id: str
    severity: int = Field(ge=1, le=100)
    confidence: float = Field(ge=0.0, le=1.0)
    threat_type: str
    rule_type: str = "signature"  # signature, anomaly, behavioral, statistical, ml
    affected_entities: list[str] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: int) -> int:
        return max(1, min(100, v))


class AlertResolution(BaseModel):
    """Resolution details for a closed alert."""

    resolution_type: str  # true_positive, false_positive, benign
    summary: str
    actions_taken: list[str] = Field(default_factory=list)
    resolved_by: str = ""
    resolved_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Alert(BaseModel):
    """Security alert with full lifecycle tracking. Req 17.1-17.12."""

    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    detection_id: str
    rule_id: str = ""
    title: str = ""
    description: str = ""
    severity: int = Field(ge=1, le=100)
    confidence: float = Field(ge=0.0, le=1.0)
    status: AlertStatus = AlertStatus.NEW
    assigned_to: str | None = None
    priority: int = Field(default=50, ge=1, le=100)
    affected_entities: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    source_events: list[str] = Field(default_factory=list)
    incident_id: str | None = None
    tags: list[str] = Field(default_factory=list)
    notification_channels: list[str] = Field(default_factory=list)
    escalation_level: int = Field(default=0, ge=0)
    suppression_rule_id: str | None = None
    resolution: AlertResolution | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    acknowledged_at: datetime | None = None
    resolved_at: datetime | None = None
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def acknowledge(self, analyst: str) -> None:
        """Acknowledge the alert. Req 17.7."""
        self.status = AlertStatus.ACKNOWLEDGED
        self.assigned_to = analyst
        self.acknowledged_at = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc)

    def resolve(self, resolution: AlertResolution) -> None:
        """Resolve the alert. Req 17.7."""
        self.status = AlertStatus.RESOLVED
        self.resolution = resolution
        self.resolved_at = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc)

    def escalate(self) -> None:
        """Escalate the alert. Req 17.6, 17.11."""
        self.escalation_level += 1
        self.updated_at = datetime.now(timezone.utc)

    def calculate_priority(self, business_impact: float = 1.0) -> int:
        """Calculate alert priority. Req 17.1."""
        score = (self.severity * 0.4 + self.confidence * 100 * 0.3 + business_impact * 100 * 0.3)
        self.priority = max(1, min(100, int(score)))
        return self.priority


class Incident(BaseModel):
    """Security incident grouping related alerts. Req 32.1-32.12."""

    incident_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str = ""
    severity: int = Field(ge=1, le=100)
    status: IncidentStatus = IncidentStatus.DETECTED
    priority: int = Field(default=50, ge=1, le=100)
    assigned_to: list[str] = Field(default_factory=list)
    alert_ids: list[str] = Field(default_factory=list)
    affected_entities: list[str] = Field(default_factory=list)
    case_id: str | None = None
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    category: str = ""  # Standardized taxonomy. Req 32.10
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    containment_actions: list[str] = Field(default_factory=list)
    lessons_learned: str = ""
    detection_time: datetime | None = None
    response_time: datetime | None = None
    containment_time: datetime | None = None
    resolution_time: datetime | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def add_alert(self, alert_id: str) -> None:
        """Add an alert to this incident. Req 2.5."""
        if alert_id not in self.alert_ids:
            self.alert_ids.append(alert_id)
            self.updated_at = datetime.now(timezone.utc)

    def add_timeline_event(self, event_type: str, description: str, details: dict[str, Any] | None = None) -> None:
        """Add event to incident timeline. Req 32.5."""
        self.timeline.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "description": description,
            "details": details or {},
        })
        self.updated_at = datetime.now(timezone.utc)
