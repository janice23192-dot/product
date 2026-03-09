"""Case management data models.

Implements Case, Evidence, Hypothesis, Finding, WorkspaceState.
Req 19.1-19.14, 44.1-44.12.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class CaseStatus(str, Enum):
    """Case lifecycle states. Req 19.3."""

    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"


class EvidenceType(str, Enum):
    """Types of evidence. Req 19.4."""

    EVENT = "event"
    ENTITY = "entity"
    FILE = "file"
    SCREENSHOT = "screenshot"
    NETWORK_CAPTURE = "network_capture"
    MEMORY_DUMP = "memory_dump"
    LOG_EXTRACT = "log_extract"
    EXTERNAL_REFERENCE = "external_reference"


class Evidence(BaseModel):
    """Evidence attached to a case with chain of custody. Req 44.1-44.7."""

    evidence_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    evidence_type: EvidenceType
    title: str
    description: str = ""
    source_reference: str = ""  # ID or URL of the source
    content_hash: str = ""  # SHA-256 hash for integrity. Req 44.1
    storage_path: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    classification: str = "unclassified"
    chain_of_custody: list[dict[str, Any]] = Field(default_factory=list)
    created_by: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_immutable: bool = True  # Req 44.5

    def add_custody_record(self, action: str, user: str, details: str = "") -> None:
        """Add a chain of custody record. Req 44.7."""
        self.chain_of_custody.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "user": user,
            "details": details,
            "hash_at_time": self.content_hash,
        })

    def compute_hash(self, content: bytes) -> str:
        """Compute SHA-256 hash for content integrity. Req 44.1."""
        self.content_hash = hashlib.sha256(content).hexdigest()
        return self.content_hash


class Hypothesis(BaseModel):
    """Investigation hypothesis. Req 23.1."""

    hypothesis_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    status: str = "proposed"  # proposed, investigating, confirmed, rejected
    supporting_evidence: list[str] = Field(default_factory=list)
    contradicting_evidence: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    created_by: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Finding(BaseModel):
    """Investigation finding/conclusion. Req 23.1."""

    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    severity: int = Field(default=50, ge=1, le=100)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    recommendations: list[str] = Field(default_factory=list)
    supporting_evidence: list[str] = Field(default_factory=list)
    related_hypotheses: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    created_by: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class WorkspaceState(BaseModel):
    """Saved investigation workspace state. Req 4.8."""

    workspace_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    case_id: str
    queries: list[dict[str, Any]] = Field(default_factory=list)
    visualizations: list[dict[str, Any]] = Field(default_factory=list)
    annotations: list[dict[str, Any]] = Field(default_factory=list)
    pivot_history: list[dict[str, Any]] = Field(default_factory=list)
    layout: dict[str, Any] = Field(default_factory=dict)
    saved_by: str = ""
    saved_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def to_json(self) -> dict[str, Any]:
        """Serialize workspace state."""
        return self.model_dump(mode="json")

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> WorkspaceState:
        """Deserialize workspace state. Supports round-trip."""
        return cls.model_validate(data)


class Case(BaseModel):
    """Investigation case with evidence and findings. Req 19.1-19.14."""

    case_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str = ""
    severity: int = Field(default=50, ge=1, le=100)
    status: CaseStatus = CaseStatus.OPEN
    assigned_to: list[str] = Field(default_factory=list)
    team: str = ""
    tags: list[str] = Field(default_factory=list)
    template_id: str | None = None  # Req 19.6
    evidence: list[Evidence] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    related_case_ids: list[str] = Field(default_factory=list)  # Req 19.8
    related_alert_ids: list[str] = Field(default_factory=list)
    related_incident_ids: list[str] = Field(default_factory=list)
    workspace_state: WorkspaceState | None = None
    access_restrictions: list[str] = Field(default_factory=list)  # Req 19.12
    history: list[dict[str, Any]] = Field(default_factory=list)  # Req 19.7
    metrics: dict[str, Any] = Field(default_factory=dict)  # Req 19.10
    created_by: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    closed_at: datetime | None = None

    def add_evidence(self, evidence: Evidence) -> None:
        """Add evidence to the case. Req 19.4."""
        self.evidence.append(evidence)
        self._record_history("evidence_added", f"Added evidence: {evidence.title}")
        self.updated_at = datetime.now(timezone.utc)

    def update_status(self, new_status: CaseStatus, user: str) -> None:
        """Update case status. Req 19.3."""
        old_status = self.status
        self.status = new_status
        self._record_history("status_changed", f"Status changed from {old_status.value} to {new_status.value}", user)
        if new_status == CaseStatus.CLOSED:
            self.closed_at = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc)

    def _record_history(self, action: str, description: str, user: str = "") -> None:
        """Record a history entry. Req 19.7."""
        self.history.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "description": description,
            "user": user,
        })
