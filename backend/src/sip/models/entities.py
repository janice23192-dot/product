"""Entity data models for the correlation engine.

Implements Entity, EntityRelationship, AttributeChange, RiskFactor.
Req 3.1-3.10, 34.1-34.12.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class AttributeChange(BaseModel):
    """Tracks changes to entity attributes over time. Req 3.10."""

    attribute_name: str
    old_value: Any = None
    new_value: Any = None
    changed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_id: str = ""
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)


class RiskFactor(BaseModel):
    """A contributing factor to an entity's risk score. Req 22.3, 34.7."""

    factor_type: str  # e.g., "vulnerability", "behavioral_anomaly", "threat_indicator"
    description: str
    score: float = Field(ge=0.0, le=100.0)
    weight: float = Field(default=1.0, ge=0.0, le=1.0)
    source: str = ""
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None


class Entity(BaseModel):
    """A distinct entity tracked by the platform. Req 3.1-3.10."""

    entity_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    entity_type: str  # user, host, ip, domain, file, process, email, device
    canonical_id: str = ""  # Resolved canonical identifier. Req 3.2
    identifiers: dict[str, str] = Field(default_factory=dict)
    attributes: dict[str, Any] = Field(default_factory=dict)
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    risk_factors: list[RiskFactor] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    classification: str = "unclassified"
    source_ids: list[str] = Field(default_factory=list)
    attribute_history: list[AttributeChange] = Field(default_factory=list)
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def update_attribute(self, name: str, value: Any, source_id: str = "", confidence: float = 1.0) -> None:
        """Update an attribute and record the change. Req 3.10."""
        old_value = self.attributes.get(name)
        if old_value != value:
            change = AttributeChange(
                attribute_name=name,
                old_value=old_value,
                new_value=value,
                source_id=source_id,
                confidence=confidence,
            )
            self.attribute_history.append(change)
            self.attributes[name] = value
            self.updated_at = datetime.now(timezone.utc)

    def calculate_risk_score(self) -> float:
        """Calculate composite risk score from factors. Req 22.3."""
        if not self.risk_factors:
            self.risk_score = 0.0
            return 0.0
        total_weight = sum(f.weight for f in self.risk_factors)
        if total_weight == 0:
            self.risk_score = 0.0
            return 0.0
        weighted_sum = sum(f.score * f.weight for f in self.risk_factors)
        self.risk_score = min(100.0, weighted_sum / total_weight)
        return self.risk_score

    def add_identifier(self, id_type: str, id_value: str) -> None:
        """Add an identifier to this entity."""
        self.identifiers[id_type] = id_value
        self.updated_at = datetime.now(timezone.utc)

    def merge_from(self, other: Entity) -> None:
        """Merge another entity into this one. Req 3.2."""
        for k, v in other.identifiers.items():
            if k not in self.identifiers:
                self.identifiers[k] = v
        for k, v in other.attributes.items():
            if k not in self.attributes:
                self.attributes[k] = v
        self.source_ids = list(set(self.source_ids + other.source_ids))
        self.risk_factors.extend(other.risk_factors)
        self.attribute_history.extend(other.attribute_history)
        self.tags = list(set(self.tags + other.tags))
        if other.first_seen < self.first_seen:
            self.first_seen = other.first_seen
        if other.last_seen > self.last_seen:
            self.last_seen = other.last_seen
        self.calculate_risk_score()


class EntityRelationship(BaseModel):
    """Relationship between two entities. Req 3.1."""

    relationship_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source_entity_id: str
    target_entity_id: str
    relationship_type: str  # CONNECTED_TO, EXECUTED, ACCESSED, COMMUNICATED_WITH, PARENT_OF
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    attributes: dict[str, Any] = Field(default_factory=dict)
    occurrence_count: int = Field(default=1, ge=1)
    first_observed: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_observed: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def increment(self) -> None:
        """Record another occurrence of this relationship."""
        self.occurrence_count += 1
        self.last_observed = datetime.now(timezone.utc)
