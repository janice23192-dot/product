"""Security event data models.

Implements SecurityEvent, ParsedEvent, NormalizedEntity and supporting types.
Req 1.8, 1.10, 28.1-28.12.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import orjson
from pydantic import BaseModel, Field, field_validator


class ClassificationLevel(str, Enum):
    """Data classification levels. Req 10.7."""

    UNCLASSIFIED = "unclassified"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"
    TOP_SECRET = "top_secret"


class EntityType(str, Enum):
    """Types of entities tracked by the platform. Req 3.1."""

    USER = "user"
    HOST = "host"
    IP = "ip"
    DOMAIN = "domain"
    FILE = "file"
    PROCESS = "process"
    EMAIL = "email"
    DEVICE = "device"
    ORGANIZATION = "organization"
    URL = "url"
    NETWORK_SEGMENT = "network_segment"
    SERVICE_ACCOUNT = "service_account"


class EntityReference(BaseModel):
    """Reference to an entity within an event."""

    entity_type: EntityType
    identifier: str
    role: str = "unknown"  # e.g., "source", "target", "actor"


class NormalizedEntity(BaseModel):
    """A normalized entity extracted from events. Req 28.4, 28.5."""

    entity_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    entity_type: EntityType
    identifiers: dict[str, str] = Field(default_factory=dict)
    attributes: dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)

    @field_validator("identifiers")
    @classmethod
    def validate_identifiers(cls, v: dict[str, str]) -> dict[str, str]:
        if not v:
            raise ValueError("Entity must have at least one identifier")
        return v


class RawEvent(BaseModel):
    """Raw event data before parsing."""

    source_id: str
    raw_data: bytes
    received_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_type: str = "unknown"


class ParsedEvent(BaseModel):
    """A parsed and normalized security event. Req 1.8, 1.10, 28.1."""

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime
    source_id: str
    event_type: str
    severity: int = Field(default=0, ge=0, le=100)
    entities: list[NormalizedEntity] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)
    raw_data: bytes = b""
    classification: ClassificationLevel = ClassificationLevel.UNCLASSIFIED
    ingestion_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    tags: dict[str, str] = Field(default_factory=dict)

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: int) -> int:
        return max(0, min(100, v))

    def fingerprint(self) -> str:
        """Generate a fingerprint for deduplication. Req 1.9."""
        data = f"{self.source_id}:{self.event_type}:{self.timestamp.isoformat()}"
        for entity in sorted(self.entities, key=lambda e: e.entity_id):
            data += f":{entity.entity_type.value}:{entity.identifier if hasattr(entity, 'identifier') else ''}"
        for key in sorted(self.attributes.keys()):
            data += f":{key}={self.attributes[key]}"
        return hashlib.sha256(data.encode()).hexdigest()

    def to_json(self) -> bytes:
        """Serialize to JSON. Req 28.11."""
        return orjson.dumps(self.model_dump(mode="json"))

    @classmethod
    def from_json(cls, data: bytes) -> ParsedEvent:
        """Deserialize from JSON. Req 28.12."""
        return cls.model_validate(orjson.loads(data))


class SecurityEvent(ParsedEvent):
    """Enriched security event with additional context.

    Extends ParsedEvent with enrichment data, threat context, and
    correlation information. This is the primary event type used
    throughout the analytics pipeline.
    """

    enrichments: dict[str, Any] = Field(default_factory=dict)
    threat_indicators: list[str] = Field(default_factory=list)
    geo_location: dict[str, Any] | None = None
    asset_context: dict[str, Any] | None = None
    correlation_ids: list[str] = Field(default_factory=list)
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
