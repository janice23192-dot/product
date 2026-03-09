"""Threat Intelligence Service implementation.

Manages threat actor profiles, campaigns, attribution, and
MITRE ATT&CK mapping. Req 33.1-33.12.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from sip.utils.logging import get_logger

logger = get_logger(__name__)


class ThreatActor(BaseModel):
    """Threat actor profile. Req 33.1."""

    actor_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    aliases: list[str] = Field(default_factory=list)
    description: str = ""
    ttps: list[dict[str, Any]] = Field(default_factory=list)
    infrastructure: list[dict[str, Any]] = Field(default_factory=list)
    targeting: list[dict[str, Any]] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    source: str = "custom"
    campaigns: list[dict[str, Any]] = Field(default_factory=list)
    relationships: list[dict[str, Any]] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ThreatIntelligenceService:
    """Threat Intelligence Service - threat actor profiling and attribution.

    Maintains threat actor profiles (Req 33.1), links activity to actors
    (Req 33.2), supports MITRE ATT&CK mapping (Req 33.4), and
    provides confidence scoring for attribution (Req 33.7).
    """

    def __init__(self) -> None:
        self._actors: dict[str, ThreatActor] = {}
        self._technique_to_actors: dict[str, list[str]] = {}

    def add_threat_actor(self, actor: ThreatActor) -> str:
        """Add a threat actor profile. Req 33.1."""
        self._actors[actor.actor_id] = actor
        for technique in actor.mitre_techniques:
            if technique not in self._technique_to_actors:
                self._technique_to_actors[technique] = []
            self._technique_to_actors[technique].append(actor.actor_id)
        return actor.actor_id

    def get_actor(self, actor_id: str) -> ThreatActor | None:
        return self._actors.get(actor_id)

    def attribute_activity(self, mitre_techniques: list[str], indicators: list[str] | None = None) -> list[dict[str, Any]]:
        """Attribute activity to threat actors. Req 33.2, 33.7."""
        candidates: dict[str, float] = {}
        for technique in mitre_techniques:
            for actor_id in self._technique_to_actors.get(technique, []):
                actor = self._actors.get(actor_id)
                if actor:
                    candidates[actor_id] = candidates.get(actor_id, 0) + actor.confidence / len(actor.mitre_techniques)

        results = []
        for actor_id, score in sorted(candidates.items(), key=lambda x: -x[1]):
            actor = self._actors[actor_id]
            results.append({
                "actor_id": actor_id,
                "actor_name": actor.name,
                "attribution_confidence": min(1.0, score),
                "matching_techniques": [t for t in mitre_techniques if t in actor.mitre_techniques],
            })
        return results

    def search_actors(self, query: str = "", limit: int = 50) -> list[ThreatActor]:
        """Search threat actors."""
        if not query:
            return list(self._actors.values())[:limit]
        query_lower = query.lower()
        return [
            a for a in self._actors.values()
            if query_lower in a.name.lower() or any(query_lower in alias.lower() for alias in a.aliases)
        ][:limit]

    def get_metrics(self) -> dict[str, Any]:
        return {"total_actors": len(self._actors), "techniques_tracked": len(self._technique_to_actors)}
