"""Correlation Engine implementation.

Identifies relationships between events, entities, and alerts across
time and data sources. Resolves entity identities and groups alerts
into incidents. Req 3.1-3.10, 32.1-32.12.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from sip.models.alerts import DetectionResult, Incident, IncidentStatus
from sip.models.entities import AttributeChange, Entity, EntityRelationship
from sip.models.events import EntityType, NormalizedEntity, ParsedEvent
from sip.utils.logging import get_logger

logger = get_logger(__name__)


class CorrelationEngine:
    """Correlation Engine - identifies relationships and resolves entities.

    Resolves entity identities across different identifier systems (Req 3.2),
    detects temporal correlations (Req 3.3), groups related alerts into
    incidents (Req 2.5), and tracks entity attribute changes (Req 3.10).
    """

    def __init__(self, max_entities: int = 20_000_000, update_timeout_seconds: int = 2) -> None:
        self.max_entities = max_entities
        self.update_timeout_seconds = update_timeout_seconds

        self._entities: dict[str, Entity] = {}
        self._relationships: dict[str, EntityRelationship] = {}
        self._identity_map: dict[str, str] = {}  # identifier -> canonical_id
        self._incidents: dict[str, Incident] = {}
        self._pending_alerts: list[DetectionResult] = []
        self._correlation_callbacks: list[Callable] = []

    # --- Entity Resolution (Req 3.2) ---

    def resolve_entity(self, identifiers: dict[str, str], entity_type: str = "unknown") -> str:
        """Resolve entity identifiers to canonical entity ID. Req 3.2."""
        # Check if any identifier is already mapped
        for id_type, id_value in identifiers.items():
            key = f"{id_type}:{id_value}"
            if key in self._identity_map:
                canonical_id = self._identity_map[key]
                # Update entity with new identifiers
                if canonical_id in self._entities:
                    entity = self._entities[canonical_id]
                    for k, v in identifiers.items():
                        entity.add_identifier(k, v)
                        self._identity_map[f"{k}:{v}"] = canonical_id
                return canonical_id

        # Create new canonical entity
        canonical_id = str(uuid.uuid4())
        entity = Entity(
            entity_id=canonical_id,
            entity_type=entity_type,
            canonical_id=canonical_id,
            identifiers=identifiers,
        )
        self._entities[canonical_id] = entity

        # Map all identifiers to canonical ID
        for id_type, id_value in identifiers.items():
            self._identity_map[f"{id_type}:{id_value}"] = canonical_id

        return canonical_id

    def merge_entities(self, entity_ids: list[str]) -> str:
        """Merge multiple entities into one. Req 3.2."""
        if not entity_ids:
            raise ValueError("No entity IDs provided")

        primary_id = entity_ids[0]
        primary = self._entities.get(primary_id)
        if not primary:
            raise ValueError(f"Primary entity not found: {primary_id}")

        for other_id in entity_ids[1:]:
            other = self._entities.get(other_id)
            if other:
                primary.merge_from(other)
                # Remap identifiers
                for id_type, id_value in other.identifiers.items():
                    self._identity_map[f"{id_type}:{id_value}"] = primary_id
                del self._entities[other_id]

        return primary_id

    def get_entity(self, entity_id: str) -> Entity | None:
        """Get entity by ID."""
        return self._entities.get(entity_id)

    def get_entity_by_identifier(self, id_type: str, id_value: str) -> Entity | None:
        """Get entity by identifier."""
        key = f"{id_type}:{id_value}"
        canonical_id = self._identity_map.get(key)
        if canonical_id:
            return self._entities.get(canonical_id)
        return None

    # --- Entity Relationships (Req 3.1) ---

    def add_relationship(
        self,
        source_id: str,
        target_id: str,
        relationship_type: str,
        confidence: float = 1.0,
        attributes: dict[str, Any] | None = None,
    ) -> str:
        """Add or update a relationship between entities. Req 3.1."""
        rel_key = f"{source_id}:{relationship_type}:{target_id}"

        if rel_key in self._relationships:
            rel = self._relationships[rel_key]
            rel.increment()
            rel.confidence = max(rel.confidence, confidence)
            if attributes:
                rel.attributes.update(attributes)
        else:
            rel = EntityRelationship(
                source_entity_id=source_id,
                target_entity_id=target_id,
                relationship_type=relationship_type,
                confidence=confidence,
                attributes=attributes or {},
            )
            self._relationships[rel_key] = rel

        return rel.relationship_id

    def get_entity_relationships(self, entity_id: str, depth: int = 2) -> dict[str, Any]:
        """Get entity and its relationships. Req 3.1."""
        nodes: dict[str, Entity] = {}
        edges: list[EntityRelationship] = []
        visited: set[str] = set()

        self._traverse_relationships(entity_id, depth, nodes, edges, visited)

        return {
            "nodes": [e.model_dump() for e in nodes.values()],
            "edges": [r.model_dump() for r in edges],
        }

    def _traverse_relationships(
        self,
        entity_id: str,
        depth: int,
        nodes: dict[str, Entity],
        edges: list[EntityRelationship],
        visited: set[str],
    ) -> None:
        if depth <= 0 or entity_id in visited:
            return

        visited.add(entity_id)
        entity = self._entities.get(entity_id)
        if entity:
            nodes[entity_id] = entity

        for rel_key, rel in self._relationships.items():
            if rel.source_entity_id == entity_id and rel.target_entity_id not in visited:
                edges.append(rel)
                self._traverse_relationships(rel.target_entity_id, depth - 1, nodes, edges, visited)
            elif rel.target_entity_id == entity_id and rel.source_entity_id not in visited:
                edges.append(rel)
                self._traverse_relationships(rel.source_entity_id, depth - 1, nodes, edges, visited)

    # --- Temporal Correlation (Req 3.3, 3.4) ---

    def correlate_events(
        self,
        events: list[ParsedEvent],
        time_window: timedelta = timedelta(minutes=5),
        correlation_type: str = "sequential",
    ) -> list[dict[str, Any]]:
        """Correlate events within a time window. Req 3.3."""
        correlations: list[dict[str, Any]] = []

        # Sort by timestamp
        sorted_events = sorted(events, key=lambda e: e.timestamp)

        for i, event_a in enumerate(sorted_events):
            for j in range(i + 1, len(sorted_events)):
                event_b = sorted_events[j]
                time_diff = event_b.timestamp - event_a.timestamp
                if time_diff > time_window:
                    break

                # Check for shared entities
                shared_entities = self._find_shared_entities(event_a, event_b)
                if shared_entities:
                    correlations.append({
                        "correlation_id": str(uuid.uuid4()),
                        "event_a_id": event_a.event_id,
                        "event_b_id": event_b.event_id,
                        "correlation_type": correlation_type,
                        "time_diff_seconds": time_diff.total_seconds(),
                        "shared_entities": shared_entities,
                        "confidence": min(1.0, 0.5 + len(shared_entities) * 0.1),
                    })

        return correlations

    def _find_shared_entities(self, event_a: ParsedEvent, event_b: ParsedEvent) -> list[str]:
        """Find entities shared between two events."""
        ids_a: set[str] = set()
        ids_b: set[str] = set()

        for entity in event_a.entities:
            for id_val in entity.identifiers.values():
                canonical = self._identity_map.get(f"{list(entity.identifiers.keys())[0]}:{id_val}", id_val)
                ids_a.add(canonical)

        for entity in event_b.entities:
            for id_val in entity.identifiers.values():
                canonical = self._identity_map.get(f"{list(entity.identifiers.keys())[0]}:{id_val}", id_val)
                ids_b.add(canonical)

        return list(ids_a.intersection(ids_b))

    # --- Incident Grouping (Req 2.5, 32.1-32.12) ---

    def group_alerts_to_incident(self, alerts: list[DetectionResult], time_window: timedelta = timedelta(seconds=5)) -> Incident:
        """Group related alerts into an incident. Req 2.5."""
        if not alerts:
            raise ValueError("No alerts to group")

        # Determine severity (max of all alerts)
        max_severity = max(a.severity for a in alerts)

        # Collect all affected entities
        all_entities: set[str] = set()
        all_tactics: set[str] = set()
        all_techniques: set[str] = set()
        for alert in alerts:
            all_entities.update(alert.affected_entities)
            all_tactics.update(alert.mitre_tactics)
            all_techniques.update(alert.mitre_techniques)

        incident = Incident(
            title=f"Incident: {alerts[0].threat_type} ({len(alerts)} related alerts)",
            description=f"Automated incident from {len(alerts)} correlated alerts",
            severity=max_severity,
            alert_ids=[a.detection_id for a in alerts],
            affected_entities=list(all_entities),
            mitre_tactics=list(all_tactics),
            mitre_techniques=list(all_techniques),
            detection_time=min(a.timestamp for a in alerts),
        )

        incident.add_timeline_event("created", f"Incident created from {len(alerts)} alerts")

        self._incidents[incident.incident_id] = incident
        return incident

    def get_incident(self, incident_id: str) -> Incident | None:
        """Get incident by ID."""
        return self._incidents.get(incident_id)

    # --- Entity Attribute Tracking (Req 3.10) ---

    def update_entity_attribute(
        self,
        entity_id: str,
        attribute_name: str,
        new_value: Any,
        source_id: str = "",
        confidence: float = 1.0,
    ) -> None:
        """Update an entity attribute with history tracking. Req 3.10."""
        entity = self._entities.get(entity_id)
        if not entity:
            return

        # Check for conflicts. Req 3.8
        old_value = entity.attributes.get(attribute_name)
        if old_value is not None and old_value != new_value:
            # Apply resolution strategy - highest confidence wins
            for change in reversed(entity.attribute_history):
                if change.attribute_name == attribute_name:
                    if change.confidence > confidence:
                        return  # Existing value has higher confidence

        entity.update_attribute(attribute_name, new_value, source_id, confidence)

    # --- Process Events Through Correlation ---

    async def process_event(self, event: ParsedEvent) -> list[str]:
        """Process an event through the correlation engine. Req 3.5."""
        created_entity_ids: list[str] = []

        # Resolve and create entities
        for normalized in event.entities:
            canonical_id = self.resolve_entity(
                normalized.identifiers,
                normalized.entity_type.value,
            )
            created_entity_ids.append(canonical_id)

            # Update entity attributes
            entity = self._entities.get(canonical_id)
            if entity:
                entity.last_seen = event.timestamp
                for key, value in normalized.attributes.items():
                    self.update_entity_attribute(canonical_id, key, value, event.source_id)

        # Create relationships between entities in the same event
        for i, eid_a in enumerate(created_entity_ids):
            for j in range(i + 1, len(created_entity_ids)):
                eid_b = created_entity_ids[j]
                self.add_relationship(
                    eid_a, eid_b, "CO_OCCURRED",
                    confidence=0.8,
                    attributes={"event_id": event.event_id, "event_type": event.event_type},
                )

        return created_entity_ids

    # --- Metrics ---

    def get_metrics(self) -> dict[str, Any]:
        """Get correlation engine metrics."""
        return {
            "total_entities": len(self._entities),
            "total_relationships": len(self._relationships),
            "total_identity_mappings": len(self._identity_map),
            "total_incidents": len(self._incidents),
        }
