"""Unit tests for data models.

Tests core data models: SecurityEvent, Alert, Entity, Case.
Validates Req 1.8, 1.10, 2.1-2.10, 3.1-3.10, 19.1-19.14.
"""

import json
from datetime import datetime, timezone

import pytest

from sip.models.events import (
    ClassificationLevel,
    EntityType,
    NormalizedEntity,
    ParsedEvent,
    SecurityEvent,
)
from sip.models.alerts import Alert, AlertResolution, AlertStatus, DetectionResult, Incident
from sip.models.entities import AttributeChange, Entity, EntityRelationship, RiskFactor
from sip.models.cases import Case, CaseStatus, Evidence, EvidenceType, WorkspaceState


class TestParsedEvent:
    """Tests for ParsedEvent model. Req 1.8, 1.10, 28.1."""

    def test_create_event(self):
        event = ParsedEvent(
            timestamp=datetime.now(timezone.utc),
            source_id="test-source",
            event_type="authentication",
            severity=75,
        )
        assert event.event_id
        assert event.source_id == "test-source"
        assert event.severity == 75

    def test_event_fingerprint(self):
        """Test deduplication fingerprint. Req 1.9."""
        event = ParsedEvent(
            timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
            source_id="src-1",
            event_type="login",
            attributes={"user": "admin"},
        )
        fp1 = event.fingerprint()
        fp2 = event.fingerprint()
        assert fp1 == fp2  # Same event produces same fingerprint

    def test_event_json_round_trip(self):
        """Test JSON serialization round-trip. Req 28.12."""
        event = ParsedEvent(
            timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
            source_id="src-1",
            event_type="dns_query",
            severity=30,
            entities=[
                NormalizedEntity(
                    entity_type=EntityType.IP,
                    identifiers={"ip": "192.168.1.1"},
                )
            ],
            attributes={"query": "example.com"},
        )
        json_bytes = event.to_json()
        restored = ParsedEvent.from_json(json_bytes)
        assert restored.event_id == event.event_id
        assert restored.source_id == event.source_id
        assert restored.severity == event.severity
        assert len(restored.entities) == 1

    def test_severity_validation(self):
        """Severity must be 0-100. Req 2.6."""
        event = ParsedEvent(
            timestamp=datetime.now(timezone.utc),
            source_id="src",
            event_type="test",
            severity=150,
        )
        assert event.severity == 100

    def test_classification_levels(self):
        """Test classification levels. Req 10.7."""
        for level in ClassificationLevel:
            event = ParsedEvent(
                timestamp=datetime.now(timezone.utc),
                source_id="src",
                event_type="test",
                classification=level,
            )
            assert event.classification == level


class TestAlert:
    """Tests for Alert model. Req 17.1-17.12."""

    def test_create_alert(self):
        alert = Alert(
            detection_id="det-1",
            severity=85,
            confidence=0.9,
        )
        assert alert.status == AlertStatus.NEW
        assert alert.severity == 85

    def test_acknowledge_alert(self):
        """Test alert acknowledgment. Req 17.7."""
        alert = Alert(detection_id="det-1", severity=80, confidence=0.8)
        alert.acknowledge("analyst1")
        assert alert.status == AlertStatus.ACKNOWLEDGED
        assert alert.assigned_to == "analyst1"
        assert alert.acknowledged_at is not None

    def test_resolve_alert(self):
        """Test alert resolution. Req 17.7."""
        alert = Alert(detection_id="det-1", severity=80, confidence=0.8)
        resolution = AlertResolution(
            resolution_type="true_positive",
            summary="Confirmed brute force attack",
        )
        alert.resolve(resolution)
        assert alert.status == AlertStatus.RESOLVED
        assert alert.resolved_at is not None

    def test_escalate_alert(self):
        """Test alert escalation. Req 17.6, 17.11."""
        alert = Alert(detection_id="det-1", severity=80, confidence=0.8)
        assert alert.escalation_level == 0
        alert.escalate()
        assert alert.escalation_level == 1
        alert.escalate()
        assert alert.escalation_level == 2

    def test_priority_calculation(self):
        """Test priority calculation. Req 17.1."""
        alert = Alert(detection_id="det-1", severity=90, confidence=0.9)
        priority = alert.calculate_priority(business_impact=0.8)
        assert 1 <= priority <= 100


class TestEntity:
    """Tests for Entity model. Req 3.1-3.10."""

    def test_create_entity(self):
        entity = Entity(
            entity_type="ip",
            identifiers={"ip": "192.168.1.1"},
        )
        assert entity.entity_id
        assert entity.entity_type == "ip"

    def test_attribute_tracking(self):
        """Test attribute change history. Req 3.10."""
        entity = Entity(entity_type="host", identifiers={"hostname": "server1"})
        entity.update_attribute("os", "Windows 10", "src-1", 0.9)
        entity.update_attribute("os", "Windows 11", "src-2", 0.95)

        assert entity.attributes["os"] == "Windows 11"
        assert len(entity.attribute_history) == 2
        assert entity.attribute_history[0].old_value is None
        assert entity.attribute_history[1].old_value == "Windows 10"

    def test_risk_score_calculation(self):
        """Test risk score calculation. Req 22.3."""
        entity = Entity(entity_type="user", identifiers={"username": "admin"})
        entity.risk_factors = [
            RiskFactor(factor_type="vulnerability", description="CVE-2024-0001", score=80, weight=0.5),
            RiskFactor(factor_type="behavioral_anomaly", description="Unusual login", score=60, weight=0.3),
        ]
        score = entity.calculate_risk_score()
        assert 0 <= score <= 100

    def test_entity_merge(self):
        """Test entity merging. Req 3.2."""
        entity1 = Entity(
            entity_type="user",
            identifiers={"username": "admin"},
            attributes={"department": "IT"},
        )
        entity2 = Entity(
            entity_type="user",
            identifiers={"email": "admin@company.com"},
            attributes={"phone": "555-0100"},
        )
        entity1.merge_from(entity2)
        assert "email" in entity1.identifiers
        assert "phone" in entity1.attributes


class TestCase:
    """Tests for Case model. Req 19.1-19.14."""

    def test_create_case(self):
        case = Case(title="Test Investigation", severity=75)
        assert case.status == CaseStatus.OPEN
        assert case.case_id

    def test_case_status_update(self):
        """Test case status tracking. Req 19.3."""
        case = Case(title="Test", severity=50)
        case.update_status(CaseStatus.INVESTIGATING, "analyst1")
        assert case.status == CaseStatus.INVESTIGATING
        assert len(case.history) == 1

    def test_evidence_chain_of_custody(self):
        """Test evidence chain of custody. Req 44.1, 44.7."""
        evidence = Evidence(
            evidence_type=EvidenceType.FILE,
            title="Malware sample",
        )
        evidence.compute_hash(b"malware content here")
        assert evidence.content_hash != ""

        evidence.add_custody_record("added", "analyst1", "Initial submission")
        assert len(evidence.chain_of_custody) == 1
        assert evidence.chain_of_custody[0]["action"] == "added"

    def test_workspace_state_round_trip(self):
        """Test workspace state persistence. Req 4.8."""
        state = WorkspaceState(
            case_id="case-1",
            queries=[{"type": "search", "text": "malware"}],
            annotations=[{"target": "entity-1", "text": "suspicious"}],
        )
        json_data = state.to_json()
        restored = WorkspaceState.from_json(json_data)
        assert restored.case_id == state.case_id
        assert len(restored.queries) == 1
        assert len(restored.annotations) == 1


class TestDetectionResult:
    """Tests for DetectionResult model. Req 2.1-2.10."""

    def test_severity_range(self):
        """Severity scores must be 1-100. Req 2.6."""
        result = DetectionResult(
            rule_id="rule-1",
            event_id="evt-1",
            severity=85,
            confidence=0.9,
            threat_type="brute_force",
        )
        assert 1 <= result.severity <= 100

    def test_confidence_range(self):
        """Confidence scores must be 0-1. Req 2.7."""
        result = DetectionResult(
            rule_id="rule-1",
            event_id="evt-1",
            severity=50,
            confidence=0.75,
            threat_type="anomaly",
        )
        assert 0 <= result.confidence <= 1
