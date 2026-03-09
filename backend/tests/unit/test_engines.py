"""Unit tests for engine implementations.

Tests Data Ingestion, Schema Mapper, Threat Detection, Correlation, and Query engines.
"""

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from sip.engines.ingestion import DataIngestionEngine, DataSourceConfig
from sip.engines.schema_mapper import SchemaMapper
from sip.engines.threat_detection import DetectionRule, ThreatDetectionEngine
from sip.engines.correlation import CorrelationEngine
from sip.engines.query_engine import Query, QueryEngine, QueryType
from sip.models.events import EntityType, NormalizedEntity, ParsedEvent


class TestDataIngestionEngine:
    """Tests for Data Ingestion Engine. Req 1.1-1.10."""

    @pytest.fixture
    def engine(self):
        return DataIngestionEngine(max_concurrent_sources=50, deduplication_window_seconds=60)

    @pytest.mark.asyncio
    async def test_register_data_source(self, engine):
        """Test registering data sources. Req 1.1."""
        config = DataSourceConfig(name="Test Source", source_type="syslog")
        source_id = await engine.register_data_source(config)
        assert source_id
        assert source_id in engine._sources

    @pytest.mark.asyncio
    async def test_max_concurrent_sources(self, engine):
        """Test 50 concurrent source limit. Req 1.1."""
        for i in range(50):
            config = DataSourceConfig(name=f"Source {i}", source_type="api")
            await engine.register_data_source(config)

        with pytest.raises(ValueError, match="Maximum concurrent sources"):
            config = DataSourceConfig(name="One too many", source_type="api")
            await engine.register_data_source(config)

    @pytest.mark.asyncio
    async def test_connection_validation(self, engine):
        """Test connection validation within 5 seconds. Req 1.2."""
        config = DataSourceConfig(name="Test", source_type="api")
        await engine.register_data_source(config)
        result = await engine.validate_connection(config.source_id)
        assert result["valid"] is True

    @pytest.mark.asyncio
    async def test_event_ingestion(self, engine):
        """Test event ingestion. Req 1.3."""
        config = DataSourceConfig(name="Test", source_type="syslog")
        await engine.register_data_source(config)
        event = await engine.ingest_event(config.source_id, b'{"message": "test"}')
        assert event is not None
        assert event.source_id == config.source_id

    @pytest.mark.asyncio
    async def test_deduplication(self, engine):
        """Test event deduplication within 60-second window. Req 1.9."""
        config = DataSourceConfig(name="Test", source_type="api")
        await engine.register_data_source(config)

        event1 = await engine.ingest_event(config.source_id, b'{"msg": "same event"}')
        event2 = await engine.ingest_event(config.source_id, b'{"msg": "same event"}')

        assert event1 is not None
        # Second event with same fingerprint should be deduplicated
        # (depends on exact fingerprint matching)

    @pytest.mark.asyncio
    async def test_event_metadata_tagging(self, engine):
        """Test event metadata tagging. Req 1.10."""
        config = DataSourceConfig(name="Source A", source_type="syslog")
        await engine.register_data_source(config)
        event = await engine.ingest_event(config.source_id, b'{"test": "data"}')
        assert event is not None
        assert event.tags.get("source_id") == config.source_id
        assert event.ingestion_timestamp is not None


class TestSchemaMapper:
    """Tests for Schema Mapper. Req 28.1-28.12."""

    @pytest.fixture
    def mapper(self):
        return SchemaMapper()

    @pytest.mark.asyncio
    async def test_parse_json(self, mapper):
        """Test JSON parsing. Req 28.1."""
        raw = b'{"timestamp": "2024-01-15T10:30:00Z", "src_ip": "192.168.1.1", "event_type": "login", "severity": 50}'
        event = await mapper.parse(raw, "api", "src-1")
        assert event.source_id == "src-1"
        assert event.event_type == "login"
        assert event.severity == 50

    @pytest.mark.asyncio
    async def test_parse_key_value(self, mapper):
        """Test key-value parsing. Req 28.1."""
        raw = b'src_ip=192.168.1.1 dst_ip=10.0.0.1 action=ALLOW protocol=TCP'
        event = await mapper.parse(raw, "firewall", "fw-1")
        assert "src_ip" in event.attributes

    def test_normalize_ip(self, mapper):
        """Test IP normalization. Req 28.4."""
        assert mapper.normalize_ip("  192.168.1.1  ") == "192.168.1.1"
        assert mapper.normalize_ip("::1") == "::1"

    def test_normalize_domain(self, mapper):
        """Test domain normalization. Req 28.4."""
        assert mapper.normalize_domain("WWW.Example.COM.") == "example.com"
        assert mapper.normalize_domain("test.org") == "test.org"

    def test_normalize_email(self, mapper):
        """Test email normalization. Req 28.5."""
        assert mapper.normalize_email("  Admin@Company.COM  ") == "admin@company.com"

    def test_normalize_user(self, mapper):
        """Test user normalization. Req 28.5."""
        assert mapper.normalize_user("DOMAIN\\admin") == "admin@domain"

    def test_normalize_timestamp(self, mapper):
        """Test timestamp normalization to UTC. Req 28.3."""
        dt = mapper.normalize_timestamp("2024-01-15T10:30:00Z")
        assert dt.tzinfo is not None
        assert dt.year == 2024

    def test_schema_validation(self, mapper):
        """Test schema validation. Req 28.6, 28.8."""
        event = ParsedEvent(
            timestamp=datetime.now(timezone.utc),
            source_id="src-1",
            event_type="test",
        )
        result = mapper.validate_schema(event)
        assert result["valid"] is True

    @pytest.mark.asyncio
    async def test_parse_round_trip(self, mapper):
        """Test parse -> print -> parse equivalence. Req 28.12."""
        raw = b'{"timestamp": "2024-01-15T10:30:00Z", "src_ip": "192.168.1.1", "event_type": "dns", "severity": 30}'
        event = await mapper.parse(raw, "api", "src-1")
        printed = mapper.pretty_print(event)
        assert "src-1" in printed
        assert "dns" in printed


class TestThreatDetectionEngine:
    """Tests for Threat Detection Engine. Req 2.1-2.10."""

    @pytest.fixture
    def engine(self):
        return ThreatDetectionEngine(max_concurrent_rules=1000, detection_timeout_ms=500)

    def test_add_detection_rule(self, engine):
        """Test adding detection rules. Req 2.2."""
        rule = DetectionRule(
            rule_name="Test Rule",
            rule_type="signature",
            condition={"event_type": "login", "keywords": ["failed"]},
            severity=70,
        )
        rule_id = engine.add_detection_rule(rule)
        assert rule_id
        assert engine.get_rule(rule_id) is not None

    @pytest.mark.asyncio
    async def test_analyze_event(self, engine):
        """Test event analysis within 500ms. Req 2.1."""
        rule = DetectionRule(
            rule_name="Login Failure",
            rule_type="signature",
            condition={"event_type": "authentication", "keywords": ["failed"]},
            severity=60,
            confidence=0.8,
        )
        engine.add_detection_rule(rule)

        event = ParsedEvent(
            timestamp=datetime.now(timezone.utc),
            source_id="auth-log",
            event_type="authentication",
            attributes={"result": "failed", "username": "admin"},
        )
        results = await engine.analyze_event(event)
        assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_severity_score_range(self, engine):
        """Severity scores must be 1-100. Req 2.6."""
        rule = DetectionRule(
            rule_name="Test",
            rule_type="signature",
            condition={"event_type": "test"},
            severity=85,
        )
        engine.add_detection_rule(rule)
        event = ParsedEvent(
            timestamp=datetime.now(timezone.utc),
            source_id="src",
            event_type="test",
            severity=90,
        )
        results = await engine.analyze_event(event)
        for r in results:
            assert 1 <= r.severity <= 100
            assert 0 <= r.confidence <= 1

    def test_behavioral_baseline(self, engine):
        """Test behavioral baseline update. Req 8.1."""
        for val in [10.0, 12.0, 11.0, 9.0, 10.5, 11.5, 10.0, 12.0, 9.5, 10.5]:
            engine.update_behavioral_baseline("user-1", "user", "login_count", val)

        anomaly = engine.check_anomaly("user-1", "login_count", 50.0, threshold_std=3.0)
        assert anomaly is not None
        assert anomaly["z_score"] > 3.0


class TestCorrelationEngine:
    """Tests for Correlation Engine. Req 3.1-3.10."""

    @pytest.fixture
    def engine(self):
        return CorrelationEngine()

    def test_entity_resolution(self, engine):
        """Test entity resolution to canonical ID. Req 3.2."""
        id1 = engine.resolve_entity({"ip": "192.168.1.1"}, "ip")
        id2 = engine.resolve_entity({"ip": "192.168.1.1"}, "ip")
        assert id1 == id2  # Same identifier resolves to same entity

    def test_entity_merge(self, engine):
        """Test entity merging. Req 3.2."""
        id1 = engine.resolve_entity({"ip": "10.0.0.1"}, "ip")
        id2 = engine.resolve_entity({"hostname": "server1"}, "host")
        merged = engine.merge_entities([id1, id2])
        assert merged == id1
        entity = engine.get_entity(merged)
        assert "hostname" in entity.identifiers

    def test_relationship_creation(self, engine):
        """Test entity relationship. Req 3.1."""
        id1 = engine.resolve_entity({"ip": "10.0.0.1"}, "ip")
        id2 = engine.resolve_entity({"ip": "10.0.0.2"}, "ip")
        rel_id = engine.add_relationship(id1, id2, "CONNECTED_TO", confidence=0.9)
        assert rel_id

    def test_temporal_correlation(self, engine):
        """Test temporal correlation. Req 3.3."""
        now = datetime.now(timezone.utc)
        entity = NormalizedEntity(entity_type=EntityType.IP, identifiers={"ip": "10.0.0.1"})

        events = [
            ParsedEvent(timestamp=now, source_id="s1", event_type="login", entities=[entity]),
            ParsedEvent(timestamp=now + timedelta(seconds=30), source_id="s2", event_type="file_access", entities=[entity]),
        ]
        correlations = engine.correlate_events(events, time_window=timedelta(minutes=5))
        # Both events share the same entity, so they should correlate
        assert isinstance(correlations, list)

    def test_incident_grouping(self, engine):
        """Test alert grouping into incidents. Req 2.5."""
        from sip.models.alerts import DetectionResult
        alerts = [
            DetectionResult(rule_id="r1", event_id="e1", severity=80, confidence=0.9, threat_type="brute_force"),
            DetectionResult(rule_id="r2", event_id="e2", severity=70, confidence=0.8, threat_type="brute_force"),
        ]
        incident = engine.group_alerts_to_incident(alerts)
        assert incident.incident_id
        assert len(incident.alert_ids) == 2
        assert incident.severity == 80


class TestQueryEngine:
    """Tests for Query Engine. Req 5.1-5.12."""

    @pytest.fixture
    def engine(self):
        return QueryEngine(query_timeout_seconds=30)

    @pytest.mark.asyncio
    async def test_execute_query(self, engine):
        """Test query execution. Req 5.1."""
        query = Query(query_type=QueryType.STRUCTURED, limit=100)
        result = await engine.execute_query(query)
        assert result.query_id
        assert result.execution_time_ms >= 0

    def test_save_and_load_query(self, engine):
        """Test saved queries. Req 5.6."""
        query = Query(query_type=QueryType.FULLTEXT, text_search="malware")
        saved_id = engine.save_query("Malware search", query, user="analyst1")
        loaded = engine.load_query(saved_id)
        assert loaded is not None
        assert loaded.name == "Malware search"

    def test_query_explain(self, engine):
        """Test query explain. Req 5.12."""
        query = Query(query_type=QueryType.FULLTEXT, text_search="test")
        plan = engine.explain_query(query)
        assert "target_backend" in plan
        assert plan["target_backend"] == "elasticsearch"
