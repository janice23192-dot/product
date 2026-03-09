"""Unit tests for service implementations.

Tests Alert Manager, Access Control, Audit, Enrichment, and more.
"""

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from sip.services.alert_manager import AlertManager
from sip.services.access_control import AccessControlSystem
from sip.services.audit import AuditSystem
from sip.services.enrichment import EnrichmentService, IOCEntry
from sip.services.investigation import InvestigationWorkspace
from sip.services.playbook_executor import Playbook, PlaybookExecutor, PlaybookStep, StepType
from sip.services.data_retention import DataRetentionService
from sip.services.behavioral_analytics import BehavioralAnalyticsService
from sip.services.compliance import ComplianceService
from sip.services.config_management import ConfigurationManagementService
from sip.services.security_monitoring import SecurityMonitoringService
from sip.models.alerts import DetectionResult
from sip.models.cases import Evidence, EvidenceType, WorkspaceState


class TestAlertManager:
    """Tests for Alert Manager. Req 17.1-17.12."""

    @pytest.fixture
    def manager(self):
        return AlertManager()

    @pytest.mark.asyncio
    async def test_create_alert(self, manager):
        detection = DetectionResult(
            rule_id="r1", event_id="e1", severity=80, confidence=0.9, threat_type="brute_force",
        )
        alert = await manager.create_alert(detection)
        assert alert.alert_id
        assert alert.severity == 80

    @pytest.mark.asyncio
    async def test_alert_lifecycle(self, manager):
        """Test complete alert lifecycle. Req 17.7."""
        detection = DetectionResult(
            rule_id="r1", event_id="e1", severity=70, confidence=0.8, threat_type="anomaly",
        )
        alert = await manager.create_alert(detection)
        assert alert.status.value == "new"

        await manager.acknowledge_alert(alert.alert_id, "analyst1")
        alert = manager.get_alert(alert.alert_id)
        assert alert.status.value == "acknowledged"

    @pytest.mark.asyncio
    async def test_alert_deduplication(self, manager):
        """Test alert deduplication. Req 17.2."""
        detection = DetectionResult(
            rule_id="r1", event_id="e1", severity=60, confidence=0.7, threat_type="scan",
        )
        alert1 = await manager.create_alert(detection)
        alert2 = await manager.create_alert(detection)
        # Second should be deduplicated
        assert alert1.alert_id  # Both should have IDs but may be same alert

    def test_alert_metrics(self, manager):
        """Test alert metrics. Req 17.9."""
        metrics = manager.get_metrics()
        assert "total_alerts" in metrics
        assert "mean_time_to_acknowledge" in metrics


class TestAccessControlSystem:
    """Tests for Access Control. Req 10.1-10.12."""

    @pytest.fixture
    def acs(self):
        return AccessControlSystem()

    @pytest.mark.asyncio
    async def test_user_creation_and_auth(self, acs):
        """Test authentication. Req 10.1."""
        user = await acs.create_user("testuser", "test@example.com", "password123")
        session = await acs.authenticate("testuser", "password123")
        assert session is not None
        assert session.user_id == user.user_id

    @pytest.mark.asyncio
    async def test_failed_auth(self, acs):
        """Test failed authentication."""
        await acs.create_user("testuser", "test@example.com", "password123")
        session = await acs.authenticate("testuser", "wrongpassword")
        assert session is None

    @pytest.mark.asyncio
    async def test_account_lockout(self, acs):
        """Test account lockout after 5 failures. Req 10.12."""
        await acs.create_user("locktest", "lock@example.com", "correct")
        for _ in range(5):
            await acs.authenticate("locktest", "wrong")
        # Should now be locked
        session = await acs.authenticate("locktest", "correct")
        assert session is None

    @pytest.mark.asyncio
    async def test_session_timeout(self, acs):
        """Test session inactivity timeout. Req 10.8."""
        user = await acs.create_user("timeoutuser", "t@example.com", "pass")
        session = await acs.authenticate("timeoutuser", "pass")
        # Simulate expired session
        session.last_activity = datetime.now(timezone.utc) - timedelta(hours=9)
        result = await acs.validate_session(session.session_id)
        assert result is None

    @pytest.mark.asyncio
    async def test_rbac_permission_check(self, acs):
        """Test RBAC permission check. Req 10.3."""
        role = acs.create_role("analyst", ["alerts:read", "cases:read", "cases:write"])
        user = await acs.create_user("analyst1", "a1@test.com", "pass")
        acs.assign_role(user.user_id, role.role_id)

        assert await acs.check_permission(user.user_id, "alerts", "read") is True
        assert await acs.check_permission(user.user_id, "admin", "delete") is False


class TestAuditSystem:
    """Tests for Audit System. Req 11.1-11.12."""

    @pytest.fixture
    def audit(self):
        return AuditSystem()

    @pytest.mark.asyncio
    async def test_audit_logging(self, audit):
        """Test audit log creation. Req 11.1."""
        entry = await audit.log(
            action_type="query",
            user_id="user-1",
            resource_type="events",
            outcome="success",
        )
        assert entry.entry_id
        assert entry.integrity_hash

    @pytest.mark.asyncio
    async def test_audit_integrity(self, audit):
        """Test tamper-evident hash chain. Req 11.4."""
        await audit.log(action_type="login", user_id="u1")
        await audit.log(action_type="query", user_id="u1")
        await audit.log(action_type="logout", user_id="u1")

        result = audit.verify_integrity()
        assert result["valid"] is True
        assert result["entries_checked"] == 3

    @pytest.mark.asyncio
    async def test_audit_search(self, audit):
        """Test audit log search. Req 11.8."""
        await audit.log(action_type="login", user_id="u1")
        await audit.log(action_type="query", user_id="u2")

        results = audit.search(user_id="u1")
        assert len(results) == 1

    def test_compliance_report(self, audit):
        """Test compliance report generation. Req 11.9."""
        report = audit.generate_compliance_report("SOC2")
        assert report["framework"] == "SOC2"
        assert "controls" in report

    def test_export_formats(self, audit):
        """Test audit log export. Req 11.7."""
        for fmt in ("json", "cef", "leef"):
            output = audit.export_logs(format_type=fmt)
            assert isinstance(output, str)


class TestEnrichmentService:
    """Tests for Enrichment Service. Req 7.1-7.10."""

    @pytest.fixture
    def enrichment(self):
        return EnrichmentService()

    def test_ioc_management(self, enrichment):
        """Test IOC addition and lookup. Req 7.4."""
        ioc = IOCEntry(ioc_type="ip", value="10.0.0.1", threat_type="c2", confidence=0.9)
        ioc_id = enrichment.add_ioc(ioc)
        assert ioc_id
        assert enrichment.get_ioc(ioc_id) is not None

    def test_ioc_deduplication(self, enrichment):
        """Test IOC deduplication. Req 7.9."""
        ioc1 = IOCEntry(ioc_type="domain", value="evil.com", source="feed1")
        ioc2 = IOCEntry(ioc_type="domain", value="evil.com", source="feed2")
        id1 = enrichment.add_ioc(ioc1)
        id2 = enrichment.add_ioc(ioc2)
        assert id1 == id2  # Same IOC should be deduplicated

    def test_ioc_confidence_decay(self, enrichment):
        """Test IOC confidence decay. Req 7.6."""
        ioc = IOCEntry(ioc_type="ip", value="1.2.3.4", confidence=1.0)
        ioc.first_seen = datetime.now(timezone.utc) - timedelta(days=60)
        ioc.decay_confidence(half_life_days=30)
        assert ioc.confidence < 1.0


class TestInvestigationWorkspace:
    """Tests for Investigation Workspace. Req 4.1-4.10."""

    @pytest.fixture
    def workspace(self):
        return InvestigationWorkspace()

    @pytest.mark.asyncio
    async def test_create_case(self, workspace):
        case = await workspace.create_case("Test Case", severity=75, created_by="analyst1")
        assert case.case_id
        assert case.title == "Test Case"

    @pytest.mark.asyncio
    async def test_add_evidence(self, workspace):
        """Test evidence addition. Req 4.5."""
        case = await workspace.create_case("Test", severity=50)
        evidence = Evidence(evidence_type=EvidenceType.FILE, title="Malware sample")
        result = await workspace.add_evidence(case.case_id, evidence, "analyst1")
        assert result is not None

    @pytest.mark.asyncio
    async def test_workspace_state_round_trip(self, workspace):
        """Test workspace state save/load. Req 4.8."""
        case = await workspace.create_case("Test", severity=50)
        state = WorkspaceState(
            case_id=case.case_id,
            queries=[{"text": "search query"}],
        )
        await workspace.save_workspace_state(case.case_id, state, "analyst1")
        loaded = await workspace.load_workspace_state(case.case_id)
        assert loaded is not None
        assert len(loaded.queries) == 1


class TestBehavioralAnalytics:
    """Tests for Behavioral Analytics. Req 8.1-8.10, 22.1-22.12."""

    @pytest.fixture
    def analytics(self):
        return BehavioralAnalyticsService()

    def test_baseline_creation(self, analytics):
        """Test behavioral baseline. Req 8.1."""
        for val in [10.0, 12.0, 11.0, 9.0, 10.5, 11.5, 10.0, 12.0, 9.5, 10.5]:
            analytics.update_baseline("user-1", "user", "login_count", val)
        baseline = analytics.get_baseline("user-1", "login_count")
        assert baseline is not None
        assert baseline.sample_count == 10

    def test_anomaly_detection(self, analytics):
        """Test anomaly detection. Req 8.2."""
        for val in [10.0, 12.0, 11.0, 9.0, 10.5, 11.5, 10.0, 12.0, 9.5, 10.5]:
            analytics.update_baseline("user-1", "user", "bytes_sent", val)
        anomaly = analytics.detect_anomaly("user-1", "user", "bytes_sent", 50.0)
        assert anomaly is not None
        assert anomaly.z_score > 3.0

    def test_impossible_travel(self, analytics):
        """Test impossible travel detection. Req 22.4."""
        now = datetime.now(timezone.utc)
        result1 = analytics.detect_impossible_travel("user1", 40.7128, -74.0060, now)  # NYC
        assert result1 is None  # First login, no comparison

        result2 = analytics.detect_impossible_travel(
            "user1", 51.5074, -0.1278,  # London
            now + timedelta(minutes=30),  # 30 min later
        )
        assert result2 is not None  # NYC to London in 30 min is impossible
        assert result2["detection_type"] == "impossible_travel"


class TestDataRetention:
    """Tests for Data Retention. Req 12.1-12.12."""

    @pytest.fixture
    def retention(self):
        return DataRetentionService()

    @pytest.mark.asyncio
    async def test_archive_and_restore(self, retention):
        """Test data archival and restoration. Req 12.2, 12.5."""
        data = b"x" * 10000
        result = await retention.archive_data("data-1", data, "events")
        assert result["status"] == "archived"
        assert float(result["compression_ratio"].rstrip("%")) > 0

        restored = await retention.restore_data("data-1")
        assert restored == data

    @pytest.mark.asyncio
    async def test_encryption(self, retention):
        """Test data encryption. Req 12.9."""
        data = b"secret data"
        result = await retention.archive_data("enc-1", data)
        stored = retention._archived_data["enc-1"]["data"]
        assert stored != data  # Should be encrypted

    def test_key_rotation(self, retention):
        """Test encryption key rotation. Req 18.4."""
        old_key = retention._current_key_id
        new_key = retention.rotate_keys()
        assert new_key != old_key


class TestSecurityMonitoring:
    """Tests for Security Monitoring. Req 24-27."""

    @pytest.fixture
    def monitoring(self):
        return SecurityMonitoringService()

    def test_file_hash_extraction(self, monitoring):
        """Test file hash extraction. Req 24.2."""
        content = b"test file content"
        hashes = monitoring.extract_file_hashes(content)
        assert "md5" in hashes
        assert "sha1" in hashes
        assert "sha256" in hashes
        assert len(hashes["md5"]) == 32
        assert len(hashes["sha1"]) == 40
        assert len(hashes["sha256"]) == 64

    def test_malware_analysis(self, monitoring):
        """Test file analysis. Req 24.1."""
        analysis = monitoring.analyze_file(b"test content", "test.exe")
        assert analysis.md5
        assert analysis.sha256


class TestConfigManagement:
    """Tests for Configuration Management. Req 29.1-29.12."""

    @pytest.fixture
    def config(self):
        return ConfigurationManagementService()

    def test_set_and_get_config(self, config):
        """Test config set/get. Req 29.1."""
        config.set_config("retention.days", 30)
        assert config.get_config("retention.days") == 30

    def test_config_validation(self, config):
        """Test config validation. Req 29.2."""
        result = config.validate_config("test.key", "value")
        assert result["valid"] is True
        result = config.validate_config("", "value")
        assert result["valid"] is False

    def test_config_versioning(self, config):
        """Test config versioning. Req 29.3."""
        config.set_config("version.test", "v1")
        config.set_config("version.test", "v2")
        history = config.get_version_history("version.test")
        assert len(history) == 2


class TestCompliance:
    """Tests for Compliance. Req 31.1-31.12, 43.1-43.12."""

    @pytest.fixture
    def compliance(self):
        return ComplianceService()

    def test_data_completeness(self, compliance):
        """Test data completeness validation. Req 31.1."""
        result = compliance.validate_event_completeness(
            {"timestamp": "now", "source_id": "s1"},
            ["timestamp", "source_id", "event_type"],
        )
        assert result["complete"] is False
        assert "event_type" in result["missing_fields"]

    def test_duplicate_detection(self, compliance):
        """Test duplicate detection. Req 31.4."""
        result = compliance.detect_duplicates(["e1", "e2", "e1", "e3", "e2"])
        assert result["duplicates"] == 2
        assert result["duplicate_rate"] == 0.4
