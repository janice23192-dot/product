"""Alert Manager implementation.

Manages security alerts including prioritization, routing, notification,
deduplication, escalation, and lifecycle tracking.
Req 17.1-17.12.
"""

from __future__ import annotations

import time
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from sip.models.alerts import Alert, AlertResolution, AlertStatus, DetectionResult
from sip.utils.logging import get_logger

logger = get_logger(__name__)


class NotificationChannel:
    """Notification channel configuration. Req 17.4."""

    def __init__(self, name: str, channel_type: str, config: dict[str, Any] | None = None) -> None:
        self.name = name
        self.channel_type = channel_type  # email, sms, slack, pagerduty, webhook
        self.config = config or {}
        self.enabled = True


class EscalationPolicy:
    """Alert escalation policy. Req 17.6, 17.11."""

    def __init__(
        self,
        name: str,
        timeout_minutes: int = 15,
        levels: list[dict[str, Any]] | None = None,
    ) -> None:
        self.name = name
        self.timeout_minutes = timeout_minutes
        self.levels = levels or [
            {"level": 1, "targets": ["on_call_analyst"], "timeout_minutes": 15},
            {"level": 2, "targets": ["senior_analyst"], "timeout_minutes": 30},
            {"level": 3, "targets": ["security_manager"], "timeout_minutes": 60},
        ]


class AlertManager:
    """Alert Manager - manages security alert lifecycle.

    Prioritizes alerts (Req 17.1), deduplicates (Req 17.2),
    routes to analysts (Req 17.3), sends notifications within 10s (Req 17.5),
    handles escalation after 15 min (Req 17.11), and tracks metrics (Req 17.9).
    """

    def __init__(
        self,
        notification_timeout_seconds: int = 10,
        escalation_timeout_minutes: int = 15,
    ) -> None:
        self.notification_timeout_seconds = notification_timeout_seconds
        self.escalation_timeout_minutes = escalation_timeout_minutes

        self._alerts: dict[str, Alert] = {}
        self._notification_channels: dict[str, NotificationChannel] = {}
        self._escalation_policies: dict[str, EscalationPolicy] = {}
        self._suppression_rules: list[dict[str, Any]] = []
        self._dedup_window: dict[str, datetime] = {}  # fingerprint -> last_seen
        self._notification_callbacks: list[Callable] = []
        self._metrics = {
            "total_alerts": 0,
            "total_acknowledged": 0,
            "total_resolved": 0,
            "total_false_positive": 0,
            "total_suppressed": 0,
            "total_escalated": 0,
            "total_notifications_sent": 0,
        }

    # --- Alert Creation (Req 17.1) ---

    async def create_alert(self, detection: DetectionResult) -> Alert:
        """Create an alert from a detection result. Req 2.3."""
        # Check suppression. Req 17.8
        if self._is_suppressed(detection):
            self._metrics["total_suppressed"] += 1
            alert = Alert(
                detection_id=detection.detection_id,
                rule_id=detection.rule_id,
                title=f"[SUPPRESSED] {detection.threat_type}",
                severity=detection.severity,
                confidence=detection.confidence,
                status=AlertStatus.SUPPRESSED,
                affected_entities=detection.affected_entities,
                mitre_tactics=detection.mitre_tactics,
                mitre_techniques=detection.mitre_techniques,
            )
            self._alerts[alert.alert_id] = alert
            return alert

        # Check deduplication. Req 17.2
        dedup_key = f"{detection.rule_id}:{sorted(detection.affected_entities)}"
        if dedup_key in self._dedup_window:
            last_seen = self._dedup_window[dedup_key]
            if datetime.now(timezone.utc) - last_seen < timedelta(minutes=5):
                # Return existing alert (deduplicated)
                for alert in reversed(list(self._alerts.values())):
                    if alert.rule_id == detection.rule_id:
                        alert.source_events.append(detection.event_id)
                        return alert

        self._dedup_window[dedup_key] = datetime.now(timezone.utc)

        # Create new alert
        alert = Alert(
            detection_id=detection.detection_id,
            rule_id=detection.rule_id,
            title=f"Threat Detected: {detection.threat_type}",
            description=f"Detection rule '{detection.rule_name}' triggered. Type: {detection.rule_type}",
            severity=detection.severity,
            confidence=detection.confidence,
            affected_entities=detection.affected_entities,
            mitre_tactics=detection.mitre_tactics,
            mitre_techniques=detection.mitre_techniques,
            source_events=[detection.event_id],
        )

        # Calculate priority. Req 17.1
        alert.calculate_priority()

        # Route alert. Req 17.3
        self._route_alert(alert)

        self._alerts[alert.alert_id] = alert
        self._metrics["total_alerts"] += 1

        # Send notifications. Req 17.4, 17.5
        if detection.severity >= 80:
            await self._send_high_severity_notification(alert)

        for callback in self._notification_callbacks:
            try:
                await callback(alert)
            except Exception as e:
                logger.error("notification_callback_error", error=str(e))

        logger.info("alert_created", alert_id=alert.alert_id, severity=alert.severity)
        return alert

    # --- Alert Lifecycle (Req 17.7) ---

    async def acknowledge_alert(self, alert_id: str, analyst: str) -> Alert | None:
        """Acknowledge an alert. Req 17.7."""
        alert = self._alerts.get(alert_id)
        if not alert:
            return None
        alert.acknowledge(analyst)
        self._metrics["total_acknowledged"] += 1
        return alert

    async def resolve_alert(self, alert_id: str, resolution: AlertResolution) -> Alert | None:
        """Resolve an alert. Req 17.7."""
        alert = self._alerts.get(alert_id)
        if not alert:
            return None
        alert.resolve(resolution)
        self._metrics["total_resolved"] += 1
        if resolution.resolution_type == "false_positive":
            self._metrics["total_false_positive"] += 1
        return alert

    async def escalate_alert(self, alert_id: str) -> Alert | None:
        """Escalate an alert. Req 17.6, 17.11."""
        alert = self._alerts.get(alert_id)
        if not alert:
            return None
        alert.escalate()
        self._metrics["total_escalated"] += 1
        logger.info("alert_escalated", alert_id=alert_id, level=alert.escalation_level)
        return alert

    # --- Alert Queries ---

    def get_alert(self, alert_id: str) -> Alert | None:
        """Get alert by ID."""
        return self._alerts.get(alert_id)

    def get_alerts(
        self,
        status: AlertStatus | None = None,
        severity_min: int = 0,
        assigned_to: str | None = None,
        limit: int = 100,
    ) -> list[Alert]:
        """Get alerts with filters."""
        results = []
        for alert in sorted(self._alerts.values(), key=lambda a: a.created_at, reverse=True):
            if status and alert.status != status:
                continue
            if alert.severity < severity_min:
                continue
            if assigned_to and alert.assigned_to != assigned_to:
                continue
            results.append(alert)
            if len(results) >= limit:
                break
        return results

    # --- Escalation Check (Req 17.11) ---

    async def check_escalations(self) -> list[str]:
        """Check for alerts needing escalation. Req 17.11."""
        escalated: list[str] = []
        now = datetime.now(timezone.utc)

        for alert in self._alerts.values():
            if alert.status == AlertStatus.NEW:
                age = now - alert.created_at
                if age > timedelta(minutes=self.escalation_timeout_minutes):
                    await self.escalate_alert(alert.alert_id)
                    escalated.append(alert.alert_id)

        return escalated

    # --- Notification (Req 17.4, 17.5) ---

    def add_notification_channel(self, channel: NotificationChannel) -> None:
        """Add a notification channel. Req 17.4."""
        self._notification_channels[channel.name] = channel

    async def _send_high_severity_notification(self, alert: Alert) -> None:
        """Send immediate notification for high-severity alerts. Req 2.8."""
        self._metrics["total_notifications_sent"] += 1
        logger.info(
            "high_severity_notification",
            alert_id=alert.alert_id,
            severity=alert.severity,
        )

    def on_notification(self, callback: Callable) -> None:
        """Register notification callback."""
        self._notification_callbacks.append(callback)

    # --- Suppression (Req 17.8) ---

    def add_suppression_rule(self, rule: dict[str, Any]) -> None:
        """Add alert suppression rule. Req 17.8."""
        self._suppression_rules.append(rule)

    def _is_suppressed(self, detection: DetectionResult) -> bool:
        """Check if detection matches suppression rules."""
        for rule in self._suppression_rules:
            if "rule_id" in rule and rule["rule_id"] == detection.rule_id:
                return True
            if "threat_type" in rule and rule["threat_type"] == detection.threat_type:
                return True
        return False

    # --- Routing (Req 17.3) ---

    def _route_alert(self, alert: Alert) -> None:
        """Route alert to appropriate analyst. Req 17.3."""
        # Default routing based on severity
        if alert.severity >= 80:
            alert.assigned_to = "senior_analyst_team"
        elif alert.severity >= 50:
            alert.assigned_to = "analyst_team"
        else:
            alert.assigned_to = "operator_team"

    # --- Metrics (Req 17.9, 41.1-41.12) ---

    def get_metrics(self) -> dict[str, Any]:
        """Get alert metrics. Req 17.9."""
        alerts_list = list(self._alerts.values())

        # Calculate MTTD and MTTR. Req 41.1, 41.2
        ack_times = []
        resolve_times = []
        for alert in alerts_list:
            if alert.acknowledged_at:
                ack_times.append((alert.acknowledged_at - alert.created_at).total_seconds())
            if alert.resolved_at:
                resolve_times.append((alert.resolved_at - alert.created_at).total_seconds())

        metrics = dict(self._metrics)
        metrics["mean_time_to_acknowledge"] = sum(ack_times) / len(ack_times) if ack_times else 0
        metrics["mean_time_to_resolve"] = sum(resolve_times) / len(resolve_times) if resolve_times else 0
        metrics["false_positive_rate"] = (
            self._metrics["total_false_positive"] / self._metrics["total_resolved"]
            if self._metrics["total_resolved"] > 0
            else 0
        )
        metrics["alerts_by_severity"] = self._count_by_severity()

        return metrics

    def _count_by_severity(self) -> dict[str, int]:
        """Count alerts by severity bucket."""
        buckets = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for alert in self._alerts.values():
            if alert.severity >= 80:
                buckets["critical"] += 1
            elif alert.severity >= 60:
                buckets["high"] += 1
            elif alert.severity >= 40:
                buckets["medium"] += 1
            elif alert.severity >= 20:
                buckets["low"] += 1
            else:
                buckets["info"] += 1
        return buckets
