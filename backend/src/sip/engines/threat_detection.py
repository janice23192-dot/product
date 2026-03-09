"""Threat Detection Engine implementation.

Analyzes events in real-time to identify security threats using
signature-based, anomaly-based, behavioral, and statistical detection.
Req 2.1-2.10, 8.1-8.10.
"""

from __future__ import annotations

import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from pydantic import BaseModel, Field

from sip.models.alerts import DetectionResult
from sip.models.events import ParsedEvent
from sip.utils.logging import get_logger

logger = get_logger(__name__)


class DetectionRule(BaseModel):
    """Detection rule definition. Req 2.2, 2.4."""

    rule_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    rule_name: str
    rule_type: str = "signature"  # signature, anomaly, behavioral, statistical, ml
    description: str = ""
    condition: dict[str, Any] = Field(default_factory=dict)
    severity: int = Field(default=50, ge=1, le=100)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    enabled: bool = True
    priority: int = Field(default=100, ge=1)
    source: str = "custom"
    version: int = 1


class BehavioralBaseline(BaseModel):
    """Behavioral baseline for anomaly detection. Req 8.1."""

    entity_id: str
    entity_type: str
    feature_name: str
    mean: float = 0.0
    std_dev: float = 1.0
    min_value: float = 0.0
    max_value: float = 0.0
    sample_count: int = 0
    last_updated: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ThreatDetectionEngine:
    """Threat Detection Engine - analyzes events for security threats.

    Evaluates events against 1000+ concurrent rules (Req 2.2),
    within 500ms of ingestion (Req 2.1), assigns severity (Req 2.6)
    and confidence scores (Req 2.7).
    """

    def __init__(self, max_concurrent_rules: int = 1000, detection_timeout_ms: int = 500) -> None:
        self.max_concurrent_rules = max_concurrent_rules
        self.detection_timeout_ms = detection_timeout_ms

        self._rules: dict[str, DetectionRule] = {}
        self._baselines: dict[str, BehavioralBaseline] = {}
        self._detection_callbacks: list[Callable] = []
        self._metrics = {
            "total_analyzed": 0,
            "total_detections": 0,
            "total_timeout": 0,
            "avg_analysis_time_ms": 0.0,
            "false_positive_count": 0,
            "true_positive_count": 0,
        }

    # --- Rule Management (Req 2.2) ---

    def add_detection_rule(self, rule: DetectionRule) -> str:
        """Add a detection rule. Req 2.2."""
        if len(self._rules) >= self.max_concurrent_rules:
            raise ValueError(f"Maximum rules ({self.max_concurrent_rules}) reached")
        self._rules[rule.rule_id] = rule
        logger.info("detection_rule_added", rule_id=rule.rule_id, name=rule.rule_name)
        return rule.rule_id

    def update_detection_rule(self, rule_id: str, rule: DetectionRule) -> None:
        """Update an existing rule."""
        if rule_id not in self._rules:
            raise ValueError(f"Rule not found: {rule_id}")
        rule.rule_id = rule_id
        self._rules[rule_id] = rule

    def remove_detection_rule(self, rule_id: str) -> None:
        """Remove a detection rule."""
        self._rules.pop(rule_id, None)

    def get_rule(self, rule_id: str) -> DetectionRule | None:
        """Get a detection rule by ID."""
        return self._rules.get(rule_id)

    def get_all_rules(self) -> list[DetectionRule]:
        """Get all active rules."""
        return [r for r in self._rules.values() if r.enabled]

    # --- Event Analysis (Req 2.1) ---

    async def analyze_event(self, event: ParsedEvent) -> list[DetectionResult]:
        """Analyze a single event against all rules within 500ms. Req 2.1."""
        start_time = time.monotonic()
        results: list[DetectionResult] = []

        # Sort rules by priority for efficient evaluation
        active_rules = sorted(
            (r for r in self._rules.values() if r.enabled),
            key=lambda r: r.priority,
        )

        for rule in active_rules:
            elapsed_ms = (time.monotonic() - start_time) * 1000
            if elapsed_ms > self.detection_timeout_ms:
                self._metrics["total_timeout"] += 1
                logger.warning("detection_timeout", elapsed_ms=elapsed_ms)
                break

            try:
                match = self._evaluate_rule(rule, event)
                if match:
                    detection = DetectionResult(
                        rule_id=rule.rule_id,
                        rule_name=rule.rule_name,
                        event_id=event.event_id,
                        severity=self._calculate_severity(rule, event),
                        confidence=self._calculate_confidence(rule, event),
                        threat_type=rule.condition.get("threat_type", "unknown"),
                        rule_type=rule.rule_type,
                        affected_entities=[e.entity_id for e in event.entities],
                        context={
                            "rule_name": rule.rule_name,
                            "event_type": event.event_type,
                            "source_id": event.source_id,
                            "match_details": match,
                        },
                        mitre_tactics=rule.mitre_tactics,
                        mitre_techniques=rule.mitre_techniques,
                    )
                    results.append(detection)

            except Exception as e:
                logger.error("rule_evaluation_error", rule_id=rule.rule_id, error=str(e))

        # Update metrics
        analysis_time = (time.monotonic() - start_time) * 1000
        self._metrics["total_analyzed"] += 1
        self._metrics["total_detections"] += len(results)
        n = self._metrics["total_analyzed"]
        self._metrics["avg_analysis_time_ms"] = (
            (self._metrics["avg_analysis_time_ms"] * (n - 1) + analysis_time) / n
        )

        # Notify callbacks
        for detection in results:
            for callback in self._detection_callbacks:
                try:
                    await callback(detection)
                except Exception as e:
                    logger.error("detection_callback_error", error=str(e))

        return results

    async def analyze_batch(self, events: list[ParsedEvent]) -> list[DetectionResult]:
        """Analyze a batch of events. Req 2.1."""
        all_results: list[DetectionResult] = []
        for event in events:
            results = await self.analyze_event(event)
            all_results.extend(results)
        return all_results

    # --- Behavioral Baseline (Req 8.1) ---

    def update_behavioral_baseline(self, entity_id: str, entity_type: str, feature_name: str, value: float) -> None:
        """Update behavioral baseline for an entity. Req 8.1."""
        key = f"{entity_id}:{feature_name}"
        if key not in self._baselines:
            self._baselines[key] = BehavioralBaseline(
                entity_id=entity_id,
                entity_type=entity_type,
                feature_name=feature_name,
            )
        baseline = self._baselines[key]

        # Online mean and std dev update (Welford's algorithm)
        baseline.sample_count += 1
        n = baseline.sample_count
        delta = value - baseline.mean
        baseline.mean += delta / n
        delta2 = value - baseline.mean
        m2 = baseline.std_dev ** 2 * (n - 1) + delta * delta2
        baseline.std_dev = (m2 / n) ** 0.5 if n > 1 else 0.0
        baseline.min_value = min(baseline.min_value, value)
        baseline.max_value = max(baseline.max_value, value)
        baseline.last_updated = datetime.now(timezone.utc)

    def check_anomaly(self, entity_id: str, feature_name: str, value: float, threshold_std: float = 3.0) -> dict[str, Any] | None:
        """Check if value is anomalous based on baseline. Req 8.2."""
        key = f"{entity_id}:{feature_name}"
        baseline = self._baselines.get(key)
        if not baseline or baseline.sample_count < 10:
            return None

        if baseline.std_dev == 0:
            return None

        z_score = abs(value - baseline.mean) / baseline.std_dev
        if z_score > threshold_std:
            return {
                "entity_id": entity_id,
                "feature": feature_name,
                "value": value,
                "mean": baseline.mean,
                "std_dev": baseline.std_dev,
                "z_score": z_score,
                "threshold": threshold_std,
                "anomaly_score": min(100.0, z_score * 20),
            }
        return None

    # --- Testing Rules ---

    def test_detection_rule(self, rule: DetectionRule, test_events: list[ParsedEvent]) -> dict[str, Any]:
        """Test a rule against sample events. Req 2.4."""
        matches = 0
        non_matches = 0
        for event in test_events:
            match = self._evaluate_rule(rule, event)
            if match:
                matches += 1
            else:
                non_matches += 1
        return {
            "total_events": len(test_events),
            "matches": matches,
            "non_matches": non_matches,
            "match_rate": matches / len(test_events) if test_events else 0,
        }

    # --- Callbacks ---

    def on_detection(self, callback: Callable) -> None:
        """Register callback for new detections."""
        self._detection_callbacks.append(callback)

    def get_metrics(self) -> dict[str, Any]:
        """Get detection engine metrics."""
        return dict(self._metrics)

    # --- Rule Evaluation ---

    def _evaluate_rule(self, rule: DetectionRule, event: ParsedEvent) -> dict[str, Any] | None:
        """Evaluate a single rule against an event."""
        condition = rule.condition

        if rule.rule_type == "signature":
            return self._evaluate_signature(condition, event)
        elif rule.rule_type == "anomaly":
            return self._evaluate_anomaly(condition, event)
        elif rule.rule_type == "behavioral":
            return self._evaluate_behavioral(condition, event)
        elif rule.rule_type == "statistical":
            return self._evaluate_statistical(condition, event)
        elif rule.rule_type == "ml":
            return self._evaluate_ml(condition, event)
        return None

    def _evaluate_signature(self, condition: dict[str, Any], event: ParsedEvent) -> dict[str, Any] | None:
        """Evaluate signature-based rule. Req 2.4."""
        # Match on event type
        if "event_type" in condition:
            if event.event_type != condition["event_type"]:
                return None

        # Match on severity threshold
        if "min_severity" in condition:
            if event.severity < condition["min_severity"]:
                return None

        # Match on attribute patterns
        if "attribute_patterns" in condition:
            for attr_name, pattern in condition["attribute_patterns"].items():
                attr_value = str(event.attributes.get(attr_name, ""))
                if not re.search(pattern, attr_value, re.IGNORECASE):
                    return None

        # Match on entity types
        if "entity_types" in condition:
            event_entity_types = {e.entity_type.value for e in event.entities}
            required = set(condition["entity_types"])
            if not required.intersection(event_entity_types):
                return None

        # Match on keywords in attributes
        if "keywords" in condition:
            flat = str(event.attributes).lower()
            if not any(kw.lower() in flat for kw in condition["keywords"]):
                return None

        return {"match_type": "signature", "conditions_matched": list(condition.keys())}

    def _evaluate_anomaly(self, condition: dict[str, Any], event: ParsedEvent) -> dict[str, Any] | None:
        """Evaluate anomaly-based rule. Req 2.4, 8.2."""
        feature = condition.get("feature", "")
        threshold = condition.get("threshold_std", 3.0)

        for entity in event.entities:
            value = event.attributes.get(feature, None)
            if value is not None and isinstance(value, (int, float)):
                anomaly = self.check_anomaly(entity.entity_id, feature, float(value), threshold)
                if anomaly:
                    return {"match_type": "anomaly", **anomaly}
        return None

    def _evaluate_behavioral(self, condition: dict[str, Any], event: ParsedEvent) -> dict[str, Any] | None:
        """Evaluate behavioral rule. Req 2.4."""
        # Check for behavioral patterns like unusual timing, frequency, etc.
        behavior_type = condition.get("behavior_type", "")

        if behavior_type == "unusual_time" and "hour" in event.attributes:
            hour = int(event.attributes["hour"])
            if condition.get("min_hour", 0) <= hour <= condition.get("max_hour", 23):
                return None  # Within normal hours
            return {"match_type": "behavioral", "behavior": "unusual_time", "hour": hour}

        if behavior_type == "high_frequency":
            # Would check frequency counters in production
            pass

        return None

    def _evaluate_statistical(self, condition: dict[str, Any], event: ParsedEvent) -> dict[str, Any] | None:
        """Evaluate statistical rule. Req 2.4."""
        # Statistical rules check for patterns like frequency spikes
        return None

    def _evaluate_ml(self, condition: dict[str, Any], event: ParsedEvent) -> dict[str, Any] | None:
        """Evaluate ML-based rule. Req 8.1-8.10."""
        # ML model inference - in production would call model serving
        return None

    def _calculate_severity(self, rule: DetectionRule, event: ParsedEvent) -> int:
        """Calculate severity score (1-100). Req 2.6."""
        base_severity = rule.severity
        event_severity = event.severity

        # Combine rule and event severity
        combined = int(base_severity * 0.6 + event_severity * 0.4)
        return max(1, min(100, combined))

    def _calculate_confidence(self, rule: DetectionRule, event: ParsedEvent) -> float:
        """Calculate confidence score (0-1). Req 2.7."""
        base_confidence = rule.confidence

        # Adjust based on entity count (more entities = more context = higher confidence)
        entity_boost = min(0.1, len(event.entities) * 0.02)

        return min(1.0, base_confidence + entity_boost)
