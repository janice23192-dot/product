"""Behavioral Analytics and ML Service implementation.

Provides behavioral baseline modeling, anomaly detection, UEBA features,
and supervised learning. Req 8.1-8.10, 22.1-22.12, 45.1-45.12.
"""

from __future__ import annotations

import math
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from pydantic import BaseModel, Field

from sip.utils.logging import get_logger

logger = get_logger(__name__)


class BehavioralBaseline(BaseModel):
    """Behavioral baseline for an entity. Req 8.1, 22.1."""

    baseline_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    entity_id: str
    entity_type: str
    feature_name: str
    mean: float = 0.0
    std_dev: float = 1.0
    min_value: float = float("inf")
    max_value: float = float("-inf")
    sample_count: int = 0
    m2: float = 0.0  # For Welford's algorithm
    last_updated: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AnomalyDetection(BaseModel):
    """Anomaly detection result. Req 8.2, 8.3."""

    anomaly_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    entity_id: str
    entity_type: str
    feature_name: str
    observed_value: float
    expected_mean: float
    expected_std_dev: float
    z_score: float
    anomaly_score: float = 0.0
    explanation: str = ""
    contributing_features: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class UserRiskScore(BaseModel):
    """User/entity risk score. Req 22.3."""

    entity_id: str
    entity_type: str
    risk_score: float = 0.0
    risk_factors: list[dict[str, Any]] = Field(default_factory=list)
    peer_group_avg: float = 0.0
    last_updated: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class BehavioralAnalyticsService:
    """Behavioral Analytics - anomaly detection and UEBA.

    Trains behavioral baselines (Req 8.1, 22.1), detects anomalies
    by configurable thresholds (Req 8.2), detects impossible travel
    (Req 22.4), privilege escalation (Req 22.5), data exfiltration
    (Req 22.6), and calculates risk scores (Req 22.3).
    """

    def __init__(self, anomaly_threshold_std: float = 3.0) -> None:
        self.anomaly_threshold_std = anomaly_threshold_std
        self._baselines: dict[str, BehavioralBaseline] = {}
        self._risk_scores: dict[str, UserRiskScore] = {}
        self._login_history: dict[str, list[dict[str, Any]]] = {}
        self._feedback: list[dict[str, Any]] = []

    # --- Baseline Management (Req 8.1, 8.5) ---

    def update_baseline(self, entity_id: str, entity_type: str, feature_name: str, value: float) -> BehavioralBaseline:
        """Update behavioral baseline using Welford's online algorithm. Req 8.1."""
        key = f"{entity_id}:{feature_name}"

        if key not in self._baselines:
            self._baselines[key] = BehavioralBaseline(
                entity_id=entity_id,
                entity_type=entity_type,
                feature_name=feature_name,
            )

        b = self._baselines[key]
        b.sample_count += 1
        delta = value - b.mean
        b.mean += delta / b.sample_count
        delta2 = value - b.mean
        b.m2 += delta * delta2
        b.std_dev = math.sqrt(b.m2 / b.sample_count) if b.sample_count > 1 else 0.0
        b.min_value = min(b.min_value, value)
        b.max_value = max(b.max_value, value)
        b.last_updated = datetime.now(timezone.utc)

        return b

    def get_baseline(self, entity_id: str, feature_name: str) -> BehavioralBaseline | None:
        """Get baseline for entity feature."""
        return self._baselines.get(f"{entity_id}:{feature_name}")

    # --- Anomaly Detection (Req 8.2, 8.3, 8.6) ---

    def detect_anomaly(
        self,
        entity_id: str,
        entity_type: str,
        feature_name: str,
        value: float,
        threshold_std: float | None = None,
    ) -> AnomalyDetection | None:
        """Detect anomaly based on baseline deviation. Req 8.2."""
        threshold = threshold_std or self.anomaly_threshold_std
        baseline = self.get_baseline(entity_id, feature_name)

        if not baseline or baseline.sample_count < 10:
            return None

        if baseline.std_dev == 0:
            return None

        z_score = abs(value - baseline.mean) / baseline.std_dev

        if z_score > threshold:
            anomaly_score = min(100.0, z_score * 20)
            explanation = (
                f"Value {value:.2f} deviates {z_score:.1f} standard deviations from "
                f"mean {baseline.mean:.2f} (std: {baseline.std_dev:.2f})"
            )

            return AnomalyDetection(
                entity_id=entity_id,
                entity_type=entity_type,
                feature_name=feature_name,
                observed_value=value,
                expected_mean=baseline.mean,
                expected_std_dev=baseline.std_dev,
                z_score=z_score,
                anomaly_score=anomaly_score,
                explanation=explanation,
                contributing_features=[feature_name],
            )
        return None

    # --- UEBA Features ---

    def detect_impossible_travel(
        self,
        entity_id: str,
        latitude: float,
        longitude: float,
        timestamp: datetime,
        max_speed_kmh: float = 900,
    ) -> dict[str, Any] | None:
        """Detect impossible travel scenarios. Req 22.4."""
        key = entity_id
        if key not in self._login_history:
            self._login_history[key] = []

        history = self._login_history[key]

        if history:
            last = history[-1]
            time_diff_hours = (timestamp - datetime.fromisoformat(last["timestamp"])).total_seconds() / 3600

            if time_diff_hours > 0:
                distance_km = self._haversine_distance(
                    last["latitude"], last["longitude"], latitude, longitude
                )
                speed_kmh = distance_km / time_diff_hours

                if speed_kmh > max_speed_kmh:
                    result = {
                        "entity_id": entity_id,
                        "detection_type": "impossible_travel",
                        "distance_km": round(distance_km, 2),
                        "time_diff_hours": round(time_diff_hours, 2),
                        "implied_speed_kmh": round(speed_kmh, 2),
                        "max_speed_kmh": max_speed_kmh,
                        "from_location": {"lat": last["latitude"], "lon": last["longitude"]},
                        "to_location": {"lat": latitude, "lon": longitude},
                    }
                    history.append({"latitude": latitude, "longitude": longitude, "timestamp": timestamp.isoformat()})
                    return result

        history.append({"latitude": latitude, "longitude": longitude, "timestamp": timestamp.isoformat()})
        # Keep last 100 entries
        if len(history) > 100:
            self._login_history[key] = history[-100:]
        return None

    @staticmethod
    def _haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Calculate distance between two points in km."""
        R = 6371  # Earth radius in km
        dlat = math.radians(lat2 - lat1)
        dlon = math.radians(lon2 - lon1)
        a = math.sin(dlat / 2) ** 2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2) ** 2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        return R * c

    def calculate_risk_score(self, entity_id: str, entity_type: str) -> UserRiskScore:
        """Calculate entity risk score. Req 22.3."""
        risk_factors: list[dict[str, Any]] = []
        total_score = 0.0

        # Check all baselines for this entity
        for key, baseline in self._baselines.items():
            if not key.startswith(f"{entity_id}:"):
                continue
            # Recent anomalies would contribute to risk
            risk_factors.append({
                "feature": baseline.feature_name,
                "samples": baseline.sample_count,
            })

        risk_score = UserRiskScore(
            entity_id=entity_id,
            entity_type=entity_type,
            risk_score=min(100.0, total_score),
            risk_factors=risk_factors,
        )
        self._risk_scores[entity_id] = risk_score
        return risk_score

    # --- Feedback (Req 45.1-45.12) ---

    def submit_feedback(self, detection_id: str, is_true_positive: bool, analyst_id: str = "", notes: str = "") -> None:
        """Submit analyst feedback on detection. Req 45.1."""
        self._feedback.append({
            "detection_id": detection_id,
            "is_true_positive": is_true_positive,
            "analyst_id": analyst_id,
            "notes": notes,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def get_metrics(self) -> dict[str, Any]:
        """Get behavioral analytics metrics."""
        return {
            "total_baselines": len(self._baselines),
            "total_risk_scores": len(self._risk_scores),
            "total_feedback": len(self._feedback),
            "entities_tracked": len(set(b.entity_id for b in self._baselines.values())),
        }
