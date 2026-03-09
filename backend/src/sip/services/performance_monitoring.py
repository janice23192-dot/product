"""Performance Monitoring and Observability Service implementation.

Collects metrics, monitors health, provides dashboards, and
supports distributed tracing. Req 30.1-30.12.
"""

from __future__ import annotations

import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from sip.utils.logging import get_logger

logger = get_logger(__name__)


class PerformanceMonitoringService:
    """Performance Monitoring - metrics collection and health monitoring.

    Collects CPU/memory/disk/network metrics (Req 30.1), monitors
    query performance (Req 30.2), tracks ingestion rates (Req 30.3),
    and generates alerts (Req 30.6).
    """

    def __init__(self) -> None:
        self._metrics: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._component_health: dict[str, dict[str, Any]] = {}
        self._alert_thresholds: dict[str, float] = {}
        self._traces: dict[str, list[dict[str, Any]]] = {}

    def record_metric(self, name: str, value: float, tags: dict[str, str] | None = None) -> None:
        """Record a metric value. Req 30.1."""
        self._metrics[name].append({
            "value": value,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tags": tags or {},
        })
        # Keep last 10000 entries per metric
        if len(self._metrics[name]) > 10000:
            self._metrics[name] = self._metrics[name][-10000:]

        # Check thresholds. Req 30.6
        threshold = self._alert_thresholds.get(name)
        if threshold and value > threshold:
            logger.warning("performance_alert", metric=name, value=value, threshold=threshold)

    def update_component_health(self, component: str, status: str, details: dict[str, Any] | None = None) -> None:
        """Update component health status. Req 30.4."""
        self._component_health[component] = {
            "status": status,
            "last_check": datetime.now(timezone.utc).isoformat(),
            "details": details or {},
        }

    def set_alert_threshold(self, metric_name: str, threshold: float) -> None:
        """Set alert threshold for a metric. Req 30.6."""
        self._alert_thresholds[metric_name] = threshold

    def start_trace(self, trace_id: str | None = None) -> str:
        """Start a distributed trace. Req 30.7."""
        tid = trace_id or str(uuid.uuid4())
        self._traces[tid] = []
        return tid

    def add_trace_span(self, trace_id: str, span_name: str, duration_ms: float, details: dict[str, Any] | None = None) -> None:
        """Add a span to a trace. Req 30.7."""
        if trace_id in self._traces:
            self._traces[trace_id].append({
                "span_name": span_name,
                "duration_ms": duration_ms,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "details": details or {},
            })

    def get_metric_summary(self, name: str) -> dict[str, Any]:
        """Get metric summary statistics. Req 30.5."""
        values = [m["value"] for m in self._metrics.get(name, [])]
        if not values:
            return {"name": name, "count": 0}
        return {
            "name": name,
            "count": len(values),
            "avg": sum(values) / len(values),
            "min": min(values),
            "max": max(values),
            "latest": values[-1],
        }

    def get_health_status(self) -> dict[str, Any]:
        """Get overall health status. Req 30.4."""
        healthy = sum(1 for c in self._component_health.values() if c["status"] == "healthy")
        total = len(self._component_health)
        return {
            "overall": "healthy" if healthy == total and total > 0 else "degraded",
            "components": dict(self._component_health),
            "healthy_count": healthy,
            "total_count": total,
        }

    def get_metrics(self) -> dict[str, Any]:
        return {
            "tracked_metrics": len(self._metrics),
            "components_monitored": len(self._component_health),
            "active_traces": len(self._traces),
        }
