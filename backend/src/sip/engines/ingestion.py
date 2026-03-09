"""Data Ingestion Engine implementation.

Collects security data from heterogeneous sources, validates connections,
handles retries with exponential backoff, deduplicates events, and tags
metadata. Req 1.1-1.10.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from pydantic import BaseModel, Field

from sip.models.events import ClassificationLevel, ParsedEvent, RawEvent
from sip.utils.logging import get_logger

logger = get_logger(__name__)


class DataSourceConfig(BaseModel):
    """Configuration for a data source connection. Req 1.1, 1.2."""

    source_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    source_type: str  # syslog, api, agent, file, stream
    connection_params: dict[str, Any] = Field(default_factory=dict)
    authentication: dict[str, Any] = Field(default_factory=dict)
    classification: ClassificationLevel = ClassificationLevel.UNCLASSIFIED
    retry_policy: dict[str, Any] = Field(default_factory=lambda: {
        "max_attempts": 5,
        "initial_delay_ms": 100,
        "max_delay_ms": 30000,
        "multiplier": 2.0,
    })
    enabled: bool = True


class ConnectionHealth(BaseModel):
    """Health status for a data source connection."""

    source_id: str
    status: str = "unknown"  # healthy, degraded, disconnected, error
    last_event_at: datetime | None = None
    events_per_second: float = 0.0
    bytes_per_second: float = 0.0
    error_rate: float = 0.0
    connection_uptime: float = 0.0
    retry_count: int = 0
    last_error: str = ""


class IngestionMetrics(BaseModel):
    """Metrics for the ingestion engine. Req 1.6."""

    total_events_ingested: int = 0
    total_events_deduplicated: int = 0
    total_errors: int = 0
    events_per_second: float = 0.0
    active_sources: int = 0
    source_metrics: dict[str, dict[str, Any]] = Field(default_factory=dict)


class DataIngestionEngine:
    """Data Ingestion Engine - collects and normalizes security data.

    Supports 50+ concurrent data sources (Req 1.1), validates connections
    within 5 seconds (Req 1.2), retries with exponential backoff (Req 1.5),
    deduplicates within 60-second windows (Req 1.9), and tags metadata (Req 1.10).
    """

    def __init__(
        self,
        max_concurrent_sources: int = 50,
        deduplication_window_seconds: int = 60,
        max_retry_attempts: int = 5,
    ) -> None:
        self.max_concurrent_sources = max_concurrent_sources
        self.deduplication_window_seconds = deduplication_window_seconds
        self.max_retry_attempts = max_retry_attempts

        self._sources: dict[str, DataSourceConfig] = {}
        self._health: dict[str, ConnectionHealth] = {}
        self._dedup_cache: dict[str, float] = {}  # fingerprint -> timestamp
        self._metrics = IngestionMetrics()
        self._event_callbacks: list[Callable] = []
        self._alert_callbacks: list[Callable] = []
        self._running = False

    # --- Connection Management ---

    async def register_data_source(self, config: DataSourceConfig) -> str:
        """Register a new data source. Req 1.1."""
        if len(self._sources) >= self.max_concurrent_sources:
            raise ValueError(
                f"Maximum concurrent sources ({self.max_concurrent_sources}) reached"
            )

        self._sources[config.source_id] = config
        self._health[config.source_id] = ConnectionHealth(
            source_id=config.source_id, status="registered"
        )

        logger.info("data_source_registered", source_id=config.source_id, name=config.name)
        return config.source_id

    async def validate_connection(self, source_id: str) -> dict[str, Any]:
        """Validate a data source connection within 5 seconds. Req 1.2."""
        if source_id not in self._sources:
            return {"valid": False, "error": "Source not found"}

        config = self._sources[source_id]
        start_time = time.monotonic()

        try:
            # Simulate connection validation based on source type
            await asyncio.wait_for(
                self._test_connection(config), timeout=5.0
            )

            elapsed = time.monotonic() - start_time
            self._health[source_id].status = "healthy"
            return {"valid": True, "latency_ms": elapsed * 1000}

        except asyncio.TimeoutError:
            self._health[source_id].status = "error"
            return {"valid": False, "error": "Connection validation timed out (>5s)"}
        except Exception as e:
            self._health[source_id].status = "error"
            self._health[source_id].last_error = str(e)
            return {"valid": False, "error": str(e)}

    async def remove_data_source(self, source_id: str) -> None:
        """Remove a data source."""
        self._sources.pop(source_id, None)
        self._health.pop(source_id, None)
        logger.info("data_source_removed", source_id=source_id)

    # --- Data Ingestion ---

    async def ingest_event(self, source_id: str, raw_data: bytes) -> ParsedEvent | None:
        """Ingest a single event from a data source. Req 1.3."""
        if source_id not in self._sources:
            raise ValueError(f"Unknown source: {source_id}")

        config = self._sources[source_id]
        raw_event = RawEvent(
            source_id=source_id,
            raw_data=raw_data,
            source_type=config.source_type,
        )

        # Create a basic parsed event (schema mapper will do full parsing)
        event = ParsedEvent(
            timestamp=datetime.now(timezone.utc),
            source_id=source_id,
            event_type=config.source_type,
            raw_data=raw_data,
            classification=config.classification,
            tags={
                "source_id": source_id,
                "source_name": config.name,
                "source_type": config.source_type,
            },
        )

        # Deduplication check. Req 1.9
        fingerprint = event.fingerprint()
        if self._is_duplicate(fingerprint):
            self._metrics.total_events_deduplicated += 1
            return None

        # Record in dedup cache
        self._dedup_cache[fingerprint] = time.time()

        # Update metrics
        self._metrics.total_events_ingested += 1
        self._update_source_metrics(source_id)

        # Notify callbacks
        for callback in self._event_callbacks:
            try:
                await callback(event)
            except Exception as e:
                logger.error("event_callback_error", error=str(e))

        return event

    async def ingest_batch(self, source_id: str, events_data: list[bytes]) -> dict[str, Any]:
        """Ingest a batch of events. Req 1.6."""
        results = {"ingested": 0, "deduplicated": 0, "errors": 0}

        for raw_data in events_data:
            try:
                event = await self.ingest_event(source_id, raw_data)
                if event:
                    results["ingested"] += 1
                else:
                    results["deduplicated"] += 1
            except Exception as e:
                results["errors"] += 1
                logger.error("batch_ingest_error", source_id=source_id, error=str(e))

        return results

    # --- Retry Logic (Req 1.5) ---

    async def ingest_with_retry(self, source_id: str, raw_data: bytes) -> ParsedEvent | None:
        """Ingest with exponential backoff retry. Req 1.5."""
        config = self._sources.get(source_id)
        if not config:
            raise ValueError(f"Unknown source: {source_id}")

        policy = config.retry_policy
        max_attempts = policy.get("max_attempts", self.max_retry_attempts)
        delay_ms = policy.get("initial_delay_ms", 100)
        max_delay_ms = policy.get("max_delay_ms", 30000)
        multiplier = policy.get("multiplier", 2.0)

        last_error: Exception | None = None
        for attempt in range(1, max_attempts + 1):
            try:
                return await self.ingest_event(source_id, raw_data)
            except Exception as e:
                last_error = e
                self._health[source_id].retry_count += 1
                logger.warning(
                    "ingestion_retry",
                    source_id=source_id,
                    attempt=attempt,
                    max_attempts=max_attempts,
                    error=str(e),
                )
                if attempt < max_attempts:
                    await asyncio.sleep(delay_ms / 1000.0)
                    delay_ms = min(delay_ms * multiplier, max_delay_ms)

        # All retries exhausted - generate system alert. Req 1.7
        self._health[source_id].status = "error"
        self._health[source_id].last_error = str(last_error)
        self._metrics.total_errors += 1

        for callback in self._alert_callbacks:
            try:
                await callback({
                    "type": "ingestion_failure",
                    "source_id": source_id,
                    "error": str(last_error),
                    "attempts": max_attempts,
                })
            except Exception:
                pass

        logger.error("ingestion_failed_all_retries", source_id=source_id, error=str(last_error))
        return None

    # --- Deduplication (Req 1.9) ---

    def _is_duplicate(self, fingerprint: str) -> bool:
        """Check if event is duplicate within the deduplication window."""
        now = time.time()
        if fingerprint in self._dedup_cache:
            cached_time = self._dedup_cache[fingerprint]
            if now - cached_time < self.deduplication_window_seconds:
                return True
        return False

    def cleanup_dedup_cache(self) -> int:
        """Remove expired entries from the dedup cache."""
        now = time.time()
        expired = [
            fp for fp, ts in self._dedup_cache.items()
            if now - ts >= self.deduplication_window_seconds
        ]
        for fp in expired:
            del self._dedup_cache[fp]
        return len(expired)

    # --- Health Monitoring ---

    def get_source_health(self, source_id: str) -> ConnectionHealth:
        """Get health status for a data source."""
        return self._health.get(source_id, ConnectionHealth(source_id=source_id, status="unknown"))

    def get_metrics(self) -> IngestionMetrics:
        """Get ingestion metrics. Req 1.6."""
        self._metrics.active_sources = sum(
            1 for h in self._health.values() if h.status == "healthy"
        )
        return self._metrics

    # --- Callbacks ---

    def on_event(self, callback: Callable) -> None:
        """Register callback for ingested events."""
        self._event_callbacks.append(callback)

    def on_alert(self, callback: Callable) -> None:
        """Register callback for system alerts. Req 1.7."""
        self._alert_callbacks.append(callback)

    # --- Internal ---

    async def _test_connection(self, config: DataSourceConfig) -> None:
        """Test connection to a data source."""
        # In production, this would actually test the connection
        # For now, simulate successful connection
        await asyncio.sleep(0.01)

    def _update_source_metrics(self, source_id: str) -> None:
        """Update per-source metrics."""
        if source_id not in self._metrics.source_metrics:
            self._metrics.source_metrics[source_id] = {
                "total_events": 0,
                "last_event_at": None,
            }
        metrics = self._metrics.source_metrics[source_id]
        metrics["total_events"] += 1
        metrics["last_event_at"] = datetime.now(timezone.utc).isoformat()

        health = self._health.get(source_id)
        if health:
            health.last_event_at = datetime.now(timezone.utc)
