"""InfluxDB time-series database client.

Stores security events as time-series data with retention policies.
Req 1.1-1.10, 12.1-12.12.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any


class InfluxDBClient:
    """InfluxDB client for time-series security event storage."""

    # Retention policies: hot (30d), warm (1y), cold (7y). Req 12.4
    RETENTION_POLICIES = {
        "hot": 30 * 24 * 3600,      # 30 days in seconds
        "warm": 365 * 24 * 3600,    # 1 year
        "cold": 7 * 365 * 24 * 3600,  # 7 years
    }

    def __init__(self, url: str, token: str, org: str, bucket: str) -> None:
        self.url = url
        self.token = token
        self.org = org
        self.bucket = bucket
        self._client: Any = None
        self._write_api: Any = None
        self._query_api: Any = None

    async def init(self) -> None:
        """Initialize InfluxDB connection."""
        from influxdb_client import InfluxDBClient as _InfluxClient
        from influxdb_client.client.write_api import SYNCHRONOUS

        self._client = _InfluxClient(url=self.url, token=self.token, org=self.org)
        self._write_api = self._client.write_api(write_options=SYNCHRONOUS)
        self._query_api = self._client.query_api()

    def write_event(self, event_data: dict[str, Any]) -> None:
        """Write a security event to InfluxDB."""
        from influxdb_client import Point

        point = Point("security_event")
        point.tag("source_id", event_data.get("source_id", "unknown"))
        point.tag("event_type", event_data.get("event_type", "unknown"))
        point.tag("severity_level", self._severity_bucket(event_data.get("severity", 0)))
        point.tag("classification", event_data.get("classification", "unclassified"))

        point.field("event_id", event_data.get("event_id", ""))
        point.field("severity", event_data.get("severity", 0))
        point.field("risk_score", event_data.get("risk_score", 0.0))
        point.field("entity_count", len(event_data.get("entities", [])))

        if "timestamp" in event_data:
            point.time(event_data["timestamp"])

        self._write_api.write(bucket=self.bucket, record=point)

    def write_events_batch(self, events: list[dict[str, Any]]) -> None:
        """Write multiple events in a batch."""
        from influxdb_client import Point

        points = []
        for event_data in events:
            point = Point("security_event")
            point.tag("source_id", event_data.get("source_id", "unknown"))
            point.tag("event_type", event_data.get("event_type", "unknown"))
            point.tag("severity_level", self._severity_bucket(event_data.get("severity", 0)))
            point.field("event_id", event_data.get("event_id", ""))
            point.field("severity", event_data.get("severity", 0))
            point.field("risk_score", event_data.get("risk_score", 0.0))
            if "timestamp" in event_data:
                point.time(event_data["timestamp"])
            points.append(point)

        self._write_api.write(bucket=self.bucket, record=points)

    def query_time_range(
        self,
        start: str,
        stop: str = "now()",
        filters: dict[str, str] | None = None,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        """Query events within a time range. Req 5.11, 14.12."""
        flux = f"""
        from(bucket: "{self.bucket}")
            |> range(start: {start}, stop: {stop})
            |> filter(fn: (r) => r._measurement == "security_event")
        """
        if filters:
            for key, value in filters.items():
                flux += f'    |> filter(fn: (r) => r.{key} == "{value}")\n'
        flux += f"    |> limit(n: {limit})"

        results: list[dict[str, Any]] = []
        tables = self._query_api.query(flux, org=self.org)
        for table in tables:
            for record in table.records:
                results.append({
                    "time": record.get_time().isoformat(),
                    "field": record.get_field(),
                    "value": record.get_value(),
                    **{k: v for k, v in record.values.items() if not k.startswith("_")},
                })
        return results

    def query_aggregation(
        self,
        start: str,
        stop: str = "now()",
        window: str = "1h",
        fn: str = "count",
    ) -> list[dict[str, Any]]:
        """Query aggregated metrics over time windows."""
        flux = f"""
        from(bucket: "{self.bucket}")
            |> range(start: {start}, stop: {stop})
            |> filter(fn: (r) => r._measurement == "security_event")
            |> aggregateWindow(every: {window}, fn: {fn})
            |> yield(name: "{fn}")
        """
        results: list[dict[str, Any]] = []
        tables = self._query_api.query(flux, org=self.org)
        for table in tables:
            for record in table.records:
                results.append({
                    "time": record.get_time().isoformat(),
                    "value": record.get_value(),
                })
        return results

    def close(self) -> None:
        """Close the InfluxDB client."""
        if self._client:
            self._client.close()

    def ping(self) -> bool:
        """Health check."""
        try:
            return self._client.ping()
        except Exception:
            return False

    @staticmethod
    def _severity_bucket(severity: int) -> str:
        """Categorize severity into buckets for efficient tagging."""
        if severity >= 80:
            return "critical"
        elif severity >= 60:
            return "high"
        elif severity >= 40:
            return "medium"
        elif severity >= 20:
            return "low"
        return "info"
