"""Network Traffic Analysis Service implementation.

Analyzes network traffic patterns, detects anomalies, and
performs DNS analysis. Req 21.1-21.12.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from sip.utils.logging import get_logger

logger = get_logger(__name__)


class NetworkFlow(BaseModel):
    """Network flow record. Req 21.1."""

    flow_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    src_ip: str
    dst_ip: str
    src_port: int = 0
    dst_port: int = 0
    protocol: str = "TCP"
    bytes_sent: int = 0
    bytes_received: int = 0
    packets: int = 0
    start_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: datetime | None = None
    flow_type: str = ""  # netflow, sflow, ipfix


class DNSQuery(BaseModel):
    """DNS query record. Req 21.9."""

    query_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    src_ip: str
    query_name: str
    query_type: str = "A"
    response_code: str = ""
    response_ips: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_suspicious: bool = False
    suspicion_reason: str = ""


class NetworkAnalysisService:
    """Network Analysis Service - traffic analysis and anomaly detection.

    Ingests network flow data (Req 21.1), detects anomalies (Req 21.4),
    analyzes DNS (Req 21.9), and calculates baselines (Req 21.6).
    """

    def __init__(self) -> None:
        self._flows: list[NetworkFlow] = []
        self._dns_queries: list[DNSQuery] = []
        self._traffic_baselines: dict[str, dict[str, float]] = {}
        self._suspicious_domains: set[str] = set()

    def ingest_flow(self, flow: NetworkFlow) -> str:
        """Ingest a network flow. Req 21.1."""
        self._flows.append(flow)
        self._update_baseline(flow)
        return flow.flow_id

    def analyze_dns_query(self, query: DNSQuery) -> DNSQuery:
        """Analyze a DNS query for suspicious patterns. Req 21.9."""
        # DGA detection - check for high entropy domain names
        domain = query.query_name
        if self._is_dga_domain(domain):
            query.is_suspicious = True
            query.suspicion_reason = "Potential DGA domain"

        # DNS tunneling - unusually long subdomain
        if len(domain) > 100:
            query.is_suspicious = True
            query.suspicion_reason = "Potential DNS tunneling"

        # Known suspicious domain
        if domain in self._suspicious_domains:
            query.is_suspicious = True
            query.suspicion_reason = "Known suspicious domain"

        self._dns_queries.append(query)
        return query

    def detect_port_scan(self, src_ip: str, time_window_seconds: int = 60) -> dict[str, Any] | None:
        """Detect port scanning activity. Req 21.4."""
        now = datetime.now(timezone.utc)
        recent_flows = [
            f for f in self._flows
            if f.src_ip == src_ip and (now - f.start_time).total_seconds() < time_window_seconds
        ]
        unique_ports = set(f.dst_port for f in recent_flows)
        if len(unique_ports) > 20:
            return {
                "detection_type": "port_scan",
                "src_ip": src_ip,
                "ports_scanned": len(unique_ports),
                "time_window_seconds": time_window_seconds,
            }
        return None

    def detect_data_exfiltration(self, src_ip: str, threshold_bytes: int = 100_000_000) -> dict[str, Any] | None:
        """Detect potential data exfiltration. Req 21.4."""
        total_bytes = sum(f.bytes_sent for f in self._flows if f.src_ip == src_ip)
        baseline = self._traffic_baselines.get(src_ip, {}).get("bytes_sent_avg", 0)
        if total_bytes > threshold_bytes or (baseline > 0 and total_bytes > baseline * 5):
            return {
                "detection_type": "data_exfiltration",
                "src_ip": src_ip,
                "total_bytes": total_bytes,
                "baseline_avg": baseline,
            }
        return None

    @staticmethod
    def _is_dga_domain(domain: str) -> bool:
        """Detect DGA domain by entropy analysis."""
        import math
        if not domain:
            return False
        parts = domain.split(".")
        if len(parts) < 2:
            return False
        subdomain = parts[0]
        if len(subdomain) < 8:
            return False
        # Calculate Shannon entropy
        freq: dict[str, int] = {}
        for c in subdomain:
            freq[c] = freq.get(c, 0) + 1
        entropy = -sum((count / len(subdomain)) * math.log2(count / len(subdomain)) for count in freq.values())
        return entropy > 3.5 and len(subdomain) > 12

    def _update_baseline(self, flow: NetworkFlow) -> None:
        """Update traffic baseline."""
        key = flow.src_ip
        if key not in self._traffic_baselines:
            self._traffic_baselines[key] = {"bytes_sent_avg": 0, "count": 0}
        b = self._traffic_baselines[key]
        b["count"] += 1
        b["bytes_sent_avg"] = (b["bytes_sent_avg"] * (b["count"] - 1) + flow.bytes_sent) / b["count"]

    def get_metrics(self) -> dict[str, Any]:
        return {
            "total_flows": len(self._flows),
            "total_dns_queries": len(self._dns_queries),
            "suspicious_dns": sum(1 for q in self._dns_queries if q.is_suspicious),
            "baselines_tracked": len(self._traffic_baselines),
        }
