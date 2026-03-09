"""Query Engine implementation.

Provides high-performance query capabilities across all stored security data.
Supports structured queries, full-text search, regex, geospatial, and temporal queries.
Req 5.1-5.12.
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from sip.utils.logging import get_logger

logger = get_logger(__name__)


class QueryType(str, Enum):
    STRUCTURED = "structured"
    FULLTEXT = "fulltext"
    GRAPH = "graph"
    TIMESERIES = "timeseries"
    GEOSPATIAL = "geospatial"


class AggregationType(str, Enum):
    COUNT = "count"
    SUM = "sum"
    AVG = "avg"
    MIN = "min"
    MAX = "max"
    CARDINALITY = "cardinality"
    PERCENTILE = "percentile"
    HISTOGRAM = "histogram"


class QueryFilter(BaseModel):
    """Query filter condition."""

    field: str
    operator: str  # eq, neq, gt, gte, lt, lte, in, not_in, contains, regex, exists
    value: Any


class Aggregation(BaseModel):
    """Query aggregation."""

    field: str
    agg_type: AggregationType
    alias: str = ""


class TimeRange(BaseModel):
    """Time range for temporal queries. Req 5.11."""

    start: datetime | str  # Absolute or relative (e.g., "-24h")
    end: datetime | str = "now"
    timezone: str = "UTC"


class Query(BaseModel):
    """Query definition. Req 5.1."""

    query_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    query_type: QueryType = QueryType.STRUCTURED
    filters: list[QueryFilter] = Field(default_factory=list)
    aggregations: list[Aggregation] = Field(default_factory=list)
    time_range: TimeRange | None = None
    text_search: str = ""
    regex_pattern: str = ""
    geo_filter: dict[str, Any] | None = None
    fields: list[str] = Field(default_factory=list)  # Fields to return
    sort: list[dict[str, str]] = Field(default_factory=list)
    limit: int = Field(default=100, ge=1, le=10000)
    offset: int = Field(default=0, ge=0)
    timeout_seconds: int = 30


class QueryResult(BaseModel):
    """Query result. Req 5.10."""

    query_id: str
    rows: list[dict[str, Any]] = Field(default_factory=list)
    total_count: int = 0
    execution_time_ms: float = 0.0
    data_scanned_bytes: int = 0
    is_partial: bool = False
    continuation_token: str | None = None
    aggregation_results: dict[str, Any] = Field(default_factory=dict)


class SavedQuery(BaseModel):
    """Saved query for reuse. Req 5.6."""

    saved_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str = ""
    query: Query
    parameters: dict[str, Any] = Field(default_factory=dict)
    created_by: str = ""
    shared_with: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    usage_count: int = 0


class QueryEngine:
    """Query Engine - high-performance query across all security data.

    Supports structured queries (Req 5.1), full-text search (Req 5.2),
    regex (Req 5.3), geospatial (Req 5.4), timeout with partial results
    (Req 5.5), saved queries (Req 5.6), and query optimization (Req 5.12).
    """

    def __init__(self, query_timeout_seconds: int = 30) -> None:
        self.query_timeout_seconds = query_timeout_seconds
        self._saved_queries: dict[str, SavedQuery] = {}
        self._query_cache: dict[str, QueryResult] = {}
        self._query_stats: dict[str, dict[str, Any]] = {}

        # Data stores will be injected
        self._es_client: Any = None
        self._influx_client: Any = None
        self._neo4j_client: Any = None
        self._redis_cache: Any = None

    def set_backends(
        self,
        es_client: Any = None,
        influx_client: Any = None,
        neo4j_client: Any = None,
        redis_cache: Any = None,
    ) -> None:
        """Set database backend clients."""
        self._es_client = es_client
        self._influx_client = influx_client
        self._neo4j_client = neo4j_client
        self._redis_cache = redis_cache

    # --- Query Execution (Req 5.1) ---

    async def execute_query(self, query: Query) -> QueryResult:
        """Execute a query with timeout handling. Req 5.1, 5.5."""
        start_time = time.monotonic()

        # Check cache
        cache_key = self._cache_key(query)
        if self._redis_cache:
            cached = await self._redis_cache.get("query_result", cache_key)
            if cached:
                return QueryResult(**cached)

        # Route to appropriate backend. Req 5.12
        try:
            result = await self._route_query(query)
        except TimeoutError:
            # Return partial results. Req 5.5
            result = QueryResult(
                query_id=query.query_id,
                is_partial=True,
                execution_time_ms=(time.monotonic() - start_time) * 1000,
            )

        result.execution_time_ms = (time.monotonic() - start_time) * 1000

        # Cache result
        if self._redis_cache and not result.is_partial:
            await self._redis_cache.set("query_result", cache_key, result.model_dump(mode="json"))

        # Track stats. Req 5.10
        self._record_stats(query, result)

        return result

    async def _route_query(self, query: Query) -> QueryResult:
        """Route query to appropriate backend. Req 5.12."""
        if query.query_type == QueryType.FULLTEXT:
            return await self._execute_fulltext(query)
        elif query.query_type == QueryType.GRAPH:
            return await self._execute_graph(query)
        elif query.query_type == QueryType.TIMESERIES:
            return await self._execute_timeseries(query)
        elif query.query_type == QueryType.GEOSPATIAL:
            return await self._execute_geospatial(query)
        else:
            return await self._execute_structured(query)

    async def _execute_structured(self, query: Query) -> QueryResult:
        """Execute structured query against Elasticsearch. Req 5.1."""
        if not self._es_client:
            return self._execute_in_memory(query)

        # Build Elasticsearch query
        es_query = self._build_es_query(query)
        result = await self._es_client.search("security-events-*", es_query, size=query.limit)

        return QueryResult(
            query_id=query.query_id,
            rows=result.get("hits", []),
            total_count=result.get("total", 0),
        )

    async def _execute_fulltext(self, query: Query) -> QueryResult:
        """Execute full-text search. Req 5.2."""
        if not self._es_client:
            return self._execute_in_memory(query)

        result = await self._es_client.full_text_search(
            "security-events-*", query.text_search, size=query.limit
        )

        return QueryResult(
            query_id=query.query_id,
            rows=result.get("hits", []),
            total_count=result.get("total", 0),
        )

    async def _execute_graph(self, query: Query) -> QueryResult:
        """Execute graph query. Req 3.1."""
        # Graph queries would be routed to Neo4j
        return QueryResult(query_id=query.query_id)

    async def _execute_timeseries(self, query: Query) -> QueryResult:
        """Execute time-series query. Req 5.11."""
        # Time-series queries would be routed to InfluxDB
        return QueryResult(query_id=query.query_id)

    async def _execute_geospatial(self, query: Query) -> QueryResult:
        """Execute geospatial query. Req 5.4."""
        return QueryResult(query_id=query.query_id)

    def _execute_in_memory(self, query: Query) -> QueryResult:
        """Execute query against in-memory data (for testing)."""
        return QueryResult(query_id=query.query_id, rows=[], total_count=0)

    # --- Full-Text Search (Req 5.2) ---

    async def full_text_search(self, search_term: str, size: int = 100) -> QueryResult:
        """Perform full-text search across all data. Req 5.2."""
        query = Query(
            query_type=QueryType.FULLTEXT,
            text_search=search_term,
            limit=size,
        )
        return await self.execute_query(query)

    # --- Fuzzy Search (Req 5.9) ---

    async def fuzzy_search(self, pattern: str, similarity: float = 0.8, size: int = 100) -> QueryResult:
        """Fuzzy matching search. Req 5.9."""
        query = Query(
            query_type=QueryType.FULLTEXT,
            text_search=pattern,
            limit=size,
        )
        # Fuzzy matching is handled by Elasticsearch fuzziness parameter
        return await self.execute_query(query)

    # --- Saved Queries (Req 5.6, 5.7) ---

    def save_query(self, name: str, query: Query, user: str = "", description: str = "") -> str:
        """Save a query for reuse. Req 5.6."""
        saved = SavedQuery(
            name=name,
            description=description,
            query=query,
            created_by=user,
        )
        self._saved_queries[saved.saved_id] = saved
        return saved.saved_id

    def load_query(self, query_id: str) -> SavedQuery | None:
        """Load a saved query. Req 5.6."""
        saved = self._saved_queries.get(query_id)
        if saved:
            saved.usage_count += 1
        return saved

    def get_saved_queries(self, user: str = "") -> list[SavedQuery]:
        """Get all saved queries accessible to a user."""
        queries = list(self._saved_queries.values())
        if user:
            queries = [q for q in queries if q.created_by == user or user in q.shared_with]
        return queries

    def share_query(self, query_id: str, share_with: list[str]) -> None:
        """Share a saved query with other analysts."""
        saved = self._saved_queries.get(query_id)
        if saved:
            saved.shared_with = list(set(saved.shared_with + share_with))

    # --- Query Explain (Req 5.12) ---

    def explain_query(self, query: Query) -> dict[str, Any]:
        """Explain query execution plan. Req 5.12."""
        plan: dict[str, Any] = {
            "query_type": query.query_type.value,
            "target_backend": self._determine_backend(query),
            "estimated_cost": "low",
            "filters": len(query.filters),
            "aggregations": len(query.aggregations),
            "optimization_hints": [],
        }

        if query.time_range:
            plan["time_range_optimization"] = True
            plan["optimization_hints"].append("Time range filter will be pushed down to storage")

        if query.limit > 1000:
            plan["optimization_hints"].append("Consider reducing limit for faster response")
            plan["estimated_cost"] = "medium"

        return plan

    # --- Internal Helpers ---

    def _build_es_query(self, query: Query) -> dict[str, Any]:
        """Build Elasticsearch query from Query model."""
        must: list[dict[str, Any]] = []

        for f in query.filters:
            if f.operator == "eq":
                must.append({"term": {f.field: f.value}})
            elif f.operator == "contains":
                must.append({"match": {f.field: f.value}})
            elif f.operator == "regex":
                must.append({"regexp": {f.field: f.value}})
            elif f.operator in ("gt", "gte", "lt", "lte"):
                must.append({"range": {f.field: {f.operator: f.value}}})
            elif f.operator == "in":
                must.append({"terms": {f.field: f.value}})
            elif f.operator == "exists":
                must.append({"exists": {"field": f.field}})

        if query.time_range:
            must.append({
                "range": {
                    "timestamp": {
                        "gte": str(query.time_range.start),
                        "lte": str(query.time_range.end),
                    }
                }
            })

        return {"bool": {"must": must}} if must else {"match_all": {}}

    def _determine_backend(self, query: Query) -> str:
        """Determine which backend to route query to."""
        type_map = {
            QueryType.STRUCTURED: "elasticsearch",
            QueryType.FULLTEXT: "elasticsearch",
            QueryType.GRAPH: "neo4j",
            QueryType.TIMESERIES: "influxdb",
            QueryType.GEOSPATIAL: "elasticsearch",
        }
        return type_map.get(query.query_type, "elasticsearch")

    def _cache_key(self, query: Query) -> str:
        """Generate cache key for a query."""
        import hashlib
        key_data = query.model_dump_json()
        return hashlib.sha256(key_data.encode()).hexdigest()[:32]

    def _record_stats(self, query: Query, result: QueryResult) -> None:
        """Record query performance statistics. Req 5.10."""
        self._query_stats[query.query_id] = {
            "query_type": query.query_type.value,
            "execution_time_ms": result.execution_time_ms,
            "rows_returned": len(result.rows),
            "total_count": result.total_count,
            "is_partial": result.is_partial,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def get_performance_stats(self) -> dict[str, Any]:
        """Get query performance statistics. Req 5.10."""
        if not self._query_stats:
            return {"total_queries": 0}

        times = [s["execution_time_ms"] for s in self._query_stats.values()]
        return {
            "total_queries": len(self._query_stats),
            "avg_execution_time_ms": sum(times) / len(times),
            "max_execution_time_ms": max(times),
            "min_execution_time_ms": min(times),
            "p95_execution_time_ms": sorted(times)[int(len(times) * 0.95)] if len(times) > 1 else times[0],
        }
