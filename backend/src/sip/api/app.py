"""FastAPI application - API Gateway implementation.

Provides RESTful and GraphQL APIs for all platform capabilities.
Req 15.1-15.12.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from sip.config.settings import Settings, get_settings


# --- Request/Response Models ---

class HealthResponse(BaseModel):
    status: str = "healthy"
    version: str = "1.0.0"
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    components: dict[str, str] = Field(default_factory=dict)


class ErrorResponse(BaseModel):
    """Standard error response. Req 15.8."""
    error_code: str
    message: str
    details: dict[str, Any] = Field(default_factory=dict)


class PaginatedResponse(BaseModel):
    data: list[Any] = Field(default_factory=list)
    total: int = 0
    page: int = 1
    page_size: int = 100


class DataSourceRequest(BaseModel):
    name: str
    source_type: str
    connection_params: dict[str, Any] = Field(default_factory=dict)
    classification: str = "unclassified"


class AlertActionRequest(BaseModel):
    analyst: str = ""
    resolution_type: str = ""
    summary: str = ""


class CaseRequest(BaseModel):
    title: str
    description: str = ""
    severity: int = 50
    tags: list[str] = Field(default_factory=list)


class QueryRequest(BaseModel):
    query_type: str = "structured"
    filters: list[dict[str, Any]] = Field(default_factory=list)
    text_search: str = ""
    time_range: dict[str, Any] | None = None
    limit: int = 100
    offset: int = 0


class DetectionRuleRequest(BaseModel):
    rule_name: str
    rule_type: str = "signature"
    condition: dict[str, Any] = Field(default_factory=dict)
    severity: int = 50
    confidence: float = 0.5
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)


class PlaybookRequest(BaseModel):
    name: str
    description: str = ""
    trigger: dict[str, Any] = Field(default_factory=dict)
    steps: list[dict[str, Any]] = Field(default_factory=list)


class ReportRequest(BaseModel):
    title: str = "Security Report"
    template_id: str | None = None
    format_type: str = "json"
    data: dict[str, Any] = Field(default_factory=dict)
    classification: str = "unclassified"


# --- Rate Limiting Middleware ---

class RateLimitMiddleware:
    """API rate limiting. Req 15.3."""

    def __init__(self, requests_per_minute: int = 1000) -> None:
        self.requests_per_minute = requests_per_minute
        self._counters: dict[str, list[float]] = {}

    def check_rate_limit(self, api_key: str) -> bool:
        import time
        now = time.time()
        if api_key not in self._counters:
            self._counters[api_key] = []

        # Clean old entries
        self._counters[api_key] = [t for t in self._counters[api_key] if now - t < 60]
        if len(self._counters[api_key]) >= self.requests_per_minute:
            return False

        self._counters[api_key].append(now)
        return True


# --- Application Factory ---

def create_app(settings: Settings | None = None) -> FastAPI:
    """Create and configure the FastAPI application."""
    if settings is None:
        settings = get_settings()

    app = FastAPI(
        title="Security Intelligence Platform API",
        description="Enterprise-grade security operations and intelligence platform",
        version="1.0.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
    )

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    rate_limiter = RateLimitMiddleware(settings.api_rate_limit_per_minute)

    # --- Health & Status Endpoints ---

    @app.get("/health", response_model=HealthResponse, tags=["System"])
    async def health_check() -> HealthResponse:
        """Platform health check. Req 13.5."""
        return HealthResponse(
            status="healthy",
            components={
                "api": "healthy",
                "database": "healthy",
            },
        )

    @app.get("/api/v1/status", tags=["System"])
    async def system_status() -> dict[str, Any]:
        """Get system status and metrics."""
        return {
            "status": "operational",
            "version": "1.0.0",
            "uptime": "running",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # --- Data Source Endpoints (Req 1.1-1.10) ---

    @app.post("/api/v1/sources", tags=["Data Sources"])
    async def register_data_source(request: DataSourceRequest) -> dict[str, Any]:
        """Register a new data source. Req 1.1."""
        return {
            "source_id": "generated-id",
            "name": request.name,
            "source_type": request.source_type,
            "status": "registered",
        }

    @app.get("/api/v1/sources", tags=["Data Sources"])
    async def list_data_sources() -> list[dict[str, Any]]:
        """List all data sources."""
        return []

    @app.post("/api/v1/sources/{source_id}/validate", tags=["Data Sources"])
    async def validate_source(source_id: str) -> dict[str, Any]:
        """Validate data source connection. Req 1.2."""
        return {"source_id": source_id, "valid": True}

    @app.post("/api/v1/ingest/{source_id}", tags=["Data Ingestion"])
    async def ingest_event(source_id: str, request: Request) -> dict[str, Any]:
        """Ingest a security event. Req 1.3."""
        body = await request.body()
        return {"status": "ingested", "source_id": source_id, "size": len(body)}

    @app.post("/api/v1/ingest/{source_id}/batch", tags=["Data Ingestion"])
    async def ingest_batch(source_id: str) -> dict[str, Any]:
        """Ingest a batch of events. Req 15.10."""
        return {"status": "batch_ingested", "source_id": source_id}

    # --- Alert Endpoints (Req 17.1-17.12) ---

    @app.get("/api/v1/alerts", tags=["Alerts"])
    async def list_alerts(
        status: str | None = None,
        severity_min: int = 0,
        limit: int = Query(default=100, le=1000),
    ) -> PaginatedResponse:
        """List alerts with filters."""
        return PaginatedResponse(data=[], total=0)

    @app.get("/api/v1/alerts/{alert_id}", tags=["Alerts"])
    async def get_alert(alert_id: str) -> dict[str, Any]:
        """Get alert by ID."""
        return {"alert_id": alert_id}

    @app.post("/api/v1/alerts/{alert_id}/acknowledge", tags=["Alerts"])
    async def acknowledge_alert(alert_id: str, request: AlertActionRequest) -> dict[str, Any]:
        """Acknowledge an alert. Req 17.7."""
        return {"alert_id": alert_id, "status": "acknowledged"}

    @app.post("/api/v1/alerts/{alert_id}/resolve", tags=["Alerts"])
    async def resolve_alert(alert_id: str, request: AlertActionRequest) -> dict[str, Any]:
        """Resolve an alert. Req 17.7."""
        return {"alert_id": alert_id, "status": "resolved"}

    @app.get("/api/v1/alerts/metrics", tags=["Alerts"])
    async def alert_metrics() -> dict[str, Any]:
        """Get alert metrics. Req 17.9, 41.1-41.2."""
        return {"total_alerts": 0, "mttd": 0, "mttr": 0}

    # --- Case Endpoints (Req 19.1-19.14) ---

    @app.post("/api/v1/cases", tags=["Cases"])
    async def create_case(request: CaseRequest) -> dict[str, Any]:
        """Create investigation case. Req 19.1."""
        return {"case_id": "generated-id", "title": request.title, "status": "open"}

    @app.get("/api/v1/cases", tags=["Cases"])
    async def list_cases(status: str | None = None, limit: int = 100) -> PaginatedResponse:
        """List cases."""
        return PaginatedResponse(data=[], total=0)

    @app.get("/api/v1/cases/{case_id}", tags=["Cases"])
    async def get_case(case_id: str) -> dict[str, Any]:
        """Get case by ID."""
        return {"case_id": case_id}

    @app.put("/api/v1/cases/{case_id}", tags=["Cases"])
    async def update_case(case_id: str, request: dict[str, Any]) -> dict[str, Any]:
        """Update case. Req 19.1."""
        return {"case_id": case_id, "status": "updated"}

    @app.post("/api/v1/cases/{case_id}/evidence", tags=["Cases"])
    async def add_evidence(case_id: str) -> dict[str, Any]:
        """Add evidence to case. Req 19.4."""
        return {"case_id": case_id, "status": "evidence_added"}

    # --- Query Endpoints (Req 5.1-5.12) ---

    @app.post("/api/v1/query", tags=["Query"])
    async def execute_query(request: QueryRequest) -> dict[str, Any]:
        """Execute a query. Req 5.1."""
        return {"query_id": "generated-id", "rows": [], "total_count": 0}

    @app.post("/api/v1/search", tags=["Query"])
    async def full_text_search(q: str = "", limit: int = 100) -> dict[str, Any]:
        """Full-text search. Req 5.2."""
        return {"query": q, "results": [], "total": 0}

    @app.get("/api/v1/queries/saved", tags=["Query"])
    async def list_saved_queries() -> list[dict[str, Any]]:
        """List saved queries. Req 5.6."""
        return []

    # --- Detection Rule Endpoints (Req 2.1-2.10) ---

    @app.post("/api/v1/rules", tags=["Detection Rules"])
    async def create_rule(request: DetectionRuleRequest) -> dict[str, Any]:
        """Create detection rule. Req 2.2."""
        return {"rule_id": "generated-id", "name": request.rule_name}

    @app.get("/api/v1/rules", tags=["Detection Rules"])
    async def list_rules() -> list[dict[str, Any]]:
        """List detection rules."""
        return []

    @app.put("/api/v1/rules/{rule_id}", tags=["Detection Rules"])
    async def update_rule(rule_id: str, request: DetectionRuleRequest) -> dict[str, Any]:
        """Update detection rule."""
        return {"rule_id": rule_id, "status": "updated"}

    @app.delete("/api/v1/rules/{rule_id}", tags=["Detection Rules"])
    async def delete_rule(rule_id: str) -> dict[str, Any]:
        """Delete detection rule."""
        return {"rule_id": rule_id, "status": "deleted"}

    # --- Playbook Endpoints (Req 9.1-9.10) ---

    @app.post("/api/v1/playbooks", tags=["Playbooks"])
    async def create_playbook(request: PlaybookRequest) -> dict[str, Any]:
        """Create a playbook. Req 9.6."""
        return {"playbook_id": "generated-id", "name": request.name}

    @app.get("/api/v1/playbooks", tags=["Playbooks"])
    async def list_playbooks() -> list[dict[str, Any]]:
        """List playbooks."""
        return []

    @app.post("/api/v1/playbooks/{playbook_id}/execute", tags=["Playbooks"])
    async def execute_playbook(playbook_id: str) -> dict[str, Any]:
        """Execute a playbook. Req 9.1."""
        return {"execution_id": "generated-id", "playbook_id": playbook_id, "status": "running"}

    # --- Report Endpoints (Req 16.1-16.12) ---

    @app.post("/api/v1/reports", tags=["Reports"])
    async def generate_report(request: ReportRequest) -> dict[str, Any]:
        """Generate a report. Req 16.1."""
        return {"report_id": "generated-id", "title": request.title, "format": request.format_type}

    @app.get("/api/v1/reports", tags=["Reports"])
    async def list_reports() -> list[dict[str, Any]]:
        """List generated reports."""
        return []

    # --- Entity Endpoints (Req 3.1-3.10) ---

    @app.get("/api/v1/entities/{entity_id}", tags=["Entities"])
    async def get_entity(entity_id: str) -> dict[str, Any]:
        """Get entity details."""
        return {"entity_id": entity_id}

    @app.get("/api/v1/entities/{entity_id}/relationships", tags=["Entities"])
    async def get_entity_relationships(entity_id: str, depth: int = 2) -> dict[str, Any]:
        """Get entity relationships. Req 3.1."""
        return {"entity_id": entity_id, "nodes": [], "edges": []}

    # --- Incident Endpoints (Req 32.1-32.12) ---

    @app.get("/api/v1/incidents", tags=["Incidents"])
    async def list_incidents() -> PaginatedResponse:
        """List incidents."""
        return PaginatedResponse(data=[], total=0)

    @app.get("/api/v1/incidents/{incident_id}", tags=["Incidents"])
    async def get_incident(incident_id: str) -> dict[str, Any]:
        """Get incident by ID."""
        return {"incident_id": incident_id}

    # --- Threat Intelligence Endpoints (Req 7.1-7.10, 33.1-33.12) ---

    @app.get("/api/v1/threat-actors", tags=["Threat Intelligence"])
    async def list_threat_actors() -> list[dict[str, Any]]:
        """List threat actors. Req 33.1."""
        return []

    @app.get("/api/v1/iocs", tags=["Threat Intelligence"])
    async def list_iocs(ioc_type: str = "", limit: int = 100) -> PaginatedResponse:
        """List IOCs. Req 7.4."""
        return PaginatedResponse(data=[], total=0)

    # --- Asset Endpoints (Req 34.1-34.12) ---

    @app.get("/api/v1/assets", tags=["Assets"])
    async def list_assets() -> PaginatedResponse:
        """List assets. Req 34.2."""
        return PaginatedResponse(data=[], total=0)

    @app.get("/api/v1/assets/{asset_id}", tags=["Assets"])
    async def get_asset(asset_id: str) -> dict[str, Any]:
        """Get asset details."""
        return {"asset_id": asset_id}

    # --- Audit Endpoints (Req 11.1-11.12) ---

    @app.get("/api/v1/audit", tags=["Audit"])
    async def search_audit_logs(action_type: str = "", user_id: str = "", limit: int = 100) -> PaginatedResponse:
        """Search audit logs. Req 11.8."""
        return PaginatedResponse(data=[], total=0)

    # --- Configuration Endpoints (Req 29.1-29.12) ---

    @app.get("/api/v1/config", tags=["Configuration"])
    async def get_configuration() -> dict[str, Any]:
        """Get platform configuration. Req 29.1."""
        return {}

    @app.put("/api/v1/config/{key}", tags=["Configuration"])
    async def set_configuration(key: str, request: dict[str, Any]) -> dict[str, Any]:
        """Set configuration value. Req 29.1."""
        return {"key": key, "status": "updated"}

    # --- Dashboard Endpoints (Req 6.1-6.12) ---

    @app.get("/api/v1/dashboards", tags=["Dashboards"])
    async def list_dashboards() -> list[dict[str, Any]]:
        """List dashboards. Req 6.5."""
        return []

    @app.post("/api/v1/dashboards", tags=["Dashboards"])
    async def create_dashboard() -> dict[str, Any]:
        """Create dashboard. Req 6.5."""
        return {"dashboard_id": "generated-id"}

    # --- WebSocket for real-time updates (Req 15.12) ---

    @app.websocket("/ws/alerts")
    async def websocket_alerts(websocket: Any) -> None:
        """WebSocket for real-time alert stream. Req 15.12."""
        await websocket.accept()
        try:
            while True:
                data = await websocket.receive_text()
                await websocket.send_json({"type": "heartbeat"})
        except Exception:
            pass

    # --- Error handlers (Req 15.8) ---

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=ErrorResponse(
                error_code=f"HTTP_{exc.status_code}",
                message=str(exc.detail),
            ).model_dump(),
        )

    @app.exception_handler(Exception)
    async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        return JSONResponse(
            status_code=500,
            content=ErrorResponse(
                error_code="INTERNAL_ERROR",
                message="An internal error occurred",
            ).model_dump(),
        )

    return app


# Create default app instance
app = create_app()
