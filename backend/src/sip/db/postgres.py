"""PostgreSQL database setup and connection management.

Creates tables for users, roles, permissions, cases, alerts, configurations, audit_logs.
Req 10.1-10.12, 11.1-11.12, 19.1-19.14.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, AsyncGenerator

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


# --- User and Access Control Tables (Req 10.1-10.12) ---

class UserTable(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(255), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(255), default="")
    is_active = Column(Boolean, default=True)
    is_locked = Column(Boolean, default=False)
    failed_login_attempts = Column(Integer, default=0)
    clearance_level = Column(String(50), default="unclassified")
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String(255), nullable=True)
    last_login = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    sessions = relationship("SessionTable", back_populates="user", cascade="all, delete-orphan")
    role_assignments = relationship("UserRoleTable", back_populates="user", cascade="all, delete-orphan")


class RoleTable(Base):
    __tablename__ = "roles"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(255), unique=True, nullable=False)
    description = Column(Text, default="")
    is_system = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    permissions = relationship("RolePermissionTable", back_populates="role", cascade="all, delete-orphan")
    user_assignments = relationship("UserRoleTable", back_populates="role", cascade="all, delete-orphan")


class PermissionTable(Base):
    __tablename__ = "permissions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    resource = Column(String(255), nullable=False)
    action = Column(String(100), nullable=False)
    description = Column(Text, default="")
    level = Column(String(50), default="feature")  # data, feature, ui

    __table_args__ = (Index("ix_permissions_resource_action", "resource", "action"),)


class UserRoleTable(Base):
    __tablename__ = "user_roles"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    role_id = Column(String(36), ForeignKey("roles.id"), nullable=False)
    granted_by = Column(String(36), nullable=True)
    granted_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime(timezone=True), nullable=True)

    user = relationship("UserTable", back_populates="role_assignments")
    role = relationship("RoleTable", back_populates="user_assignments")


class RolePermissionTable(Base):
    __tablename__ = "role_permissions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    role_id = Column(String(36), ForeignKey("roles.id"), nullable=False)
    permission_id = Column(String(36), ForeignKey("permissions.id"), nullable=False)

    role = relationship("RoleTable", back_populates="permissions")


class SessionTable(Base):
    __tablename__ = "sessions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    token_hash = Column(String(255), nullable=False)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_activity = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime(timezone=True), nullable=False)

    user = relationship("UserTable", back_populates="sessions")

    __table_args__ = (Index("ix_sessions_user_active", "user_id", "is_active"),)


# --- Case Management Tables (Req 19.1-19.14) ---

class CaseTable(Base):
    __tablename__ = "cases"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = Column(String(500), nullable=False)
    description = Column(Text, default="")
    severity = Column(Integer, default=50)
    status = Column(String(50), default="open", index=True)
    assigned_to = Column(JSON, default=list)
    team = Column(String(255), default="")
    tags = Column(JSON, default=list)
    template_id = Column(String(36), nullable=True)
    related_case_ids = Column(JSON, default=list)
    related_alert_ids = Column(JSON, default=list)
    related_incident_ids = Column(JSON, default=list)
    access_restrictions = Column(JSON, default=list)
    metrics = Column(JSON, default=dict)
    created_by = Column(String(36), default="")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    closed_at = Column(DateTime(timezone=True), nullable=True)

    evidence_items = relationship("EvidenceTable", back_populates="case", cascade="all, delete-orphan")
    history_entries = relationship("CaseHistoryTable", back_populates="case", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_cases_created_at", "created_at"),
        Index("ix_cases_status_severity", "status", "severity"),
    )


class EvidenceTable(Base):
    __tablename__ = "evidence"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String(36), ForeignKey("cases.id"), nullable=False)
    evidence_type = Column(String(50), nullable=False)
    title = Column(String(500), nullable=False)
    description = Column(Text, default="")
    source_reference = Column(String(500), default="")
    content_hash = Column(String(64), default="")
    storage_path = Column(String(1000), default="")
    metadata_json = Column(JSON, default=dict)
    tags = Column(JSON, default=list)
    classification = Column(String(50), default="unclassified")
    chain_of_custody = Column(JSON, default=list)
    created_by = Column(String(36), default="")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    is_immutable = Column(Boolean, default=True)

    case = relationship("CaseTable", back_populates="evidence_items")


class CaseHistoryTable(Base):
    __tablename__ = "case_history"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String(36), ForeignKey("cases.id"), nullable=False)
    action = Column(String(100), nullable=False)
    description = Column(Text, default="")
    user_id = Column(String(36), default="")
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    details = Column(JSON, default=dict)

    case = relationship("CaseTable", back_populates="history_entries")

    __table_args__ = (Index("ix_case_history_case_ts", "case_id", "timestamp"),)


# --- Alert Tables (Req 17.1-17.12) ---

class AlertTable(Base):
    __tablename__ = "alerts"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    detection_id = Column(String(36), nullable=False)
    rule_id = Column(String(36), default="")
    title = Column(String(500), default="")
    description = Column(Text, default="")
    severity = Column(Integer, nullable=False)
    confidence = Column(Float, default=0.0)
    status = Column(String(50), default="new", index=True)
    assigned_to = Column(String(36), nullable=True)
    priority = Column(Integer, default=50)
    affected_entities = Column(JSON, default=list)
    mitre_tactics = Column(JSON, default=list)
    mitre_techniques = Column(JSON, default=list)
    source_events = Column(JSON, default=list)
    incident_id = Column(String(36), nullable=True, index=True)
    tags = Column(JSON, default=list)
    escalation_level = Column(Integer, default=0)
    resolution = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    acknowledged_at = Column(DateTime(timezone=True), nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("ix_alerts_severity_status", "severity", "status"),
        Index("ix_alerts_created_at", "created_at"),
    )


class IncidentTable(Base):
    __tablename__ = "incidents"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = Column(String(500), nullable=False)
    description = Column(Text, default="")
    severity = Column(Integer, nullable=False)
    status = Column(String(50), default="detected", index=True)
    priority = Column(Integer, default=50)
    assigned_to = Column(JSON, default=list)
    alert_ids = Column(JSON, default=list)
    affected_entities = Column(JSON, default=list)
    case_id = Column(String(36), nullable=True)
    mitre_tactics = Column(JSON, default=list)
    mitre_techniques = Column(JSON, default=list)
    category = Column(String(100), default="")
    timeline = Column(JSON, default=list)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


# --- Audit Tables (Req 11.1-11.12) ---

class AuditLogTable(Base):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    user_id = Column(String(36), default="system")
    action_type = Column(String(100), nullable=False, index=True)
    resource_type = Column(String(100), default="")
    resource_id = Column(String(500), default="")
    outcome = Column(String(50), default="success")
    details = Column(JSON, default=dict)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    integrity_hash = Column(String(64), default="")

    __table_args__ = (
        Index("ix_audit_user_action", "user_id", "action_type"),
        Index("ix_audit_resource", "resource_type", "resource_id"),
    )


# --- Configuration Tables (Req 29.1-29.12) ---

class ConfigurationTable(Base):
    __tablename__ = "configurations"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    key = Column(String(500), unique=True, nullable=False, index=True)
    value = Column(JSON, nullable=False)
    value_type = Column(String(50), default="string")
    description = Column(Text, default="")
    is_sensitive = Column(Boolean, default=False)
    version = Column(Integer, default=1)
    parent_key = Column(String(500), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_by = Column(String(36), default="system")


class ConfigurationVersionTable(Base):
    __tablename__ = "configuration_versions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    config_key = Column(String(500), nullable=False, index=True)
    value = Column(JSON, nullable=False)
    version = Column(Integer, nullable=False)
    changed_by = Column(String(36), default="system")
    changed_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    change_reason = Column(Text, default="")


# --- Detection Rule Tables ---

class DetectionRuleTable(Base):
    __tablename__ = "detection_rules"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(500), nullable=False)
    description = Column(Text, default="")
    rule_type = Column(String(50), nullable=False)  # signature, anomaly, behavioral, statistical, ml
    condition = Column(JSON, nullable=False)
    severity = Column(Integer, default=50)
    confidence = Column(Float, default=0.5)
    mitre_tactics = Column(JSON, default=list)
    mitre_techniques = Column(JSON, default=list)
    enabled = Column(Boolean, default=True)
    version = Column(Integer, default=1)
    source = Column(String(100), default="custom")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    __table_args__ = (Index("ix_rules_type_enabled", "rule_type", "enabled"),)


# --- Playbook Tables ---

class PlaybookTable(Base):
    __tablename__ = "playbooks"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(500), nullable=False)
    description = Column(Text, default="")
    trigger = Column(JSON, nullable=False)
    steps = Column(JSON, nullable=False, default=list)
    error_handling = Column(JSON, default=dict)
    enabled = Column(Boolean, default=True)
    version = Column(Integer, default=1)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class PlaybookExecutionTable(Base):
    __tablename__ = "playbook_executions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    playbook_id = Column(String(36), ForeignKey("playbooks.id"), nullable=False)
    status = Column(String(50), default="running")  # running, completed, failed, cancelled, awaiting_approval
    current_step = Column(String(100), default="")
    context = Column(JSON, default=dict)
    step_results = Column(JSON, default=list)
    started_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime(timezone=True), nullable=True)
    error_message = Column(Text, nullable=True)


# --- Data Source Tables ---

class DataSourceTable(Base):
    __tablename__ = "data_sources"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(255), nullable=False)
    source_type = Column(String(50), nullable=False)  # syslog, api, agent, file, stream
    connection_params = Column(JSON, nullable=False)
    authentication = Column(JSON, default=dict)
    classification = Column(String(50), default="unclassified")
    retry_policy = Column(JSON, default=dict)
    is_active = Column(Boolean, default=True)
    health_status = Column(String(50), default="unknown")
    last_event_at = Column(DateTime(timezone=True), nullable=True)
    events_per_second = Column(Float, default=0.0)
    error_rate = Column(Float, default=0.0)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


# --- Threat Intelligence Tables ---

class ThreatActorTable(Base):
    __tablename__ = "threat_actors"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(255), nullable=False, index=True)
    aliases = Column(JSON, default=list)
    description = Column(Text, default="")
    ttps = Column(JSON, default=list)
    infrastructure = Column(JSON, default=list)
    targeting = Column(JSON, default=list)
    mitre_techniques = Column(JSON, default=list)
    confidence = Column(Float, default=0.5)
    source = Column(String(100), default="custom")
    first_seen = Column(DateTime(timezone=True), nullable=True)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class IOCTable(Base):
    __tablename__ = "indicators_of_compromise"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    ioc_type = Column(String(50), nullable=False, index=True)  # ip, domain, url, hash, email
    value = Column(String(1000), nullable=False, index=True)
    threat_type = Column(String(100), default="unknown")
    confidence = Column(Float, default=0.5)
    severity = Column(Integer, default=50)
    source = Column(String(255), default="")
    feed_id = Column(String(36), nullable=True)
    threat_actor_id = Column(String(36), nullable=True)
    tags = Column(JSON, default=list)
    context = Column(JSON, default=dict)
    first_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, default=True)

    __table_args__ = (Index("ix_ioc_type_value", "ioc_type", "value"),)


# --- Asset Tables (Req 34.1-34.12) ---

class AssetTable(Base):
    __tablename__ = "assets"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    hostname = Column(String(255), nullable=True, index=True)
    ip_addresses = Column(JSON, default=list)
    mac_addresses = Column(JSON, default=list)
    os_type = Column(String(100), default="")
    os_version = Column(String(100), default="")
    asset_type = Column(String(50), default="unknown")  # server, workstation, network_device, cloud_resource
    owner = Column(String(255), default="")
    business_unit = Column(String(255), default="")
    criticality = Column(String(50), default="medium")
    classification = Column(String(50), default="unclassified")
    tags = Column(JSON, default=list)
    software_inventory = Column(JSON, default=list)
    vulnerabilities = Column(JSON, default=list)
    risk_score = Column(Float, default=0.0)
    status = Column(String(50), default="active")
    discovered_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


# --- Database initialization ---

class PostgresDB:
    """PostgreSQL database manager."""

    def __init__(self, database_url: str) -> None:
        self.engine = create_async_engine(database_url, echo=False, pool_size=20, max_overflow=10)
        self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)

    async def init(self) -> None:
        """Create all tables."""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def close(self) -> None:
        """Close the database engine."""
        await self.engine.dispose()

    def get_session(self) -> AsyncSession:
        """Get a new database session."""
        return self.session_factory()


# Module-level singleton
_db: PostgresDB | None = None


async def init_postgres(database_url: str) -> PostgresDB:
    """Initialize PostgreSQL connection and create tables."""
    global _db
    _db = PostgresDB(database_url)
    await _db.init()
    return _db


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Dependency for getting database sessions."""
    if _db is None:
        raise RuntimeError("Database not initialized. Call init_postgres first.")
    async with _db.session_factory() as session:
        yield session
