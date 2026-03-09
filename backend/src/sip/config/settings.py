"""Platform configuration management.

Centralizes all configuration with environment variable support,
validation, and sensible defaults. Req 29.1, 29.2, 29.11.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings


class Environment(str, Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class DatabaseSettings(BaseSettings):
    """PostgreSQL connection settings."""

    host: str = Field(default="localhost", alias="POSTGRES_HOST")
    port: int = Field(default=5432, alias="POSTGRES_PORT")
    user: str = Field(default="sip", alias="POSTGRES_USER")
    password: str = Field(default="sip_secret", alias="POSTGRES_PASSWORD")
    database: str = Field(default="security_intelligence", alias="POSTGRES_DB")

    @property
    def url(self) -> str:
        return f"postgresql+asyncpg://{self.user}:{self.password}@{self.host}:{self.port}/{self.database}"

    @property
    def sync_url(self) -> str:
        return f"postgresql://{self.user}:{self.password}@{self.host}:{self.port}/{self.database}"


class RedisSettings(BaseSettings):
    """Redis cache settings."""

    host: str = Field(default="localhost", alias="REDIS_HOST")
    port: int = Field(default=6379, alias="REDIS_PORT")
    password: str = Field(default="", alias="REDIS_PASSWORD")
    db: int = Field(default=0, alias="REDIS_DB")

    @property
    def url(self) -> str:
        auth = f":{self.password}@" if self.password else ""
        return f"redis://{auth}{self.host}:{self.port}/{self.db}"


class ElasticsearchSettings(BaseSettings):
    """Elasticsearch settings."""

    hosts: list[str] = Field(default=["http://localhost:9200"], alias="ES_HOSTS")
    username: str = Field(default="elastic", alias="ES_USERNAME")
    password: str = Field(default="elastic_secret", alias="ES_PASSWORD")
    index_prefix: str = Field(default="sip", alias="ES_INDEX_PREFIX")


class Neo4jSettings(BaseSettings):
    """Neo4j graph database settings."""

    uri: str = Field(default="bolt://localhost:7687", alias="NEO4J_URI")
    username: str = Field(default="neo4j", alias="NEO4J_USERNAME")
    password: str = Field(default="neo4j_secret", alias="NEO4J_PASSWORD")


class InfluxDBSettings(BaseSettings):
    """InfluxDB time-series database settings."""

    url: str = Field(default="http://localhost:8086", alias="INFLUXDB_URL")
    token: str = Field(default="influx_token", alias="INFLUXDB_TOKEN")
    org: str = Field(default="sip", alias="INFLUXDB_ORG")
    bucket: str = Field(default="security_events", alias="INFLUXDB_BUCKET")


class KafkaSettings(BaseSettings):
    """Apache Kafka settings."""

    bootstrap_servers: list[str] = Field(
        default=["localhost:9092"], alias="KAFKA_BOOTSTRAP_SERVERS"
    )
    security_protocol: str = Field(default="PLAINTEXT", alias="KAFKA_SECURITY_PROTOCOL")
    events_topic: str = Field(default="sip.events.raw", alias="KAFKA_EVENTS_TOPIC")
    alerts_topic: str = Field(default="sip.alerts", alias="KAFKA_ALERTS_TOPIC")


class S3Settings(BaseSettings):
    """S3/MinIO object storage settings."""

    endpoint_url: str = Field(default="http://localhost:9000", alias="S3_ENDPOINT_URL")
    access_key: str = Field(default="minioadmin", alias="S3_ACCESS_KEY")
    secret_key: str = Field(default="minioadmin", alias="S3_SECRET_KEY")
    region: str = Field(default="us-east-1", alias="S3_REGION")
    raw_bucket: str = Field(default="sip-raw-data", alias="S3_RAW_BUCKET")
    archive_bucket: str = Field(default="sip-archived-data", alias="S3_ARCHIVE_BUCKET")
    evidence_bucket: str = Field(default="sip-evidence", alias="S3_EVIDENCE_BUCKET")
    reports_bucket: str = Field(default="sip-reports", alias="S3_REPORTS_BUCKET")
    backups_bucket: str = Field(default="sip-backups", alias="S3_BACKUPS_BUCKET")


class JWTSettings(BaseSettings):
    """JWT authentication settings."""

    secret_key: str = Field(default="change-me-in-production", alias="JWT_SECRET_KEY")
    algorithm: str = Field(default="HS256", alias="JWT_ALGORITHM")
    access_token_expire_minutes: int = Field(default=480, alias="JWT_ACCESS_TOKEN_EXPIRE_MINUTES")
    refresh_token_expire_days: int = Field(default=7, alias="JWT_REFRESH_TOKEN_EXPIRE_DAYS")


class Settings(BaseSettings):
    """Main application settings."""

    environment: Environment = Field(default=Environment.DEVELOPMENT, alias="SIP_ENVIRONMENT")
    debug: bool = Field(default=False, alias="SIP_DEBUG")
    log_level: str = Field(default="INFO", alias="SIP_LOG_LEVEL")
    api_host: str = Field(default="0.0.0.0", alias="SIP_API_HOST")
    api_port: int = Field(default=8000, alias="SIP_API_PORT")
    api_prefix: str = Field(default="/api/v1", alias="SIP_API_PREFIX")
    cors_origins: list[str] = Field(default=["http://localhost:3000"], alias="SIP_CORS_ORIGINS")

    # Sub-configurations
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    redis: RedisSettings = Field(default_factory=RedisSettings)
    elasticsearch: ElasticsearchSettings = Field(default_factory=ElasticsearchSettings)
    neo4j: Neo4jSettings = Field(default_factory=Neo4jSettings)
    influxdb: InfluxDBSettings = Field(default_factory=InfluxDBSettings)
    kafka: KafkaSettings = Field(default_factory=KafkaSettings)
    s3: S3Settings = Field(default_factory=S3Settings)
    jwt: JWTSettings = Field(default_factory=JWTSettings)

    # Ingestion settings
    max_concurrent_sources: int = Field(default=50)
    ingestion_throughput_target: int = Field(default=100_000)
    deduplication_window_seconds: int = Field(default=60)
    retry_max_attempts: int = Field(default=5)

    # Detection settings
    max_concurrent_rules: int = Field(default=1000)
    detection_timeout_ms: int = Field(default=500)
    high_severity_threshold: int = Field(default=80)
    threat_intel_update_interval_minutes: int = Field(default=5)

    # Correlation settings
    entity_update_timeout_seconds: int = Field(default=2)
    incident_grouping_timeout_seconds: int = Field(default=5)
    max_entities: int = Field(default=20_000_000)

    # Query settings
    query_timeout_seconds: int = Field(default=30)
    search_index_update_seconds: int = Field(default=10)

    # Session settings
    session_inactivity_timeout_hours: int = Field(default=8)
    max_failed_login_attempts: int = Field(default=5)

    # Alert settings
    alert_notification_timeout_seconds: int = Field(default=10)
    alert_escalation_timeout_minutes: int = Field(default=15)

    # Retention settings
    hot_retention_days: int = Field(default=30)
    warm_retention_days: int = Field(default=365)
    cold_retention_years: int = Field(default=7)
    encryption_key_rotation_days: int = Field(default=90)

    # Rate limiting
    api_rate_limit_per_minute: int = Field(default=1000)

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        valid = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if v.upper() not in valid:
            raise ValueError(f"log_level must be one of {valid}")
        return v.upper()


def get_settings() -> Settings:
    """Get cached application settings."""
    return Settings()
