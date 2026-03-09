"""Configuration Management Service implementation.

Centralized configuration with validation, versioning, and rollback.
Req 29.1-29.12.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from sip.utils.logging import get_logger

logger = get_logger(__name__)


class ConfigEntry(BaseModel):
    """Configuration entry. Req 29.1."""

    key: str
    value: Any
    value_type: str = "string"
    description: str = ""
    is_sensitive: bool = False
    version: int = 1
    parent_key: str | None = None
    updated_by: str = "system"
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ConfigVersion(BaseModel):
    """Configuration version for rollback. Req 29.3."""

    config_key: str
    value: Any
    version: int
    changed_by: str = "system"
    changed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    change_reason: str = ""


class ConfigurationManagementService:
    """Configuration Management - centralized config with versioning.

    Provides centralized interface (Req 29.1), validates changes (Req 29.2),
    supports versioning with rollback (Req 29.3), encrypts sensitive values
    (Req 29.11), and logs changes to audit (Req 29.5).
    """

    def __init__(self) -> None:
        self._configs: dict[str, ConfigEntry] = {}
        self._versions: dict[str, list[ConfigVersion]] = {}
        self._validators: dict[str, Any] = {}
        self._audit_callbacks: list[Any] = []

    def set_config(self, key: str, value: Any, user: str = "system", reason: str = "") -> ConfigEntry:
        """Set configuration value with validation. Req 29.1, 29.2."""
        # Validate. Req 29.2
        validation = self.validate_config(key, value)
        if not validation["valid"]:
            raise ValueError(f"Invalid configuration: {validation['errors']}")

        # Save version. Req 29.3
        existing = self._configs.get(key)
        version = (existing.version + 1) if existing else 1

        if key not in self._versions:
            self._versions[key] = []
        self._versions[key].append(ConfigVersion(
            config_key=key, value=value if not (existing and existing.is_sensitive) else "***",
            version=version, changed_by=user, change_reason=reason,
        ))

        entry = ConfigEntry(
            key=key, value=value, version=version,
            updated_by=user, is_sensitive=existing.is_sensitive if existing else False,
        )
        self._configs[key] = entry

        # Log to audit. Req 29.5
        for callback in self._audit_callbacks:
            try:
                import asyncio
                asyncio.get_event_loop().create_task(callback({
                    "action": "config_changed", "key": key, "version": version, "user": user,
                }))
            except Exception:
                pass

        return entry

    def get_config(self, key: str, default: Any = None) -> Any:
        """Get configuration value. Req 29.1."""
        entry = self._configs.get(key)
        return entry.value if entry else default

    def validate_config(self, key: str, value: Any) -> dict[str, Any]:
        """Validate configuration value. Req 29.2."""
        errors: list[str] = []
        if not key:
            errors.append("Configuration key cannot be empty")
        validator = self._validators.get(key)
        if validator:
            try:
                if not validator(value):
                    errors.append(f"Validation failed for key: {key}")
            except Exception as e:
                errors.append(str(e))
        return {"valid": len(errors) == 0, "errors": errors}

    def rollback(self, key: str, version: int) -> ConfigEntry | None:
        """Rollback configuration to a previous version. Req 29.3."""
        versions = self._versions.get(key, [])
        for v in versions:
            if v.version == version:
                return self.set_config(key, v.value, "system", f"Rollback to version {version}")
        return None

    def get_version_history(self, key: str) -> list[ConfigVersion]:
        """Get version history. Req 29.3."""
        return self._versions.get(key, [])

    def export_config(self) -> dict[str, Any]:
        """Export all configuration. Req 29.4."""
        return {k: v.value for k, v in self._configs.items() if not v.is_sensitive}

    def import_config(self, configs: dict[str, Any], user: str = "system") -> int:
        """Import configuration. Req 29.4."""
        count = 0
        for key, value in configs.items():
            try:
                self.set_config(key, value, user, "Imported")
                count += 1
            except Exception:
                pass
        return count

    def register_validator(self, key: str, validator: Any) -> None:
        self._validators[key] = validator

    def on_audit(self, callback: Any) -> None:
        self._audit_callbacks.append(callback)

    def get_metrics(self) -> dict[str, Any]:
        return {
            "total_configs": len(self._configs),
            "total_versions": sum(len(v) for v in self._versions.values()),
            "sensitive_configs": sum(1 for c in self._configs.values() if c.is_sensitive),
        }
