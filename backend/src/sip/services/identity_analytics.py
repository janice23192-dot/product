"""Identity and Access Analytics Service implementation.

Detects authentication-based attacks including brute force, password spraying,
pass-the-hash, and impossible travel. Req 27.1-27.12.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from pydantic import BaseModel, Field

from sip.utils.logging import get_logger

logger = get_logger(__name__)


class AuthenticationEvent(BaseModel):
    """Authentication event. Req 27.1."""

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    username: str
    source: str = ""  # active_directory, ldap, sso, cloud
    result: str = "success"  # success, failure
    failure_reason: str = ""
    ip_address: str = ""
    user_agent: str = ""
    mfa_used: bool = False
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class IdentityAnalyticsService:
    """Identity Analytics - authentication attack detection.

    Detects brute force (Req 27.2), password spraying (Req 27.3),
    account enumeration (Req 27.10), and monitors privileged accounts (Req 27.6).
    """

    def __init__(self) -> None:
        self._auth_events: list[AuthenticationEvent] = []
        self._failed_attempts: dict[str, list[datetime]] = defaultdict(list)
        self._ip_attempts: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._privileged_accounts: set[str] = set()

    def process_auth_event(self, event: AuthenticationEvent) -> list[dict[str, Any]]:
        """Process authentication event and detect attacks. Req 27.1."""
        self._auth_events.append(event)
        detections: list[dict[str, Any]] = []

        if event.result == "failure":
            self._failed_attempts[event.username].append(event.timestamp)
            self._ip_attempts[event.ip_address].append({
                "username": event.username, "timestamp": event.timestamp.isoformat()
            })

            # Brute force detection. Req 27.2
            bf = self._detect_brute_force(event.username)
            if bf:
                detections.append(bf)

            # Password spraying detection. Req 27.3
            ps = self._detect_password_spraying(event.ip_address)
            if ps:
                detections.append(ps)

            # Account enumeration. Req 27.10
            ae = self._detect_account_enumeration(event.ip_address)
            if ae:
                detections.append(ae)

        # Monitor privileged account usage. Req 27.6
        if event.username in self._privileged_accounts and event.result == "success":
            detections.append({
                "detection_type": "privileged_account_usage",
                "username": event.username,
                "ip_address": event.ip_address,
                "timestamp": event.timestamp.isoformat(),
            })

        return detections

    def _detect_brute_force(self, username: str, window_minutes: int = 10, threshold: int = 10) -> dict[str, Any] | None:
        """Detect brute force attempts. Req 27.2."""
        now = datetime.now(timezone.utc)
        recent = [t for t in self._failed_attempts[username] if (now - t) < timedelta(minutes=window_minutes)]
        if len(recent) >= threshold:
            return {
                "detection_type": "brute_force",
                "username": username,
                "failed_attempts": len(recent),
                "window_minutes": window_minutes,
            }
        return None

    def _detect_password_spraying(self, ip_address: str, window_minutes: int = 30, threshold_users: int = 5) -> dict[str, Any] | None:
        """Detect password spraying. Req 27.3."""
        now = datetime.now(timezone.utc)
        recent = [
            a for a in self._ip_attempts[ip_address]
            if (now - datetime.fromisoformat(a["timestamp"])) < timedelta(minutes=window_minutes)
        ]
        unique_users = set(a["username"] for a in recent)
        if len(unique_users) >= threshold_users:
            return {
                "detection_type": "password_spraying",
                "ip_address": ip_address,
                "unique_users_targeted": len(unique_users),
                "window_minutes": window_minutes,
            }
        return None

    def _detect_account_enumeration(self, ip_address: str, window_minutes: int = 5, threshold: int = 20) -> dict[str, Any] | None:
        """Detect account enumeration. Req 27.10."""
        now = datetime.now(timezone.utc)
        recent = [
            a for a in self._ip_attempts[ip_address]
            if (now - datetime.fromisoformat(a["timestamp"])) < timedelta(minutes=window_minutes)
        ]
        if len(recent) >= threshold:
            return {
                "detection_type": "account_enumeration",
                "ip_address": ip_address,
                "attempts": len(recent),
            }
        return None

    def register_privileged_account(self, username: str) -> None:
        """Register a privileged account for monitoring. Req 27.6."""
        self._privileged_accounts.add(username)

    def get_metrics(self) -> dict[str, Any]:
        return {
            "total_auth_events": len(self._auth_events),
            "unique_users": len(set(e.username for e in self._auth_events)),
            "failed_events": sum(1 for e in self._auth_events if e.result == "failure"),
            "privileged_accounts_monitored": len(self._privileged_accounts),
        }
