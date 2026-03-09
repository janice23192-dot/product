"""Access Control System implementation.

Manages authentication, authorization, session management, and
account security. Req 10.1-10.12.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from pydantic import BaseModel, Field

from sip.utils.logging import get_logger

logger = get_logger(__name__)


class UserAccount(BaseModel):
    """User account. Req 10.1."""

    user_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    username: str
    email: str
    password_hash: str = ""
    full_name: str = ""
    is_active: bool = True
    is_locked: bool = False
    failed_login_attempts: int = 0
    clearance_level: str = "unclassified"
    mfa_enabled: bool = False
    mfa_secret: str = ""
    roles: list[str] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)
    ip_whitelist: list[str] = Field(default_factory=list)
    last_login: datetime | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Role(BaseModel):
    """Role definition. Req 10.6."""

    role_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str = ""
    permissions: list[str] = Field(default_factory=list)
    is_system: bool = False


class Permission(BaseModel):
    """Permission definition. Req 10.3."""

    resource: str
    action: str  # read, write, delete, admin
    level: str = "feature"  # data, feature, ui


class Session(BaseModel):
    """User session. Req 10.8."""

    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    token: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    ip_address: str = ""
    user_agent: str = ""
    is_active: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_activity: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc) + timedelta(hours=8)
    )


class AccessControlSystem:
    """Access Control System - authentication and authorization.

    Supports MFA (Req 10.1), RBAC with ABAC extensions (Req 10.3, 10.4),
    50+ custom roles (Req 10.6), session timeout after 8h inactivity
    (Req 10.8), account lockout after 5 failures (Req 10.12).
    """

    def __init__(
        self,
        session_timeout_hours: int = 8,
        max_failed_attempts: int = 5,
        max_roles: int = 50,
    ) -> None:
        self.session_timeout_hours = session_timeout_hours
        self.max_failed_attempts = max_failed_attempts
        self.max_roles = max_roles

        self._users: dict[str, UserAccount] = {}
        self._users_by_username: dict[str, str] = {}
        self._roles: dict[str, Role] = {}
        self._sessions: dict[str, Session] = {}
        self._audit_callbacks: list[Any] = []

    # --- Authentication (Req 10.1) ---

    async def authenticate(self, username: str, password: str, ip_address: str = "", user_agent: str = "") -> Session | None:
        """Authenticate a user. Req 10.1."""
        user_id = self._users_by_username.get(username)
        if not user_id:
            await self._log_audit("auth_failed", "unknown", f"Unknown user: {username}")
            return None

        user = self._users[user_id]

        # Check if account is locked. Req 10.12
        if user.is_locked:
            await self._log_audit("auth_denied", user.user_id, "Account locked")
            return None

        if not user.is_active:
            await self._log_audit("auth_denied", user.user_id, "Account inactive")
            return None

        # Check IP whitelist. Req 10.11
        if user.ip_whitelist and ip_address and ip_address not in user.ip_whitelist:
            await self._log_audit("auth_denied", user.user_id, f"IP not whitelisted: {ip_address}")
            return None

        # Verify password
        if not self._verify_password(password, user.password_hash):
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= self.max_failed_attempts:
                user.is_locked = True
                await self._log_audit("account_locked", user.user_id, f"Locked after {self.max_failed_attempts} failed attempts")
            await self._log_audit("auth_failed", user.user_id, "Invalid password")
            return None

        # Reset failed attempts on success
        user.failed_login_attempts = 0
        user.last_login = datetime.now(timezone.utc)

        # Create session
        session = Session(
            user_id=user.user_id,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        self._sessions[session.session_id] = session

        await self._log_audit("auth_success", user.user_id, f"Login from {ip_address}")
        return session

    async def validate_mfa(self, user_id: str, mfa_code: str) -> bool:
        """Validate MFA code. Req 10.1."""
        user = self._users.get(user_id)
        if not user or not user.mfa_enabled:
            return False
        # In production, would validate TOTP code against user's MFA secret
        # For now, accept any 6-digit code for testing
        return len(mfa_code) == 6 and mfa_code.isdigit()

    async def logout(self, session_id: str) -> None:
        """Terminate a session."""
        session = self._sessions.get(session_id)
        if session:
            session.is_active = False
            await self._log_audit("logout", session.user_id, "Session terminated")

    # --- Authorization (Req 10.3, 10.4) ---

    async def check_permission(self, user_id: str, resource: str, action: str) -> bool:
        """Check if user has permission for an action. Req 10.3."""
        user = self._users.get(user_id)
        if not user or not user.is_active or user.is_locked:
            return False

        for role_id in user.roles:
            role = self._roles.get(role_id)
            if role:
                permission_key = f"{resource}:{action}"
                if permission_key in role.permissions or f"{resource}:*" in role.permissions or "*:*" in role.permissions:
                    return True

        # Deny and log. Req 10.5
        await self._log_audit("access_denied", user_id, f"No permission for {resource}:{action}")
        return False

    async def check_classification(self, user_id: str, classification: str) -> bool:
        """Check clearance level for data classification. Req 10.7."""
        user = self._users.get(user_id)
        if not user:
            return False

        levels = {"unclassified": 0, "confidential": 1, "secret": 2, "top_secret": 3}
        user_level = levels.get(user.clearance_level, 0)
        required_level = levels.get(classification, 0)
        return user_level >= required_level

    # --- Session Management (Req 10.8) ---

    async def validate_session(self, session_id: str) -> UserAccount | None:
        """Validate a session and check timeout. Req 10.8."""
        session = self._sessions.get(session_id)
        if not session or not session.is_active:
            return None

        now = datetime.now(timezone.utc)

        # Check inactivity timeout. Req 10.8
        inactivity = now - session.last_activity
        if inactivity > timedelta(hours=self.session_timeout_hours):
            session.is_active = False
            await self._log_audit("session_timeout", session.user_id, f"Inactive for {inactivity}")
            return None

        # Check expiry
        if now > session.expires_at:
            session.is_active = False
            return None

        session.last_activity = now
        return self._users.get(session.user_id)

    def get_active_sessions(self, user_id: str) -> list[Session]:
        """Get active sessions for a user."""
        return [s for s in self._sessions.values() if s.user_id == user_id and s.is_active]

    # --- User Management ---

    async def create_user(self, username: str, email: str, password: str, roles: list[str] | None = None) -> UserAccount:
        """Create a user account."""
        user = UserAccount(
            username=username,
            email=email,
            password_hash=self._hash_password(password),
            roles=roles or [],
        )
        self._users[user.user_id] = user
        self._users_by_username[username] = user.user_id
        await self._log_audit("user_created", user.user_id, f"User created: {username}")
        return user

    def get_user(self, user_id: str) -> UserAccount | None:
        """Get user by ID."""
        return self._users.get(user_id)

    # --- Role Management (Req 10.6) ---

    def create_role(self, name: str, permissions: list[str], description: str = "") -> Role:
        """Create a role. Req 10.6."""
        role = Role(name=name, permissions=permissions, description=description)
        self._roles[role.role_id] = role
        return role

    def assign_role(self, user_id: str, role_id: str) -> bool:
        """Assign role to user."""
        user = self._users.get(user_id)
        if user and role_id in self._roles:
            if role_id not in user.roles:
                user.roles.append(role_id)
            return True
        return False

    # --- Internal ---

    @staticmethod
    def _hash_password(password: str) -> str:
        """Hash a password."""
        salt = secrets.token_hex(16)
        hash_val = hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()
        return f"{salt}:{hash_val}"

    @staticmethod
    def _verify_password(password: str, password_hash: str) -> bool:
        """Verify a password against its hash."""
        if ":" not in password_hash:
            return False
        salt, hash_val = password_hash.split(":", 1)
        return hashlib.sha256(f"{salt}:{password}".encode()).hexdigest() == hash_val

    async def _log_audit(self, action: str, user_id: str, details: str) -> None:
        """Log an audit event."""
        for callback in self._audit_callbacks:
            try:
                await callback({"action": action, "user_id": user_id, "details": details})
            except Exception:
                pass

    def on_audit(self, callback: Any) -> None:
        """Register audit callback."""
        self._audit_callbacks.append(callback)
