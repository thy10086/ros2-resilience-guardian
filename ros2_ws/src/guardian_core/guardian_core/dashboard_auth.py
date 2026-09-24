"""Small in-memory session gate for the localhost dashboard."""

from __future__ import annotations

import hashlib
import hmac
import math
import os
import secrets
import time
from threading import RLock


DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "admin"
DEFAULT_TTL_SEC = 8 * 60 * 60


class DashboardAuth:
    """Authenticate one local demo account without persisting credentials."""

    def __init__(self, *, username: str = DEFAULT_USERNAME, password: str = DEFAULT_PASSWORD, ttl_sec: float = DEFAULT_TTL_SEC) -> None:
        if not isinstance(username, str) or not username:
            raise ValueError("dashboard username must be a non-empty string")
        if not isinstance(password, str) or not password:
            raise ValueError("dashboard password must be a non-empty string")
        ttl = float(ttl_sec)
        if not math.isfinite(ttl) or ttl <= 0:
            raise ValueError("dashboard session TTL must be positive and finite")
        self.username = username
        self._password = password
        self.ttl_sec = ttl
        self._sessions: dict[str, float] = {}
        self._lock = RLock()

    @classmethod
    def from_environment(cls) -> "DashboardAuth":
        raw_ttl = os.getenv("GUARDIAN_DASHBOARD_SESSION_TTL_SEC", str(DEFAULT_TTL_SEC))
        try:
            ttl = float(raw_ttl)
        except (TypeError, ValueError):
            ttl = DEFAULT_TTL_SEC
        return cls(
            username=os.getenv("GUARDIAN_DASHBOARD_USER", DEFAULT_USERNAME),
            password=os.getenv("GUARDIAN_DASHBOARD_PASSWORD", DEFAULT_PASSWORD),
            ttl_sec=ttl,
        )

    @staticmethod
    def _digest(token: str) -> str:
        return hashlib.sha256(token.encode("ascii")).hexdigest()

    def _prune_locked(self, now: float) -> None:
        for digest, expires_at in tuple(self._sessions.items()):
            if expires_at <= now:
                self._sessions.pop(digest, None)

    def login(self, username: str, password: str, *, now: float | None = None) -> str | None:
        if not isinstance(username, str) or not isinstance(password, str):
            return None
        current = time.monotonic() if now is None else float(now)
        if not math.isfinite(current):
            return None
        if not hmac.compare_digest(username, self.username) or not hmac.compare_digest(password, self._password):
            return None
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._prune_locked(current)
            self._sessions[self._digest(token)] = current + self.ttl_sec
        return token

    def validate(self, token: str | None, *, now: float | None = None) -> bool:
        if not isinstance(token, str) or not token:
            return False
        current = time.monotonic() if now is None else float(now)
        if not math.isfinite(current):
            return False
        try:
            digest = self._digest(token)
        except (UnicodeEncodeError, AttributeError):
            return False
        with self._lock:
            self._prune_locked(current)
            return digest in self._sessions

    def logout(self, token: str | None) -> None:
        if not isinstance(token, str) or not token:
            return
        try:
            digest = self._digest(token)
        except (UnicodeEncodeError, AttributeError):
            return
        with self._lock:
            self._sessions.pop(digest, None)


__all__ = ["DashboardAuth", "DEFAULT_PASSWORD", "DEFAULT_TTL_SEC", "DEFAULT_USERNAME"]
