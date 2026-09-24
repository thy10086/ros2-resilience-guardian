"""Small in-memory session gate for the localhost dashboard."""

from __future__ import annotations

import hashlib
import hmac
import math
import os
import secrets
import time
from threading import RLock
from .dashboard_credentials import JevKeyStore


DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "admin"
DEFAULT_TTL_SEC = 8 * 60 * 60


class DashboardAuth:
    """Authenticate one local demo account without persisting credentials."""

    def __init__(self, *, username: str = DEFAULT_USERNAME, password: str = DEFAULT_PASSWORD, ttl_sec: float = DEFAULT_TTL_SEC, key_store: JevKeyStore | None = None) -> None:
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
        self.key_store = key_store if key_store is not None else JevKeyStore()
        self._lock = RLock()

    @classmethod
    def from_environment(cls) -> "DashboardAuth":
        raw_ttl = os.getenv("GUARDIAN_DASHBOARD_SESSION_TTL_SEC", str(DEFAULT_TTL_SEC))
        try:
            ttl = float(raw_ttl)
        except (TypeError, ValueError):
            ttl = DEFAULT_TTL_SEC
        username = os.getenv("GUARDIAN_DASHBOARD_USER", DEFAULT_USERNAME)
        return cls(
            username=username,
            key_store=JevKeyStore.for_account(username),
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

    def remember_jev_key(self, token: str | None, api_key: str, *, now: float | None = None) -> bool:
        """Persist the account key after authenticating the current session."""

        if not isinstance(api_key, str) or not api_key:
            return False
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
            expires_at = self._sessions.get(digest)
            if expires_at is None or expires_at <= current:
                return False
            self.key_store.save(api_key)
            return True

    def get_jev_key(self, token: str | None, *, now: float | None = None) -> str | None:
        """Use the account key only for a currently authenticated request."""

        if not isinstance(token, str) or not token:
            return None
        current = time.monotonic() if now is None else float(now)
        if not math.isfinite(current):
            return None
        try:
            digest = self._digest(token)
        except (UnicodeEncodeError, AttributeError):
            return None
        with self._lock:
            self._prune_locked(current)
            return self.key_store.get() if digest in self._sessions else None

    def has_jev_key(self, token: str | None, *, now: float | None = None) -> bool:
        return self.get_jev_key(token, now=now) is not None

    def clear_jev_key(self, token: str | None) -> None:
        with self._lock:
            if self.validate(token):
                self.key_store.clear()


__all__ = ["DashboardAuth", "DEFAULT_PASSWORD", "DEFAULT_TTL_SEC", "DEFAULT_USERNAME"]
