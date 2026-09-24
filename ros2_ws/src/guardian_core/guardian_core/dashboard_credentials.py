"""Account-scoped local credentials; never returned by a dashboard API.

Production uses the WSL user's Linux filesystem, outside the repository.
Tests may omit a path for isolated in-memory storage with the same lifecycle.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
from threading import RLock

from .dashboard_jev import _validate_api_key, JevRequestError


class CredentialStoreError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("本机 Key 存储不可用，请检查服务用户目录权限；原有记录不会被自动清除")


class JevKeyStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self._key: str | None = None
        self._lock = RLock()

    @classmethod
    def for_account(cls, username: str) -> "JevKeyStore":
        account = hashlib.sha256(username.encode("utf-8")).hexdigest()[:24]
        return cls(Path.home() / ".local" / "state" / "ros2-resilience-guardian" / f"jev-{account}.json")

    def get(self) -> str | None:
        with self._lock:
            if self.path is None:
                return self._key
            try:
                descriptor = os.open(self.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            except FileNotFoundError:
                return None
            except OSError:
                raise CredentialStoreError() from None
            try:
                with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
                    info = os.fstat(stream.fileno())
                    if not stat.S_ISREG(info.st_mode) or info.st_size > 2048:
                        raise CredentialStoreError()
                    if os.name == "posix" and (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077):
                        raise CredentialStoreError()
                    value = json.loads(stream.read(2049))
                    if not isinstance(value, dict) or value.get("version") != 1:
                        raise CredentialStoreError()
                    return _validate_api_key(value.get("api_key"))
            except (OSError, UnicodeError, ValueError, JevRequestError):
                raise CredentialStoreError() from None

    def save(self, key: str) -> None:
        key = _validate_api_key(key)
        with self._lock:
            if self.path is None:
                self._key = key
                return
            temporary = None
            try:
                directory = self.path.parent
                directory.mkdir(parents=True, exist_ok=True, mode=0o700)
                if directory.is_symlink() or self.path.is_symlink():
                    raise CredentialStoreError()
                if os.name == "posix" and directory.stat().st_uid != os.getuid():
                    raise CredentialStoreError()
                directory.chmod(0o700)
                descriptor, temporary = tempfile.mkstemp(prefix=".jev-", dir=directory)
                with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                    if os.name == "posix":
                        os.fchmod(stream.fileno(), 0o600)
                    json.dump({"version": 1, "api_key": key}, stream)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, self.path)
                temporary = None
                self._sync_directory()
            except OSError:
                raise CredentialStoreError() from None
            finally:
                if temporary is not None:
                    try:
                        Path(temporary).unlink(missing_ok=True)
                    except OSError:
                        pass

    def clear(self) -> None:
        with self._lock:
            if self.path is None:
                self._key = None
                return
            try:
                self.path.unlink(missing_ok=True)
                if self.path.parent.exists():
                    self._sync_directory()
            except OSError:
                raise CredentialStoreError() from None

    def _sync_directory(self) -> None:
        if os.name == "posix":
            descriptor = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
