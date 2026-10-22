from __future__ import annotations

import json
from pathlib import Path
from threading import Lock
from typing import Any


class AuditLogger:
    def __init__(
        self,
        path: str | Path | None = None,
        *,
        max_bytes: int = 4 * 1024 * 1024,
        max_files: int = 3,
    ) -> None:
        self.path = Path(path) if path else None
        if max_bytes <= 0 or max_files < 1:
            raise ValueError("audit limits must be positive")
        self.max_bytes = max_bytes
        self.max_files = max_files
        self._lock = Lock()

    def emit(self, kind: str, payload: dict[str, Any]) -> None:
        if self.path is None:
            return
        row = {"kind": kind, **payload}
        encoded = (json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
        if len(encoded) > self.max_bytes:
            return
        try:
            with self._lock:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                if self.path.exists() and self.path.stat().st_size + len(encoded) > self.max_bytes:
                    for index in range(self.max_files, 0, -1):
                        source = self.path.with_name(f"{self.path.name}.{index}")
                        if source.exists():
                            if index == self.max_files:
                                source.unlink(missing_ok=True)
                            else:
                                source.replace(self.path.with_name(f"{self.path.name}.{index + 1}"))
                    self.path.replace(self.path.with_name(f"{self.path.name}.1"))
                with self.path.open("ab") as stream:
                    stream.write(encoded)
        except OSError:
            return
