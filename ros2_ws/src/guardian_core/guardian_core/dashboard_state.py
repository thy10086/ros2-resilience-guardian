"""Thread-safe state cache used by the ROS 2 dashboard bridge."""

from __future__ import annotations

from collections import deque
from copy import deepcopy
from threading import Lock
from typing import Any


class DashboardState:
    """Keep the latest Guardian messages and a small audit-friendly timeline."""

    def __init__(self, timeline_limit: int = 100) -> None:
        self._lock = Lock()
        self._timeline: deque[dict[str, Any]] = deque(maxlen=timeline_limit)
        self._state: dict[str, Any] = {
            "updated_at": None,
            "risk": {
                "timestamp": None,
                "state": "STARTING",
                "risk": 0.0,
                "psi": 0.0,
                "delta": False,
                "gamma": False,
                "active_components": [],
                "critical_components": [],
                "reason": "等待 Guardian ROS 2 状态",
            },
            "mitigation": {
                "timestamp": None,
                "plan_id": "",
                "action": "NONE",
                "components": [],
                "requires_safe_stop": False,
                "reason": "尚未生成缓解方案",
            },
            "safety": {
                "timestamp": None,
                "state": "STARTING",
                "speed_limit": 0.0,
                "mission_allowed": False,
                "reason": "等待 Guardian ROS 2 状态",
                "plan_id": "",
            },
            "timeline": [],
        }

    def update_risk(self, message: Any) -> None:
        payload = {
            "timestamp": float(message.timestamp),
            "state": str(message.state),
            "risk": float(message.risk),
            "psi": float(message.psi),
            "delta": bool(message.delta),
            "gamma": bool(message.gamma),
            "active_components": sorted(str(item) for item in message.active_components),
            "critical_components": sorted(str(item) for item in message.critical_components),
            "reason": str(message.reason),
        }
        self._update("risk", payload, payload["timestamp"])

    def update_mitigation(self, message: Any) -> None:
        payload = {
            "timestamp": float(message.timestamp),
            "plan_id": str(message.plan_id),
            "action": str(message.action),
            "components": sorted(str(item) for item in message.components),
            "requires_safe_stop": bool(message.requires_safe_stop),
            "reason": str(message.reason),
        }
        self._update("mitigation", payload, payload["timestamp"])

    def update_safety(self, message: Any) -> None:
        payload = {
            "timestamp": float(message.timestamp),
            "state": str(message.state),
            "speed_limit": float(message.speed_limit),
            "mission_allowed": bool(message.mission_allowed),
            "reason": str(message.reason),
            "plan_id": str(message.plan_id),
        }
        self._update("safety", payload, payload["timestamp"])

    def _update(self, category: str, payload: dict[str, Any], timestamp: float) -> None:
        with self._lock:
            self._state[category] = payload
            self._state["updated_at"] = timestamp
            self._timeline.appendleft({"category": category, **payload})
            self._state["timeline"] = list(self._timeline)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return deepcopy(self._state)

