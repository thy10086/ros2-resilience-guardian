"""Thread-safe state cache used by the ROS 2 dashboard bridge."""

from __future__ import annotations

from collections import deque
from copy import deepcopy
import json
import math
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
            "simulation": {
                "robot_id": "amr-07",
                "mission": "pallet_transfer",
                "route": "A-12 → P-07",
                "phase": "SIMULATOR_OFFLINE",
                "mission_running": False,
                "pallet_loaded": False,
                "x": 0.0,
                "y": 0.0,
                "elapsed": 0.0,
                "requested_speed": 0.0,
                "actual_speed": 0.0,
                "speed_limit": 0.35,
                "safety_state": "STARTING",
                "mission_allowed": False,
                "mitigation_action": "NONE",
                "mitigation_components": [],
                "attack_mode": None,
                "grip_force": 45.0,
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

    def update_simulation(self, message: Any) -> None:
        """Cache bounded simulator telemetry without flooding the timeline."""
        try:
            payload = json.loads(str(message.data))
        except (AttributeError, TypeError, json.JSONDecodeError):
            return
        if not isinstance(payload, dict):
            return
        clean: dict[str, Any] = {}
        for key, value in payload.items():
            if key == "attack_mode":
                if value is None or isinstance(value, str):
                    clean[key] = value if value is None else value[:128]
            elif key in {"robot_id", "mission", "route", "phase", "safety_state", "mitigation_action"}:
                if isinstance(value, str):
                    clean[key] = value[:128]
            elif key in {"mission_running", "pallet_loaded", "mission_allowed"}:
                if isinstance(value, bool):
                    clean[key] = value
            elif key in {"x", "y", "elapsed", "requested_speed", "actual_speed", "speed_limit", "grip_force"}:
                if isinstance(value, (int, float)) and math.isfinite(float(value)):
                    clean[key] = float(value)
            elif key == "mitigation_components" and isinstance(value, list):
                clean[key] = [str(item)[:64] for item in value[:8]]
        with self._lock:
            self._state["simulation"].update(clean)

    def _update(self, category: str, payload: dict[str, Any], timestamp: float) -> None:
        with self._lock:
            self._state[category] = payload
            self._state["updated_at"] = timestamp
            self._timeline.appendleft({"category": category, **payload})
            self._state["timeline"] = list(self._timeline)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return deepcopy(self._state)
