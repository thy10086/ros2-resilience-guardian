"""Laptop-friendly ROS 2 AMR engineering simulator.

The simulator is intentionally deterministic and controller-facing: it models a
differential-drive base, a pallet/gripper state, bounded fault injection and
the feedback loop from Guardian's safety messages. It does not pretend to be a
physics engine and never talks to a real actuator.
"""
from __future__ import annotations

import json
import math
import time
from typing import Any, Iterable

from geometry_msgs.msg import Twist
from nav_msgs.msg import Odometry
import rclpy
from rclpy.node import Node
from std_msgs.msg import String

from guardian_interfaces.msg import AttackEvent, MitigationCommand, SafetyStatus


ALLOWED_ATTACKS = frozenset({"speed_abuse", "replay", "gripper_fault"})
ALLOWED_ACTIONS = frozenset({"start", "stop", "reset", "attack"})


class SimulationCommandError(ValueError):
    """Raised when a simulation control command is outside the bounded API."""


class AmrSimulationModel:
    """Deterministic state model shared by the ROS node and unit tests."""

    def __init__(self, robot_id: str = "amr-07") -> None:
        self.robot_id = robot_id
        self.route_length = 10.0
        self.x = 0.0
        self.y = 0.0
        self.elapsed = 0.0
        self.phase = "IDLE"
        self.mission_running = False
        self.pallet_loaded = False
        self.gripper_force = 45.0
        self.requested_speed = 0.0
        self.actual_speed = 0.0
        self.safety_state = "NORMAL"
        self.safety_limit = 0.35
        self.mission_allowed = True
        self.mitigation_action = "NONE"
        self.mitigation_components: list[str] = []
        self.attack_mode: str | None = None
        self._pending_events: list[dict[str, Any]] = []
        self._replay_counter = 0

    def handle_command(self, command: dict[str, Any]) -> None:
        if not isinstance(command, dict) or set(command) - {"action", "type"}:
            raise SimulationCommandError("simulation command fields are invalid")
        action = command.get("action")
        if action not in ALLOWED_ACTIONS:
            raise SimulationCommandError("action must be start, stop, reset or attack")
        if action == "start":
            self.mission_running = True
            self.pallet_loaded = True
            if self.phase in {"IDLE", "COMPLETE"}:
                self.phase = "DOCK_TO_PALLET"
            return
        if action == "stop":
            self.mission_running = False
            self.requested_speed = 0.0
            self.actual_speed = 0.0
            self.phase = "STOPPED"
            return
        if action == "reset":
            self.__init__(self.robot_id)
            return
        attack_type = command.get("type")
        if attack_type not in ALLOWED_ATTACKS:
            raise SimulationCommandError("type must be speed_abuse, replay or gripper_fault")
        self.attack_mode = str(attack_type)
        if attack_type == "speed_abuse":
            self._pending_events.append(self._event_template("UNSAFE_COMMAND", "left_wheels", 7001))
        elif attack_type == "replay":
            self._replay_counter = 0
            self._pending_events.extend([
                self._event_template("UNSAFE_COMMAND", "left_wheels", 7001),
                self._event_template("UNSAFE_COMMAND", "left_wheels", 7001),
            ])
        else:
            self.gripper_force = 0.0
            self._pending_events.append(self._event_template("SEMANTIC_MISBEHAVIOR", "right_arm", 7003))

    def update_safety(self, safety: dict[str, Any]) -> None:
        state = safety.get("state")
        if isinstance(state, str) and state:
            self.safety_state = state[:32]
        try:
            limit = float(safety.get("speed_limit", self.safety_limit))
        except (TypeError, ValueError):
            limit = self.safety_limit
        if math.isfinite(limit):
            self.safety_limit = max(0.0, min(1.0, limit))
        self.mission_allowed = bool(safety.get("mission_allowed", self.mission_allowed))

    def update_mitigation(self, mitigation: dict[str, Any]) -> None:
        action = mitigation.get("action")
        if isinstance(action, str):
            self.mitigation_action = action[:40]
        components = mitigation.get("components", [])
        if isinstance(components, list):
            self.mitigation_components = [str(item)[:64] for item in components[:8]]

    def update(self, dt: float) -> None:
        if not isinstance(dt, (int, float)) or not math.isfinite(dt):
            dt = 0.0
        dt = max(0.0, min(0.5, float(dt)))
        if self.attack_mode in {"speed_abuse", "replay"}:
            self.requested_speed = 0.62
        elif self.phase == "PALLET_STABILIZE":
            self.requested_speed = 0.08
        else:
            self.requested_speed = 0.20 if self.mission_running else 0.0
        if not self.mission_running or not self.mission_allowed or self.safety_state in {"SAFE_STOP", "ABORTED"}:
            self.actual_speed = 0.0
        else:
            self.actual_speed = min(self.requested_speed, self.safety_limit)
        self.elapsed += dt
        self.x = min(self.route_length, self.x + self.actual_speed * dt)
        if self.mission_running and self.x >= 8.0:
            self.phase = "PALLET_STABILIZE"
        if self.mission_running and self.x >= self.route_length:
            self.phase = "COMPLETE"
            self.mission_running = False
            self.actual_speed = 0.0

    def poll_attack_events(self, timestamp: float) -> list[dict[str, Any]]:
        # Publish at most one injected event per simulator tick. This keeps
        # replay attacks observable as two ROS 2 messages instead of collapsing
        # both records into one callback burst.
        events = self._pending_events[:1]
        self._pending_events = self._pending_events[1:]
        result: list[dict[str, Any]] = []
        for event in events:
            item = dict(event)
            item["timestamp"] = float(timestamp)
            if self.attack_mode == "replay":
                item["event_id"] = f"{self.robot_id}-replay-{self._replay_counter}"
                self._replay_counter += 1
            result.append(item)
        return result

    def _event_template(self, attack_type: str, component: str, sequence: int) -> dict[str, Any]:
        return {
            "event_id": f"{self.robot_id}-{component}-{sequence}",
            "source": "amr_simulator",
            "component": component,
            "attack_type": attack_type,
            "sequence": sequence,
            "timestamp": 0.0,
            "confidence": 0.98 if component == "left_wheels" else 0.91,
        }

    def gripper_payload(self) -> str:
        return json.dumps({"robot_id": self.robot_id, "load_present": self.pallet_loaded, "grip_force": self.gripper_force}, ensure_ascii=False)

    def snapshot(self) -> dict[str, Any]:
        return {
            "robot_id": self.robot_id,
            "mission": "pallet_transfer",
            "route": "A-12 → P-07",
            "phase": self.phase,
            "mission_running": self.mission_running,
            "pallet_loaded": self.pallet_loaded,
            "x": round(self.x, 3),
            "y": round(self.y, 3),
            "elapsed": round(self.elapsed, 3),
            "requested_speed": round(self.requested_speed, 3),
            "actual_speed": round(self.actual_speed, 3),
            "speed_limit": round(self.safety_limit, 3),
            "safety_state": self.safety_state,
            "mission_allowed": self.mission_allowed,
            "mitigation_action": self.mitigation_action,
            "mitigation_components": list(self.mitigation_components),
            "attack_mode": self.attack_mode,
            "grip_force": self.gripper_force,
        }


class AmrSimulatorNode(Node):
    """ROS 2 adapter for :class:`AmrSimulationModel`."""

    def __init__(self) -> None:
        super().__init__("amr_simulator")
        self.model = AmrSimulationModel()
        self.cmd_pub = self.create_publisher(Twist, "/cmd_vel", 20)
        self.odom_pub = self.create_publisher(Odometry, "/amr_07/odom", 20)
        self.gripper_pub = self.create_publisher(String, "/amr_07/gripper_state", 20)
        self.telemetry_pub = self.create_publisher(String, "guardian/sim_state", 20)
        self.attack_pub = self.create_publisher(AttackEvent, "guardian/attack_events", 20)
        self.create_subscription(String, "/amr_07/sim_control", self.on_control, 20)
        self.create_subscription(SafetyStatus, "guardian/safety_status", self.on_safety, 20)
        self.create_subscription(MitigationCommand, "guardian/mitigation_command", self.on_mitigation, 20)
        self._last_tick = time.monotonic()
        self.create_timer(0.1, self.tick)

    def on_control(self, message: String) -> None:
        try:
            command = json.loads(message.data)
            self.model.handle_command(command)
        except (json.JSONDecodeError, SimulationCommandError) as error:
            self.get_logger().warning(f"Ignored simulation command: {error}")

    def on_safety(self, message: SafetyStatus) -> None:
        self.model.update_safety({"state": message.state, "speed_limit": message.speed_limit, "mission_allowed": message.mission_allowed})

    def on_mitigation(self, message: MitigationCommand) -> None:
        self.model.update_mitigation({"action": message.action, "components": list(message.components)})

    def tick(self) -> None:
        now_monotonic = time.monotonic()
        self.model.update(now_monotonic - self._last_tick)
        self._last_tick = now_monotonic
        stamp = self.get_clock().now()
        for event in self.model.poll_attack_events(stamp.nanoseconds / 1e9):
            message = AttackEvent()
            message.event_id = event["event_id"]
            message.source = event["source"]
            message.component = event["component"]
            message.attack_type = event["attack_type"]
            message.sequence = int(event["sequence"])
            message.timestamp = float(event["timestamp"])
            message.confidence = float(event["confidence"])
            self.attack_pub.publish(message)
        twist = Twist()
        twist.linear.x = float(self.model.actual_speed)
        self.cmd_pub.publish(twist)
        odom = Odometry()
        odom.header.stamp = stamp.to_msg()
        odom.header.frame_id = "map"
        odom.child_frame_id = "base_link"
        odom.pose.pose.position.x = float(self.model.x)
        odom.pose.pose.position.y = float(self.model.y)
        odom.twist.twist.linear.x = float(self.model.actual_speed)
        self.odom_pub.publish(odom)
        self.gripper_pub.publish(String(data=self.model.gripper_payload()))
        self.telemetry_pub.publish(String(data=json.dumps(self.model.snapshot(), ensure_ascii=False)))


def main(args: Iterable[str] | None = None) -> None:
    rclpy.init(args=args)
    node = AmrSimulatorNode()
    try:
        rclpy.spin(node)
    finally:
        node.destroy_node()
        if rclpy.ok():
            rclpy.shutdown()


__all__ = ["AmrSimulationModel", "AmrSimulatorNode", "SimulationCommandError", "main"]
