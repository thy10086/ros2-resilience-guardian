"""Laptop-friendly ROS 2 AMR engineering simulator.

The simulator is intentionally deterministic and controller-facing: it models a
differential-drive base, a pallet/gripper state, bounded fault injection and
the feedback loop from Guardian's safety messages. It does not pretend to be a
physics engine and never talks to a real actuator.
"""
from __future__ import annotations

import json
import math
import os
import time
from typing import Any, Callable, Iterable

from geometry_msgs.msg import Twist
from nav_msgs.msg import Odometry
from sensor_msgs.msg import LaserScan
import rclpy
from rclpy.executors import ExternalShutdownException
from rclpy.clock import Clock, ClockType
from rclpy.node import Node
from std_msgs.msg import String

from guardian_interfaces.msg import AttackEvent, MitigationAck, MitigationCommand, SafetyStatus, RecoveryTelemetry

from .feedback_auth import sign_ack, verify_command, verify_status
from .feedback_auth import RECOVERY_TELEMETRY_FIELDS, sign_recovery_telemetry
from .verifier import EventVerifier
from .models import AttackEvent as CoreAttackEvent

ALLOWED_ATTACKS = frozenset({"speed_abuse", "replay", "gripper_fault"})
ALLOWED_ACTIONS = frozenset({"start", "stop", "reset", "attack"})


class SimulationCommandError(ValueError):
    """Raised when a simulation control command is outside the bounded API."""


class AmrSimulationModel:
    """Deterministic state model shared by the ROS node and unit tests."""

    def __init__(self, robot_id: str = "amr-07", *,
                 monotonic_clock: Callable[[], float] | None = None,
                 authorization_timeout_sec: float = 0.5) -> None:
        if not math.isfinite(authorization_timeout_sec) or authorization_timeout_sec <= 0:
            raise ValueError("authorization timeout must be finite and positive")
        self._monotonic_clock = monotonic_clock or time.monotonic
        self._authorization_timeout_sec = authorization_timeout_sec
        self._last_authorization_clock: float | None = None
        self._authorization_clock_fault = False
        self._command_received_at: float | None = None
        self._status_received_at: float | None = None
        self.robot_id = robot_id
        self.safety_state = "SAFE_STOP"
        self.safety_limit = 0.35
        self.mission_allowed = False
        self.mitigation_action = "NONE"
        self.mitigation_components: list[str] = []
        self.command_epoch = 0
        self.command_transmission_id = 0
        self.command_adapter_id = "default-actuator"
        self.command_profile_id = "amr-default"
        self.command_plan_id = ""
        self.command_accepted = False
        self._command_fingerprint: tuple[str, str, tuple[str, ...]] | None = None
        self._command_bootstrapped = False
        self._ordering_fault = False
        self._safety_identity = (0, 0)
        self._safety_adapter_id = self.command_adapter_id
        self._safety_profile_id = self.command_profile_id
        self._feedback_sequence = 0
        self._attack_sequence = 7000
        self.isolated_components: set[str] = set()
        self._reset_scene()

    def _reset_scene(self) -> None:
        # Scene controls must not reset protocol counters or fault latches.
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
            self._reset_scene()
            self._force_safe_stop()
            return
        attack_type = command.get("type")
        if attack_type not in ALLOWED_ATTACKS:
            raise SimulationCommandError("type must be speed_abuse, replay or gripper_fault")
        self.attack_mode = str(attack_type)
        if attack_type == "speed_abuse":
            self._pending_events.append(self._new_attack_event("UNSAFE_COMMAND", "left_wheels"))
        elif attack_type == "replay":
            self._replay_counter = 0
            event = self._new_attack_event("UNSAFE_COMMAND", "left_wheels")
            self._pending_events.extend([event, dict(event)])
        else:
            self.gripper_force = 0.0
            self._pending_events.append(self._new_attack_event("SEMANTIC_MISBEHAVIOR", "right_arm"))

    def update_safety(self, safety: dict[str, Any], *, source_age_sec: float = 0.0) -> None:
        now = self._check_authorization_leases()
        if now is None or not math.isfinite(source_age_sec) or not 0 <= source_age_sec < self._authorization_timeout_sec:
            self._force_safe_stop()
            return
        legacy_identity = not any(
            key in safety for key in ("command_epoch", "transmission_id", "adapter_id", "profile_id")
        )
        try:
            epoch = int(safety.get("command_epoch", self.command_epoch))
            transmission_id = int(safety.get("transmission_id", self.command_transmission_id))
        except (TypeError, ValueError):
            self._force_safe_stop()
            return
        adapter_id = str(safety.get("adapter_id", self.command_adapter_id))[:96]
        profile_id = str(safety.get("profile_id", self.command_profile_id))[:96]
        identity = (epoch, transmission_id)
        if identity < self._safety_identity:
            return
        state = safety.get("state")
        try:
            limit = float(safety.get("speed_limit", self.safety_limit))
        except (TypeError, ValueError):
            limit = self.safety_limit
        if not isinstance(state, str) or not state or not math.isfinite(limit):
            self._force_safe_stop()
            return
        fingerprint = (state[:32], max(0.0, min(1.0, limit)), bool(safety.get("mission_allowed", self.mission_allowed)))
        if legacy_identity:
            # Compatibility for in-process callers; production ROS callbacks
            # always supply transport identity. An old identity cannot renew.
            if identity > self._safety_identity:
                self._status_received_at = now - source_age_sec
            self._safety_identity = (self.command_epoch, self.command_transmission_id)
            self._safety_adapter_id = self.command_adapter_id
            self._safety_profile_id = self.command_profile_id
            self.safety_state, self.safety_limit, self.mission_allowed = fingerprint
            return
        if identity == self._safety_identity:
            previous = (self.safety_state, self.safety_limit, self.mission_allowed)
            if fingerprint != previous:
                self._force_safe_stop()
            return
        self._safety_identity = identity
        self._status_received_at = now - source_age_sec
        self._safety_adapter_id = adapter_id
        self._safety_profile_id = profile_id
        self.safety_state, self.safety_limit, self.mission_allowed = fingerprint

    def update_mitigation(self, mitigation: dict[str, Any], *, source_age_sec: float = 0.0) -> None:
        now = self._check_authorization_leases()
        if now is None or not math.isfinite(source_age_sec) or not 0 <= source_age_sec < self._authorization_timeout_sec:
            self._force_safe_stop()
            return
        try:
            epoch = int(mitigation.get("command_epoch", self.command_epoch))
            transmission_id = int(mitigation.get("transmission_id", self.command_transmission_id))
        except (TypeError, ValueError):
            self._force_safe_stop()
            return
        action = mitigation.get("action")
        if not isinstance(action, str) or not action:
            self._force_safe_stop()
            return
        normalized_action = action[:40]
        components = mitigation.get("components", [])
        if not isinstance(components, list):
            self._force_safe_stop()
            return
        normalized_components = tuple(str(item)[:64] for item in components[:8])
        fingerprint = (str(mitigation.get("plan_id", ""))[:128], normalized_action, normalized_components)
        if epoch <= 0 or transmission_id <= 0:
            self._force_safe_stop()
            return
        if self._command_bootstrapped and (epoch < self.command_epoch or (
            epoch == self.command_epoch and transmission_id <= self.command_transmission_id
        )):
            return
        if epoch == self.command_epoch:
            if self._command_bootstrapped and fingerprint != self._command_fingerprint:
                self.command_transmission_id = max(self.command_transmission_id, transmission_id)
                self._ordering_fault = True
                self._force_safe_stop()
                return
        elif self._command_bootstrapped and epoch != self.command_epoch + 1:
            self.command_epoch = max(self.command_epoch, epoch)
            self.command_transmission_id = max(self.command_transmission_id, transmission_id)
            self._ordering_fault = True
            self._force_safe_stop()
            return
        if self._ordering_fault:
            return
        self.command_epoch = epoch
        self.command_transmission_id = transmission_id
        self._command_bootstrapped = True
        self._command_received_at = now - source_age_sec
        self.command_adapter_id = str(mitigation.get("adapter_id", self.command_adapter_id))[:96]
        self.command_profile_id = str(mitigation.get("profile_id", self.command_profile_id))[:96]
        self.command_plan_id, self.mitigation_action, self.mitigation_components = fingerprint
        self._command_fingerprint = fingerprint
        self.command_accepted = self.mitigation_action in {
            "NONE", "ISOLATE_COMPONENT", "LIMIT_SPEED", "DEGRADED_RUN", "SAFE_STOP"
        }
        self.isolated_components = (
            set(self.mitigation_components)
            if self.mitigation_action == "ISOLATE_COMPONENT"
            else set()
        )
        if not self.command_accepted:
            self._force_safe_stop()

    def mitigation_ack(self, timestamp: float) -> dict[str, Any] | None:
        self._check_authorization_leases()
        if not self.command_accepted:
            return None
        safe_stop = self.mitigation_action == "SAFE_STOP"
        self._feedback_sequence += 1
        return {
            "timestamp": float(timestamp),
            "command_epoch": self.command_epoch,
            "transmission_id": self.command_transmission_id,
            "feedback_sequence": self._feedback_sequence,
            "adapter_id": self.command_adapter_id,
            "profile_id": self.command_profile_id,
            "plan_id": self.command_plan_id,
            "action": self.mitigation_action,
            "components": list(self.mitigation_components),
            "accepted": True,
            "active": True,
            "safe_stop_confirmed": safe_stop and self.actual_speed == 0.0,
            "reason": "mitigation command applied",
        }

    def _force_safe_stop(self) -> None:
        self._command_received_at = None
        self._status_received_at = None
        self.actual_speed = 0.0
        self.command_accepted = False
        self.mitigation_action = "SAFE_STOP"
        self.mitigation_components = []
        self.isolated_components = set()
        self.safety_state = "SAFE_STOP"
        self.safety_limit = 0.0
        self.mission_allowed = False

    def _check_authorization_leases(self) -> float | None:
        now = self._monotonic_clock()
        if (not math.isfinite(now) or self._authorization_clock_fault
                or (self._last_authorization_clock is not None and now < self._last_authorization_clock)):
            self._authorization_clock_fault = True
            self._force_safe_stop()
            return None
        self._last_authorization_clock = now
        if any(received is not None and now - received >= self._authorization_timeout_sec
                for received in (self._command_received_at, self._status_received_at)):
            self._force_safe_stop()
        return now

    def update(self, dt: float) -> None:
        self._check_authorization_leases()
        if not isinstance(dt, (int, float)) or not math.isfinite(dt):
            dt = 0.0
        dt = max(0.0, min(0.5, float(dt)))
        if self.attack_mode in {"speed_abuse", "replay"}:
            self.requested_speed = 0.62
        elif self.phase == "PALLET_STABILIZE":
            self.requested_speed = 0.08
        else:
            self.requested_speed = 0.20 if self.mission_running else 0.0
        drive_isolated = bool({"left_wheels", "right_wheels"} & self.isolated_components)
        safety_identity_matches = (
            self._safety_identity == (self.command_epoch, self.command_transmission_id)
            and self._safety_adapter_id == self.command_adapter_id
            and self._safety_profile_id == self.command_profile_id
        )
        if (
            not self.mission_running
            or not self.mission_allowed
            or not self.command_accepted
            or self._command_received_at is None
            or self._status_received_at is None
            or not safety_identity_matches
            or self.safety_state in {"SAFE_STOP", "ABORTED"}
            or drive_isolated
            or self.mitigation_action == "SAFE_STOP"
        ):
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
                item["event_id"] = f"{self.robot_id}-replay-{item['sequence']}-{self._replay_counter}"
                self._replay_counter += 1
            result.append(item)
        return result

    def _new_attack_event(self, attack_type: str, component: str) -> dict[str, Any]:
        # The source verifier survives scene reset; new incidents must too.
        self._attack_sequence += 1
        return self._event_template(attack_type, component, self._attack_sequence)

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
            "command_epoch": self.command_epoch,
            "transmission_id": self.command_transmission_id,
            "adapter_id": self.command_adapter_id,
            "feedback_sequence": self._feedback_sequence,
            "isolated_components": sorted(self.isolated_components),
            "attack_mode": self.attack_mode,
            "grip_force": self.gripper_force,
        }


class AmrSimulatorNode(Node):
    """ROS 2 adapter for :class:`AmrSimulationModel`."""

    def __init__(self) -> None:
        super().__init__("amr_simulator")
        self.model = AmrSimulationModel()
        self._authorization_source_clocks = None
        self._authorization_source_offset = None
        self._authorization_source_suspect = False
        self._authorization_source_resumed = False
        self._authorization_frozen_ros_high_water = None
        self._authorization_source_fault = False
        self._authorization_latest_stamp = None
        self._feedback_secret = os.getenv("GUARDIAN_FEEDBACK_SECRET", "").encode("utf-8") or None
        self._event_secret = os.getenv("GUARDIAN_EVENT_SECRET", "").encode("utf-8") or self._feedback_secret
        self.cmd_pub = self.create_publisher(Twist, "/cmd_vel", 20)
        self.odom_pub = self.create_publisher(Odometry, "/amr_07/odom", 20)
        self.scan_pub = self.create_publisher(LaserScan, "/amr_07/scan", 20)
        self._sensor_mode = "normal"
        self._last_sensor_messages = None
        self._obstacle_x = self.model.route_length + 5.0
        self.gripper_pub = self.create_publisher(String, "/amr_07/gripper_state", 20)
        self.telemetry_pub = self.create_publisher(String, "guardian/sim_state", 20)
        self.attack_pub = self.create_publisher(AttackEvent, "guardian/attack_events", 20)
        self.ack_pub = self.create_publisher(MitigationAck, "guardian/mitigation_ack", 20)
        self.recovery_pub = self.create_publisher(RecoveryTelemetry, "guardian/recovery_telemetry", 20)
        self._observation_sequence = 0
        self.create_subscription(String, "/amr_07/sim_control", self.on_control, 20)
        self.create_subscription(SafetyStatus, "guardian/safety_status", self.on_safety, 20)
        self.create_subscription(MitigationCommand, "guardian/mitigation_command", self.on_mitigation, 20)
        self._last_tick = time.monotonic()
        self._steady_clock = Clock(clock_type=ClockType.STEADY_TIME)
        self.create_timer(0.1, self.tick, clock=self._steady_clock)

    def on_control(self, message: String) -> None:
        try:
            command = json.loads(message.data)
            if not isinstance(command, dict):
                raise SimulationCommandError("simulation command must be an object")
            if command.get("action") == "sensor_fault":
                mode = command.get("mode")
                if not isinstance(mode, str) or set(command) - {"action", "mode"}:
                    raise SimulationCommandError("invalid sensor fault fields")
                if mode == "restart_endpoints":
                    self.destroy_publisher(self.odom_pub)
                    self.destroy_publisher(self.scan_pub)
                    self.odom_pub = self.create_publisher(Odometry, "/amr_07/odom", 20)
                    self.scan_pub = self.create_publisher(LaserScan, "/amr_07/scan", 20)
                    return
                if mode not in {"normal", "paused", "stale", "replay", "invalid_scan", "speed_mismatch", "near_obstacle"}:
                    raise SimulationCommandError("unsupported sensor fault mode")
                self._sensor_mode = mode
                return
            self.model.handle_command(command)
            if command.get("action") == "reset":
                self._sensor_mode = "normal"
        except (json.JSONDecodeError, SimulationCommandError) as error:
            self.get_logger().warning(f"Ignored simulation command: {error}")

    def now_seconds(self) -> float:
        return self.get_clock().now().nanoseconds / 1e9

    def _observe_authorization_source_clock(self):
        now, now_ros = self.model._monotonic_clock(), self.now_seconds()
        previous = self._authorization_source_clocks
        if (self._authorization_source_fault or not all(math.isfinite(value) for value in (now, now_ros))
                or (previous is not None and (now < previous[0] or now_ros < previous[1]))):
            self._authorization_source_fault = True
            self.model._force_safe_stop()
            return None
        if previous is not None:
            elapsed, ros_elapsed = now - previous[0], now_ros - previous[1]
            if elapsed > 0 and ros_elapsed < elapsed * 0.5:
                self._authorization_source_suspect = True
                self._authorization_source_resumed = False
                # Recovery must cross the paused chain's observed ROS time,
                # including publication stamps that arrived too late to use.
                self._authorization_frozen_ros_high_water = (now_ros
                    if self._authorization_frozen_ros_high_water is None
                    else max(now_ros, self._authorization_frozen_ros_high_water))
            elif elapsed > 0 and ros_elapsed > 0:
                self._authorization_source_resumed = True
        self._authorization_source_clocks = (now, now_ros)
        # Freeze the paused source chain; normal clock drift is local to each
        # reception and never accumulates across the process lifetime.
        if self._authorization_source_offset is None or not self._authorization_source_suspect:
            self._authorization_source_offset = now - now_ros
        return now, now_ros

    def _authorization_source_age(self, timestamp: float) -> float:
        clocks = self._observe_authorization_source_clock()
        if clocks is None or not math.isfinite(timestamp):
            return math.inf
        now, now_ros = clocks
        source_age = now_ros - timestamp
        timeout = self.model._authorization_timeout_sec
        if not 0 <= source_age < timeout:
            return math.inf
        if (self._authorization_source_suspect and self._authorization_source_resumed
                and source_age <= timeout * 0.1
                and self._authorization_frozen_ros_high_water is not None
                and timestamp > self._authorization_frozen_ros_high_water
                and (self._authorization_latest_stamp is None or timestamp > self._authorization_latest_stamp)):
            # Only a current publication beyond the frozen ROS high water
            # can establish a new chain. Queued higher IDs cannot re-anchor.
            self._authorization_source_offset = now - now_ros
            self._authorization_source_suspect = False
            self._authorization_frozen_ros_high_water = None
        age = max(source_age, now - (timestamp + self._authorization_source_offset))
        if age < timeout:
            self._authorization_latest_stamp = (timestamp if self._authorization_latest_stamp is None
                else max(timestamp, self._authorization_latest_stamp))
        return age

    def on_safety(self, message: SafetyStatus) -> None:
        if not verify_status(
            self._feedback_secret,
            message.signature,
            timestamp=message.timestamp,
            profile_id=message.profile_id,
            command_epoch=message.command_epoch,
            transmission_id=message.transmission_id,
            adapter_id=message.adapter_id,
            state=message.state,
            speed_limit=message.speed_limit,
            mission_allowed=message.mission_allowed,
            plan_id=message.plan_id,
        ):
            self.model._force_safe_stop()
            return
        self.model.update_safety({
            "profile_id": message.profile_id,
            "command_epoch": message.command_epoch,
            "transmission_id": message.transmission_id,
            "adapter_id": message.adapter_id,
            "state": message.state,
            "speed_limit": message.speed_limit,
            "mission_allowed": message.mission_allowed,
        }, source_age_sec=self._authorization_source_age(message.timestamp))

    def on_mitigation(self, message: MitigationCommand) -> None:
        if not verify_command(
            self._feedback_secret,
            message.signature,
            timestamp=message.timestamp,
            profile_id=message.profile_id,
            command_epoch=message.command_epoch,
            transmission_id=message.transmission_id,
            adapter_id=message.adapter_id,
            plan_id=message.plan_id,
            action=message.action,
            components=message.components,
            requires_safe_stop=message.requires_safe_stop,
        ):
            self.model._force_safe_stop()
            return
        self.model.update_mitigation({
            "profile_id": message.profile_id,
            "command_epoch": message.command_epoch,
            "transmission_id": message.transmission_id,
            "adapter_id": message.adapter_id,
            "plan_id": message.plan_id,
            "action": message.action,
            "components": list(message.components),
        }, source_age_sec=self._authorization_source_age(message.timestamp))

    def recovery_message(self, timestamp=None) -> RecoveryTelemetry:
        self._observation_sequence += 1
        message = RecoveryTelemetry()
        message.timestamp = self.get_clock().now().nanoseconds / 1e9 if timestamp is None else timestamp
        message.profile_id = self.model.command_profile_id
        message.adapter_id = self.model.command_adapter_id
        message.command_epoch = self.model.command_epoch
        message.transmission_id = self.model.command_transmission_id
        message.observation_sequence = self._observation_sequence
        message.actual_speed = float(self.model.actual_speed)
        # Adapter claim is independent of the observer's scan processing.
        message.free_distance = max(0.05, self._obstacle_x - self.model.x)
        message.sensor_fresh = True
        message.attack_active = self.model.attack_mode is not None
        message.commands_cleared = not self.model._pending_events and self.model.attack_mode is None
        message.probe_success = self.model.gripper_force >= 40.0 and not self.model._ordering_fault
        fields = {key: getattr(message, key) for key in RECOVERY_TELEMETRY_FIELDS}
        message.signature = sign_recovery_telemetry(self._feedback_secret, **fields) if self._feedback_secret else ""
        return message

    def tick(self) -> None:
        self._observe_authorization_source_clock()
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
            if self._event_secret:
                message.signature = EventVerifier.sign_event(self._event_secret, CoreAttackEvent(
                    message.event_id, message.source, message.component, message.attack_type,
                    message.sequence, message.timestamp, message.confidence))
            self.attack_pub.publish(message)
        ack = self.model.mitigation_ack(stamp.nanoseconds / 1e9)
        if ack is not None:
            message = MitigationAck()
            message.timestamp = ack["timestamp"]
            message.profile_id = ack["profile_id"]
            message.command_epoch = ack["command_epoch"]
            message.transmission_id = ack["transmission_id"]
            message.feedback_sequence = ack["feedback_sequence"]
            message.adapter_id = ack["adapter_id"]
            message.plan_id = ack["plan_id"]
            message.action = ack["action"]
            message.components = ack["components"]
            message.accepted = ack["accepted"]
            message.active = ack["active"]
            message.safe_stop_confirmed = ack["safe_stop_confirmed"]
            message.reason = ack["reason"]
            message.signature = sign_ack(
                self._feedback_secret or b"",
                profile_id=message.profile_id,
                command_epoch=message.command_epoch,
                transmission_id=message.transmission_id,
                feedback_sequence=message.feedback_sequence,
                adapter_id=message.adapter_id,
                plan_id=message.plan_id,
                action=message.action,
                components=message.components,
                accepted=message.accepted,
                active=message.active,
                safe_stop_confirmed=message.safe_stop_confirmed,
            ) if self._feedback_secret else ""
            self.ack_pub.publish(message)
        self.recovery_pub.publish(self.recovery_message(stamp.nanoseconds / 1e9))
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
        scan = LaserScan()
        scan.header.stamp = stamp.to_msg()
        scan.header.frame_id = "base_scan"
        scan.angle_min, scan.angle_max, scan.angle_increment = -0.3, 0.3, 0.3
        scan.range_min, scan.range_max = 0.05, 20.0
        distance = max(0.05, self._obstacle_x - self.model.x)
        scan.ranges = [distance, distance, distance]
        if self._sensor_mode == "stale":
            odom.header.stamp.sec -= 2
            scan.header.stamp.sec -= 2
        elif self._sensor_mode == "invalid_scan":
            scan.ranges = [math.nan] * 3
        elif self._sensor_mode == "speed_mismatch":
            odom.twist.twist.linear.x += 0.4
        elif self._sensor_mode == "near_obstacle":
            scan.ranges = [0.08] * 3
        if self._sensor_mode == "replay" and self._last_sensor_messages:
            odom, scan = self._last_sensor_messages
        elif self._sensor_mode == "normal":
            self._last_sensor_messages = (odom, scan)
        if self._sensor_mode != "paused":
            self.odom_pub.publish(odom)
            self.scan_pub.publish(scan)
        self.gripper_pub.publish(String(data=self.model.gripper_payload()))
        self.telemetry_pub.publish(String(data=json.dumps(self.model.snapshot(), ensure_ascii=False)))


def main(args: Iterable[str] | None = None) -> None:
    rclpy.init(args=args)
    node = AmrSimulatorNode()
    try:
        rclpy.spin(node)
    except (KeyboardInterrupt, ExternalShutdownException):
        pass
    except RuntimeError:
        if rclpy.ok():
            raise
    finally:
        if rclpy.ok():
            node.destroy_node()
            rclpy.try_shutdown()


__all__ = ["AmrSimulationModel", "AmrSimulatorNode", "SimulationCommandError", "main"]
