from __future__ import annotations

import os
import hashlib
import json
import math
import time
from collections import deque
from typing import Iterable

import rclpy
from rclpy.clock import Clock, ClockType
from rclpy.executors import ExternalShutdownException
from rcl_interfaces.msg import ParameterDescriptor
from rclpy.node import Node

from guardian_interfaces.msg import (
    AttackEvent as AttackEventMsg,
    MitigationAck,
    MitigationCommand,
    RiskState,
    SafetyStatus,
    RecoveryTelemetry as RecoveryTelemetryMsg,
    IndependentObservation,
)

from .audit import AuditLogger
from .config import (
    DEFAULT_CONTAINMENT_POLICY_JSON,
    DEFAULT_SECURITY_PROFILE_JSON,
    parse_containment_policies,
)
from .models import (
    ActionType,
    AttackEvent,
    ContainmentPolicy,
    GuardianConfig,
    MitigationPlan,
    SafetyDecision,
    SafetyState,
)
from .planner import MitigationPlanner
from .registry import AttackRegistry
from .risk_engine import RiskEngine
from .security_profile import parse_security_profile
from .supervisor import SafetySupervisor
from .verifier import EventVerifier
from .feedback_auth import sign_command, sign_status, verify_ack
from .feedback_auth import RECOVERY_TELEMETRY_FIELDS, verify_recovery_telemetry
from .bound_recovery import EvidenceBoundRecovery, RecoveryTelemetry
from .predictive_envelope import PredictiveConfig
from .recovery_protocol import RecoveryConfig
from .recovery_graph import recovery_graph_fingerprint
from .independent_observation import IndependentSample, ObserverSessionTracker, fuse_observations
from .feedback_auth import INDEPENDENT_OBSERVATION_FIELDS, verify_independent_observation


class GuardianNode(Node):
    def __init__(self) -> None:
        super().__init__("guardian_node")
        startup_parameters = {
            "task": "navigate_to_goal",
            "goal": "box2",
            "max_event_age_sec": 5.0,
            "mitigation_delay_sec": 1.0,
            "feedback_timeout_sec": 0.5,
            "startup_feedback_grace_sec": 0.0,
            "max_active_events": 1024,
            "max_planner_candidates": 128,
            "default_speed_limit": 0.35,
            "safe_stop_speed": 0.0,
            "containment_policy_json": DEFAULT_CONTAINMENT_POLICY_JSON,
            "security_profile_json": DEFAULT_SECURITY_PROFILE_JSON,
            "require_signature": False,
            "require_feedback_signature": True,
            "audit_path": "",
            "evidence_bound_recovery": False,
            "recovery_dwell_sec": 1.0,
            "recovery_stable_window_sec": 0.5,
            "recovery_telemetry_max_age_sec": 0.5,
            "independent_observation_required": False,
        }
        for name, value in startup_parameters.items():
            self.declare_parameter(name, value, ParameterDescriptor(read_only=True))
        self.declare_parameter("task_phase", "default")

        self._configuration_error: str | None = None
        policy_payload = str(self.get_parameter("containment_policy_json").value)
        profile_payload = str(self.get_parameter("security_profile_json").value)
        try:
            containment_policies, default_containment_policy = parse_containment_policies(policy_payload)
        except ValueError as error:
            self._configuration_error = "invalid containment policy; correct configuration and restart"
            self.get_logger().error(f"invalid containment_policy_json; forcing safe stop: {error}")
            containment_policies = {}
            default_containment_policy = ContainmentPolicy(ActionType.SAFE_STOP, 0.0, False)
        try:
            profile = parse_security_profile(profile_payload)
        except ValueError as error:
            self._configuration_error = "invalid security profile; correct configuration and restart"
            self.get_logger().error(f"invalid security_profile_json; forcing safe stop: {error}")
            profile = parse_security_profile(DEFAULT_SECURITY_PROFILE_JSON)

        config = GuardianConfig(
            task=str(self.get_parameter("task").value),
            goal=str(self.get_parameter("goal").value),
            tau=profile.tau,
            epsilon=profile.epsilon,
            theta_crit=0.8,
            theta_base=0.72,
            alpha_crit=0.15,
            alpha_base=0.2,
            max_event_age_sec=float(self.get_parameter("max_event_age_sec").value),
            mitigation_delay_sec=float(self.get_parameter("mitigation_delay_sec").value),
            feedback_timeout_sec=float(self.get_parameter("feedback_timeout_sec").value),
            max_planner_candidates=int(self.get_parameter("max_planner_candidates").value),
            default_speed_limit=float(self.get_parameter("default_speed_limit").value),
            safe_stop_speed=float(self.get_parameter("safe_stop_speed").value),
            task_phase=str(self.get_parameter("task_phase").value),
            profile_id=profile.profile_id,
            actuator_adapter_id=profile.adapter_id,
            containment_policies=containment_policies,
            default_containment_policy=default_containment_policy,
            trusted_sources=profile.trusted_sources,
            mitigatable_devices=profile.mitigatable_devices,
        )
        signature_secret = os.getenv("GUARDIAN_EVENT_SECRET", "").encode("utf-8") or None
        self._feedback_secret = os.getenv("GUARDIAN_FEEDBACK_SECRET", "").encode("utf-8") or None
        bound_enabled = bool(self.get_parameter("evidence_bound_recovery").value)
        if bound_enabled:
            signature_secret = signature_secret or self._feedback_secret
        self._require_feedback_signature = bool(self.get_parameter("require_feedback_signature").value)
        if self._require_feedback_signature and not self._feedback_secret:
            self._configuration_error = (
                self._configuration_error
                or "feedback authentication is not configured; set GUARDIAN_FEEDBACK_SECRET and restart"
            )
        self.verifier = EventVerifier(
            set(config.trusted_sources), config.max_event_age_sec,
            signature_secret=signature_secret,
            require_signature=bool(self.get_parameter("require_signature").value) or (bound_enabled and bool(signature_secret)),
        )
        self._registry_capacity_error: str | None = None
        self.registry = AttackRegistry(
            config.max_event_age_sec,
            max_records=int(self.get_parameter("max_active_events").value),
        )
        self.risk_engine = RiskEngine(config)
        self.planner = MitigationPlanner(config, self.risk_engine)
        self.supervisor = SafetySupervisor(config.default_speed_limit, config.safe_stop_speed)
        self.config = config
        audit_path = str(self.get_parameter("audit_path").value)
        self.audit = AuditLogger(audit_path or None)
        self._feedback_timeout_sec = config.feedback_timeout_sec
        self._startup_feedback_grace_sec = float(
            self.get_parameter("startup_feedback_grace_sec").value
        )
        if self._startup_feedback_grace_sec < 0.0:
            self._configuration_error = (
                self._configuration_error
                or "startup_feedback_grace_sec must be non-negative"
            )
        self._command_epoch = 0
        self._transmission_id = 0
        self._adapter_id = config.actuator_adapter_id
        self._last_command_fingerprint: tuple[str, str, tuple[str, ...], bool] | None = None
        self._expected_feedback: tuple[int, int, str, str, str, tuple[str, ...], bool] | None = None
        self._command_sent_at: float | None = None
        self._command_sent_at_monotonic: float | None = None
        self._feedback_ready = False
        self._last_feedback_at: float | None = None
        self._last_feedback_monotonic: float | None = None
        self._last_feedback_sequence = 0
        self._last_feedback_transmission_id = 0
        self._last_watchdog_monotonic: float | None = None
        self._watchdog_latched = False
        self._bound_recovery_enabled = bool(self.get_parameter("evidence_bound_recovery").value)
        self._independent_required = bool(self.get_parameter("independent_observation_required").value)
        self._observation_secret = os.getenv("GUARDIAN_OBSERVATION_SECRET", "").encode() or None
        self._independent_sample = None
        self._independent_sequence = 0
        self._observer_sessions = ObserverSessionTracker()
        self._independent_source_time = None
        self._adapter_samples = deque(maxlen=8)
        self._independent_samples = deque(maxlen=8)
        self._effective_source_time = None
        if self._independent_required and (not self._bound_recovery_enabled
                or not self._observation_secret or self._observation_secret == self._feedback_secret):
            self._configuration_error = "independent observation requires bound recovery and a separate observation signing key"
        self._recovery_telemetry = None
        self._recovery_last_clock = None
        self._recovery_clock_fault = False
        self._recovery_ros_to_monotonic_offset = None
        self._recovery_clock_suspect = False
        self._recovery_clock_resumed = False
        self._recovery_frozen_ros_high_water = None
        self._observation_sequence = 0
        self._stop_ack_epoch = None
        self._last_incident_at = None
        self._last_incident_ros_at = None
        self._recovery_observed_ros_time = None
        self._recovery_plan_id = ""
        self._last_recovery_phase = None
        self.recovery = EvidenceBoundRecovery()
        if self._bound_recovery_enabled:
            try:
                self.recovery = EvidenceBoundRecovery(
                    RecoveryConfig(
                        dwell_sec=float(self.get_parameter("recovery_dwell_sec").value),
                        stable_window_sec=float(self.get_parameter("recovery_stable_window_sec").value),
                    ),
                    max_age_sec=float(self.get_parameter("recovery_telemetry_max_age_sec").value),
                    predictive_config=PredictiveConfig(default_speed_limit=config.default_speed_limit),
                )
            except ValueError:
                self._configuration_error = "invalid evidence-bound recovery configuration"
            if (not self._feedback_secret or not self._require_feedback_signature
                    or config.profile_id != "amr-default" or self._adapter_id != "default-actuator"):
                self._configuration_error = "bound recovery requires authenticated AMR profile"
        policy_material = [profile_payload, policy_payload, self.recovery.config.__dict__,
            self.recovery.envelope.config.__dict__, self.recovery.max_age_sec,
            config.task, config.goal, config.max_event_age_sec, config.feedback_timeout_sec,
            self._independent_required, 0.03, 0.15]
        self._recovery_policy_fingerprint = hashlib.sha256(
            json.dumps(policy_material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self._steady_clock = Clock(clock_type=ClockType.STEADY_TIME)

        self.create_subscription(AttackEventMsg, "guardian/attack_events", self.on_attack_event, 20)
        self.create_subscription(MitigationAck, "guardian/mitigation_ack", self.on_mitigation_ack, 20)
        self.create_subscription(RecoveryTelemetryMsg, "guardian/recovery_telemetry", self.on_recovery_telemetry, 20)
        if self._independent_required:
            self.create_subscription(IndependentObservation, "guardian/independent_observation", self.on_independent_observation, 20)
        self.risk_pub = self.create_publisher(RiskState, "guardian/risk_state", 20)
        self.command_pub = self.create_publisher(MitigationCommand, "guardian/mitigation_command", 20)
        self.status_pub = self.create_publisher(SafetyStatus, "guardian/safety_status", 20)
        self.create_timer(0.1, self.tick, clock=self._steady_clock)

    def now_seconds(self) -> float:
        return self.get_clock().now().nanoseconds / 1e9

    def monotonic_seconds(self) -> float:
        return time.monotonic()

    def on_attack_event(self, message: AttackEvent) -> None:
        now = self.now_seconds()
        event = AttackEvent(
            event_id=message.event_id,
            source=message.source,
            component=message.component,
            attack_type=message.attack_type,
            sequence=int(message.sequence),
            timestamp=float(message.timestamp),
            confidence=float(message.confidence),
            signature=message.signature,
        )
        result = self.verifier.verify(event, now)
        self.audit.emit("event_verification", {"event_id": event.event_id, "code": result.code.value, "accepted": result.accepted, "reason": result.reason})
        if result.accepted:
            try:
                self.registry.upsert(event, now)
                if self._bound_recovery_enabled:
                    incident_now = self.monotonic_seconds()
                    self._last_incident_at = incident_now
                    self._last_incident_ros_at = now
                    self.recovery.record_incident(event, now=incident_now,
                        policy=self._recovery_policy_fingerprint)
            except RuntimeError as error:
                self._registry_capacity_error = str(error)
                self.audit.emit(
                    "event_registry",
                    {"accepted": False, "reason": str(error)},
                )

    def on_mitigation_ack(self, message: MitigationAck) -> None:
        if self._require_feedback_signature and not verify_ack(
            self._feedback_secret,
            message.signature,
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
        ):
            self.audit.emit("mitigation_feedback", {"accepted": False, "reason": "invalid feedback signature"})
            return
        expected = self._expected_feedback
        if expected is None:
            self.audit.emit("mitigation_feedback", {"accepted": False, "reason": "no command awaiting feedback"})
            return
        expected_epoch, expected_transmission, expected_adapter, expected_plan, expected_action, expected_components, expected_stop = expected
        if (
            message.command_epoch != expected_epoch
            or message.transmission_id <= 0
            or message.transmission_id > expected_transmission
            or message.transmission_id < self._last_feedback_transmission_id
            or message.profile_id != self.config.profile_id
            or message.adapter_id != expected_adapter
        ):
            self.audit.emit("mitigation_feedback", {
                "accepted": False,
                "reason": "unexpected command identity",
                "command_epoch": int(message.command_epoch),
                "transmission_id": int(message.transmission_id),
                "adapter_id": str(message.adapter_id),
            })
            return
        reference = self._last_feedback_monotonic or self._command_sent_at_monotonic
        now_monotonic = self.monotonic_seconds()
        feedback_deadline = self._feedback_timeout_sec
        if self._last_feedback_monotonic is None:
            feedback_deadline = max(feedback_deadline, self._startup_feedback_grace_sec)
        if (
            reference is not None
            and now_monotonic - reference >= feedback_deadline
        ):
            self._watchdog_latched = True
            self.audit.emit("mitigation_feedback", {
                "accepted": False,
                "reason": "feedback arrived after watchdog deadline",
            })
            return
        actual = (
            str(message.plan_id),
            str(message.action),
            tuple(sorted(str(item) for item in message.components)),
            bool(message.action == "SAFE_STOP"),
        )
        if (
            not bool(message.accepted)
            or not bool(message.active)
            or int(message.feedback_sequence) <= self._last_feedback_sequence
            or actual[:3] != (expected_plan, expected_action, expected_components)
            or (expected_stop and not bool(message.safe_stop_confirmed))
        ):
            self.audit.emit("mitigation_feedback", {"accepted": False, "reason": "feedback does not match command"})
            return
        self._feedback_ready = True
        self._last_feedback_at = self.now_seconds()
        self._last_feedback_monotonic = self.monotonic_seconds()
        self._last_feedback_sequence = int(message.feedback_sequence)
        self._last_feedback_transmission_id = int(message.transmission_id)
        self._stop_ack_epoch = expected_epoch if expected_stop and message.safe_stop_confirmed else None
        self.audit.emit("mitigation_feedback", {
            "accepted": True,
            "command_epoch": expected_epoch,
            "transmission_id": expected_transmission,
            "feedback_sequence": self._last_feedback_sequence,
        })

    def on_recovery_telemetry(self, message: RecoveryTelemetryMsg) -> None:
        if not self._bound_recovery_enabled:
            return
        fields = {key: getattr(message, key) for key in RECOVERY_TELEMETRY_FIELDS}
        now = self.monotonic_seconds()
        now_ros = self.now_seconds()
        valid = verify_recovery_telemetry(self._feedback_secret, message.signature, **fields)
        valid = valid and (
            self._recovery_clock_valid(now, now_ros)
            and message.profile_id == self.config.profile_id
            and message.adapter_id == self._adapter_id
            and message.command_epoch == self._command_epoch
            and max(1, self._transmission_id - 2) <= message.transmission_id <= self._transmission_id
            and message.observation_sequence > self._observation_sequence
            and all(math.isfinite(x) for x in (message.timestamp, message.actual_speed, message.free_distance))
            and 0 <= now_ros - message.timestamp <= self.recovery.max_age_sec
            and (self._recovery_observed_ros_time is None or message.timestamp > self._recovery_observed_ros_time)
        )
        if not valid:
            self.audit.emit("recovery_observation", {"accepted": False, "reason": "signature, identity, sequence or freshness mismatch"})
            return
        self._observation_sequence = message.observation_sequence
        self._recovery_observed_ros_time = message.timestamp
        if (self._recovery_clock_suspect and self._recovery_clock_resumed
                and self._recovery_frozen_ros_high_water is not None
                and message.timestamp > self._recovery_frozen_ros_high_water
                and now_ros - message.timestamp <= self.recovery.max_age_sec * 0.1):
            # A resumed clock and a current acquisition can start a new chain;
            # delayed samples from the paused chain retain its old deadline.
            self._recovery_ros_to_monotonic_offset = now - now_ros
            self._recovery_clock_suspect = False
            self._recovery_frozen_ros_high_water = None
        self._recovery_telemetry = RecoveryTelemetry(
            # Carry the remaining acquisition lifetime into the receiver's
            # monotonic domain. Arrival never grants a new full source TTL.
            message.timestamp + self._recovery_ros_to_monotonic_offset,
            message.actual_speed, message.free_distance, message.sensor_fresh,
            message.attack_active, message.commands_cleared, message.probe_success,
        )
        self._adapter_samples.append((message.timestamp, self._recovery_telemetry))

    def _independent_endpoint_gid(self) -> str:
        endpoints = self.get_publishers_info_by_topic(self.resolve_topic_name("guardian/independent_observation"))
        if (len(endpoints) != 1 or endpoints[0].node_name != "recovery_observer"
                or endpoints[0].topic_type != "guardian_interfaces/msg/IndependentObservation"):
            return ""
        return bytes(endpoints[0].endpoint_gid).hex()

    def on_independent_observation(self, message: IndependentObservation) -> None:
        if not self._independent_required:
            return
        fields = {key: getattr(message, key) for key in INDEPENDENT_OBSERVATION_FIELDS}
        if not verify_independent_observation(self._observation_secret, message.signature, **fields):
            self.audit.emit("independent_observation", {"accepted": False, "reason": "signature mismatch"})
            return
        if (message.observer_id != "recovery-observer" or message.profile_id != self.config.profile_id
                or message.command_epoch != self._command_epoch
                or not max(1, self._transmission_id - 2) <= message.transmission_id <= self._transmission_id):
            self.audit.emit("independent_observation", {"accepted": False, "reason": "identity, epoch or sequence mismatch"})
            return
        try:
            gid = self._independent_endpoint_gid()
        except (RuntimeError, ValueError, TypeError, AttributeError):
            gid = ""
        previous_session = self._observer_sessions.session
        if not self._observer_sessions.accept(message.observer_session, gid, message.observation_sequence):
            if self._observer_sessions.fault:
                self._configuration_error = "independent observation session capacity exhausted; restart after review"
                self._independent_sample = None
            self.audit.emit("independent_observation", {"accepted": False, "reason": "session, endpoint or sequence mismatch"})
            return
        if previous_session != self._observer_sessions.session:
            self._independent_samples.clear()
        self._independent_sequence = message.observation_sequence
        # A current authenticated invalid report immediately withdraws cached
        # evidence. Replays and unauthenticated messages cannot renew evidence.
        self._independent_sample = None
        self._independent_source_time = None
        now_ros = self.now_seconds()
        finite = all(math.isfinite(x) for x in (message.timestamp, message.odom_timestamp,
            message.scan_timestamp, message.actual_speed, message.free_distance))
        valid = (finite and message.valid and message.actual_speed >= 0 and message.free_distance >= 0
            and all(0 <= now_ros - stamp <= self.recovery.max_age_sec for stamp in
                (message.timestamp, message.odom_timestamp, message.scan_timestamp))
            and max(message.odom_timestamp, message.scan_timestamp) <= message.timestamp
            and abs(message.odom_timestamp - message.scan_timestamp) <= 0.15)
        if valid:
            self._independent_source_time = min(message.odom_timestamp, message.scan_timestamp)
            self._independent_sample = IndependentSample(self.monotonic_seconds(), message.actual_speed,
                message.free_distance, message.odom_timestamp, message.scan_timestamp)
            self._independent_samples.append(self._independent_sample)
        else:
            self._independent_samples.clear()
        self.audit.emit("independent_observation", {"accepted": bool(valid),
            "sequence": message.observation_sequence, "epoch": message.command_epoch})

    def _recovery_clock_valid(self, now: float, now_ros: float) -> bool:
        if (self._recovery_clock_fault or not all(math.isfinite(value) for value in (now, now_ros))
                or (self._recovery_last_clock is not None and any(
                    value < previous for value, previous in zip((now, now_ros), self._recovery_last_clock)))):
            self._recovery_clock_fault = True
            self._recovery_telemetry = None
            self._adapter_samples.clear()
            return False
        offset = now - now_ros
        if self._recovery_last_clock is not None:
            elapsed = now - self._recovery_last_clock[0]
            ros_elapsed = now_ros - self._recovery_last_clock[1]
            if elapsed > 0 and ros_elapsed < elapsed * 0.5:
                self._recovery_clock_suspect = True
                self._recovery_clock_resumed = False
                # Keep this watermark through normal clock resumption; old
                # acquisitions near the current time still belong to the
                # paused chain until their stamp strictly crosses it.
                self._recovery_frozen_ros_high_water = (now_ros
                    if self._recovery_frozen_ros_high_water is None
                    else max(now_ros, self._recovery_frozen_ros_high_water))
            elif elapsed > 0 and ros_elapsed > 0:
                self._recovery_clock_resumed = True
        self._recovery_last_clock = (now, now_ros)
        # Freeze only a clock chain that has stalled substantially. Healthy
        # clocks use each reception's source age; small drift cannot accumulate
        # over the process lifetime and permanently age every new acquisition.
        if self._recovery_ros_to_monotonic_offset is None or not self._recovery_clock_suspect:
            self._recovery_ros_to_monotonic_offset = offset
        return True

    def _effective_recovery_telemetry(self, now: float):
        now_ros = self.now_seconds()
        if (not self._recovery_clock_valid(now, now_ros)
                or self._recovery_telemetry is None
                or not self._recovery_telemetry.healthy(now, self.recovery.max_age_sec)
                or self._recovery_observed_ros_time is None
                or not 0 <= now_ros - self._recovery_observed_ros_time <= self.recovery.max_age_sec):
            return None
        if not self._independent_required:
            return self._recovery_telemetry
        sample = self._independent_sample
        if (sample is None or not all(0 <= now_ros - stamp <= self.recovery.max_age_sec
                for stamp in (sample.odom_at, sample.scan_at))):
            return None
        # The adapter must label its feedback with the corresponding odometry
        # acquisition stamp. Do not compare different ticks just because they
        # arrived consecutively in the two ROS processes.
        for independent in reversed(self._independent_samples):
            for stamp, adapter in reversed(self._adapter_samples):
                if abs(stamp - independent.odom_at) > 1e-6:
                    continue
                if not all(0 <= now_ros - source <= self.recovery.max_age_sec
                        for source in (stamp, independent.odom_at, independent.scan_at)):
                    continue
                self._effective_source_time = min(stamp, independent.odom_at, independent.scan_at)
                # Never fall back to an older good pair if this newer aligned
                # pair contradicts the adapter or has expired at the receiver.
                return fuse_observations(adapter, independent, now=now, max_age=self.recovery.max_age_sec)
        self._effective_source_time = None
        return None

    def _recovery_graph_fingerprint(self) -> str:
        return recovery_graph_fingerprint(self, independent=self._independent_required)

    def _matching_stop_ack(self, now: float) -> bool:
        return (self._stop_ack_epoch == self._command_epoch
            and self._last_feedback_monotonic is not None
            and 0 <= now - self._last_feedback_monotonic < self._feedback_timeout_sec)

    def _feedback_timed_out(self, now_monotonic: float) -> bool:
        if self._watchdog_latched:
            return True
        if (
            self._last_watchdog_monotonic is not None
            and now_monotonic < self._last_watchdog_monotonic
        ):
            return True
        self._last_watchdog_monotonic = now_monotonic
        reference = self._last_feedback_monotonic or self._command_sent_at_monotonic
        if reference is None:
            return False
        timeout = self._feedback_timeout_sec
        if self._last_feedback_monotonic is None:
            timeout = max(timeout, self._startup_feedback_grace_sec)
        return now_monotonic - reference >= timeout

    def tick(self) -> None:
        # Offline trace collection is opt-in through the existing bounded audit.
        recovery_trace = None
        now = self.now_seconds()
        now_monotonic = self.monotonic_seconds()
        if self._bound_recovery_enabled:
            telemetry = self._effective_recovery_telemetry(now_monotonic)
            if (telemetry is not None and telemetry.healthy(now_monotonic, self.recovery.max_age_sec)
                    and telemetry.speed <= 1e-6 and self._matching_stop_ack(now_monotonic)
                    and (self._last_incident_at is None or telemetry.received_at > self._last_incident_at)
                    and (self._last_incident_ros_at is None or (
                        self._recovery_observed_ros_time is not None
                        and self._recovery_observed_ros_time > self._last_incident_ros_at))
                    and (not self._independent_required or self._last_incident_ros_at is None
                        or (self._effective_source_time is not None
                            and self._effective_source_time > self._last_incident_ros_at))):
                # Only this AMR adapter can resolve its own simulator incidents.
                # Absence of new IDS messages or event TTL cannot clear an attack.
                has_sim_incident = any(record.event.source == "amr_simulator"
                    for record in self.registry.active_records())
                resolved = []
                if has_sim_incident and self.recovery.resolve_source("amr_simulator",
                        now=now_monotonic, policy=self._recovery_policy_fingerprint):
                    resolved = self.registry.clear_source("amr_simulator")
                if resolved:
                    self.audit.emit("incident_resolution", {"source": "amr_simulator", "event_ids": resolved})
        else:
            self.registry.expire(now)
        records = self.registry.active_records()
        assessment = self.risk_engine.evaluate(records, now)
        phase = str(self.get_parameter("task_phase").value) or "default"
        if self._configuration_error or self._registry_capacity_error:
            plan = MitigationPlan(
                "configuration-error", ActionType.SAFE_STOP, frozenset(), now, now,
                self._configuration_error or self._registry_capacity_error or "event registry capacity exceeded",
                assessment.psi, True, False, 0.0,
            )
        elif self.planner.should_replan(records, phase) or self.planner.current_plan is None:
            plan = self.planner.plan(
                records,
                assessment,
                now,
                phase=phase,
            )
            self.audit.emit("mitigation_plan", {"plan_id": plan.plan_id, "action": plan.action.value, "components": sorted(plan.components), "reason": plan.reason})
        else:
            plan = self.planner.current_plan
        decision = self.supervisor.decide(assessment, plan)
        if self._feedback_timed_out(now_monotonic):
            self._watchdog_latched = True
            decision = SafetyDecision(
                now,
                SafetyState.SAFE_STOP,
                False,
                0.0,
                "actuator feedback timeout; watchdog latched SAFE_STOP",
                plan.plan_id,
            )
        if self._bound_recovery_enabled:
            phase_material = f"{self._recovery_policy_fingerprint}:{phase}"
            policy_fingerprint = hashlib.sha256(phase_material.encode()).hexdigest()
            effective = self._effective_recovery_telemetry(now_monotonic)
            graph_fingerprint = self._recovery_graph_fingerprint()
            stopped_ack = self._matching_stop_ack(now_monotonic)
            input_epoch = self._command_epoch
            forced_stop = not decision.mission_allowed
            bound = self.recovery.update(
                now=now_monotonic, telemetry=effective,
                graph_fingerprint=graph_fingerprint,
                policy_fingerprint=policy_fingerprint, command_epoch=self._command_epoch,
                stopped_ack=stopped_ack,
                unresolved=bool(records), forced_stop=forced_stop,
            )
            if bound.mission_allowed:
                self._recovery_plan_id = f"recovery-{bound.proof_id}"
                plan = MitigationPlan(self._recovery_plan_id, ActionType.NONE, frozenset(),
                    now, now, bound.reason, assessment.psi, False, True, bound.speed_limit)
                decision = SafetyDecision(now, SafetyState(bound.phase), True,
                    min(decision.speed_limit, bound.speed_limit), bound.reason, plan.plan_id)
            else:
                self._recovery_plan_id = ""
                plan = MitigationPlan("bound-stop", ActionType.SAFE_STOP, frozenset(),
                    now, now, bound.reason, assessment.psi, True, False, 0.0)
                state = SafetyState.SAFE_STOP if bound.phase == "SAFE_STOP" else SafetyState.RECOVERING
                decision = SafetyDecision(now, state, False, 0.0, bound.reason, plan.plan_id)
            if self._last_recovery_phase != bound.phase:
                self.audit.emit("bound_recovery", {
                    "phase": bound.phase, "mission_allowed": bound.mission_allowed,
                    "proof_id": bound.proof_id, "reason": bound.reason,
                    "graph_fingerprint": self.recovery._evidence_context[0] if self.recovery._evidence_context else "",
                    "ledger_anchor": self.recovery.ledger.anchor().__dict__,
                    "next_command_epoch": self._command_epoch + (1 if bound.phase == "RESUMABLE" else 0),
                })
                self._last_recovery_phase = bound.phase
            if self.audit.path is not None:
                from .recovery_feedback import RecoveryFrame, evidence_state, proof_summary
                from .predictive_envelope import MotionSample
                state = evidence_state(effective, now_monotonic, self.recovery.max_age_sec)
                if state == "healthy" and not self.recovery.envelope.evaluate(MotionSample(
                        effective.speed, effective.free_distance, 0.0,
                        sensor_fresh=effective.sensor_fresh)).mission_allowed:
                    state = "unsafe_distance"
                anchor = self.recovery.ledger.anchor()
                recovery_trace = RecoveryFrame(now_monotonic, phase, bound.phase, state,
                    stopped_ack, bool(records), forced_stop, graph_fingerprint, policy_fingerprint,
                    f"{anchor.count}:{anchor.head}", input_epoch, input_epoch,
                    decision.mission_allowed, decision.speed_limit,
                    effective.speed if effective is not None else 0.0,
                    proof_summary(self.recovery.pending_proof), bound.proof_id).to_dict()
        self.publish(assessment, plan, decision)
        if recovery_trace is not None:
            recovery_trace["next_command_epoch"] = self._command_epoch
            self.audit.emit("recovery_trace", recovery_trace)

    def publish(self, assessment, plan, decision) -> None:
        risk = RiskState()
        risk.timestamp = assessment.timestamp
        risk.profile_id = self.config.profile_id
        risk.state = decision.state.value
        risk.risk = float(assessment.risk)
        risk.psi = float(assessment.psi)
        risk.delta = bool(assessment.delta)
        risk.gamma = bool(assessment.gamma)
        risk.active_components = sorted(assessment.active_components)
        risk.critical_components = sorted(assessment.critical_components)
        risk.reason = assessment.reason
        self.risk_pub.publish(risk)

        command = MitigationCommand()
        command.timestamp = assessment.timestamp
        command.profile_id = self.config.profile_id
        command.plan_id = plan.plan_id
        # Never transmit a pending actuation as though it were already active.
        hold_stop = decision.state == SafetyState.SAFE_STOP or (
            plan.action != ActionType.NONE and assessment.timestamp < plan.activate_at
        )
        effective_action = ActionType.SAFE_STOP.value if hold_stop else plan.action.value
        effective_components = tuple() if hold_stop else tuple(sorted(plan.components))
        effective_requires_safe_stop = hold_stop or plan.requires_safe_stop
        fingerprint = (plan.plan_id, effective_action, effective_components, effective_requires_safe_stop)
        if fingerprint != self._last_command_fingerprint:
            self._command_epoch += 1
            self._last_command_fingerprint = fingerprint
            # A cached observation belongs to the epoch it acknowledged.
            # New epochs require new authenticated observations, even if the
            # previous sample has not reached its age limit.
            self._recovery_telemetry = None
            self._recovery_observed_ros_time = None
            self._independent_sample = None
            self._independent_source_time = None
            self._effective_source_time = None
            self._adapter_samples.clear()
            self._independent_samples.clear()
        self._transmission_id += 1
        self._expected_feedback = (
            self._command_epoch,
            self._transmission_id,
            self._adapter_id,
            plan.plan_id,
            effective_action,
            effective_components,
            effective_requires_safe_stop,
        )
        self._command_sent_at = assessment.timestamp
        if self._command_sent_at_monotonic is None or self._feedback_ready:
            self._command_sent_at_monotonic = self.monotonic_seconds()
        self._feedback_ready = False
        command.command_epoch = self._command_epoch
        command.transmission_id = self._transmission_id
        command.adapter_id = self._adapter_id
        command.action = effective_action
        command.components = list(effective_components)
        command.requires_safe_stop = effective_requires_safe_stop
        command.reason = decision.reason if hold_stop else plan.reason
        command.signature = sign_command(
            self._feedback_secret or b"",
            timestamp=command.timestamp,
            profile_id=command.profile_id,
            command_epoch=command.command_epoch,
            transmission_id=command.transmission_id,
            adapter_id=command.adapter_id,
            plan_id=command.plan_id,
            action=command.action,
            components=command.components,
            requires_safe_stop=command.requires_safe_stop,
        ) if self._feedback_secret else ""
        self.command_pub.publish(command)

        status = SafetyStatus()
        status.timestamp = decision.timestamp
        status.profile_id = self.config.profile_id
        status.command_epoch = self._command_epoch
        status.transmission_id = self._transmission_id
        status.adapter_id = self._adapter_id
        status.state = decision.state.value
        status.speed_limit = float(decision.speed_limit)
        status.mission_allowed = decision.mission_allowed
        status.reason = decision.reason
        status.plan_id = decision.plan_id or ""
        status.signature = sign_status(
            self._feedback_secret or b"",
            timestamp=status.timestamp,
            profile_id=status.profile_id,
            command_epoch=status.command_epoch,
            transmission_id=status.transmission_id,
            adapter_id=status.adapter_id,
            state=status.state,
            speed_limit=status.speed_limit,
            mission_allowed=status.mission_allowed,
            plan_id=status.plan_id,
        ) if self._feedback_secret else ""
        self.status_pub.publish(status)


def main(args: Iterable[str] | None = None) -> None:
    rclpy.init(args=args)
    node = GuardianNode()
    try:
        rclpy.spin(node)
    except (KeyboardInterrupt, ExternalShutdownException):
        pass
    except RuntimeError:
        # SIGINT may invalidate a taken ROS message during conversion.
        # A RuntimeError with a live context remains a real failure.
        if rclpy.ok():
            raise
    finally:
        if rclpy.ok():
            node.destroy_node()
            rclpy.try_shutdown()

