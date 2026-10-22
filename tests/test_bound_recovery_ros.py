"""Real DDS/ROS 2 software closed-loop acceptance tests (isolated localhost)."""
import time

from guardian_interfaces.msg import RecoveryTelemetry, SafetyStatus
from guardian_core.feedback_auth import RECOVERY_TELEMETRY_FIELDS, sign_recovery_telemetry
from guardian_core.models import AttackEvent as CoreAttackEvent
from guardian_core.verifier import EventVerifier
from rclpy.parameter import Parameter
from test_guardian_runtime import runtime  # pytest fixture reuses existing ROS executor


def start_loop(runtime, **parameters):
    return runtime(real_time=True, evidence_bound_recovery=True,
        recovery_dwell_sec=0.2, recovery_stable_window_sec=0.1,
        startup_feedback_grace_sec=3.0, max_event_age_sec=0.3, **parameters)


def test_amr_attack_stop_persistent_alert_then_evidence_bound_recovery(runtime):
    rt = start_loop(runtime)
    rt.simulator.model.handle_command({"action": "start"})
    rt.wait_for(lambda: rt.simulator.model.actual_speed > 0)
    assert rt.guardian.recovery.last_proof_id
    rt.simulator.model.handle_command({"action": "attack", "type": "speed_abuse"})
    rt.wait_for(lambda: bool(rt.guardian.registry.active_records())
        and not rt.statuses[-1].mission_allowed and rt.simulator.model.actual_speed == 0)
    first_stop = time.monotonic()
    rt.wait_for(lambda: time.monotonic() - first_stop > 0.6)
    assert not rt.statuses[-1].mission_allowed
    assert rt.simulator.model.actual_speed == 0
    assert rt.guardian.registry.active_records()  # TTL is not proof of resolution
    previous_proof = rt.guardian.recovery.last_proof_id
    rt.simulator.model.handle_command({"action": "reset"})
    rt.simulator.model.handle_command({"action": "start"})
    assert rt.simulator.model.actual_speed == 0
    rt.wait_for(lambda: rt.simulator.model.actual_speed > 0
        and rt.guardian.recovery.last_proof_id != previous_proof)
    assert rt.guardian.registry.active_records() == ()
    # The actuator and probe have separate DDS subscriptions. Motion can be
    # observed before the probe callback receives the corresponding command.
    expected_plan = f"recovery-{rt.guardian.recovery.last_proof_id}"
    rt.wait_for(lambda: any(command.plan_id == expected_plan for command in rt.commands))
    command = next(command for command in rt.commands if command.plan_id == expected_plan)
    assert not command.requires_safe_stop
    assert command.action == "NONE"


def test_extra_control_publisher_invalidates_live_recovery_context(runtime):
    rt = start_loop(runtime)
    rt.wait_for(lambda: rt.guardian.recovery.pending_proof is not None)
    proof = rt.guardian.recovery.pending_proof.proof_id
    rt.probe.create_publisher(SafetyStatus, "guardian/safety_status", 20)
    rt.wait_for(lambda: rt.guardian._recovery_graph_fingerprint() == "")
    rt.wait_for(lambda: not rt.statuses[-1].mission_allowed
        and rt.guardian.recovery.pending_proof is None)
    assert rt.guardian.recovery.last_proof_id != proof
    assert rt.simulator.model.actual_speed == 0


def test_telemetry_replay_and_wrong_signature_do_not_renew_observation(runtime):
    rt = start_loop(runtime)
    rt.wait_for(lambda: rt.guardian._recovery_telemetry is not None)
    original = rt.guardian._recovery_telemetry
    msg = rt.simulator.recovery_message()
    fields = {key: getattr(msg, key) for key in RECOVERY_TELEMETRY_FIELDS}
    msg.observation_sequence = rt.guardian._observation_sequence
    fields["observation_sequence"] = msg.observation_sequence
    msg.signature = sign_recovery_telemetry(b"runtime-feedback-secret", **fields)
    rt.guardian.on_recovery_telemetry(msg)
    assert rt.guardian._recovery_telemetry is original
    msg.observation_sequence += 100
    msg.signature = "invalid"
    rt.guardian.on_recovery_telemetry(msg)
    assert rt.guardian._recovery_telemetry is original


def test_new_incident_cannot_be_cleared_by_earlier_healthy_observation(runtime):
    from guardian_interfaces.msg import AttackEvent
    rt = start_loop(runtime)
    rt.wait_for(lambda: rt.guardian.recovery.pending_proof is not None)
    # Healthy telemetry and stop ACK predate this new incident.
    event = AttackEvent(event_id="late", source="amr_simulator", component="left_wheels",
        attack_type="UNSAFE_COMMAND", sequence=8800,
        timestamp=rt.guardian.now_seconds(), confidence=0.98)
    core = CoreAttackEvent(event.event_id, event.source, event.component, event.attack_type,
        event.sequence, event.timestamp, event.confidence)
    event.signature = EventVerifier.sign_event(b"runtime-feedback-secret", core)
    rt.guardian.on_attack_event(event)
    rt.guardian.tick()
    assert rt.guardian.registry.active_records()
    assert rt.guardian.recovery.pending_proof is None


def test_unsigned_attack_source_is_not_trusted_in_bound_mode(runtime):
    from guardian_interfaces.msg import AttackEvent
    rt = start_loop(runtime)
    event = AttackEvent(event_id="spoof", source="amr_simulator", component="left_wheels",
        attack_type="UNSAFE_COMMAND", sequence=9000,
        timestamp=rt.guardian.now_seconds(), confidence=0.98)
    rt.guardian.on_attack_event(event)
    assert rt.guardian.registry.active_records() == ()


def test_command_epoch_change_invalidates_cached_health(runtime):
    rt = start_loop(runtime)
    rt.wait_for(lambda: rt.simulator.model.mission_allowed
        and rt.guardian._recovery_telemetry is not None)
    assert rt.guardian._recovery_telemetry is not None
    old_epoch = rt.guardian._command_epoch
    rt.guardian._configuration_error = "test fault"
    rt.guardian.tick()
    assert rt.guardian._command_epoch == old_epoch + 1
    assert rt.guardian._recovery_telemetry is None


def test_task_phase_change_between_proof_issue_and_use_requires_new_proof(runtime):
    rt = start_loop(runtime)
    rt.wait_for(lambda: rt.guardian.recovery.pending_proof is not None)
    proof = rt.guardian.recovery.pending_proof
    result = rt.guardian.set_parameters([Parameter("task_phase", value="PALLET_STABILIZE")])
    assert result[0].successful
    rt.guardian.tick()
    assert rt.guardian.recovery.pending_proof is None
    assert rt.guardian.recovery.last_proof_id != proof.proof_id
    rt.wait_for(lambda: rt.guardian.recovery.last_proof_id
        and rt.simulator.model.mission_allowed)
    assert rt.guardian.recovery.last_proof_id != proof.proof_id


def test_first_recovered_command_uses_consumed_proof_epoch(runtime):
    rt = start_loop(runtime)
    rt.wait_for(lambda: rt.guardian.recovery.pending_proof is not None)
    proof = rt.guardian.recovery.pending_proof
    rt.wait_for(lambda: any(item.plan_id == f"recovery-{proof.proof_id}" for item in rt.commands))
    command = next(item for item in rt.commands if item.plan_id == f"recovery-{proof.proof_id}")
    assert command.command_epoch == proof.command_epoch
    assert command.action == "NONE"
    rt.wait_for(lambda: any(item.plan_id == command.plan_id for item in rt.statuses))
    status = next(item for item in rt.statuses if item.plan_id == command.plan_id)
    assert status.command_epoch == proof.command_epoch
    assert status.transmission_id == command.transmission_id
