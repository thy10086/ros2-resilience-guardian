import hashlib
import hmac
import json
import os
import time
from types import SimpleNamespace

import pytest
import rclpy
from rcl_interfaces.srv import ListParameters
from rclpy.executors import SingleThreadedExecutor
from rclpy.parameter import Parameter

from guardian_interfaces.msg import AttackEvent, MitigationAck, MitigationCommand, SafetyStatus
from guardian_core.amr_simulator import AmrSimulatorNode
from guardian_core.feedback_auth import sign_ack
from guardian_core.guardian_node import GuardianNode


def test_bound_recovery_audit_trace_uses_published_epoch(runtime, tmp_path):
    from guardian_core.recovery_feedback import RecoveryFrame, SafetyOracle
    path = tmp_path / "audit.jsonl"
    rt = runtime(evidence_bound_recovery=True, audit_path=str(path))
    rt.guardian.tick()
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    traces = [RecoveryFrame.from_dict({k: v for k, v in row.items() if k != "kind"})
        for row in rows if row["kind"] == "recovery_trace"]
    assert len(traces) == 1
    assert traces[0].next_command_epoch == rt.guardian._command_epoch
    assert not SafetyOracle().check_trace(traces)


@pytest.fixture
def runtime(monkeypatch):
    # Isolate integration traffic from any user's running robot or dashboard.
    monkeypatch.setenv("ROS_DOMAIN_ID", str(170 + os.getpid() % 30))
    monkeypatch.setenv("ROS_LOCALHOST_ONLY", "1")
    monkeypatch.delenv("GUARDIAN_EVENT_SECRET", raising=False)
    monkeypatch.setenv("GUARDIAN_FEEDBACK_SECRET", "runtime-feedback-secret")
    nodes = []
    executor = None

    def start(auto_feedback=True, real_time=False, **parameters):
        nonlocal executor
        args = ["guardian_runtime_test", "--ros-args"]
        for name, value in parameters.items():
            args.extend(["-p", f"guardian_node:{name}:={json.dumps(value)}"])
        rclpy.init(args=args)
        executor = SingleThreadedExecutor()
        guardian = GuardianNode()
        nodes.append(guardian)
        simulator = AmrSimulatorNode()
        nodes.append(simulator)
        probe = rclpy.create_node("guardian_test_probe")
        nodes.append(probe)
        for node in nodes:
            for timer in node.timers:
                timer.cancel()
            executor.add_node(node)
        clock = [10.0]
        monotonic = [100.0]
        if not real_time:
            guardian.now_seconds = lambda: clock[0]
            guardian.monotonic_seconds = lambda: monotonic[0]
            simulator.now_seconds = lambda: clock[0]
        commands, statuses = [], []
        probe.create_subscription(MitigationCommand, "guardian/mitigation_command", commands.append, 20)
        probe.create_subscription(SafetyStatus, "guardian/safety_status", statuses.append, 20)
        publisher = probe.create_publisher(AttackEvent, "guardian/attack_events", 20)
        ack_publisher = probe.create_publisher(MitigationAck, "guardian/mitigation_ack", 20)

        def wait_for(predicate):
            deadline = time.monotonic() + 5.0
            while not predicate() and time.monotonic() < deadline:
                if auto_feedback:
                    simulator.tick()
                executor.spin_once(timeout_sec=0.02)
            assert predicate(), "ROS messages did not reach the expected state"

        wait_for(lambda: publisher.get_subscription_count() == 1
                 and ack_publisher.get_subscription_count() == 1
                 and guardian.command_pub.get_subscription_count() >= 2
                 and guardian.status_pub.get_subscription_count() >= 2)
        if real_time:
            for timer in guardian.timers:
                timer.reset()
        return SimpleNamespace(
            guardian=guardian, simulator=simulator, probe=probe, clock=clock,
            monotonic=monotonic,
            commands=commands, statuses=statuses, publisher=publisher,
            ack_publisher=ack_publisher, wait_for=wait_for,
        )

    yield start
    for node in reversed(nodes):
        executor.remove_node(node)
        node.destroy_node()
    if executor is not None:
        executor.shutdown()
    if rclpy.ok():
        rclpy.shutdown()


def publish_attack(rt, *, source="scenario_injector", event_id="one", component="right_arm"):
    message = AttackEvent(
        event_id=event_id, source=source, component=component, attack_type="FAULT",
        sequence=1, timestamp=rt.clock[0], confidence=0.98,
    )
    rt.publisher.publish(message)
    rt.wait_for(lambda: any(record.event.source == source and record.event.event_id == event_id
                           for record in rt.guardian.registry.active_records()))


def test_pending_isolation_is_not_executed_before_activation(runtime):
    rt = runtime(
        mitigation_delay_sec=2.0,
        containment_policy_json=json.dumps({
            "FAULT": {"action": "ISOLATE_COMPONENT", "speed_limit": 0.1, "mission_allowed": True},
        }),
    )
    rt.simulator.model.handle_command({"action": "start"})
    publish_attack(rt)
    rt.guardian.tick()
    rt.wait_for(lambda: rt.commands and rt.statuses and rt.simulator.model.mitigation_action != "NONE")
    assert rt.commands[-1].action == "SAFE_STOP"
    assert list(rt.commands[-1].components) == []
    assert rt.commands[-1].requires_safe_stop
    assert not rt.statuses[-1].mission_allowed
    rt.wait_for(lambda: rt.guardian._feedback_ready)
    rt.simulator.model.update(0.1)
    assert rt.simulator.model.actual_speed == 0.0
    assert rt.simulator.model.isolated_components == set()

    rt.clock[0] = 11.9
    rt.wait_for(lambda: rt.guardian._last_feedback_at == 11.9)
    rt.clock[0] = 12.0
    rt.guardian.tick()
    rt.wait_for(lambda: (
        rt.simulator.model.isolated_components == {"right_arm"}
        and rt.simulator.model.mission_allowed
        and rt.commands[-1].action == "ISOLATE_COMPONENT"
    ))
    rt.simulator.model.update(0.1)
    assert rt.simulator.model.actual_speed == pytest.approx(0.1)


@pytest.mark.parametrize("payload", ["{broken", "", "   "])
def test_invalid_policy_keeps_robot_stopped_without_active_attacks(runtime, payload):
    rt = runtime(containment_policy_json=payload)
    rt.simulator.model.handle_command({"action": "start"})
    for now in (10.0, 11.0, 12.0):
        rt.clock[0] = now
        rt.guardian.tick()
        rt.wait_for(lambda: rt.commands and rt.statuses
                    and rt.commands[-1].timestamp == now
                    and rt.statuses[-1].timestamp == now
                    and rt.simulator.model.safety_state == "SAFE_STOP")
        assert rt.commands[-1].action == "SAFE_STOP"
        assert rt.statuses[-1].state == "SAFE_STOP"
        assert not rt.statuses[-1].mission_allowed
        rt.simulator.model.update(0.1)
        assert rt.simulator.model.actual_speed == 0.0


@pytest.mark.parametrize("name,value", [
    ("mitigation_delay_sec", 0.0),
    ("feedback_timeout_sec", 0.1),
    ("default_speed_limit", 0.9),
    ("containment_policy_json", "{}"),
    ("security_profile_json", json.dumps({
        "profile_id": "runtime-test",
        "adapter_id": "runtime-adapter",
        "trusted_sources": ["scenario_injector"],
        "resources": {"right_arm": {"tau": 1, "epsilon": 0, "mitigatable": True}},
    })),
    ("require_signature", True),
])
def test_startup_only_parameters_reject_ineffective_runtime_updates(runtime, name, value):
    rt = runtime()
    before = rt.guardian.get_parameter(name).value
    result = rt.guardian.set_parameters([Parameter(name, value=value)])[0]
    assert not result.successful
    assert rt.guardian.get_parameter(name).value == before


def test_phase_parameter_change_replans_in_runtime(runtime):
    rt = runtime(
        task_phase="DOCK",
        mitigation_delay_sec=0.0,
        containment_policy_json=json.dumps({"FAULT": {
            "DOCK": {"action": "LIMIT_SPEED", "speed_limit": 0.1, "mission_allowed": True},
            "STABILIZE": {"action": "SAFE_STOP", "speed_limit": 0.0, "mission_allowed": False},
        }}),
    )
    publish_attack(rt)
    rt.guardian.tick()
    rt.wait_for(lambda: rt.commands)
    assert rt.commands[-1].action == "LIMIT_SPEED"
    assert rt.guardian.set_parameters([Parameter("task_phase", value="STABILIZE")])[0].successful
    rt.clock[0] = 10.1
    rt.guardian.tick()
    rt.wait_for(lambda: rt.commands[-1].action == "SAFE_STOP")
    assert rt.guardian.planner.current_plan.requires_safe_stop


def test_replacing_same_id_from_another_source_replans_in_runtime(runtime):
    rt = runtime(mitigation_delay_sec=0.0)
    publish_attack(rt, source="scenario_injector", component="right_arm")
    rt.guardian.tick()
    assert rt.guardian.planner.current_plan.action.value == "NONE"
    rt.clock[0] = 16.0
    publish_attack(rt, source="amr_simulator", component="left_wheels")
    rt.guardian.tick()
    assert rt.guardian.planner.current_plan.action.value == "ISOLATE_COMPONENT"
    assert rt.guardian.planner.current_plan.components == frozenset({"left_wheels"})


def test_signature_secret_is_environment_only_and_not_a_ros_parameter(runtime, monkeypatch):
    secret = "integration-test-only-secret"
    monkeypatch.setenv("GUARDIAN_EVENT_SECRET", secret)
    rt = runtime(require_signature=True)
    payload = "one|scenario_injector|right_arm|FAULT|1|10.000000|0.500000".encode()
    message = AttackEvent(
        event_id="one", source="scenario_injector", component="right_arm", attack_type="FAULT",
        sequence=1, timestamp=10.0, confidence=0.5,
        signature=hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest(),
    )
    rt.publisher.publish(message)
    rt.wait_for(lambda: rt.guardian.registry.active_records())
    assert not rt.guardian.has_parameter("signature_secret")
    client = rt.probe.create_client(ListParameters, "/guardian_node/list_parameters")
    rt.wait_for(client.service_is_ready)
    response = client.call_async(ListParameters.Request())
    rt.wait_for(response.done)
    assert "signature_secret" not in response.result().result.names


def _ack_for(command, *, epoch=None, action=None, components=None):
    message = MitigationAck()
    message.timestamp = command.timestamp
    message.profile_id = command.profile_id
    message.adapter_id = command.adapter_id
    message.command_epoch = command.command_epoch if epoch is None else epoch
    message.transmission_id = command.transmission_id
    message.feedback_sequence = 1
    message.plan_id = command.plan_id
    message.action = command.action if action is None else action
    message.components = list(command.components if components is None else components)
    message.accepted = True
    message.active = True
    message.safe_stop_confirmed = message.action == "SAFE_STOP"
    message.reason = "adapter applied command"
    message.signature = sign_ack(
        b"runtime-feedback-secret",
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
    )
    return message


def test_profile_can_protect_a_non_vehicle_ros2_resource(runtime):
    rt = runtime(
        mitigation_delay_sec=0.0,
        security_profile_json=json.dumps({
            "profile_id": "manipulator-runtime",
            "adapter_id": "ros2-control-adapter",
            "trusted_sources": ["scenario_injector"],
            "resources": {
                "joint_1_controller": {"tau": 2, "epsilon": 0, "mitigatable": True},
            },
        }),
    )
    publish_attack(rt, component="joint_1_controller")
    rt.guardian.tick()
    rt.wait_for(lambda: rt.commands and rt.commands[-1].action == "ISOLATE_COMPONENT"
                and rt.statuses and rt.statuses[-1].profile_id == "manipulator-runtime")
    assert list(rt.commands[-1].components) == ["joint_1_controller"]
    assert rt.commands[-1].adapter_id == "ros2-control-adapter"
    assert rt.statuses[-1].profile_id == "manipulator-runtime"


def test_ros_clock_pause_does_not_disable_feedback_watchdog(runtime):
    rt = runtime(auto_feedback=False, feedback_timeout_sec=0.5)
    rt.guardian.tick()
    rt.wait_for(lambda: rt.commands and rt.commands[-1].timestamp == 10.0)

    rt.clock[0] = 10.0
    rt.monotonic[0] = 100.6
    rt.guardian.tick()
    rt.wait_for(lambda: rt.commands[-1].action == "SAFE_STOP"
                and rt.statuses[-1].state == "SAFE_STOP")
    assert rt.statuses[-1].state == "SAFE_STOP"


def test_startup_feedback_grace_handles_a_delayed_first_adapter_ack(runtime):
    rt = runtime(
        auto_feedback=False,
        feedback_timeout_sec=0.5,
        startup_feedback_grace_sec=1.0,
    )
    rt.guardian.tick()
    rt.wait_for(lambda: rt.commands and rt.commands[-1].timestamp == 10.0)

    rt.monotonic[0] = 100.6
    rt.clock[0] = 10.6
    rt.guardian.tick()
    rt.wait_for(lambda: rt.statuses and rt.statuses[-1].timestamp == 10.6)
    assert rt.statuses[-1].state != "SAFE_STOP"

    rt.ack_publisher.publish(_ack_for(rt.commands[-1]))
    rt.wait_for(lambda: rt.guardian._feedback_ready)


def test_ack_for_previous_same_epoch_transmission_can_refresh_watchdog(runtime):
    rt = runtime(auto_feedback=False, feedback_timeout_sec=0.5)
    rt.guardian.tick()
    rt.wait_for(lambda: rt.commands and rt.commands[-1].timestamp == 10.0)
    first = rt.commands[-1]
    first_ack = _ack_for(first)
    rt.ack_publisher.publish(first_ack)
    rt.wait_for(lambda: rt.guardian._feedback_ready)

    rt.clock[0] = 10.1
    rt.monotonic[0] = 100.1
    rt.guardian.tick()
    rt.wait_for(lambda: rt.commands[-1].transmission_id > first.transmission_id)
    second = rt.commands[-1]
    assert not rt.guardian._feedback_ready

    stale_ack = _ack_for(first)
    stale_ack.feedback_sequence = 2
    stale_ack.signature = sign_ack(
        b"runtime-feedback-secret",
        profile_id=stale_ack.profile_id,
        command_epoch=stale_ack.command_epoch,
        transmission_id=stale_ack.transmission_id,
        feedback_sequence=stale_ack.feedback_sequence,
        adapter_id=stale_ack.adapter_id,
        plan_id=stale_ack.plan_id,
        action=stale_ack.action,
        components=stale_ack.components,
        accepted=stale_ack.accepted,
        active=stale_ack.active,
        safe_stop_confirmed=stale_ack.safe_stop_confirmed,
    )
    rt.ack_publisher.publish(stale_ack)
    rt.wait_for(lambda: rt.guardian._feedback_ready)

    rt.clock[0] = 10.2
    rt.monotonic[0] = 100.4
    rt.guardian.tick()
    rt.wait_for(lambda: rt.commands[-1].action == "NONE")
    assert rt.guardian._watchdog_latched is False


def test_duplicate_feedback_sequence_is_rejected(runtime):
    rt = runtime(auto_feedback=False)
    rt.guardian.tick()
    rt.wait_for(lambda: rt.commands)
    ack = _ack_for(rt.commands[-1])
    rt.ack_publisher.publish(ack)
    rt.wait_for(lambda: rt.guardian._feedback_ready)
    rt.ack_publisher.publish(ack)
    rt.wait_for(lambda: rt.guardian._feedback_ready)
    assert rt.guardian._last_feedback_sequence == 1


def test_matching_fields_with_invalid_feedback_signature_cannot_clear_watchdog(runtime):
    rt = runtime(auto_feedback=False, feedback_timeout_sec=0.5)
    rt.guardian.tick()
    rt.wait_for(lambda: rt.commands)
    forged = _ack_for(rt.commands[-1])
    forged.signature = "0" * 64
    rt.ack_publisher.publish(forged)
    rt.wait_for(lambda: not rt.guardian._feedback_ready)

    rt.monotonic[0] = 100.6
    rt.guardian.tick()
    rt.wait_for(lambda: rt.commands[-1].action == "SAFE_STOP")
    assert rt.guardian._watchdog_latched


def test_ack_from_another_security_profile_does_not_clear_watchdog(runtime):
    rt = runtime(auto_feedback=False, feedback_timeout_sec=0.5)
    rt.guardian.tick()
    rt.wait_for(lambda: rt.commands)
    ack = _ack_for(rt.commands[-1])
    ack.profile_id = "another-profile"
    rt.ack_publisher.publish(ack)
    rt.wait_for(lambda: not rt.guardian._feedback_ready)

    rt.monotonic[0] = 100.6
    rt.guardian.tick()
    rt.wait_for(lambda: rt.commands[-1].action == "SAFE_STOP"
                and rt.statuses and rt.statuses[-1].state == "SAFE_STOP")
    assert rt.statuses[-1].state == "SAFE_STOP"


def test_guardian_enters_safe_stop_when_actuator_feedback_times_out(runtime):
    rt = runtime(auto_feedback=False, feedback_timeout_sec=0.5)
    rt.guardian.tick()
    rt.wait_for(lambda: rt.commands and rt.statuses and rt.commands[-1].timestamp == 10.0)
    assert rt.commands[-1].action == "NONE"

    rt.clock[0] = 11.0
    rt.monotonic[0] = 101.0
    rt.guardian.tick()
    rt.wait_for(lambda: rt.commands[-1].timestamp == 11.0
                and rt.statuses[-1].timestamp == 11.0)

    assert rt.commands[-1].action == "SAFE_STOP"
    assert rt.commands[-1].requires_safe_stop
    assert rt.statuses[-1].state == "SAFE_STOP"
    assert not rt.statuses[-1].mission_allowed
    assert "feedback timeout" in rt.statuses[-1].reason


def test_matching_actuator_feedback_prevents_watchdog_trip(runtime):
    rt = runtime(auto_feedback=False, feedback_timeout_sec=0.5)
    rt.guardian.tick()
    rt.wait_for(lambda: rt.commands and rt.commands[-1].timestamp == 10.0)
    rt.ack_publisher.publish(_ack_for(rt.commands[-1]))
    rt.wait_for(lambda: rt.guardian._last_feedback_at == 10.0)

    rt.clock[0] = 10.4
    rt.monotonic[0] = 100.4
    rt.guardian.tick()
    rt.wait_for(lambda: rt.statuses[-1].timestamp == 10.4)
    assert rt.statuses[-1].state == "NORMAL"
    assert rt.commands[-1].action == "NONE"

    rt.clock[0] = 10.6
    rt.monotonic[0] = 100.6
    rt.guardian.tick()
    rt.wait_for(lambda: rt.commands[-1].timestamp == 10.6
                and rt.statuses[-1].timestamp == 10.6)
    assert rt.commands[-1].action == "SAFE_STOP"
    assert rt.statuses[-1].state == "SAFE_STOP"


def test_mismatched_actuator_feedback_does_not_clear_watchdog(runtime):
    rt = runtime(auto_feedback=False, feedback_timeout_sec=0.5)
    rt.guardian.tick()
    rt.wait_for(lambda: rt.commands and rt.commands[-1].timestamp == 10.0)
    rt.ack_publisher.publish(_ack_for(rt.commands[-1], epoch=rt.commands[-1].command_epoch + 1))
    rt.wait_for(lambda: not rt.guardian._feedback_ready)

    rt.clock[0] = 10.6
    rt.monotonic[0] = 100.6
    rt.guardian.tick()
    rt.wait_for(lambda: rt.commands[-1].timestamp == 10.6
                and rt.statuses[-1].timestamp == 10.6)
    assert rt.commands[-1].action == "SAFE_STOP"
    assert "feedback timeout" in rt.statuses[-1].reason


@pytest.mark.parametrize("initial_ack", [False, True])
def test_continuous_publication_does_not_extend_feedback_deadline(runtime, initial_ack):
    rt = runtime(auto_feedback=False, feedback_timeout_sec=0.5)
    rt.guardian.tick()
    rt.wait_for(lambda: rt.commands)
    if initial_ack:
        rt.guardian.on_mitigation_ack(_ack_for(rt.commands[-1]))
        assert rt.guardian._feedback_ready
    for step in range(1, 8):
        rt.monotonic[0] = 100.0 + step * 0.1
        rt.clock[0] = 10.0 + step * 0.1
        rt.guardian.tick()
        rt.wait_for(lambda: rt.statuses and rt.statuses[-1].timestamp == rt.clock[0])
    assert rt.statuses[-1].state == "SAFE_STOP"
    assert rt.guardian._watchdog_latched


def test_real_timer_stops_without_any_sim_clock_messages(runtime):
    rt = runtime(auto_feedback=False, real_time=True, use_sim_time=True, feedback_timeout_sec=0.3)
    rt.guardian.tick()
    rt.wait_for(lambda: rt.statuses)
    assert rt.guardian.now_seconds() == 0.0
    rt.wait_for(lambda: rt.statuses[-1].state == "SAFE_STOP")


def test_late_ack_cannot_resurrect_an_expired_deadline(runtime):
    rt = runtime(auto_feedback=False, feedback_timeout_sec=0.5)
    rt.guardian.tick()
    rt.wait_for(lambda: rt.commands)
    rt.monotonic[0] = 100.6
    rt.guardian.on_mitigation_ack(_ack_for(rt.commands[-1]))
    rt.guardian.tick()
    rt.wait_for(lambda: rt.statuses and rt.statuses[-1].transmission_id == 2)
    assert rt.statuses[-1].state == "SAFE_STOP"


def _submit_recovery_sample(rt, source_time, sequence=1):
    from guardian_core.feedback_auth import RECOVERY_TELEMETRY_FIELDS, sign_recovery_telemetry
    message = rt.simulator.recovery_message(source_time)
    message.command_epoch = rt.guardian._command_epoch
    message.transmission_id = rt.guardian._transmission_id
    message.observation_sequence = sequence
    fields = {key: getattr(message, key) for key in RECOVERY_TELEMETRY_FIELDS}
    message.signature = sign_recovery_telemetry(b"runtime-feedback-secret", **fields)
    rt.guardian.on_recovery_telemetry(message)


def test_simulator_execution_watchdog_runs_without_ros_clock(runtime):
    rt = runtime(auto_feedback=False)
    rt.simulator.set_parameters([Parameter("use_sim_time", value=True)])
    rt.guardian.tick()
    rt.wait_for(lambda: rt.simulator.model.mission_allowed and rt.simulator.model.command_accepted)
    rt.simulator.model.handle_command({"action": "start"})
    rt.simulator.model.update(0.1)
    assert rt.simulator.model.actual_speed == 0.2
    for timer in rt.simulator.timers:
        timer.reset()
    rt.wait_for(lambda: not rt.simulator.model.mission_allowed)
    assert rt.simulator.model.actual_speed == 0.0


@pytest.mark.parametrize("ros_advance", [0.0, 0.25])
def test_recovery_source_age_is_not_reset_at_arrival(runtime, ros_advance):
    rt = runtime(auto_feedback=False, evidence_bound_recovery=True)
    rt.guardian.tick()
    _submit_recovery_sample(rt, 9.51)
    assert rt.guardian._effective_recovery_telemetry(100.0) is not None
    rt.clock[0] += ros_advance
    rt.monotonic[0] = 100.25
    assert rt.guardian._effective_recovery_telemetry(100.25) is None


@pytest.mark.parametrize("rollback", ["ros", "monotonic"])
def test_recovery_clock_rollback_withdraws_cached_evidence(runtime, rollback):
    rt = runtime(auto_feedback=False, evidence_bound_recovery=True)
    rt.guardian.tick()
    _submit_recovery_sample(rt, 9.9)
    assert rt.guardian._effective_recovery_telemetry(100.0) is not None
    if rollback == "ros":
        rt.clock[0] = 9.95  # Still after source time, but before reception time.
    else:
        rt.monotonic[0] = 99.99
    assert rt.guardian._effective_recovery_telemetry(rt.monotonic[0]) is None


def test_repeated_acquisition_cannot_extend_recovery_deadline(runtime):
    rt = runtime(auto_feedback=False, evidence_bound_recovery=True)
    rt.guardian.tick()
    _submit_recovery_sample(rt, 9.9)
    rt.monotonic[0] = 100.3
    # ROS time paused: a larger transport sequence is not a new acquisition.
    _submit_recovery_sample(rt, 9.9, sequence=2)
    rt.monotonic[0] = 100.45
    assert rt.guardian._effective_recovery_telemetry(100.45) is None


def test_delayed_acquisition_backlog_cannot_extend_lifetime_when_ros_time_pauses(runtime):
    rt = runtime(auto_feedback=False, evidence_bound_recovery=True)
    rt.guardian.tick()
    _submit_recovery_sample(rt, 9.9)
    rt.monotonic[0] = 100.3
    _submit_recovery_sample(rt, 9.91, sequence=2)
    rt.monotonic[0] = 100.45
    assert rt.guardian._effective_recovery_telemetry(100.45) is None


def test_current_acquisition_recovers_after_ros_clock_resumes(runtime):
    rt = runtime(auto_feedback=False, evidence_bound_recovery=True)
    rt.guardian.tick()
    _submit_recovery_sample(rt, 10.0)
    assert rt.guardian._effective_recovery_telemetry(100.0) is not None
    rt.monotonic[0], rt.clock[0] = 101.0, 10.1
    _submit_recovery_sample(rt, 10.1, sequence=2)
    assert rt.guardian._effective_recovery_telemetry(101.0) is None
    rt.monotonic[0], rt.clock[0] = 102.0, 11.1
    _submit_recovery_sample(rt, 11.01, sequence=3)
    assert rt.guardian._effective_recovery_telemetry(102.0) is None
    _submit_recovery_sample(rt, 11.1, sequence=4)
    assert rt.guardian._effective_recovery_telemetry(102.0) is not None


def test_fresh_acquisitions_survive_two_hours_of_small_ros_clock_drift(runtime):
    rt = runtime(auto_feedback=False, evidence_bound_recovery=True)
    rt.guardian.tick()
    _submit_recovery_sample(rt, 10.0)
    for step in range(1, 73):
        rt.monotonic[0] = 100.0 + step * 100.0
        rt.clock[0] = 10.0 + step * 99.99  # ROS clock runs 100 ppm slow.
        _submit_recovery_sample(rt, rt.clock[0], sequence=step + 1)
        assert rt.guardian._effective_recovery_telemetry(rt.monotonic[0]) is not None


def _undelivered_authorization_runtime(runtime, **parameters):
    rt = runtime(auto_feedback=False, **parameters)
    # Keep real publishers and the probe subscriptions, but deliver to the
    # actuator explicitly so a queued transmission can remain unseen.
    for subscription in list(rt.simulator.subscriptions):
        if subscription.topic_name in {"/guardian/mitigation_command", "/guardian/safety_status"}:
            rt.simulator.destroy_subscription(subscription)
    rt.simulator.model._monotonic_clock = lambda: rt.monotonic[0]
    rt.simulator.now_seconds = lambda: rt.clock[0]
    rt.simulator.model.handle_command({"action": "start"})
    return rt


def _published_pair(rt):
    rt.guardian.tick()
    rt.wait_for(lambda: rt.commands and rt.statuses
        and rt.commands[-1].timestamp == rt.clock[0] and rt.statuses[-1].timestamp == rt.clock[0])
    return rt.commands[-1], rt.statuses[-1]


def _deliver_authorization_pair(rt, pair):
    command, status = pair
    rt.simulator.on_mitigation(command)
    rt.simulator.on_safety(status)
    rt.simulator.model.update(0.1)


def test_unseen_higher_transmission_cannot_restart_motion_after_source_expiry(runtime):
    rt = _undelivered_authorization_runtime(runtime)
    _deliver_authorization_pair(rt, _published_pair(rt))
    assert rt.simulator.model.actual_speed == 0.2
    rt.clock[0], rt.monotonic[0] = 10.1, 100.1
    queued = _published_pair(rt)
    rt.clock[0], rt.monotonic[0] = 10.7, 100.7
    rt.simulator.model.update(0.1)
    assert rt.simulator.model.actual_speed == 0.0
    _deliver_authorization_pair(rt, queued)
    assert rt.simulator.model.actual_speed == 0.0
    assert not rt.simulator.model.command_accepted


@pytest.mark.parametrize("which", [0, 1])
def test_command_and_status_signatures_bind_publication_time(runtime, which):
    rt = _undelivered_authorization_runtime(runtime)
    pair = _published_pair(rt)
    pair[which].timestamp = 10.1
    rt.clock[0], rt.monotonic[0] = 10.1, 100.1
    _deliver_authorization_pair(rt, pair)
    assert rt.simulator.model.actual_speed == 0.0


def test_execution_lease_retains_only_remaining_source_lifetime(runtime):
    rt = _undelivered_authorization_runtime(runtime)
    pair = _published_pair(rt)
    rt.clock[0], rt.monotonic[0] = 10.49, 100.49
    _deliver_authorization_pair(rt, pair)
    assert rt.simulator.model.actual_speed == 0.2
    rt.monotonic[0] = 100.51
    rt.simulator.model.update(0.1)
    assert rt.simulator.model.actual_speed == 0.0


def test_future_publication_time_does_not_authorize_motion(runtime):
    rt = _undelivered_authorization_runtime(runtime)
    pair = _published_pair(rt)
    rt.clock[0] = 9.9
    _deliver_authorization_pair(rt, pair)
    assert rt.simulator.model.actual_speed == 0.0


def test_frozen_ros_clock_cannot_reauthorize_delayed_transmissions_then_resumes(runtime):
    rt = _undelivered_authorization_runtime(runtime, feedback_timeout_sec=20.0)
    _deliver_authorization_pair(rt, _published_pair(rt))
    assert rt.simulator.model.actual_speed == 0.2
    delayed = []
    for source in (10.01, 10.02):
        rt.clock[0], rt.monotonic[0] = source, 100.0 + source - 10.0
        delayed.append(_published_pair(rt))
    rt.monotonic[0] = 100.8
    rt.simulator.tick()  # Steady timer observes the paused source clock.
    assert rt.simulator.model.actual_speed == 0.0
    for pair in delayed:
        _deliver_authorization_pair(rt, pair)
        assert rt.simulator.model.actual_speed == 0.0
        assert not rt.simulator.model.command_accepted
    rt.clock[0], rt.monotonic[0] = 11.02, 101.8
    _deliver_authorization_pair(rt, _published_pair(rt))
    assert rt.simulator.model.actual_speed == 0.2


def test_adapter_current_publications_survive_two_hours_of_small_clock_drift(runtime):
    from guardian_core.feedback_auth import sign_command, sign_status
    rt = _undelivered_authorization_runtime(runtime)
    command, status = _published_pair(rt)
    for step in range(73):
        rt.monotonic[0] = 100.0 + step * 100.0
        rt.clock[0] = 10.0 + step * 99.99
        for message in (command, status):
            message.timestamp = rt.clock[0]
            message.transmission_id = step + 1
        command.signature = sign_command(b"runtime-feedback-secret", **{
            key: getattr(command, key) for key in ("timestamp", "profile_id", "command_epoch",
                "transmission_id", "adapter_id", "plan_id", "action", "components", "requires_safe_stop")})
        status.signature = sign_status(b"runtime-feedback-secret", **{
            key: getattr(status, key) for key in ("timestamp", "profile_id", "command_epoch",
                "transmission_id", "adapter_id", "plan_id", "state", "speed_limit", "mission_allowed")})
        _deliver_authorization_pair(rt, (command, status))
        assert rt.simulator.model.actual_speed == 0.2


def test_adapter_small_clock_resume_cannot_reanchor_a_rejected_paused_publication(runtime):
    rt = _undelivered_authorization_runtime(runtime, feedback_timeout_sec=20.0)
    _deliver_authorization_pair(rt, _published_pair(rt))
    rt.clock[0], rt.monotonic[0] = 10.02, 100.02
    queued = _published_pair(rt)
    rt.monotonic[0] = 100.8
    rt.simulator.tick()
    _deliver_authorization_pair(rt, queued)
    assert rt.simulator.model.actual_speed == 0.0
    rt.clock[0], rt.monotonic[0] = 10.03, 100.81
    _deliver_authorization_pair(rt, queued)
    assert rt.simulator.model.actual_speed == 0.0
    _deliver_authorization_pair(rt, _published_pair(rt))
    assert rt.simulator.model.actual_speed == 0.2


def test_recovery_small_clock_resume_cannot_reanchor_paused_acquisition_backlog(runtime):
    rt = runtime(auto_feedback=False, evidence_bound_recovery=True)
    rt.guardian.tick()
    _submit_recovery_sample(rt, 10.0)
    rt.clock[0], rt.monotonic[0] = 10.02, 100.8
    _submit_recovery_sample(rt, 10.01, sequence=2)
    assert rt.guardian._effective_recovery_telemetry(100.8) is None
    rt.clock[0], rt.monotonic[0] = 10.03, 100.81
    _submit_recovery_sample(rt, 10.02, sequence=3)
    assert rt.guardian._effective_recovery_telemetry(100.81) is None
    _submit_recovery_sample(rt, 10.03, sequence=4)
    assert rt.guardian._effective_recovery_telemetry(100.81) is not None
