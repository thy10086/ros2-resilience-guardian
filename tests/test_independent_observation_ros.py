import time

import pytest

from guardian_interfaces.msg import IndependentObservation
from guardian_core.feedback_auth import INDEPENDENT_OBSERVATION_FIELDS, sign_independent_observation
from test_guardian_runtime import runtime


def start_independent(runtime, monkeypatch, secret="independent-runtime-key"):
    monkeypatch.setenv("GUARDIAN_OBSERVATION_SECRET", secret)
    rt = runtime(real_time=True, evidence_bound_recovery=True,
        independent_observation_required=True, recovery_dwell_sec=0.2,
        recovery_stable_window_sec=0.1, startup_feedback_grace_sec=3.0)
    # Callback-level acceptance tests provide the endpoint the real DDS graph
    # lookup would supply. The separate launch test exercises native discovery.
    rt.guardian._independent_endpoint_gid = lambda: "test-endpoint"
    return rt


def test_independent_mode_requires_separate_key(runtime, monkeypatch):
    rt = start_independent(runtime, monkeypatch, secret="")
    assert "observation" in rt.guardian._configuration_error
    rt.guardian.tick()
    rt.wait_for(lambda: rt.statuses and not rt.statuses[-1].mission_allowed)


def test_adapter_feedback_alone_cannot_authorize_independent_mode(runtime, monkeypatch):
    rt = start_independent(runtime, monkeypatch)
    rt.simulator.model.handle_command({"action": "start"})
    rt.wait_for(lambda: rt.guardian._recovery_telemetry is not None)
    deadline = time.monotonic() + 0.7
    rt.wait_for(lambda: time.monotonic() > deadline)
    assert rt.guardian.recovery.last_proof_id == ""
    assert rt.simulator.model.actual_speed == 0


def report(rt, **changes):
    now = rt.guardian.now_seconds()
    sampled = rt.guardian._recovery_observed_ros_time or now
    fields = dict(timestamp=now, observer_id="recovery-observer", observer_session="a" * 32, profile_id="amr-default",
        command_epoch=rt.guardian._command_epoch, transmission_id=rt.guardian._transmission_id,
        observation_sequence=1, odom_timestamp=sampled, scan_timestamp=sampled,
        actual_speed=0.0, free_distance=2.0, valid=True)
    fields.update(changes)
    message = IndependentObservation(**fields)
    message.signature = sign_independent_observation(b"independent-runtime-key", **fields)
    return message


def test_authenticated_independent_report_replay_cannot_refresh_cache(runtime, monkeypatch):
    rt = start_independent(runtime, monkeypatch)
    rt.wait_for(lambda: rt.guardian._recovery_telemetry is not None)
    msg = report(rt)
    rt.guardian.on_independent_observation(msg)
    original = rt.guardian._independent_sample
    assert original is not None
    rt.guardian.on_independent_observation(msg)
    assert rt.guardian._independent_sample is original
    assert rt.guardian._effective_recovery_telemetry(rt.guardian.monotonic_seconds()) is not None
    bad = report(rt, observation_sequence=2, actual_speed=0.4)
    rt.guardian.on_independent_observation(bad)
    assert rt.guardian._effective_recovery_telemetry(rt.guardian.monotonic_seconds()) is None


@pytest.mark.parametrize("change", [dict(odom_timestamp=1.0), dict(valid=False),
    dict(command_epoch=0), dict(observer_id="unknown"), dict(actual_speed=float("nan"))])
def test_invalid_independent_observation_is_not_evidence(runtime, monkeypatch, change):
    rt = start_independent(runtime, monkeypatch)
    rt.wait_for(lambda: rt.guardian._recovery_telemetry is not None)
    rt.guardian.on_independent_observation(report(rt, **change))
    assert rt.guardian._effective_recovery_telemetry(rt.guardian.monotonic_seconds()) is None


def test_observer_key_equal_to_adapter_key_is_configuration_error(runtime, monkeypatch):
    rt = start_independent(runtime, monkeypatch, secret="runtime-feedback-secret")
    assert "observation" in rt.guardian._configuration_error


def test_new_report_with_preincident_raw_samples_cannot_clear_new_incident(runtime, monkeypatch):
    from guardian_interfaces.msg import AttackEvent
    from guardian_core.models import AttackEvent as CoreAttackEvent
    from guardian_core.verifier import EventVerifier
    rt = start_independent(runtime, monkeypatch)
    rt.wait_for(lambda: rt.guardian._recovery_telemetry is not None)
    source_time = rt.guardian.now_seconds()
    event = AttackEvent(event_id="independent-late", source="amr_simulator", component="left_wheels",
        attack_type="UNSAFE_COMMAND", sequence=9500, timestamp=rt.guardian.now_seconds(), confidence=0.98)
    event.signature = EventVerifier.sign_event(b"runtime-feedback-secret", CoreAttackEvent(
        event.event_id, event.source, event.component, event.attack_type,
        event.sequence, event.timestamp, event.confidence))
    rt.guardian.on_attack_event(event)
    rt.guardian.on_recovery_telemetry(rt.simulator.recovery_message())
    rt.guardian.on_independent_observation(report(rt, odom_timestamp=source_time, scan_timestamp=source_time))
    assert rt.guardian._independent_sample is not None
    rt.guardian.tick()
    assert rt.guardian.registry.active_records()


def test_new_endpoint_session_restarts_watermark_and_rejects_old_boot(runtime, monkeypatch):
    rt = start_independent(runtime, monkeypatch)
    rt.wait_for(lambda: rt.guardian._recovery_telemetry is not None)
    rt.guardian.on_independent_observation(report(rt, observation_sequence=90000))
    assert rt.guardian._independent_sample is not None
    rt.guardian._independent_endpoint_gid = lambda: "new-endpoint"
    rt.guardian.on_independent_observation(report(rt, observer_session="b" * 32, observation_sequence=1))
    new = rt.guardian._independent_sample
    assert new is not None and rt.guardian._independent_sequence == 1
    rt.guardian.on_independent_observation(report(rt, observation_sequence=90001))
    assert rt.guardian._independent_sample is new


def test_report_without_unique_discovered_observer_does_not_consume_session(runtime, monkeypatch):
    rt = start_independent(runtime, monkeypatch)
    rt.wait_for(lambda: rt.guardian._recovery_telemetry is not None)
    rt.guardian._independent_endpoint_gid = lambda: ""
    rt.guardian.on_independent_observation(report(rt))
    assert rt.guardian._observer_sessions.session == ""
    assert rt.guardian._independent_sequence == 0
    assert rt.guardian._independent_sample is None


def test_asynchronous_reports_are_joined_by_source_time_not_arrival_order(runtime, monkeypatch):
    rt = start_independent(runtime, monkeypatch)
    rt.wait_for(lambda: rt.guardian._recovery_telemetry is not None)
    earlier = rt.guardian._recovery_observed_ros_time
    rt.guardian.on_independent_observation(report(rt, odom_timestamp=earlier, scan_timestamp=earlier))
    assert rt.guardian._effective_recovery_telemetry(rt.guardian.monotonic_seconds()).speed == 0.0
    rt.simulator.model.actual_speed = 0.2
    newer = rt.simulator.recovery_message()
    rt.guardian.on_recovery_telemetry(newer)
    # The earlier complete pair remains fresh while the observer's next pair
    # is in transit. Comparing new adapter data with old observer data is wrong.
    effective = rt.guardian._effective_recovery_telemetry(rt.guardian.monotonic_seconds())
    assert effective is not None and effective.speed == 0.0
    rt.guardian.on_independent_observation(report(rt, observation_sequence=2,
        odom_timestamp=newer.timestamp, scan_timestamp=newer.timestamp, actual_speed=0.2))
    assert rt.guardian._effective_recovery_telemetry(rt.guardian.monotonic_seconds()).speed == 0.2
    rt.guardian.on_independent_observation(report(rt, observation_sequence=3,
        odom_timestamp=newer.timestamp, scan_timestamp=newer.timestamp, actual_speed=0.4))
    assert rt.guardian._effective_recovery_telemetry(rt.guardian.monotonic_seconds()) is None
