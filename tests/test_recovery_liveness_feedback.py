"""Liveness targets read only full-control audit traces."""
from dataclasses import replace
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "experiments"))
from guardian_core.recovery_feedback import RecoveryFrame
from recovery_scenarios import Action, execute_scenario
from recovery_liveness_feedback import RecoveryLivenessFeedback


def frame(now, **changes):
    value = RecoveryFrame(now, "stabilize", "SAFE_STOP", "healthy", True,
        False, False, "graph", "policy", "ledger", 1, 1, False, 0, 0)
    return replace(value, **changes)


def score(trace):
    return RecoveryLivenessFeedback.from_trace(trace).health_window_sec


def test_continuous_ready_window_uses_elapsed_time_not_frame_count():
    a, b, c = frame(0), frame(.2), frame(.4)
    assert score([a, b, c]) == pytest.approx(.4)
    assert score([a, a, b, b, c, c]) == pytest.approx(.4)


@pytest.mark.parametrize("changes", [
    {"evidence_state": "stale"}, {"unresolved": True}, {"forced_stop": True},
    {"stopped_ack": False}, {"observed_speed": .2},
    {"observed_speed": float("nan")}, {"graph_fingerprint": ""},
    {"policy_fingerprint": ""}, {"ledger_anchor": ""},
])
def test_ineligible_frame_breaks_continuity(changes):
    assert score([frame(0), frame(.1, **changes), frame(.2)]) == 0


@pytest.mark.parametrize("changes", [
    {"graph_fingerprint": "changed"}, {"policy_fingerprint": "changed"},
    {"ledger_anchor": "changed"}, {"command_epoch": 3, "next_command_epoch": 3},
])
def test_exact_binding_change_restarts_window(changes):
    assert score([frame(0), frame(.1, **changes)]) == 0


def test_authorized_epoch_advance_keeps_healthy_running_window():
    start = frame(0)
    resumable = frame(.2, recovery_phase="RESUMABLE", mission_allowed=True,
        stopped_ack=True, command_epoch=1, next_command_epoch=2,
        consumed_proof_id="proof", speed_limit=.2, observed_speed=.2)
    normal = frame(.4, recovery_phase="NORMAL", mission_allowed=True,
        stopped_ack=False, command_epoch=2, next_command_epoch=2,
        consumed_proof_id="proof", speed_limit=.2, observed_speed=.2)
    feedback = RecoveryLivenessFeedback.from_trace([start, resumable, normal])
    assert feedback.targets() == {"recovery_stable_health_sec": .4, "recovery_progress": 4}


@pytest.mark.parametrize(("gap", "expected"), [(.25, .25), (.250001, 0)])
def test_sampling_gap_boundary_is_explicit(gap, expected):
    assert score([frame(0), frame(gap)]) == pytest.approx(expected)


def test_long_healthy_window_is_bounded_at_six_seconds():
    assert score([frame(i / 5) for i in range(40)]) == 6


@pytest.mark.parametrize(("phase", "allowed", "consumed", "pending", "expected"), [
    ("RECOVERY_CANDIDATE", False, "", None, 1),
    ("RECOVERY_CANDIDATE", False, "", "proof", 2),
    ("RESUMABLE", True, "", None, 0),
    ("RECOVERY_PROBING", False, "", None, 1),
])
def test_progress_requires_issued_candidate_and_consumed_resume(
        phase, allowed, consumed, pending, expected):
    if pending:
        pending = {"proof_id": pending, "graph_fingerprint": "graph",
            "policy_fingerprint": "policy", "ledger_anchor": "ledger",
            "command_epoch": 1, "issued_at": 0, "expires_at": 1}
    value = frame(.1, recovery_phase=phase, mission_allowed=allowed,
        consumed_proof_id=consumed, pending_proof=pending)
    assert RecoveryLivenessFeedback.from_trace([value]).recovery_progress == expected


def test_renaming_and_time_offset_do_not_create_feedback():
    original = [frame(t) for t in (0, .2, .4)]
    transformed = [replace(item, now=item.now + 100, graph_fingerprint="g2",
        policy_fingerprint="p2", ledger_anchor="l2", command_epoch=20,
        next_command_epoch=20) for item in original]
    left, right = (RecoveryLivenessFeedback.from_trace(trace)
        for trace in (original, transformed))
    assert right.targets() == left.targets()
    assert right.features() == left.features()


@pytest.mark.parametrize("trace", [
    [frame(0), frame(-.1)], [frame(float("nan"))],
    [frame(0), frame(0, ledger_anchor="conflicting")],
])
def test_invalid_timeline_is_rejected(trace):
    with pytest.raises(ValueError):
        RecoveryLivenessFeedback.from_trace(trace)


def test_window_is_time_shift_invariant_at_the_real_frame_gap_boundary():
    times = (0, .25, .5, .7500000000000002, 1, 1.25, 1.5, 1.75, 2, 2.25, 2.5)
    ordinary = score([frame(t) for t in times])
    shifted = score([frame(100 + t) for t in times])
    assert ordinary == pytest.approx(2.5)
    assert shifted == pytest.approx(ordinary)


def test_real_recovery_trace_is_time_shift_invariant_at_sampling_boundary():
    trace = execute_scenario([Action("healthy", .25), Action("healthy", .5),
        Action("gap", .25), Action("wait", 1)])
    gaps = [b.now - a.now for a, b in zip(trace, trace[1:])]
    assert any(.25 < gap <= .25 + 1e-9 for gap in gaps)
    shifted = [replace(item, now=item.now + 100) for item in trace]
    ordinary = RecoveryLivenessFeedback.from_trace(trace)
    translated = RecoveryLivenessFeedback.from_trace(shifted)
    assert ordinary.health_window_sec == pytest.approx(1.95)
    assert translated.targets() == ordinary.targets()
    assert translated.features() == ordinary.features()


@pytest.mark.parametrize("changed", [
    {"graph_fingerprint": "graph-B"}, {"policy_fingerprint": "policy-B"},
    {"ledger_anchor": "3:new-anchor"}, {"evidence_state": "stale"},
    {"evidence_state": "attack"},
])
def test_context_or_unhealthy_evidence_resets_continuous_window(changed):
    trace = [frame(t) for t in (0.0, .2, .4)]
    trace.extend([frame(.6, **changed), frame(.8, **changed), frame(1.0, **changed)])
    assert score(trace) == pytest.approx(.4)
