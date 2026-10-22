from dataclasses import replace

from guardian_core.recovery_feedback import RecoveryFrame, SemanticCoverage, SafetyOracle


def frame(**fields):
    defaults = dict(now=1.0, task_phase="navigate", recovery_phase="SAFE_STOP",
        evidence_state="healthy", stopped_ack=True, unresolved=False, forced_stop=False,
        graph_fingerprint="g", policy_fingerprint="p", ledger_anchor="l",
        command_epoch=1, next_command_epoch=1, mission_allowed=False, speed_limit=0.0)
    defaults.update(fields)
    return RecoveryFrame(**defaults)


def test_feedback_normalizes_identifiers_and_heartbeat():
    a = [frame(), frame(now=2), frame(now=3, graph_fingerprint="new")]
    b = [frame(now=100, graph_fingerprint="other", ledger_anchor="other"),
         frame(now=101, graph_fingerprint="changed", ledger_anchor="other")]
    first, second = SemanticCoverage(), SemanticCoverage()
    first.observe_trace(a)
    second.observe_trace(b)
    assert first.states == second.states
    assert first.edges == second.edges
    assert len(first.edges) == 1
    assert not first.observe_trace(a)


def test_unsafe_motion_is_a_violation_not_novelty():
    violations = SafetyOracle().check_trace([frame(mission_allowed=True, evidence_state="stale")])
    assert "unsafe_motion" in {v.code for v in violations}


def test_binding_expiry_and_reuse_are_checked_against_raw_values():
    proof = dict(proof_id="one", graph_fingerprint="g", policy_fingerprint="p",
        ledger_anchor="l", command_epoch=2, issued_at=1.0, expires_at=1.5)
    candidate = frame(recovery_phase="RECOVERY_CANDIDATE", pending_proof=proof)
    resumed = frame(now=1.1, recovery_phase="RESUMABLE", mission_allowed=True,
        consumed_proof_id="one", next_command_epoch=2)
    assert not SafetyOracle().check_trace([candidate, resumed])
    for changed, code in [(replace(resumed, graph_fingerprint="bad"), "context_mismatch"),
                          (replace(resumed, next_command_epoch=3), "context_mismatch"),
                          (replace(resumed, command_epoch=99), "context_mismatch"),
                          (replace(resumed, now=1.5), "expired_proof")]:
        assert code in {v.code for v in SafetyOracle().check_trace([candidate, changed])}
    assert "proof_reuse" in {v.code for v in SafetyOracle().check_trace([candidate, resumed, resumed])}


def test_liveness_requires_continuously_eligible_stopped_window():
    oracle = SafetyOracle(liveness_sec=2)
    continuous = [frame(now=1 + i * .05) for i in range(62)]
    assert "recovery_stalled" in {v.code for v in oracle.check_trace(continuous)}
    assert not oracle.check_trace([frame(), frame(now=4, forced_stop=True)])
    assert not oracle.check_trace([frame(), frame(now=4, evidence_state="missing")])


def test_controller_suspensions_are_not_continuously_eligible_recovery():
    from pathlib import Path
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "experiments"))
    from recovery_scenarios import Action, execute_scenario
    trace = execute_scenario([Action("gap", .6)] * 6 + [Action("wait", .6)])
    assert trace[-1].mission_allowed
    assert not SafetyOracle().check_trace(trace)


def test_long_sample_gap_restarts_liveness_but_later_continuous_stall_is_detected():
    oracle = SafetyOracle(liveness_sec=.5, max_frame_gap_sec=.25)
    moments = [1.0, 1.05, 2.0] + [2.0 + i * .05 for i in range(1, 12)]
    violations = oracle.check_trace([frame(now=moment) for moment in moments])
    assert [v.frame_index for v in violations if v.code == "recovery_stalled"] == [len(moments) - 1]


def test_gap_reset_does_not_disable_expired_proof_detection():
    proof = dict(proof_id="one", graph_fingerprint="g", policy_fingerprint="p",
        ledger_anchor="l", command_epoch=2, issued_at=1.0, expires_at=1.5)
    trace = [frame(recovery_phase="RECOVERY_CANDIDATE", pending_proof=proof),
        frame(now=1.6, recovery_phase="RESUMABLE", mission_allowed=True,
            consumed_proof_id="one", next_command_epoch=2)]
    assert "expired_proof" in {v.code for v in SafetyOracle().check_trace(trace)}


def test_liveness_maximum_frame_gap_is_strict_and_validated():
    import pytest
    oracle = SafetyOracle(liveness_sec=.5, max_frame_gap_sec=.25)
    assert "recovery_stalled" in {v.code for v in oracle.check_trace([
        frame(now=1 + i * .25) for i in range(4)])}
    assert not oracle.check_trace([frame(now=1 + i * .26) for i in range(4)])
    for value in (0, -1, True, float("nan"), float("inf")):
        with pytest.raises(ValueError):
            SafetyOracle(max_frame_gap_sec=value)


def test_candidate_requires_zero_motion_ack_and_healthy_evidence():
    proof = dict(proof_id="x", graph_fingerprint="g", policy_fingerprint="p",
        ledger_anchor="l", command_epoch=2, issued_at=1.0, expires_at=1.5)
    violations = SafetyOracle().check_trace([frame(recovery_phase="RECOVERY_CANDIDATE",
        pending_proof=proof, stopped_ack=False)])
    assert "unsafe_candidate" in {v.code for v in violations}


def test_roundtrip_preserves_raw_bindings():
    original = frame(graph_fingerprint="exact-hash")
    assert RecoveryFrame.from_dict(original.to_dict()) == original


def test_trace_schema_rejects_truthy_non_boolean_input():
    import pytest
    with pytest.raises(ValueError):
        frame(mission_allowed="false")


def test_resume_without_matching_stop_ack_is_detected():
    proof = dict(proof_id="one", graph_fingerprint="g", policy_fingerprint="p",
        ledger_anchor="l", command_epoch=2, issued_at=1.0, expires_at=1.5)
    trace = [frame(recovery_phase="RECOVERY_CANDIDATE", pending_proof=proof),
        frame(now=1.1, recovery_phase="RESUMABLE", mission_allowed=True,
            consumed_proof_id="one", next_command_epoch=2, stopped_ack=False)]
    assert "unsafe_resume" in {v.code for v in SafetyOracle().check_trace(trace)}


def test_safe_stop_revokes_previously_issued_proof():
    proof = dict(proof_id="one", graph_fingerprint="g", policy_fingerprint="p",
        ledger_anchor="l", command_epoch=2, issued_at=1.0, expires_at=1.5)
    trace = [frame(recovery_phase="RECOVERY_CANDIDATE", pending_proof=proof),
        frame(now=1.05, stopped_ack=False),
        frame(now=1.1, recovery_phase="RESUMABLE", mission_allowed=True,
            consumed_proof_id="one", next_command_epoch=2)]
    assert "missing_proof" in {v.code for v in SafetyOracle().check_trace(trace)}


def test_same_frame_issuance_does_not_authorize_resume():
    proof = dict(proof_id="one", graph_fingerprint="g", policy_fingerprint="p",
        ledger_anchor="l", command_epoch=2, issued_at=1.0, expires_at=1.5)
    trace = [frame(now=1.1, recovery_phase="RESUMABLE", mission_allowed=True,
        consumed_proof_id="one", next_command_epoch=2, pending_proof=proof)]
    assert "missing_proof" in {v.code for v in SafetyOracle().check_trace(trace)}


def test_normal_output_epoch_must_preserve_the_consumed_authorization():
    proof = dict(proof_id="one", graph_fingerprint="g", policy_fingerprint="p",
        ledger_anchor="l", command_epoch=2, issued_at=1.0, expires_at=1.5)
    candidate = frame(recovery_phase="RECOVERY_CANDIDATE", pending_proof=proof)
    resumed = frame(now=1.1, recovery_phase="RESUMABLE", mission_allowed=True,
        consumed_proof_id="one", next_command_epoch=2)
    normal = frame(now=1.2, recovery_phase="NORMAL", mission_allowed=True,
        stopped_ack=False, observed_speed=.2, consumed_proof_id="one",
        command_epoch=2, next_command_epoch=2)
    assert not SafetyOracle().check_trace([candidate, resumed, normal])

    violations = SafetyOracle().check_trace([
        candidate, resumed, replace(normal, next_command_epoch=999)])

    assert [(v.code, v.frame_index) for v in violations] == [("unauthorized_continuation", 2)]
