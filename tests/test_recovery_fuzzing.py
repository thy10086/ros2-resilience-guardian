from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "experiments"))
from recovery_scenarios import Action, execute_scenario
from guardian_core.recovery_feedback import SafetyOracle, SemanticCoverage


def test_nominal_scenario_executes_actual_two_phase_recovery():
    trace = execute_scenario([Action("healthy", 0.4), Action("wait", 0.1)])
    assert {f.recovery_phase for f in trace} >= {"RECOVERY_CANDIDATE", "RESUMABLE", "NORMAL"}
    assert not SafetyOracle().check_trace(trace)


def test_faults_stop_and_repairs_require_new_proof():
    for fault in ("stale", "replay", "invalid_scan", "speed_mismatch", "near_obstacle",
                  "commands_pending", "probe_failed", "incident", "graph_missing"):
        trace = execute_scenario([Action("healthy", .5), Action(fault, .2), Action("healthy", .6)])
        assert any(not f.mission_allowed for f in trace if .5 < f.now - 1 <= .7 + 1e-8)
        assert trace[-1].mission_allowed
        assert not SafetyOracle().check_trace(trace), fault


def test_pending_proof_context_change_cannot_resume_with_old_binding():
    for change in ("graph_change", "policy_change", "epoch_change"):
        trace = execute_scenario([Action("healthy", .25), Action(change, .05), Action("wait", .6)])
        assert trace[4].pending_proof is not None
        assert trace[5].recovery_phase == "SAFE_STOP"
        assert trace[-1].mission_allowed
        assert not SafetyOracle().check_trace(trace)


def test_replay_has_same_semantic_coverage():
    actions = [Action("healthy", .5), Action("replay", .2), Action("healthy", .5)]
    a, b = SemanticCoverage(), SemanticCoverage()
    a.observe_trace(execute_scenario(actions))
    b.observe_trace(execute_scenario(actions))
    assert a.states == b.states and a.edges == b.edges


def test_controller_gap_expires_candidate_in_actual_protocol():
    trace = execute_scenario([Action("healthy", .25), Action("gap", .51), Action("wait", .5)])
    assert trace[4].pending_proof is not None
    assert trace[5].recovery_phase == "SAFE_STOP"
    assert trace[5].pending_proof is None
    assert trace[-1].mission_allowed
    assert not SafetyOracle().check_trace(trace)


def test_action_validation_rejects_unbounded_or_unknown_inputs():
    import pytest
    for fields in [("unknown", .1), ("wait", -1), ("wait", float("nan")), ("wait", 100), ("wait", True)]:
        with pytest.raises(ValueError):
            Action(*fields)


def test_hypothesis_campaign_and_saved_corpus_replay(tmp_path):
    import pytest
    pytest.importorskip("hypothesis")
    from run_recovery_feedback_fuzzing import run_campaign, replay_corpus
    report = run_campaign(seed_value=42, budget=12, mode="guided", corpus_path=tmp_path / "corpus.json")
    assert report["generated_executions"] >= 12
    assert report["coverage"]["transitions"] > 0
    assert not report["violations"]
    replay = replay_corpus(tmp_path / "corpus.json")
    assert replay["coverage"] == report["coverage"]
    assert not replay["violations"]


def test_failure_reduction_produces_replayable_counterexample(tmp_path, monkeypatch):
    import pytest
    pytest.importorskip("hypothesis")
    import run_recovery_feedback_fuzzing as runner
    from guardian_core.recovery_feedback import SafetyViolation
    class InjectedOracle:
        def check_trace(self, frames):
            return [SafetyViolation("injected_resume_regression", 0, "test-only")]
    monkeypatch.setattr(runner, "SafetyOracle", InjectedOracle)
    report = runner.run_campaign(seed_value=42, budget=1, mode="unguided",
        corpus_path=tmp_path / "corpus.json")
    failure = report["violations"][0]
    assert failure["reduction"] == "hypothesis_find"
    minimized = [Action(**action) for action in failure["minimized_actions"]]
    assert len(minimized) <= len(failure["actions"])
    assert InjectedOracle().check_trace(execute_scenario(minimized))
