"""Previously unbenchmarked defects, fair time censoring and frozen sources."""
import json
from pathlib import Path
import sys
import time

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "experiments"))
from guardian_core.recovery_feedback import SafetyOracle
from recovery_scenarios import Action, execute_scenario


@pytest.mark.parametrize("family,expected", [
    ("ignore_stop_ack", {"unsafe_candidate", "unsafe_resume"}),
    ("wrong_next_epoch", {"candidate_binding_mismatch", "context_mismatch"}),
    ("never_resume", {"recovery_stalled"}),
])
def test_new_defect_challenge_fails_but_real_control_remains_safe(family, expected):
    from recovery_holdout_mutations import challenge_scenarios, execute_holdout
    actions = challenge_scenarios()[family]
    assert not SafetyOracle().check_trace(execute_scenario(actions))
    violations = SafetyOracle().check_trace(execute_holdout(actions, family))
    assert expected <= {v.code for v in violations}


def test_new_mutation_does_not_silently_match_missing_sites():
    from recovery_holdout_mutations import mutate_gate
    with pytest.raises(ValueError, match="site mismatch"):
        mutate_gate("class EvidenceBoundRecovery: pass", "ignore_stop_ack")


def test_original_core_still_resumes_after_all_holdout_variants():
    from recovery_holdout_mutations import challenge_scenarios, execute_holdout
    for family, actions in challenge_scenarios().items():
        execute_holdout(actions, family)
    trace = execute_scenario([Action("healthy", .6)])
    assert any(frame.mission_allowed for frame in trace)
    assert not SafetyOracle().check_trace(trace)


def test_time_statistics_include_misses_and_match_seeds_independently_of_order():
    from run_recovery_holdout import aggregate_holdout
    runs = []
    for seed, mode, when in ((21, "boundary", None), (20, "unguided", 2),
            (20, "boundary", 1), (21, "unguided", None)):
        runs.append({"seed": seed, "mode": mode, "wall_time_sec": 5,
            "search_elapsed_sec": 5.1, "deadline_overrun_sec": .1,
            "generated_executions": 10, "coverage": {"states": 2, "transitions": 3},
            "first_defects": {} if when is None else {"ignore_stop_ack": {"elapsed_sec": when}}})
    result = aggregate_holdout(runs)
    group = result["groups"]["boundary"]["defect_detection"]["ignore_stop_ack"]
    assert group["restricted_first_time_sec"]["median"] == 3  # (1 + capped miss 5) / 2
    assert group["detection_rate_interval"]["method"] == "Wilson 95%"
    pair = result["paired_comparisons"]["boundary_vs_unguided"]["defect_detection"]["ignore_stop_ack"]
    assert pair["restricted_first_time_deltas"] == [-1, 0]
    assert pair["detection_deltas"] == [0, 0]


@pytest.mark.parametrize("when", [-1, 5.01, float("nan")])
def test_time_aggregate_rejects_out_of_window_detection(when):
    from run_recovery_holdout import aggregate_holdout
    with pytest.raises(ValueError):
        aggregate_holdout([dict(seed=20, mode="unguided", wall_time_sec=5,
            search_elapsed_sec=5, deadline_overrun_sec=0, generated_executions=10,
            coverage={"states": 2, "transitions": 3},
            first_defects={"ignore_stop_ack": {"elapsed_sec": when}})])


def test_output_cannot_overwrite_an_earlier_experiment(tmp_path):
    from run_recovery_holdout import run_holdout_evaluation
    sentinel = tmp_path / "summary.json"
    sentinel.write_text("earlier result")
    with pytest.raises(FileExistsError):
        run_holdout_evaluation(seeds=[20], wall_time_sec=.05, execution_cap=3,
            output_dir=tmp_path, progress=lambda value: None)
    assert sentinel.read_text() == "earlier result"


def test_source_drift_is_a_failed_freeze(tmp_path):
    from run_recovery_holdout import source_hashes, verify_sources
    source = tmp_path / "source.py"
    source.write_text("original")
    frozen = source_hashes([source])
    source.write_text("changed")
    with pytest.raises(ValueError, match="source changed"):
        verify_sources(frozen)


def test_small_holdout_batch_saves_and_replays_every_case(tmp_path):
    from run_recovery_holdout import run_holdout_evaluation
    report = run_holdout_evaluation(seeds=[20, 21], wall_time_sec=.1, execution_cap=3,
        output_dir=tmp_path / "new", progress=lambda value: None)
    assert [run["mode"] for run in report["runs"]] == [
        "unguided", "guided", "boundary", "guided", "boundary", "unguided"]
    assert report["qualification"]["detected_families"] == 3
    assert not report["qualification"]["control_violations"]
    assert not report["full_mechanism_violations"]
    assert report["replay_verification"]["corpora"] == 6
    assert not report["counterexample_replay_mismatches"]
    assert not report["corpus_replay_mismatches"]
    assert report["source_freeze_verified"]
    assert all(run["seed_executions"] == 0 for run in report["runs"])
    assert all(case["elapsed_sec"] <= .1 for run in report["runs"]
        for case in run["first_defects"].values())
    stored = json.loads((tmp_path / "new" / "summary.json").read_text())
    assert stored["replay_verification"] == report["replay_verification"]


def test_detection_completed_after_deadline_is_saved_but_not_counted(tmp_path, monkeypatch):
    import run_recovery_feedback_fuzzing as campaign
    import run_recovery_holdout as evaluation
    from hypothesis import strategies as st
    original = evaluation.execute_holdout

    def slow_defect(actions, family):
        result = original(actions, family)
        time.sleep(.06)
        return result

    monkeypatch.setattr(evaluation, "execute_holdout", slow_defect)
    monkeypatch.setattr(campaign, "action_strategy", lambda: st.lists(
        st.just(Action("ack_missing", .6)), min_size=1, max_size=32))
    report = evaluation.benchmark_holdout(20, "unguided", .05, 10000, tmp_path, lambda value: None)
    assert not report["first_defects"]
    assert report["out_of_budget_defects"]["ignore_stop_ack"]["elapsed_sec"] > .05
    path = report["out_of_budget_defects"]["ignore_stop_ack"]["counterexample_path"]
    assert evaluation.replay_case(path)["matches_saved_codes"]


def test_run_preserves_source_snapshot_matching_frozen_digests(tmp_path):
    from run_recovery_holdout import run_holdout_evaluation, source_hashes
    report = run_holdout_evaluation(seeds=[20], wall_time_sec=.1, execution_cap=1,
        output_dir=tmp_path / "new", progress=lambda value: None)
    snapshots = report["protocol"]["source_snapshots"]
    for original, snapshot in snapshots.items():
        digest = source_hashes([snapshot])[str(Path(snapshot).resolve())]
        assert digest == report["protocol"]["source_sha256"][original]
