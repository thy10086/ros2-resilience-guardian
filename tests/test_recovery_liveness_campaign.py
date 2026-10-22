"""New labels, equal feature collection and replay must agree with execution."""
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "experiments"))
from recovery_scenarios import Action
from run_recovery_feedback_fuzzing import run_campaign, replay_corpus
from run_recovery_holdout import aggregate_holdout, run_holdout_evaluation


@pytest.mark.parametrize("mode,labels", [
    ("liveness", {"recovery_stable_health_sec", "recovery_progress"}),
    ("boundary_liveness", {"permit_ttl_diversity", "permit_expiry_proximity",
        "permit_context_diversity", "repair_transition_diversity",
        "recovery_stable_health_sec", "recovery_progress"}),
    ("unguided", set()),
])
def test_actual_targets_and_same_profile_collection(tmp_path, monkeypatch, mode, labels):
    import hypothesis
    observed = []
    original = hypothesis.target

    def capture(value, *, label):
        observed.append(label)
        return original(value, label=label)

    monkeypatch.setattr(hypothesis, "target", capture)
    report = run_campaign(seed_value=3, mode=mode, budget=8,
        corpus_path=tmp_path / "corpus.json", include_seeds=False,
        shrink_failures=False, collect_liveness=True)
    assert set(observed) == labels
    assert len(observed) == 8 * len(labels)
    assert set(report["active_target_labels"]) == labels
    assert set(report["liveness_target_maxima"]) == {"recovery_stable_health_sec", "recovery_progress"}
    replay = replay_corpus(tmp_path / "corpus.json")
    for key in ("coverage", "boundary_coverage", "boundary_target_maxima",
            "liveness_coverage", "liveness_target_maxima"):
        assert replay[key] == report[key]
    assert not report["violations"] and not replay["violations"]


def test_liveness_mode_records_duration_and_implicit_collection(tmp_path, monkeypatch):
    import run_recovery_feedback_fuzzing as campaign
    import hypothesis.strategies as st
    monkeypatch.setattr(campaign, "action_strategy", lambda: st.just([
        Action("healthy", 1), Action("wait", 1), Action("wait", 1), Action("wait", 1)]))
    report = run_campaign(seed_value=3, mode="liveness", budget=8,
        corpus_path=tmp_path / "corpus.json", include_seeds=False,
        shrink_failures=False)
    assert report["liveness_target_maxima"] == {"recovery_stable_health_sec": 3.95, "recovery_progress": 4}
    assert "health_window:ge_3" in report["liveness_coverage"]
    assert replay_corpus(tmp_path / "corpus.json")["liveness_target_maxima"] == report["liveness_target_maxima"]


def test_larger_window_keeps_witness_after_feature_bucket_saturation(tmp_path, monkeypatch):
    import run_recovery_feedback_fuzzing as campaign
    first = [Action("healthy", 1)] + [Action("wait", 1)] * 3
    second = first + [Action("wait", 1)]
    monkeypatch.setattr(campaign, "seed_scenarios", lambda: [first, second])
    report = run_campaign(seed_value=3, mode="fixed", budget=2,
        corpus_path=tmp_path / "corpus.json", include_seeds=False,
        shrink_failures=False, collect_liveness=True)
    assert report["interesting_cases"] == 2
    assert report["liveness_target_maxima"]["recovery_stable_health_sec"] == 4.95
    assert replay_corpus(tmp_path / "corpus.json")["liveness_target_maxima"] == report["liveness_target_maxima"]


def test_new_profile_configuration_cannot_be_silently_reinterpreted(tmp_path):
    path = tmp_path / "corpus.json"
    path.write_text(json.dumps({"schema_version": 1, "cases": [],
        "liveness_config": {"max_frame_gap_sec": 100, "window_cap_sec": 6, "duration_precision": 6}}))
    with pytest.raises(ValueError, match="liveness"):
        replay_corpus(path)


def test_four_mode_batch_rotates_and_replays_all_metrics(tmp_path):
    modes = ("unguided", "boundary", "liveness", "boundary_liveness")
    report = run_holdout_evaluation(seeds=[2, 3], wall_time_sec=.1, execution_cap=3,
        modes=modes, output_dir=tmp_path / "new", progress=lambda value: None)
    assert [run["mode"] for run in report["runs"]] == [
        "unguided", "boundary", "liveness", "boundary_liveness",
        "boundary", "liveness", "boundary_liveness", "unguided"]
    assert report["protocol"]["validation_scope"] == "known_defect_new_seed_target_validation"
    assert report["protocol"]["liveness_metrics_collected_for_all_modes"]
    assert all(run["liveness_config"] for run in report["runs"])
    assert report["replay_verification"]["corpora"] == 8
    assert not report["corpus_replay_mismatches"]
    assert not report["counterexample_replay_mismatches"]
    assert not report["full_mechanism_violations"]
    assert set(report["aggregate"]["groups"]) == set(modes)
    assert "boundary_liveness_vs_liveness" in report["aggregate"]["paired_comparisons"]


@pytest.mark.parametrize("modes", [(), ("liveness", "liveness"), ("unknown",)])
def test_bad_mode_selection_does_not_create_output(tmp_path, modes):
    output = tmp_path / "new"
    with pytest.raises(ValueError):
        run_holdout_evaluation(seeds=[2], wall_time_sec=.1, execution_cap=3,
            modes=modes, output_dir=output)
    assert not output.exists()


def test_new_mode_time_comparison_retains_misses():
    runs = []
    for seed, mode, when in ((2, "liveness", 1), (2, "unguided", None),
            (3, "unguided", 2), (3, "liveness", None)):
        runs.append(dict(seed=seed, mode=mode, wall_time_sec=5, search_elapsed_sec=5.1,
            deadline_overrun_sec=.1, generated_executions=10,
            coverage={"states": 2, "transitions": 3},
            first_defects={} if when is None else {"never_resume": {"elapsed_sec": when}}))
    result = aggregate_holdout(runs)
    pair = result["paired_comparisons"]["liveness_vs_unguided"]["defect_detection"]["never_resume"]
    assert pair["detection_deltas"] == [1, -1]
    assert pair["restricted_first_time_deltas"] == [-4, 3]
    assert pair["restricted_first_time_delta_median"] == -.5
