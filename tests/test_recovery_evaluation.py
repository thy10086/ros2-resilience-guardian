from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "experiments"))
from run_recovery_evaluation import aggregate_runs, qualify_mutants, run_evaluation, replay_counterexample
from run_recovery_feedback_fuzzing import run_campaign


def test_generated_comparison_excludes_curated_warmup(tmp_path):
    seen = []
    report = run_campaign(seed_value=0, budget=8, mode="unguided", include_seeds=False,
        shrink_failures=False, corpus_path=tmp_path / "corpus.json",
        evaluation_hook=lambda actions, trace, origin, index, elapsed: seen.append((origin, index)))
    assert report["seed_executions"] == 0
    assert report["generated_executions"] == 8
    assert {origin for origin, _ in seen} == {"generated"}
    assert [index for _, index in seen] == list(range(1, 9))


def test_qualification_replays_actual_faults_and_full_controls(tmp_path):
    report = qualify_mutants(tmp_path)
    assert report["detected_families"] == 4
    assert not report["control_violations"]
    for case in report["cases"]:
        assert replay_counterexample(case["counterexample_path"])["violation_codes"] == case["violation_codes"]


def test_paired_statistics_keep_seed_pairs():
    runs = []
    for seed, guided, unguided in [(0, 10, 8), (1, 4, 7)]:
        for mode, edges in [("guided", guided), ("unguided", unguided)]:
            runs.append(dict(seed=seed, mode=mode, coverage={"states": 1, "transitions": edges},
                elapsed_sec=1, generated_executions=10, detected_families=1))
    summary = aggregate_runs(runs)
    assert summary["paired_transition_deltas"] == [2, -3]
    assert summary["guided_transition_wins"] == 1
    assert summary["groups"]["guided"]["transitions"]["median"] == 7


def test_small_batch_persists_each_group_and_clean_full_controls(tmp_path):
    report = run_evaluation(seeds=[0], budget=8, output_dir=tmp_path, progress=lambda value: None)
    assert len(report["runs"]) == 3
    assert all(run["generated_executions"] == 8 for run in report["runs"])
    assert report["full_mechanism_violations"] == []
    assert report["qualification"]["detected_families"] == 4
    assert (tmp_path / "summary.json").is_file()


def test_batch_input_validation(tmp_path):
    with pytest.raises(ValueError):
        run_evaluation(seeds=[0, 0], budget=8, output_dir=tmp_path)


def test_ablation_separates_invalid_evidence_from_invalid_permit_and_repair_boundary():
    from run_recovery_evaluation import ablation_report
    cases = ablation_report()["cases"]
    expired = next(c for c in cases if c["scenario"] == "no_proof_ttl" and c["variant"] == "no_proof_ttl")
    assert expired["unsafe_motion_frames"] == 0
    assert expired["unsafe_authorized_frames"] > 0
    control = next(c for c in cases if c["scenario"] == "no_proof_ttl" and c["variant"] == "full")
    assert control["repair_to_allowed_sec"] is None  # no explicit repair action
    repaired = next(c for c in cases if c["scenario"] == "no_independent_observation" and c["variant"] == "full")
    assert 0 < repaired["repair_to_allowed_sec"] < .5


def test_boundary_mode_records_replayable_features_without_warmup(tmp_path):
    from run_recovery_feedback_fuzzing import replay_corpus
    report = run_campaign(seed_value=1, budget=12, mode="boundary", include_seeds=False,
        shrink_failures=False, corpus_path=tmp_path / "boundary.json")
    replay = replay_corpus(tmp_path / "boundary.json")
    assert report["generated_executions"] == 12
    assert report["seed_executions"] == 0
    assert report["boundary_coverage"] == replay["boundary_coverage"]
    assert report["boundary_target_maxima"] == replay["boundary_target_maxima"]
    assert report["boundary_coverage"]
    assert not report["violations"]


def test_boundary_paired_statistics_include_budget_censored_misses():
    runs = []
    for seed in (0, 1):
        for mode in ("unguided", "boundary"):
            first = {"no_proof_ttl": {"test_index": 2, "elapsed_sec": .1}}
            if seed == 1 and mode == "unguided":
                first = {}
            runs.append(dict(seed=seed, mode=mode, budget=10,
                coverage={"states": 1, "transitions": 5 if mode == "boundary" else 3},
                elapsed_sec=1, generated_executions=10, detected_families=len(first), first_defects=first))
    summary = aggregate_runs(runs)
    detection = summary["groups"]["unguided"]["defect_detection"]["no_proof_ttl"]
    assert detection["restricted_first_test_index"]["median"] == 6  # (2 + censored 10) / 2
    pair = summary["paired_comparisons"]["boundary_vs_unguided"]
    assert pair["transition_deltas"] == [2, 2]
    assert pair["defect_detection"]["no_proof_ttl"]["detection_deltas"] == [0, 1]
    assert pair["defect_detection"]["no_proof_ttl"]["restricted_first_index_deltas"] == [0, -8]


def test_selected_modes_are_persisted_and_rotated_without_fixed_inputs(tmp_path):
    report = run_evaluation(seeds=[0, 1], budget=3, output_dir=tmp_path,
        modes=("unguided", "guided", "boundary"), progress=lambda value: None)
    assert [run["mode"] for run in report["runs"]] == [
        "unguided", "guided", "boundary", "guided", "boundary", "unguided"]
    assert all(run["generated_executions"] == 3 and run["seed_executions"] == 0 for run in report["runs"])
    assert "boundary" in report["aggregate"]["groups"]
    assert not report["counterexample_replay_mismatches"]
    assert not report["corpus_replay_mismatches"]
    assert report["replay_verification"]["corpora"] == 6


@pytest.mark.parametrize("modes", [("guided", "guided"), ("unknown",), ()])
def test_invalid_modes_fail_before_creating_output(tmp_path, modes):
    output = tmp_path / "new"
    with pytest.raises(ValueError):
        run_evaluation(seeds=[0], budget=8, modes=modes, output_dir=output)
    assert not output.exists()
