from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "experiments"))
from run_recovery_feedback_fuzzing import run_campaign, replay_corpus
from run_recovery_evaluation import aggregate_runs, run_evaluation


@pytest.mark.parametrize("mode,labels", [
    ("ttl", {"permit_ttl_diversity", "permit_expiry_proximity"}),
    ("context_repair", {"permit_context_diversity", "repair_transition_diversity"}),
    ("boundary", {"permit_ttl_diversity", "permit_expiry_proximity",
        "permit_context_diversity", "repair_transition_diversity"}),
])
def test_actual_hypothesis_calls_apply_only_selected_target_families(tmp_path, monkeypatch, mode, labels):
    import hypothesis
    calls = []
    original = hypothesis.target
    def capture(value, *, label):
        calls.append((label, value))
        original(value, label=label)
    monkeypatch.setattr(hypothesis, "target", capture)
    report = run_campaign(seed_value=10, budget=8, mode=mode, include_seeds=False,
        shrink_failures=False, corpus_path=tmp_path / "corpus.json")
    assert report["generated_executions"] == 8 and report["seed_executions"] == 0
    assert {label for label, _ in calls} == labels
    assert len(calls) == 8 * len(labels)
    assert set(report["active_target_labels"]) == labels
    assert len(report["boundary_target_maxima"]) == 4  # collect inactive features too
    replay = replay_corpus(tmp_path / "corpus.json")
    assert replay["coverage"] == report["coverage"]
    assert replay["boundary_target_maxima"] == report["boundary_target_maxima"]
    assert replay["boundary_coverage"] == report["boundary_coverage"]
    assert not report["violations"] and not replay["violations"]


def test_ablation_pairs_include_censored_missing_detection():
    runs = []
    for mode, edge_count, first in (("unguided", 8, 4), ("boundary", 7, None),
            ("ttl", 6, 2), ("context_repair", 10, None)):
        runs.append(dict(seed=10, mode=mode, budget=8, generated_executions=8,
            coverage={"states": 2, "transitions": edge_count}, elapsed_sec=1,
            detected_families=int(first is not None),
            first_defects={} if first is None else {"no_proof_ttl": {"test_index": first, "elapsed_sec": .1}}))
    report = aggregate_runs(runs)
    assert report["groups"]["ttl"]["defect_detection"]["no_proof_ttl"]["detected_runs"] == 1
    for name, expected in (("ttl_vs_unguided", -2), ("ttl_vs_boundary", -6),
            ("context_repair_vs_boundary", 0), ("ttl_vs_context_repair", -6)):
        assert report["paired_comparisons"][name]["defect_detection"]["no_proof_ttl"][
            "restricted_first_index_deltas"] == [expected]


def test_unseen_seed_role_and_new_modes_survive_small_batch(tmp_path):
    report = run_evaluation(seeds=[10], budget=4, output_dir=tmp_path,
        modes=("unguided", "boundary", "ttl", "context_repair"), seed_role="unseen_validation",
        progress=lambda value: None)
    assert report["protocol"]["seed_role"] == "unseen_validation"
    assert len(report["runs"]) == 4
    assert report["protocol"]["target_labels_by_mode"]["ttl"] == [
        "permit_ttl_diversity", "permit_expiry_proximity"]
    assert all(run["seed_executions"] == 0 and run["generated_executions"] == 4 for run in report["runs"])
    assert report["replay_verification"]["corpora"] == 4
    assert not report["counterexample_replay_mismatches"]
    assert not report["corpus_replay_mismatches"]


def test_unknown_seed_role_rejected_before_output(tmp_path):
    output = tmp_path / "new"
    with pytest.raises(ValueError):
        run_evaluation(seeds=[10], budget=4, output_dir=output, seed_role="unknown")
    assert not output.exists()
