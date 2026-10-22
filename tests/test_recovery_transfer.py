"""New safety contracts are evaluated without adjusting feedback or Oracle."""
import hashlib
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "experiments"))
from guardian_core.recovery_feedback import SafetyOracle
from recovery_scenarios import execute_scenario


def preregistration(tmp_path, *, seeds=(2,), modes=("unguided", "liveness"), wall=.1, cap=3):
    from run_recovery_holdout import frozen_paths, source_hashes
    sources = ("experiments/recovery_liveness_feedback.py", "experiments/permit_boundary_feedback.py",
        "experiments/recovery_scenarios.py", "ros2_ws/src/guardian_core/guardian_core/recovery_feedback.py")
    hashes = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in sources}
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"schema": "guardian-recovery-holdout/v1", "protocol": {
        "validation_scope": "known_defect_new_seed_target_validation",
        "source_sha256": source_hashes(frozen_paths())}}))
    value = {"schema": "guardian-transfer-preregistration/v1", "frozen_before_new_defect_selection": True,
        "source_sha256": hashes, "baseline_report_path": str(baseline),
        "baseline_report_sha256": hashlib.sha256(baseline.read_bytes()).hexdigest(),
        "seeds": list(seeds), "modes": list(modes), "wall_time_sec": wall, "execution_cap": cap}
    path = tmp_path / "protocol.json"
    path.write_text(json.dumps(value))
    (tmp_path / "defect_selection.json").write_text(json.dumps({
        "schema": "guardian-transfer-defect-selection/v1", "feedback_and_results_read": False,
        "families": ["no_motion_envelope", "nonzero_safe_stop_limit"]}))
    return path


@pytest.mark.parametrize(("family", "expected"), [
    ("no_motion_envelope", {"unsafe_candidate", "unsafe_motion"}),
    ("nonzero_safe_stop_limit", {"invalid_speed_limit"}),
])
def test_independent_new_defects_qualify_and_control_stays_safe(family, expected):
    from recovery_transfer_mutations import challenge_scenarios, execute_transfer
    actions = challenge_scenarios()[family]
    assert not SafetyOracle().check_trace(execute_scenario(actions))
    assert expected <= {value.code for value in SafetyOracle().check_trace(execute_transfer(actions, family))}
    assert not SafetyOracle().check_trace(execute_scenario(actions))


@pytest.mark.parametrize("family", ["no_motion_envelope", "nonzero_safe_stop_limit"])
def test_transfer_mutation_refuses_a_missing_site(family):
    from recovery_transfer_mutations import mutate_gate
    with pytest.raises(ValueError, match="site mismatch"):
        mutate_gate("class EvidenceBoundRecovery: pass", family)


def test_selected_suite_has_different_families_and_replays_every_counterexample(tmp_path):
    from run_recovery_holdout import run_holdout_evaluation, replay_case
    protocol = preregistration(tmp_path)
    report = run_holdout_evaluation(seeds=[2], modes=("unguided", "liveness"),
        wall_time_sec=.1, execution_cap=3, output_dir=tmp_path / "results",
        defect_suite="transfer", preregistration=protocol, progress=lambda value: None)
    assert report["protocol"]["defect_suite"] == "transfer"
    assert report["protocol"]["validation_scope"] == "frozen_feedback_new_controlled_defects"
    assert report["preregistration_verified"]
    assert report["qualification"]["detected_families"] == 2
    assert not report["full_mechanism_violations"]
    assert not report["corpus_replay_mismatches"] and not report["counterexample_replay_mismatches"]
    assert report["replay_verification"]["corpora"] == 2
    assert set(report["aggregate"]["groups"]["liveness"]["defect_detection"]) == {
        "no_motion_envelope", "nonzero_safe_stop_limit"}
    for case in report["qualification"]["cases"]:
        assert replay_case(case["counterexample_path"])["matches_saved_codes"]


def test_transfer_requires_matching_preregistration_before_output_creation(tmp_path):
    from run_recovery_holdout import run_holdout_evaluation
    output = tmp_path / "results"
    protocol = preregistration(tmp_path)
    kwargs = dict(seeds=[2], modes=("unguided", "liveness"), wall_time_sec=.1,
        execution_cap=3, output_dir=output, defect_suite="transfer", progress=lambda value: None)
    with pytest.raises(ValueError, match="preregistration"):
        run_holdout_evaluation(**kwargs)
    value = json.loads(protocol.read_text())
    value["source_sha256"]["experiments/recovery_liveness_feedback.py"] = "0" * 64
    protocol.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="preregistration"):
        run_holdout_evaluation(**kwargs, preregistration=protocol)
    assert not output.exists()


def test_seed_or_budget_drift_does_not_start_transfer(tmp_path):
    from run_recovery_holdout import run_holdout_evaluation
    protocol = preregistration(tmp_path)
    with pytest.raises(ValueError, match="preregistration"):
        run_holdout_evaluation(seeds=[3], modes=("unguided", "liveness"),
            wall_time_sec=.1, execution_cap=3, output_dir=tmp_path / "results",
            defect_suite="transfer", preregistration=protocol)
    assert not (tmp_path / "results").exists()


def test_preregistered_snapshot_drift_is_not_accepted(tmp_path):
    from run_recovery_holdout import validate_preregistration, verify_preregistration
    path = preregistration(tmp_path)
    record = validate_preregistration(path, seeds=[2], modes=("unguided", "liveness"),
        wall_time_sec=.1, execution_cap=3)
    snapshot = tmp_path / "snapshot.json"
    snapshot.write_text("changed")
    record["path_snapshot"] = str(snapshot)
    with pytest.raises(ValueError, match="preregistration"):
        verify_preregistration(record)


def test_unknown_suite_is_rejected_before_creating_output(tmp_path):
    from run_recovery_holdout import run_holdout_evaluation
    with pytest.raises(ValueError, match="suite"):
        run_holdout_evaluation(seeds=[2], modes=("unguided",), wall_time_sec=.1,
            execution_cap=3, output_dir=tmp_path / "results", defect_suite="arbitrary")
    assert not (tmp_path / "results").exists()


def test_campaign_driver_drift_is_rejected_against_pinned_baseline(tmp_path):
    from run_recovery_holdout import validate_preregistration
    path = preregistration(tmp_path)
    value = json.loads(path.read_text())
    baseline = Path(value["baseline_report_path"])
    earlier = json.loads(baseline.read_text())
    earlier["protocol"]["source_sha256"][str(ROOT / "experiments/run_recovery_feedback_fuzzing.py")] = "0" * 64
    baseline.write_text(json.dumps(earlier))
    value["baseline_report_sha256"] = hashlib.sha256(baseline.read_bytes()).hexdigest()
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="preregistration"):
        validate_preregistration(path, seeds=[2], modes=("unguided", "liveness"),
            wall_time_sec=.1, execution_cap=3)
