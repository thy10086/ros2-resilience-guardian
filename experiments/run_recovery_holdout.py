"""Frozen-oracle, new-defect validation with equal soft wall-clock budgets."""
import argparse
from dataclasses import asdict
import hashlib
import json
import math
from pathlib import Path
import platform
import statistics
import sys
import time
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ros2_ws/src/guardian_core"))
from guardian_core.recovery_feedback import SafetyOracle
from recovery_holdout_mutations import FAMILIES, EXPECTED_CODES, challenge_scenarios, execute_holdout
from recovery_scenarios import Action, execute_scenario
from run_recovery_feedback_fuzzing import TARGET_LABELS, run_campaign, replay_corpus, write_json
from recovery_liveness_feedback import RecoveryLivenessFeedback

MODES = ("unguided", "guided", "boundary")
ALLOWED_MODES = (*MODES, "liveness", "boundary_liveness")
PREREGISTERED_SOURCES = ("experiments/recovery_liveness_feedback.py",
    "experiments/permit_boundary_feedback.py", "experiments/recovery_scenarios.py",
    "ros2_ws/src/guardian_core/guardian_core/recovery_feedback.py")


def get_defect_suite(name="holdout"):
    if name == "holdout":
        return SimpleNamespace(families=FAMILIES, expected=EXPECTED_CODES,
            execute=execute_holdout, challenges=challenge_scenarios)
    if name == "transfer":
        import recovery_transfer_mutations as selected
        return SimpleNamespace(families=selected.FAMILIES, expected=selected.EXPECTED_CODES,
            execute=selected.execute_transfer, challenges=selected.challenge_scenarios)
    raise ValueError("unsupported defect suite")


def validate_preregistration(path, *, seeds, modes, wall_time_sec, execution_cap):
    if path is None:
        raise ValueError("transfer requires preregistration")
    path = Path(path).resolve()
    value = json.loads(path.read_text(encoding="utf-8"))
    if (value.get("schema") != "guardian-transfer-preregistration/v1"
            or value.get("frozen_before_new_defect_selection") is not True
            or value.get("seeds") != list(seeds) or value.get("modes") != list(modes)
            or value.get("wall_time_sec") != wall_time_sec or value.get("execution_cap") != execution_cap
            or set(value.get("source_sha256", {})) != set(PREREGISTERED_SOURCES)):
        raise ValueError("preregistration protocol differs from requested validation")
    for source, digest in value["source_sha256"].items():
        if hashlib.sha256((ROOT / source).read_bytes()).hexdigest() != digest:
            raise ValueError(f"preregistration source changed: {source}")
    baseline = Path(value.get("baseline_report_path",
        ROOT / "experiments/results/recovery_liveness_validation/summary.json")).resolve()
    if hashlib.sha256(baseline.read_bytes()).hexdigest() != value.get("baseline_report_sha256"):
        raise ValueError("preregistration baseline report changed")
    prior = json.loads(baseline.read_text(encoding="utf-8"))
    if (prior.get("schema") != "guardian-recovery-holdout/v1" or
            prior.get("protocol", {}).get("validation_scope") != "known_defect_new_seed_target_validation"):
        raise ValueError("preregistration baseline is not the prior target validation")
    previous_hashes = prior["protocol"].get("source_sha256", {})
    for source, digest in value["source_sha256"].items():
        matches = [old for name, old in previous_hashes.items() if Path(name).as_posix().endswith("/" + source)]
        if matches != [digest]:
            raise ValueError(f"preregistration target differs from baseline: {source}")
    # The pinned baseline also seals the actual driver and control model.
    # This runner is the sole allowed baseline change to register the new suite.
    preserved = {}
    for source in frozen_paths():
        relative = source.relative_to(ROOT).as_posix()
        if relative == "experiments/run_recovery_holdout.py":
            continue
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        matches = [old for name, old in previous_hashes.items() if Path(name).as_posix().endswith("/" + relative)]
        if matches != [digest]:
            raise ValueError(f"preregistration driver or core differs from baseline: {relative}")
        preserved[str(source)] = digest
    selection_path = path.with_name("defect_selection.json")
    selection = json.loads(selection_path.read_text(encoding="utf-8"))
    if (selection.get("schema") != "guardian-transfer-defect-selection/v1"
            or selection.get("feedback_and_results_read") is not False
            or selection.get("families") != list(get_defect_suite("transfer").families)):
        raise ValueError("preregistration defect selection differs")
    return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "selection_path": str(selection_path),
        "selection_sha256": hashlib.sha256(selection_path.read_bytes()).hexdigest(),
        "baseline_path": str(baseline), "baseline_sha256": hashlib.sha256(baseline.read_bytes()).hexdigest(),
        "preserved_baseline_sha256": preserved}


def verify_preregistration(record):
    if record:
        for key, digest in (("path", "sha256"), ("selection_path", "selection_sha256"),
                ("baseline_path", "baseline_sha256")):
            paths = [record[key]]
            if key + "_snapshot" in record:
                paths.append(record[key + "_snapshot"])
            if any(hashlib.sha256(Path(path).read_bytes()).hexdigest() != record[digest] for path in paths):
                raise ValueError("preregistration or snapshot changed during validation")


def source_hashes(paths):
    return {str(Path(path).resolve()): hashlib.sha256(Path(path).read_bytes()).hexdigest()
        for path in paths}


def verify_sources(frozen):
    for name, digest in frozen.items():
        if not Path(name).is_file() or hashlib.sha256(Path(name).read_bytes()).hexdigest() != digest:
            raise ValueError(f"frozen source changed: {name}")


def codes(trace):
    return sorted({v.code for v in SafetyOracle().check_trace(trace)})


def save_case(path, family, actions, trace, *, defect_suite="holdout"):
    write_json(path, {"schema": "guardian-holdout-counterexample/v1", "family": family,
        **({"defect_suite": defect_suite} if defect_suite != "holdout" else {}),
        "actions": [asdict(a) for a in actions], "frames": [frame.to_dict() for frame in trace],
        "violation_codes": codes(trace)})


def replay_case(path):
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    selected = get_defect_suite(value.get("defect_suite", "holdout"))
    if value.get("schema") != "guardian-holdout-counterexample/v1" or value.get("family") not in selected.families:
        raise ValueError("unsupported holdout counterexample")
    trace = selected.execute([Action(**a) for a in value["actions"]], value["family"])
    # Random proof identifiers are not replay identities; assertion codes are.
    actual = codes(trace)
    return {"family": value["family"], "violation_codes": actual,
        "matches_saved_codes": actual == value["violation_codes"], "frame_count": len(trace)}


def qualify_holdout(output_dir, *, defect_suite="holdout"):
    selected = get_defect_suite(defect_suite)
    cases, control_violations = [], []
    for family, actions in selected.challenges().items():
        control = execute_scenario(actions)
        control_violations.extend({"family": family, **asdict(v)}
            for v in SafetyOracle().check_trace(control))
        trace = selected.execute(actions, family)
        actual = codes(trace)
        path = Path(output_dir) / f"qualification_{family}.json"
        save_case(path, family, actions, trace, defect_suite=defect_suite)
        cases.append({"family": family, "violation_codes": actual,
            "qualified": selected.expected[family] <= set(actual), "counterexample_path": str(path),
            "action_count": len(actions), "reduction": "not_performed"})
    return {"cases": cases, "detected_families": sum(case["qualified"] for case in cases),
        "control_violations": control_violations}


def spread(values):
    return {"min": min(values), "median": statistics.median(values), "max": max(values)}


def detection_interval(count, total):
    # Wilson score interval, a descriptive interval over runs, not unique bugs.
    z = 1.959963984540054
    p, denominator = count / total, 1 + z * z / total
    center = (p + z * z / (2 * total)) / denominator
    margin = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    return {"method": "Wilson 95%", "low": max(0.0, center - margin), "high": min(1.0, center + margin)}


def aggregate_holdout(runs, *, defect_suite="holdout"):
    families = get_defect_suite(defect_suite).families
    groups, by_seed, comparisons = {}, {}, {}
    for run in runs:
        pair = by_seed.setdefault(run["seed"], {})
        if run["mode"] in pair:
            raise ValueError("duplicate seed/mode run")
        pair[run["mode"]] = run
        if any(family not in families for family in run["first_defects"]):
            raise ValueError("unknown detection family")
        for case in run["first_defects"].values():
            when = case["elapsed_sec"]
            if type(when) not in (int, float) or not math.isfinite(when) or not 0 <= when <= run["wall_time_sec"]:
                raise ValueError("detection outside wall budget")
    for mode in ALLOWED_MODES:
        group = [run for run in runs if run["mode"] == mode]
        if not group:
            continue
        groups[mode] = {field: spread([run[field] for run in group]) for field in (
            "generated_executions", "search_elapsed_sec", "deadline_overrun_sec")}
        groups[mode]["coverage"] = {field: spread([run["coverage"][field] for run in group])
            for field in ("states", "transitions")}
        if all("liveness_target_maxima" in run for run in group):
            groups[mode]["liveness_target_maxima"] = {
                label: spread([run["liveness_target_maxima"][label] for run in group])
                for label in ("recovery_stable_health_sec", "recovery_progress")}
        groups[mode]["defect_detection"] = {}
        for family in families:
            observed = [run["first_defects"][family]["elapsed_sec"] for run in group
                if family in run["first_defects"]]
            capped = [run["first_defects"].get(family, {}).get("elapsed_sec", run["wall_time_sec"])
                for run in group]
            groups[mode]["defect_detection"][family] = {
                "detected_runs": len(observed), "total_runs": len(group),
                "detection_rate_interval": detection_interval(len(observed), len(group)),
                "first_time_sec_observed": spread(observed) if observed else None,
                "restricted_first_time_sec": spread(capped), "misses_are_time_censored": True}
    for left, right in (("guided", "unguided"), ("boundary", "unguided"), ("boundary", "guided"),
            ("liveness", "unguided"), ("liveness", "boundary"),
            ("boundary_liveness", "unguided"), ("boundary_liveness", "boundary"),
            ("boundary_liveness", "liveness")):
        pairs = [(seed, pair[left], pair[right]) for seed, pair in sorted(by_seed.items())
            if left in pair and right in pair]
        if not pairs:
            continue
        if any(a["wall_time_sec"] != b["wall_time_sec"] for _, a, b in pairs):
            raise ValueError("paired wall budgets differ")
        comparison = {"seeds": [seed for seed, _, _ in pairs], "defect_detection": {}}
        for family in families:
            differences, binary = [], []
            for _, a, b in pairs:
                ac, bc = a["first_defects"].get(family), b["first_defects"].get(family)
                binary.append(int(ac is not None) - int(bc is not None))
                differences.append((ac["elapsed_sec"] if ac else a["wall_time_sec"]) -
                    (bc["elapsed_sec"] if bc else b["wall_time_sec"]))
            comparison["defect_detection"][family] = {"detection_deltas": binary,
                "restricted_first_time_deltas": differences,
                "restricted_first_time_delta_median": statistics.median(differences)}
        comparisons[f"{left}_vs_{right}"] = comparison
    return {"groups": groups, "paired_comparisons": comparisons}


def benchmark_holdout(seed, mode, wall_time_sec, execution_cap, output_dir, progress,
                      collect_liveness=False, defect_suite="holdout"):
    selected = get_defect_suite(defect_suite)
    families = selected.families
    found, overtime, probes = {}, {}, {family: 0 for family in families}
    prefix = f"{mode}_seed_{seed}"

    def evaluate(actions, full_trace, origin, index, elapsed):
        started = time.perf_counter()
        # Rotate probes too: each family gets each position across seed/input.
        offset = (seed + index) % len(families)
        for family in families[offset:] + families[:offset]:
            if family in found:
                continue
            probes[family] += 1
            trace = selected.execute(actions, family)
            actual = codes(trace)
            if not actual:
                continue
            path = Path(output_dir) / f"{prefix}_first_{family}.json"
            save_case(path, family, actions, trace, defect_suite=defect_suite)
            when = elapsed + time.perf_counter() - started
            case = {"test_index": index, "elapsed_sec": when, "origin": origin,
                "violation_codes": actual, "counterexample_path": str(path)}
            if when <= wall_time_sec:
                found[family] = case
            else:
                overtime[family] = case

    run = run_campaign(seed_value=seed, mode=mode, budget=execution_cap,
        corpus_path=Path(output_dir) / f"{prefix}_corpus.json", include_seeds=False,
        shrink_failures=False, evaluation_hook=evaluate, progress_hook=None,
        wall_time_sec=wall_time_sec, collect_liveness=collect_liveness)
    run.update(first_defects=found, out_of_budget_defects=overtime, mutation_probe_count=probes)
    write_json(Path(output_dir) / f"{prefix}.json", run)
    progress({"completed": prefix, "executions": run["generated_executions"],
        "detected_families": len(found), "stop_reason": run["stop_reason"],
        "overrun_sec": run["deadline_overrun_sec"]})
    return run


def frozen_paths(defect_suite="holdout"):
    paths = [ROOT / "experiments" / name for name in (
        "recovery_scenarios.py", "permit_boundary_feedback.py", "run_recovery_feedback_fuzzing.py",
        "recovery_holdout_mutations.py", "run_recovery_holdout.py", "recovery_liveness_feedback.py")] + [
        ROOT / "ros2_ws/src/guardian_core/guardian_core" / name for name in (
            "bound_recovery.py", "recovery_protocol.py", "recovery_feedback.py",
            "independent_observation.py", "predictive_envelope.py", "evidence_ledger.py")]
    if defect_suite == "transfer":
        paths.append(ROOT / "experiments/recovery_transfer_mutations.py")
    return paths


def run_holdout_evaluation(*, seeds, wall_time_sec, execution_cap, output_dir, progress=print,
                           modes=MODES, defect_suite="holdout", preregistration=None):
    selected = get_defect_suite(defect_suite)
    if not modes or len(set(modes)) != len(modes) or any(mode not in ALLOWED_MODES for mode in modes):
        raise ValueError("modes must be distinct supported comparison modes")
    modes = tuple(modes)
    collect_liveness = any(mode in ("liveness", "boundary_liveness") for mode in modes)
    if (not seeds or len(seeds) > 100 or len(set(seeds)) != len(seeds)
            or any(type(seed) is not int or seed < 0 for seed in seeds)):
        raise ValueError("seeds must be distinct non-negative integers")
    if (type(wall_time_sec) not in (int, float) or not math.isfinite(wall_time_sec)
            or not 0 < wall_time_sec <= 3600):
        raise ValueError("wall_time_sec must be finite and in (0, 3600]")
    if type(execution_cap) is not int or not 1 <= execution_cap <= 10000:
        raise ValueError("execution_cap must be in 1..10000")
    registration = (validate_preregistration(preregistration, seeds=seeds, modes=modes,
        wall_time_sec=wall_time_sec, execution_cap=execution_cap) if defect_suite == "transfer" else None)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=False)
    import hypothesis
    frozen = source_hashes(frozen_paths(defect_suite))
    snapshots = {}
    for original in frozen:
        destination = output_dir / "source_snapshot" / Path(original).relative_to(ROOT)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(Path(original).read_bytes())
        snapshots[original] = str(destination)
    verify_sources(frozen)
    verify_preregistration(registration)
    if registration:
        for name, filename in (("path", "preregistration.json"),
                ("selection_path", "defect_selection.json"), ("baseline_path", "baseline_report.json")):
            destination = output_dir / filename
            destination.write_bytes(Path(registration[name]).read_bytes())
            registration[name + "_snapshot"] = str(destination)
        verify_preregistration(registration)
    if any(source_hashes([snapshot])[str(Path(snapshot).resolve())] != frozen[original]
            for original, snapshot in snapshots.items()):
        raise ValueError("source snapshot differs from freeze")
    oracle = SafetyOracle()
    protocol = {"seeds": seeds, "modes": list(modes), "wall_time_sec": wall_time_sec,
        "execution_cap": execution_cap, "hypothesis": hypothesis.__version__,
        "python": platform.python_version(), "oracle_config": {
            "liveness_sec": oracle.liveness_sec, "max_frame_gap_sec": oracle.max_frame_gap_sec},
        "source_sha256": frozen, "source_snapshots": snapshots,
        "active_target_labels": {mode: list(TARGET_LABELS[mode]) for mode in modes},
        "liveness_metrics_collected_for_all_modes": collect_liveness,
        "liveness_config": RecoveryLivenessFeedback.configuration() if collect_liveness else None,
        "defect_suite": defect_suite, "preregistration": registration,
        "validation_scope": ("frozen_feedback_new_controlled_defects" if defect_suite == "transfer" else
            "known_defect_new_seed_target_validation" if collect_liveness else "new_injected_check_validation"),
        "families": list(selected.families), "probe_order": "rotate by seed plus input index",
        "warmup_seed_executions": 0, "target_reads_mutant_outcomes": False,
        "group_order": "rotate by seed position", "budget_boundary": "complete in-flight case",
        "holdout_scope": ("new controlled code defects selected after target freeze; known input distribution; not external blind validation"
            if defect_suite == "transfer" else "known defects used in target design; new seeds; not unseen-defect or blind validation"
            if collect_liveness else "new injected checks; known input distribution; not external or blind validation")}
    write_json(output_dir / "frozen_protocol.json", protocol)
    qualification = qualify_holdout(output_dir, defect_suite=defect_suite)
    write_json(output_dir / "qualification.json", qualification)
    report = {"schema": "guardian-recovery-holdout/v1", "protocol": protocol,
        "qualification": qualification, "runs": [], "full_mechanism_violations": [],
        "counterexample_replay_mismatches": [], "corpus_replay_mismatches": [],
        "physical_safety_validated": False, "injected_defects_are_production_findings": False}
    if qualification["control_violations"] or qualification["detected_families"] != len(selected.families):
        raise ValueError("holdout qualification failed; do not start benchmark")
    for index, seed in enumerate(seeds):
        offset = index % len(modes)
        for mode in modes[offset:] + modes[:offset]:
            verify_sources(frozen)
            verify_preregistration(registration)
            run = benchmark_holdout(seed, mode, wall_time_sec, execution_cap, output_dir, progress,
                collect_liveness=collect_liveness, defect_suite=defect_suite)
            report["runs"].append(run)
            report["full_mechanism_violations"].extend(run["violations"])
            report["aggregate"] = aggregate_holdout(report["runs"], defect_suite=defect_suite)
            write_json(output_dir / "summary.json", report)
    paths = [case["counterexample_path"] for case in qualification["cases"]]
    for run in report["runs"]:
        paths.extend(case["counterexample_path"] for group in (
            run["first_defects"], run["out_of_budget_defects"]) for case in group.values())
        replay = replay_corpus(run["corpus_path"])
        replay_fields = ("coverage", "boundary_coverage", "boundary_target_maxima")
        if collect_liveness:
            replay_fields += ("liveness_config", "liveness_coverage", "liveness_target_maxima")
        if replay["violations"] or any(replay[key] != run[key] for key in replay_fields):
            report["corpus_replay_mismatches"].append(run["corpus_path"])
    for path in paths:
        if not replay_case(path)["matches_saved_codes"]:
            report["counterexample_replay_mismatches"].append(path)
    verify_sources(frozen)
    verify_preregistration(registration)
    if registration:
        report["preregistration_verified"] = True
    report["source_freeze_verified"] = True
    report["replay_verification"] = {"counterexamples": len(paths), "corpora": len(report["runs"])}
    report["equal_wall_comparison_valid"] = all(run["stop_reason"] == "wall_time" for run in report["runs"])
    write_json(output_dir / "summary.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seeds", default=",".join(str(seed) for seed in range(20, 40)))
    parser.add_argument("--modes", default=",".join(MODES))
    parser.add_argument("--defect-suite", choices=("holdout", "transfer"), default="holdout")
    parser.add_argument("--preregistration", type=Path)
    parser.add_argument("--wall-time-sec", type=float, default=5)
    parser.add_argument("--execution-cap", type=int, default=10000)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "experiments/results/recovery_holdout_validation")
    parser.add_argument("--replay", type=Path)
    args = parser.parse_args()
    if args.replay:
        report = replay_case(args.replay)
        print(json.dumps(report))
        return int(not report["matches_saved_codes"])
    report = run_holdout_evaluation(seeds=[int(value) for value in args.seeds.split(",")],
        wall_time_sec=args.wall_time_sec, execution_cap=args.execution_cap, output_dir=args.output_dir,
        modes=tuple(args.modes.split(",")), defect_suite=args.defect_suite, preregistration=args.preregistration,
        progress=lambda value: print(json.dumps(value), flush=True))
    print(json.dumps(report["aggregate"], indent=2))
    return int(bool(report["full_mechanism_violations"] or report["counterexample_replay_mismatches"]
        or report["corpus_replay_mismatches"] or not report["equal_wall_comparison_valid"]))


if __name__ == "__main__":
    raise SystemExit(main())
