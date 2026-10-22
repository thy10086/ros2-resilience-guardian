"""Paired recovery benchmarks and offline seeded-defect qualification."""
import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import random
import platform
import statistics
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ros2_ws/src/guardian_core"))
from guardian_core.recovery_feedback import SafetyOracle
from recovery_mutations import VARIANTS, challenge_scenarios, mutation_manifest
from recovery_scenarios import Action, execute_scenario, seed_scenarios
from run_recovery_feedback_fuzzing import MODES, TARGET_LABELS, action_strategy, replay_corpus, run_campaign, write_json


def violation_codes(trace):
    return sorted({v.code for v in SafetyOracle().check_trace(trace)})


def replay_counterexample(path):
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if value.get("schema_version") != 1 or value["variant"] not in VARIANTS:
        raise ValueError("unsupported counterexample")
    trace = execute_scenario([Action(**entry) for entry in value["actions"]], variant=value["variant"])
    return {"variant": value["variant"], "violation_codes": violation_codes(trace),
        "frame_count": len(trace)}


def save_counterexample(path, variant, actions, trace):
    write_json(path, {"schema_version": 1, "variant": variant,
        "actions": [asdict(a) for a in actions], "frames": [f.to_dict() for f in trace],
        "violation_codes": violation_codes(trace)})


def qualify_mutants(output_dir):
    from hypothesis import find, settings, strategies as st
    from hypothesis.errors import NoSuchExample
    output_dir = Path(output_dir)
    cases, controls = [], []
    for variant, actions in challenge_scenarios().items():
        full = execute_scenario(actions)
        controls.extend({"variant": variant, **asdict(v)} for v in SafetyOracle().check_trace(full))
        trace = execute_scenario(actions, variant=variant)
        codes = violation_codes(trace)
        path = output_dir / f"qualification_{variant}.json"
        save_counterexample(path, variant, actions, trace)
        case = {"variant": variant, "violation_codes": codes, "counterexample_path": str(path),
            "original_action_count": len(actions)}
        if codes:
            try:
                # Including the known original is explicit and limited to
                # reduction, never to the generated benchmark input pool.
                reduced = find(st.one_of(action_strategy(), st.just(actions)),
                    lambda candidate: bool(violation_codes(execute_scenario(candidate, variant=variant))),
                    settings=settings(max_examples=128, deadline=None, database=None), random=random.Random(42))
                reduced_trace = execute_scenario(reduced, variant=variant)
                reduced_path = output_dir / f"reduced_{variant}.json"
                save_counterexample(reduced_path, variant, reduced, reduced_trace)
                case.update(reduction="hypothesis_find_with_original", reduced_action_count=len(reduced),
                    reduced_counterexample_path=str(reduced_path))
            except NoSuchExample:
                case["reduction"] = "not_rediscovered_within_budget"
        cases.append(case)
    return {"cases": cases, "detected_families": sum(bool(case["violation_codes"]) for case in cases),
        "control_violations": controls, "mutation_manifest": mutation_manifest()}


def ablation_report():
    cases = []
    challenges = list(challenge_scenarios().items()) + [(f"seed_{i}", actions)
        for i, actions in enumerate(seed_scenarios())]
    for name, actions in challenges:
        repair_at = None
        elapsed = 1.0
        for action_index, action in enumerate(actions):
            # The initial healthy action is startup, not a repair. Challenges
            # with only gap/context changes have no explicit repair command.
            if action.kind == "healthy" and action_index > 0:
                repair_at = elapsed
            elapsed += action.duration
        for variant in ("full", *VARIANTS):
            trace = execute_scenario(actions, variant=variant)
            violations = SafetyOracle().check_trace(trace)
            repaired = next((f.now - repair_at for f in trace
                if repair_at is not None and f.now > repair_at + 1e-9 and f.mission_allowed), None)
            bad_frames = {v.frame_index for v in violations}
            invalid_evidence_frames = {v.frame_index for v in violations if v.code == "unsafe_motion"}
            cases.append({"scenario": name, "variant": variant,
                "violation_codes": sorted({v.code for v in violations}),
                "unsafe_motion_frames": sum(f.mission_allowed and i in invalid_evidence_frames for i, f in enumerate(trace)),
                "unsafe_authorized_frames": sum(f.mission_allowed and i in bad_frames for i, f in enumerate(trace)),
                "unsafe_resume_events": sum(f.recovery_phase == "RESUMABLE" and i in bad_frames
                    for i, f in enumerate(trace)),
                "eligible_stall_events": sum(v.code == "recovery_stalled" for v in violations),
                "repair_to_allowed_sec": None if repaired is None else round(repaired, 4)})
    return {"cases": cases, "summary": {variant: {
        "scenarios": sum(c["variant"] == variant for c in cases),
        "violating_scenarios": sum(c["variant"] == variant and bool(c["violation_codes"]) for c in cases),
        "unsafe_motion_frames": sum(c["unsafe_motion_frames"] for c in cases if c["variant"] == variant),
        "unsafe_authorized_frames": sum(c["unsafe_authorized_frames"] for c in cases if c["variant"] == variant),
        "unsafe_resume_events": sum(c["unsafe_resume_events"] for c in cases if c["variant"] == variant),
    } for variant in ("full", *VARIANTS)}}


def relevant_variants(actions, trace):
    kinds = {a.kind for a in actions}
    result = set()
    if any(f.pending_proof and any(later.now >= f.pending_proof["expires_at"]
            for later in trace[i + 1:i + 2]) for i, f in enumerate(trace)):
        result.add("no_proof_ttl")
    if kinds & {"graph_change", "policy_change", "epoch_change"}:
        result.add("no_context_binding")
    if "replay_proof" in kinds:
        result.add("accept_proof_replay")
    if kinds & {"paused", "stale", "replay", "invalid_scan", "speed_mismatch", "near_obstacle"}:
        result.add("no_independent_observation")
    return result


def benchmark_run(seed_value, budget, mode, output_dir, progress):
    found = {}
    probes = {v: 0 for v in VARIANTS}
    skipped = {v: 0 for v in VARIANTS}
    after_found = {v: 0 for v in VARIANTS}
    probe_sec = 0.0
    prefix = f"{mode}_seed_{seed_value}"

    def evaluate(actions, trace, origin, index, elapsed):
        nonlocal probe_sec
        started = time.perf_counter()
        relevant = relevant_variants(actions, trace)
        for variant in VARIANTS:
            if variant in found:
                after_found[variant] += 1
                continue
            if variant not in relevant:
                skipped[variant] += 1
                continue
            probes[variant] += 1
            changed = execute_scenario(actions, variant=variant)
            codes = violation_codes(changed)
            if codes:
                path = Path(output_dir) / f"{prefix}_first_{variant}.json"
                save_counterexample(path, variant, actions, changed)
                found[variant] = {"test_index": index, "elapsed_sec": round(
                    elapsed + time.perf_counter() - started, 4), "origin": origin,
                    "violation_codes": codes, "counterexample_path": str(path)}
        probe_sec += time.perf_counter() - started

    report = run_campaign(seed_value=seed_value, budget=budget, mode=mode,
        corpus_path=Path(output_dir) / f"{prefix}_corpus.json", include_seeds=False,
        shrink_failures=False, evaluation_hook=evaluate, progress_hook=progress)
    report.update(detected_families=len(found), first_defects=found,
        mutation_probe_count=probes, screened_count=skipped, skipped_after_detection=after_found,
        mutation_probe_sec=round(probe_sec, 4),
        search_without_probe_sec=round(report["elapsed_sec"] - probe_sec, 4))
    write_json(Path(output_dir) / f"{prefix}.json", report)
    return report


def aggregate_runs(runs):
    def spread(values):
        return {"median": statistics.median(values), "min": min(values), "max": max(values)}
    groups = {}
    for mode in MODES:
        group = [run for run in runs if run["mode"] == mode]
        if group:
            groups[mode] = {field: spread([run["coverage"][field] for run in group])
                for field in ("states", "transitions")}
            for field in ("elapsed_sec", "generated_executions", "detected_families"):
                groups[mode][field] = spread([run[field] for run in group])
            groups[mode]["defect_detection"] = {}
            for variant in VARIANTS:
                detected = [run["first_defects"][variant] for run in group
                    if variant in run.get("first_defects", {})]
                groups[mode]["defect_detection"][variant] = {
                    "detected_runs": len(detected), "total_runs": len(group),
                    "first_test_index_observed": spread([case["test_index"] for case in detected]) if detected else None,
                    "first_time_sec_observed": spread([case["elapsed_sec"] for case in detected]) if detected else None,
                    "non_detections_are_budget_censored": True,
                    "restricted_first_test_index": spread([min(run.get("budget", run["generated_executions"]),
                        run.get("first_defects", {}).get(variant, {}).get("test_index",
                            run.get("budget", run["generated_executions"]))) for run in group])}
            if all("boundary_coverage" in run for run in group):
                groups[mode]["boundary_features"] = spread([len(run["boundary_coverage"]) for run in group])
    by_seed = {}
    for run in runs:
        by_seed.setdefault(run["seed"], {})[run["mode"]] = run
    deltas = [pair["guided"]["coverage"]["transitions"] - pair["unguided"]["coverage"]["transitions"]
        for _, pair in sorted(by_seed.items()) if "guided" in pair and "unguided" in pair]
    comparisons = {}
    for left, right in (("guided", "unguided"), ("boundary", "unguided"), ("boundary", "guided"),
            ("ttl", "unguided"), ("context_repair", "unguided"), ("ttl", "boundary"),
            ("context_repair", "boundary"), ("ttl", "context_repair")):
        pairs = [(seed_value, pair[left], pair[right]) for seed_value, pair in sorted(by_seed.items())
            if left in pair and right in pair]
        if not pairs:
            continue
        edges = [a["coverage"]["transitions"] - b["coverage"]["transitions"] for _, a, b in pairs]
        comparisons[f"{left}_vs_{right}"] = {"seeds": [s for s, _, _ in pairs],
            "transition_deltas": edges, "transition_delta_median": statistics.median(edges),
            "transition_wins": sum(d > 0 for d in edges), "transition_ties": sum(d == 0 for d in edges),
            "defect_detection": {}}
        for variant in VARIANTS:
            binary, restricted = [], []
            for _, a, b in pairs:
                a_case, b_case = a.get("first_defects", {}).get(variant), b.get("first_defects", {}).get(variant)
                binary.append(int(a_case is not None) - int(b_case is not None))
                a_budget, b_budget = a.get("budget", a["generated_executions"]), b.get("budget", b["generated_executions"])
                restricted.append(min(a_budget, a_case["test_index"] if a_case else a_budget) -
                    min(b_budget, b_case["test_index"] if b_case else b_budget))
            comparisons[f"{left}_vs_{right}"]["defect_detection"][variant] = {
                "detection_deltas": binary, "restricted_first_index_deltas": restricted,
                "restricted_first_index_delta_median": statistics.median(restricted),
                "misses_capped_at_execution_budget": True}
    return {"groups": groups, "paired_comparisons": comparisons, "paired_transition_deltas": deltas,
        "guided_transition_wins": sum(delta > 0 for delta in deltas),
        "guided_transition_ties": sum(delta == 0 for delta in deltas),
        "paired_transition_delta_median": statistics.median(deltas) if deltas else None}


def run_evaluation(*, seeds, budget, output_dir, progress=print, modes=("fixed", "unguided", "guided"),
                   seed_role="comparison"):
    if (not seeds or len(seeds) > 100 or len(set(seeds)) != len(seeds)
            or any(type(seed) is not int or seed < 0 for seed in seeds)
            or type(budget) is not int or not 1 <= budget <= 10000):
        raise ValueError("seeds must be distinct non-negative integers; budget 1..10000")
    if not modes or len(set(modes)) != len(modes) or any(mode not in MODES for mode in modes):
        raise ValueError("modes must be distinct known modes")
    if seed_role not in ("comparison", "unseen_validation"):
        raise ValueError("seed_role must be comparison or unseen_validation")
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    qualification = qualify_mutants(output_dir)
    write_json(output_dir / "qualification.json", qualification)
    ablation = ablation_report()
    write_json(output_dir / "ablation.json", ablation)
    import hypothesis
    source_paths = [ROOT / "experiments" / name for name in (
        "permit_boundary_feedback.py", "recovery_scenarios.py", "recovery_mutations.py",
        "run_recovery_feedback_fuzzing.py", "run_recovery_evaluation.py")]
    source_paths.append(ROOT / "ros2_ws/src/guardian_core/guardian_core/recovery_feedback.py")
    oracle_config = SafetyOracle()
    report = {"schema_version": 1, "seeds": seeds, "budget": budget,
        "modes": list(modes),
        "protocol": {"python": platform.python_version(), "hypothesis": hypothesis.__version__,
            "seed_role": seed_role, "target_labels_by_mode": {mode: list(TARGET_LABELS[mode]) for mode in modes},
            "oracle_config": {"liveness_sec": oracle_config.liveness_sec,
                "max_frame_gap_sec": oracle_config.max_frame_gap_sec},
            "source_sha256": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in source_paths}, "input_strategy_shared": True,
            "warmup_seed_executions": 0, "target_reads_mutant_outcomes": False,
            "group_order": "rotate generated groups across seed positions"},
        "qualification": qualification, "runs": [], "full_mechanism_violations": [],
        "physical_safety_validated": False, "injected_defects_are_production_findings": False}
    generated_modes = [mode for mode in modes if mode != "fixed"]
    for seed_index, seed_value in enumerate(seeds):
        # Rotate all selected generated modes, retaining a fixed reference first.
        offset = seed_index % len(generated_modes) if generated_modes else 0
        ordered = generated_modes[offset:] + generated_modes[:offset]
        if "fixed" in modes:
            ordered.insert(0, "fixed")
        for mode in ordered:
            run = benchmark_run(seed_value, budget, mode, output_dir, progress)
            report["runs"].append(run)
            report["full_mechanism_violations"].extend(run["violations"])
            report["aggregate"] = aggregate_runs(report["runs"])
            write_json(output_dir / "summary.json", report)
            progress({"completed": f"{mode}/seed={seed_value}", "coverage": run["coverage"],
                "defects": run["detected_families"], "elapsed_sec": run["elapsed_sec"]})
    # Replay every qualification/reduced/first-defect witness and retained corpus.
    report["counterexample_replay_mismatches"] = []
    report["corpus_replay_mismatches"] = []
    verified_examples = 0
    for case in qualification["cases"]:
        for key in ("counterexample_path", "reduced_counterexample_path"):
            if key in case:
                saved = json.loads(Path(case[key]).read_text())
                verified_examples += 1
                if replay_counterexample(case[key])["violation_codes"] != saved["violation_codes"]:
                    report["counterexample_replay_mismatches"].append({"path": case[key]})
    for run in report["runs"]:
        for variant, case in run["first_defects"].items():
            verified_examples += 1
            if replay_counterexample(case["counterexample_path"])["violation_codes"] != case["violation_codes"]:
                report["counterexample_replay_mismatches"].append({"seed": run["seed"], "mode": run["mode"], "variant": variant})
        replayed = replay_corpus(run["corpus_path"])
        if (replayed["violations"] or any(replayed[key] != run[key] for key in (
                "coverage", "boundary_coverage", "boundary_target_maxima"))):
            report["corpus_replay_mismatches"].append({"seed": run["seed"], "mode": run["mode"]})
    report["replay_verification"] = {"counterexamples": verified_examples,
        "corpora": len(report["runs"])}
    write_json(output_dir / "summary.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seeds", default="0,1,2,3,4,5,6,7,8,9")
    parser.add_argument("--budget", type=int, default=1000)
    parser.add_argument("--modes", default="fixed,unguided,guided")
    parser.add_argument("--seed-role", choices=("comparison", "unseen_validation"), default="comparison")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "experiments/results/recovery_evaluation")
    parser.add_argument("--replay", type=Path)
    args = parser.parse_args()
    if args.replay:
        print(json.dumps(replay_counterexample(args.replay)))
        return 0
    report = run_evaluation(seeds=[int(value) for value in args.seeds.split(",")], budget=args.budget,
        output_dir=args.output_dir, modes=tuple(args.modes.split(",")),
        seed_role=args.seed_role,
        progress=lambda value: print(json.dumps(value), flush=True))
    print(json.dumps(report["aggregate"], indent=2))
    return int(bool(report["full_mechanism_violations"] or report["counterexample_replay_mismatches"]
        or report["corpus_replay_mismatches"]
        or report["qualification"]["control_violations"] or report["qualification"]["detected_families"] != 4))


if __name__ == "__main__":
    raise SystemExit(main())
