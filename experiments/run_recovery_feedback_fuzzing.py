"""Hypothesis-driven semantic recovery campaign, corpus replay and shrinking."""
import argparse
from dataclasses import asdict
import json
import math
from pathlib import Path
import random
import sys
import time
from unittest import SkipTest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ros2_ws/src/guardian_core"))
from guardian_core.recovery_feedback import SafetyOracle, SemanticCoverage
from recovery_scenarios import Action, KINDS, execute_scenario, seed_scenarios
from permit_boundary_feedback import BoundaryFeedback
from recovery_liveness_feedback import RecoveryLivenessFeedback

TARGET_LABELS = {
    "fixed": (), "unguided": (), "guided": ("recovery_semantic_coverage",),
    "boundary": ("permit_ttl_diversity", "permit_expiry_proximity",
        "permit_context_diversity", "repair_transition_diversity"),
    "ttl": ("permit_ttl_diversity", "permit_expiry_proximity"),
    "context_repair": ("permit_context_diversity", "repair_transition_diversity"),
    "liveness": ("recovery_stable_health_sec", "recovery_progress"),
    "boundary_liveness": ("permit_ttl_diversity", "permit_expiry_proximity",
        "permit_context_diversity", "repair_transition_diversity",
        "recovery_stable_health_sec", "recovery_progress"),
}
MODES = tuple(TARGET_LABELS)


class CampaignTimeLimit(SkipTest):
    """Use Hypothesis's native skip path, which does not retry a failing case."""


def observe_boundary(trace, features, maxima):
    feedback = BoundaryFeedback.from_trace(trace)
    observed = feedback.features()
    interesting = bool(observed - features)
    features.update(observed)
    for label, value in feedback.targets().items():
        maxima[label] = max(maxima.get(label, 0), value)
    return feedback, interesting


def observe_liveness(trace, features, maxima):
    feedback = RecoveryLivenessFeedback.from_trace(trace)
    observed = feedback.features()
    interesting = bool(observed - features)
    features.update(observed)
    for label, value in feedback.targets().items():
        maxima[label] = max(maxima.get(label, 0), value)
    return feedback, interesting


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def action_strategy():
    from hypothesis import strategies as st
    return st.lists(st.builds(Action, st.sampled_from(KINDS),
        st.sampled_from((.01, .05, .1, .2, .25, .49, .5, .51, .6, 1.0))), min_size=1, max_size=32)


def replay_corpus(path):
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if value.get("schema_version") != 1 or len(value["cases"]) > 10000:
        raise ValueError("unsupported or oversized corpus")
    coverage, oracle, violations = SemanticCoverage(), SafetyOracle(), []
    boundary_features, boundary_maxima = set(), {}
    config = value.get("liveness_config")
    if config is not None and config != RecoveryLivenessFeedback.configuration():
        raise ValueError("unsupported liveness configuration")
    liveness_features, liveness_maxima = set(), RecoveryLivenessFeedback.from_trace([]).targets()
    for case in value["cases"]:
        trace = execute_scenario([Action(**action) for action in case["actions"]])
        coverage.observe_trace(trace)
        observe_boundary(trace, boundary_features, boundary_maxima)
        if config is not None:
            observe_liveness(trace, liveness_features, liveness_maxima)
        violations.extend(asdict(v) for v in oracle.check_trace(trace))
    return {"cases": len(value["cases"]), "coverage": coverage.summary(), "violations": violations,
        "boundary_coverage": sorted(boundary_features), "boundary_target_maxima": boundary_maxima,
        **({"liveness_config": config, "liveness_coverage": sorted(liveness_features),
            "liveness_target_maxima": liveness_maxima} if config is not None else {})}


def run_campaign(*, seed_value, budget, mode, corpus_path, include_seeds=True,
                 shrink_failures=True, evaluation_hook=None, progress_hook=None,
                 wall_time_sec=None, collect_liveness=False):
    from hypothesis import given, seed, settings, target, Phase, find, HealthCheck
    from hypothesis.errors import NoSuchExample
    if type(budget) is not int or not 1 <= budget <= 10000 or mode not in MODES:
        raise ValueError(f"budget must be 1..10000 and mode one of {MODES}")
    if type(collect_liveness) is not bool:
        raise ValueError("collect_liveness must be boolean")
    collect_liveness = collect_liveness or mode in ("liveness", "boundary_liveness")
    if wall_time_sec is not None:
        if (type(wall_time_sec) not in (int, float) or not math.isfinite(wall_time_sec)
                or not 0 < wall_time_sec <= 3600):
            raise ValueError("wall_time_sec must be finite and in (0, 3600]")
        if include_seeds or shrink_failures:
            raise ValueError("wall budget requires no seed warmup or shrinking")
    coverage, oracle, corpus, violations = SemanticCoverage(), SafetyOracle(), [], {}
    boundary_features, boundary_maxima = set(), {}
    liveness_features, liveness_maxima = set(), RecoveryLivenessFeedback.from_trace([]).targets()
    corpus_liveness_maxima = {}
    started, generated = time.perf_counter(), 0

    def check_deadline():
        if wall_time_sec is not None and time.perf_counter() - started >= wall_time_sec:
            raise CampaignTimeLimit("campaign wall budget reached")

    def evaluate(actions, origin):
        trace = execute_scenario(actions)
        interesting = coverage.observe_trace(trace)
        boundary, boundary_interesting = observe_boundary(trace, boundary_features, boundary_maxima)
        liveness, liveness_interesting = None, False
        if collect_liveness:
            liveness, liveness_interesting = observe_liveness(trace, liveness_features, liveness_maxima)
        found = oracle.check_trace(trace)
        # Maxima also need a witness in the corpus for exact score replay.
        better_target = any(value > corpus_maxima.get(label, 0) for label, value in boundary.targets().items())
        better_liveness = liveness is not None and any(
            value > corpus_liveness_maxima.get(label, 0) for label, value in liveness.targets().items())
        if interesting or boundary_interesting or better_target or liveness_interesting or better_liveness or found:
            corpus.append({"origin": origin, "actions": [asdict(a) for a in actions]})
            corpus_maxima.update(boundary_maxima)
            if collect_liveness:
                corpus_liveness_maxima.update(liveness_maxima)
        for violation in found:
            violations.setdefault(violation.code, {"violation": asdict(violation),
                "actions": [asdict(a) for a in actions]})
        local = SemanticCoverage()
        local.observe_trace(trace)
        if evaluation_hook is not None:
            evaluation_hook(actions, trace, origin, generated, time.perf_counter() - started)
        if progress_hook is not None and origin != "seed" and generated % 100 == 0:
            progress_hook({"mode": mode, "seed": seed_value, "executions": generated,
                "coverage": coverage.summary()})
        return len(local.states) + len(local.edges), {
            **boundary.targets(), **(liveness.targets() if liveness is not None else {})}

    corpus_maxima = {}
    seeds = seed_scenarios() if include_seeds else []
    for actions in seeds:
        evaluate(actions, "seed")

    @seed(seed_value)
    @settings(max_examples=budget, deadline=None, database=None,
        suppress_health_check=[HealthCheck.too_slow],
        phases=(Phase.generate, Phase.target) if TARGET_LABELS[mode] else (Phase.generate,))
    @given(action_strategy())
    def campaign(actions):
        nonlocal generated
        check_deadline()
        generated += 1
        score, boundary_targets = evaluate(actions, "generated")
        observations = {"recovery_semantic_coverage": score, **boundary_targets}
        for label in TARGET_LABELS[mode]:
            target(observations[label], label=label)
    stop_reason = "execution_cap"
    try:
        if mode == "fixed":
            fixed_cases = seed_scenarios()
            for index in range(budget):
                check_deadline()
                generated += 1
                evaluate(fixed_cases[index % len(fixed_cases)], "fixed")
        else:
            campaign()
        if generated < budget:
            stop_reason = "search_exhausted"
        elif wall_time_sec is not None and time.perf_counter() - started >= wall_time_sec:
            stop_reason = "wall_time"
    except CampaignTimeLimit:
        stop_reason = "wall_time"
    search_elapsed = time.perf_counter() - started
    for code, failure in violations.items():
        if not shrink_failures:
            failure["reduction"] = "disabled_for_benchmark"
            continue
        try:
            reduced = find(action_strategy(), lambda actions: any(v.code == code
                for v in oracle.check_trace(execute_scenario(actions))),
                settings=settings(max_examples=256, deadline=None, database=None),
                random=random.Random(seed_value))
            failure["minimized_actions"] = [asdict(a) for a in reduced]
            failure["reduction"] = "hypothesis_find"
        except NoSuchExample:
            failure["reduction"] = "not_rediscovered_within_budget"
    liveness_metadata = {"liveness_config": RecoveryLivenessFeedback.configuration()} if collect_liveness else {}
    write_json(corpus_path, {"schema_version": 1, "seed": seed_value, "mode": mode,
        "cases": corpus, **liveness_metadata})
    return {"schema_version": 1, "seed": seed_value, "mode": mode, "budget": budget,
        "generated_executions": generated, "seed_executions": len(seeds),
        "coverage": coverage.summary(), "interesting_cases": len(corpus),
        "boundary_coverage": sorted(boundary_features), "boundary_target_maxima": boundary_maxima,
        **({**liveness_metadata, "liveness_coverage": sorted(liveness_features),
            "liveness_target_maxima": liveness_maxima} if collect_liveness else {}),
        "active_target_labels": list(TARGET_LABELS[mode]),
        "violations": list(violations.values()), "elapsed_sec": round(time.perf_counter() - started, 4),
        "search_elapsed_sec": search_elapsed, "wall_time_sec": wall_time_sec,
        "stop_reason": stop_reason,
        "deadline_overrun_sec": max(0.0, search_elapsed - wall_time_sec) if wall_time_sec is not None else 0.0,
        "corpus_path": str(corpus_path), "physical_safety_validated": False,
        "feedback": (f"trace-derived targets: {', '.join(TARGET_LABELS[mode])}" if mode in (
            "boundary", "ttl", "context_repair", "liveness", "boundary_liveness") else
            "legacy per-trace states+transitions target" if mode == "guided" else "no search target"),
        "btreefuzz_algorithm_reproduced": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--budget", type=int, default=64)
    parser.add_argument("--mode", choices=MODES, default="guided")
    parser.add_argument("--output", type=Path, default=ROOT / "experiments/results/recovery_feedback_guided.json")
    parser.add_argument("--replay", type=Path)
    args = parser.parse_args()
    if args.replay:
        report = replay_corpus(args.replay)
    else:
        report = run_campaign(seed_value=args.seed, budget=args.budget, mode=args.mode,
            corpus_path=args.output.with_name(args.output.stem + "_corpus.json"))
    write_json(args.output, report)
    print(json.dumps(report, ensure_ascii=False, allow_nan=False))
    return 1 if report["violations"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
