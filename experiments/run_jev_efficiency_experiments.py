#!/usr/bin/env python3
"""Deterministic comparison for the efficient Jev judgment layer."""

from __future__ import annotations

import json
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ros2_ws" / "src" / "guardian_core"))

from guardian_core import (  # noqa: E402
    JevAdvisorConfig,
    JevEfficientJudge,
    JevEfficiencyPolicy,
    JevRoute,
    JevSemanticAdvisor,
    SemanticContext,
)


class StubTransport:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, endpoint: str, headers: dict[str, str], body: bytes, timeout: float) -> bytes:
        self.calls += 1
        return json.dumps(
            {
                "model": "jev-offline-stub",
                "answers": {
                    "attack_type": {
                        "type": "choice",
                        "choice": "unsafe_command",
                        "confidence": 0.9,
                        "probabilities": {"unsafe_command": 0.9},
                    },
                    "mission_impact": {
                        "type": "choice",
                        "choice": "critical",
                        "confidence": 0.9,
                        "probabilities": {"critical": 0.9},
                    },
                    "needs_human_review": {"type": "noul", "noul": 1.0},
                },
            }
        ).encode("utf-8")


def context(
    *,
    event_id: str,
    sequence: int,
    graph_risk: float = 0.6,
    mission_criticality: float = 0.6,
    event_confidence: float = 0.8,
    temporal_codes: tuple[str, ...] = ("REPLAY",),
    safety_state: str = "CONTAINING",
    summary: str = "verified command anomaly",
) -> SemanticContext:
    return SemanticContext(
        event_id=event_id,
        component="nav",
        attack_type="UNSAFE_COMMAND",
        event_confidence=event_confidence,
        source_verified=True,
        temporal_codes=temporal_codes,
        graph_risk=graph_risk,
        mission_criticality=mission_criticality,
        active_components=("nav", "base"),
        safety_state=safety_state,
        sequence=sequence,
        summary=summary,
    )


def advisor(transport: StubTransport) -> JevSemanticAdvisor:
    return JevSemanticAdvisor(
        JevAdvisorConfig(enabled=True, api_key="offline-stub", cache_ttl_sec=30.0),
        transport=transport,
        clock=lambda: 100.0,
    )


def main() -> int:
    repeated = [context(event_id=f"event-{index}", sequence=index) for index in range(12)]

    baseline_transport = StubTransport()
    baseline = advisor(baseline_transport)
    for item in repeated:
        baseline.evaluate(item)

    efficient_transport = StubTransport()
    judge = JevEfficientJudge(
        advisor(efficient_transport),
        policy=JevEfficiencyPolicy(max_remote_calls=12, cache_ttl_sec=30.0),
    )
    repeated_results = [judge.evaluate(item) for item in repeated]
    local_safe = judge.evaluate(
        context(
            event_id="safe-1",
            sequence=100,
            graph_risk=0.1,
            mission_criticality=0.1,
            event_confidence=0.95,
            temporal_codes=(),
            safety_state="NORMAL",
        )
    )
    local_enforced = judge.evaluate(
        context(event_id="stop-1", sequence=101, graph_risk=0.95, safety_state="SAFE_STOP")
    )
    metrics = judge.metrics()

    # A request can be descheduled after its cache lookup. The reservation
    # must use the clock sampled under the budget lock, or that older request
    # could reset a window that a newer request already advanced.
    budget_clock = [0.0]
    budget_transport = StubTransport()
    budget_advisor = JevSemanticAdvisor(
        JevAdvisorConfig(enabled=True, api_key="offline-stub", cache_ttl_sec=30.0),
        transport=budget_transport,
        clock=lambda: 0.0,
    )
    budget_judge = JevEfficientJudge(
        budget_advisor,
        policy=JevEfficiencyPolicy(max_remote_calls=1, budget_window_sec=60.0),
        clock=lambda: budget_clock[0],
    )
    delayed_context = context(event_id="budget-old", sequence=1)
    delayed_fingerprint = budget_judge._fingerprint(delayed_context)
    paused = threading.Event()
    release = threading.Event()
    original_get_cache = budget_judge._get_cache

    def delayed_cache_lookup(fingerprint, now):
        cached = original_get_cache(fingerprint, now)
        if fingerprint == delayed_fingerprint:
            paused.set()
            assert release.wait(2.0)
        return cached

    budget_judge._get_cache = delayed_cache_lookup
    with ThreadPoolExecutor(max_workers=1) as executor:
        older_future = executor.submit(budget_judge.evaluate, delayed_context)
        assert paused.wait(2.0)
        budget_clock[0] = 60.0
        newer = budget_judge.evaluate(context(event_id="budget-new", sequence=2, summary="new window"))
        release.set()
        older = older_future.result(timeout=2.0)
    following = budget_judge.evaluate(context(event_id="budget-following", sequence=3, summary="same window"))
    budget_clock[0] = 120.0
    next_window = budget_judge.evaluate(context(event_id="budget-next", sequence=4, summary="next window"))
    budget_race = {
        "newer_route": newer.route.value,
        "older_route": older.route.value,
        "following_route": following.route.value,
        "next_window_route": next_window.route.value,
        "provider_calls": budget_transport.calls,
    }

    cache_clock = [0.0]
    cache_transport = StubTransport()
    cache_advisor = JevSemanticAdvisor(
        JevAdvisorConfig(enabled=True, api_key="offline-stub", cache_ttl_sec=30.0),
        transport=cache_transport,
        clock=lambda: 0.0,
    )
    cache_judge = JevEfficientJudge(
        cache_advisor,
        policy=JevEfficiencyPolicy(cache_ttl_sec=5.0),
        clock=lambda: cache_clock[0],
    )
    cache_context = context(event_id="cache-old", sequence=1, summary="cache race")
    cache_fingerprint = cache_judge._fingerprint(cache_context)
    assert cache_judge.evaluate(cache_context).route == JevRoute.REMOTE
    cache_paused = threading.Event()
    cache_release = threading.Event()
    cache_original_get = cache_judge._get_cache

    def delayed_cache_probe(fingerprint, now):
        if fingerprint == cache_fingerprint:
            cache_paused.set()
            assert cache_release.wait(2.0)
        return cache_original_get(fingerprint, now)

    cache_judge._get_cache = delayed_cache_probe
    with ThreadPoolExecutor(max_workers=1) as executor:
        stale_future = executor.submit(cache_judge.evaluate, cache_context)
        assert cache_paused.wait(2.0)
        cache_clock[0] = 6.0
        cache_judge._now()
        cache_release.set()
        stale_result = stale_future.result(timeout=2.0)
    cache_race = {
        "route": stale_result.route.value,
        "cache_hit": stale_result.cache_hit,
        "provider_calls": cache_transport.calls,
    }
    evidence = {
        "baseline_remote_calls": baseline_transport.calls,
        "efficient_remote_calls": efficient_transport.calls,
        "call_reduction_ratio": round(1.0 - efficient_transport.calls / baseline_transport.calls, 3),
        "repeated_routes": [item.route.value for item in repeated_results],
        "local_safe_route": local_safe.route.value,
        "local_enforced_route": local_enforced.route.value,
        "budget_window_race": budget_race,
        "expired_cache_race": cache_race,
        "metrics": metrics.as_dict(),
    }
    assert baseline_transport.calls == len(repeated)
    assert efficient_transport.calls == 1
    assert repeated_results[0].route == JevRoute.REMOTE
    assert all(item.route == JevRoute.CACHE for item in repeated_results[1:])
    assert local_safe.route == JevRoute.LOCAL_SAFE
    assert local_enforced.route == JevRoute.LOCAL_ENFORCED
    assert metrics.remote_calls == 1
    assert metrics.cache_hits == len(repeated) - 1
    assert metrics.local_safe == 1
    assert metrics.local_enforced == 1
    assert budget_race == {
        "newer_route": "REMOTE",
        "older_route": "BUDGET_EXHAUSTED",
        "following_route": "BUDGET_EXHAUSTED",
        "next_window_route": "REMOTE",
        "provider_calls": 2,
    }
    assert cache_race == {"route": "REMOTE", "cache_hit": False, "provider_calls": 1}
    print(json.dumps({"passed": True, "experiment": "jev_efficiency", "evidence": evidence}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
