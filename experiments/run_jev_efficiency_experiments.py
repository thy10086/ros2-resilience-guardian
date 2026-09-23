#!/usr/bin/env python3
"""Deterministic comparison for the efficient Jev judgment layer."""

from __future__ import annotations

import json
import sys
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
        summary="verified command anomaly",
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
    evidence = {
        "baseline_remote_calls": baseline_transport.calls,
        "efficient_remote_calls": efficient_transport.calls,
        "call_reduction_ratio": round(1.0 - efficient_transport.calls / baseline_transport.calls, 3),
        "repeated_routes": [item.route.value for item in repeated_results],
        "local_safe_route": local_safe.route.value,
        "local_enforced_route": local_enforced.route.value,
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
    print(json.dumps({"passed": True, "experiment": "jev_efficiency", "evidence": evidence}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
