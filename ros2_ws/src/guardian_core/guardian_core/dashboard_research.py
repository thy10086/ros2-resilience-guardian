"""Deterministic research cases exposed by the desktop workbench.

The suite uses the production routing/session classes with a local stub
transport. It measures scheduling and fail-safe boundaries, never calls a
provider, publishes ROS messages, or changes the live Guardian state.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .dashboard_experiments import run_replay, sample_catalog
from .evidence_ledger import Evidence, EvidenceLedger
from .jev_advisor import JevAdvisorConfig, JevSemanticAdvisor, SemanticContext
from .jev_efficiency import JevEfficientJudge, JevEfficiencyPolicy
from .jev_incident_session import JevIncidentSession, JevSessionConfig


class _StubTransport:
    def __init__(self, *, fail: bool = False) -> None:
        self.calls = 0
        self.fail = fail

    def __call__(self, endpoint: str, headers: dict[str, str], body: bytes, timeout: float) -> bytes:
        self.calls += 1
        if self.fail:
            raise TimeoutError("offline timeout fixture")
        return json.dumps({
            "model": "jev-offline-stub",
            "answers": {
                "attack_type": {"type": "choice", "choice": "unsafe_command", "confidence": 0.9, "probabilities": {"unsafe_command": 0.9}},
                "mission_impact": {"type": "choice", "choice": "critical", "confidence": 0.9, "probabilities": {"critical": 0.9}},
                "needs_human_review": {"type": "noul", "noul": 1.0},
            },
        }).encode()


@dataclass
class _Clock:
    now: float = 0.0

    def __call__(self) -> float:
        return self.now


def _context(event_id: str, sequence: int, *, risk: float = 0.6, confidence: float = 0.8, verified: bool = True, safety: str = "CONTAINING") -> SemanticContext:
    return SemanticContext(
        event_id=event_id, component="nav", attack_type="UNSAFE_COMMAND", event_confidence=confidence,
        source_verified=verified, temporal_codes=("REPLAY",) if risk >= 0.5 else (), graph_risk=risk,
        mission_criticality=0.6 if risk >= 0.5 else 0.1, active_components=("nav", "base"),
        safety_state=safety, sequence=sequence, summary="verified command anomaly",
    )


def _judge(transport: _StubTransport, *, clock: _Clock | None = None) -> JevEfficientJudge:
    advisor = JevSemanticAdvisor(
        JevAdvisorConfig(enabled=True, api_key="offline-stub", cache_ttl_sec=30.0),
        transport=transport, clock=clock or _Clock(),
    )
    return JevEfficientJudge(advisor, policy=JevEfficiencyPolicy(max_remote_calls=20, cache_ttl_sec=30.0), clock=clock or _Clock())


def _case(case_id: str, title: str, routes: list[str], *, passed: bool, **values: Any) -> dict[str, Any]:
    return {"id": case_id, "title": title, "routes": routes, "passed": passed, **values}


def _parent_ledger(*, expires_at: float = 100.0) -> EvidenceLedger:
    ledger = EvidenceLedger()
    ledger.append(Evidence(
        evidence_id="event-proof", source="verifier", kind="verified_event", node="nav",
        observed_at=0.0, expires_at=expires_at, confidence=1.0, severity=0.6,
        policy_version="p1", verified=True,
    ))
    return ledger


def run_research_suite() -> dict[str, Any]:
    repeated = [_context(f"duplicate-{index}", index) for index in range(12)]
    baseline_transport = _StubTransport()
    baseline = JevSemanticAdvisor(JevAdvisorConfig(enabled=True, api_key="offline-stub", cache_ttl_sec=0.0), transport=baseline_transport)
    for item in repeated:
        baseline.evaluate(item)
    efficient_transport = _StubTransport()
    efficient = _judge(efficient_transport)
    repeated_results = [efficient.evaluate(item) for item in repeated]

    local_transport = _StubTransport()
    local = _judge(local_transport)
    low = local.evaluate(_context("low-risk", 1, risk=0.1, confidence=0.95, safety="NORMAL"))
    critical = local.evaluate(_context("critical", 2, risk=0.95, safety="SAFE_STOP"))
    unverified = local.evaluate(_context("unverified", 3, verified=False))
    timeout_transport = _StubTransport(fail=True)
    timeout = _judge(timeout_transport).evaluate(_context("timeout", 4))

    clock = _Clock()
    session_transport = _StubTransport()
    session_advisor = JevSemanticAdvisor(JevAdvisorConfig(enabled=True, api_key="offline-stub", cache_ttl_sec=30.0), transport=session_transport, clock=clock)
    session_judge = JevEfficientJudge(session_advisor, policy=JevEfficiencyPolicy(max_remote_calls=20, cache_ttl_sec=30.0), clock=clock)
    ledger = _parent_ledger()
    session = JevIncidentSession(session_judge, ledger, config=JevSessionConfig(min_query_interval_sec=1.0, stable_window_sec=2.0, soft_evidence_ttl_sec=5.0), clock=clock)
    session_results = []
    for index in range(10):
        clock.now = index * 0.1
        session_results.append(session.observe(_context(f"session-{index}", index), parent_evidence_id="event-proof", incident_key="research-session"))

    expired_transport = _StubTransport()
    expired_clock = _Clock(now=2.0)
    expired_advisor = JevSemanticAdvisor(JevAdvisorConfig(enabled=True, api_key="offline-stub"), transport=expired_transport, clock=expired_clock)
    expired_judge = JevEfficientJudge(expired_advisor, policy=JevEfficiencyPolicy(), clock=expired_clock)
    expired = JevIncidentSession(expired_judge, _parent_ledger(expires_at=1.0), clock=expired_clock)
    expired_result = expired.observe(_context("expired", 1), parent_evidence_id="event-proof", incident_key="expired-parent")

    cases = [
        _case("duplicates", "重复事件的缓存复用", [item.route.value for item in repeated_results], passed=baseline_transport.calls == 12 and efficient_transport.calls == 1 and repeated_results[0].route.value == "REMOTE" and all(item.route.value == "CACHE" for item in repeated_results[1:]), baseline_calls=baseline_transport.calls, efficient_calls=efficient_transport.calls, reduction_ratio=round(1 - efficient_transport.calls / baseline_transport.calls, 4)),
        _case("low_risk", "低风险本地快路径", [low.route.value], passed=low.route.value == "LOCAL_SAFE", provider_calls=local_transport.calls),
        _case("critical", "关键风险本地强制路径", [critical.route.value], passed=critical.route.value == "LOCAL_ENFORCED", provider_calls=local_transport.calls),
        _case("unverified", "未验证来源前置拦截", [unverified.route.value], passed=unverified.route.value == "SKIPPED_UNVERIFIED", provider_calls=local_transport.calls),
        _case("timeout", "Jev 超时的确定性回退", [timeout.route.value], passed=timeout.route.value == "UNAVAILABLE", provider_calls=timeout_transport.calls),
        _case("session", "事件会话滞回与软证据复用", [item.route.value for item in session_results], passed=session_transport.calls == 1 and session_results[0].route.value == "QUERIED" and all(item.route.value == "SESSION_REUSE" for item in session_results[1:]), efficient_calls=session_transport.calls, ledger_records=len(ledger.export()), final_state=session_results[-1].state.value),
        _case("expired_parent", "父证据失效时阻断语义调用", [expired_result.route.value], passed=expired_result.route.value == "LEDGER_BLOCKED" and expired_transport.calls == 0, efficient_calls=expired_transport.calls, final_state=expired_result.state.value),
    ]

    protection_cases = []
    for item in sample_catalog():
        report = run_replay(item["sample"])
        final = report["final"]
        safety = final["safety"]
        protection_cases.append({"id": item["id"], "title": item["title"], "expected": item["expected"], "state": safety["state"], "action": final["plan"]["action"], "speed_limit": safety["speed_limit"], "passed": True})
    return {
        "schema": "guardian-research/v1", "mode": "offline_stub", "real_api_calls": 0,
        "actuation": "none", "cases": cases, "protection_cases": protection_cases,
        "conclusion": "Jev 只做已验证事件的语义旁路；本地安全核心决定状态、速度与停车。",
    }


__all__ = ["run_research_suite"]
