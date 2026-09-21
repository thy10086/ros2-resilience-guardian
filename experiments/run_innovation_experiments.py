#!/usr/bin/env python3
"""Deterministic validation suite for the Guardian additions beyond the paper baseline."""

from __future__ import annotations

import hashlib
import hmac
import json
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ros2_ws" / "src" / "guardian_core"))

from guardian_core import (  # noqa: E402
    ActionType,
    AttackEvent,
    AttackRegistry,
    AuditLogger,
    EvidenceBundle,
    EvidenceFusion,
    EventVerifier,
    GraphEdge,
    GraphNode,
    GuardianConfig,
    MitigationPlanner,
    RecoveryEvidence,
    RecoveryGate,
    RiskEngine,
    SafetyEnvelopeController,
    SecurityGraph,
    SafetyState,
    SafetySupervisor,
    TemporalPolicyMonitor,
    TopicPolicy,
    VerificationCode,
    JevAdvisorConfig,
    JevAssessmentStatus,
    JevSemanticAdvisor,
    SemanticContext,
)
from guardian_core.dashboard_state import DashboardState  # noqa: E402


def make_event(
    sequence: int,
    *,
    event_id: str | None = None,
    source: str = "scenario_injector",
    component: str = "left_arm",
    attack_type: str = "STOP",
    timestamp: float = 100.0,
    confidence: float = 1.0,
    signature: str = "",
) -> AttackEvent:
    return AttackEvent(
        event_id or f"innovation-{sequence}",
        source,
        component,
        attack_type,
        sequence,
        timestamp,
        confidence,
        signature,
    )


def signed_event(secret: bytes, sequence: int = 1, **kwargs: object) -> AttackEvent:
    unsigned = make_event(sequence, **kwargs)
    payload = "|".join([
        unsigned.event_id,
        unsigned.source,
        unsigned.component,
        unsigned.attack_type,
        str(unsigned.sequence),
        f"{unsigned.timestamp:.6f}",
        f"{unsigned.confidence:.6f}",
    ]).encode("utf-8")
    signature = hmac.new(secret, payload, hashlib.sha256).hexdigest()
    return AttackEvent(**{**unsigned.__dict__, "signature": signature})


def config(**overrides: object) -> GuardianConfig:
    values: dict[str, object] = {
        "task": "navigate_and_pickup",
        "goal": "table2",
        "tau": {"left_wheels": 2, "right_wheels": 2, "left_arm": 1, "right_arm": 1, "left_gripper": 1, "right_gripper": 1},
        "theta_base": 0.72,
        "theta_crit": 0.8,
        "alpha_base": 0.2,
        "alpha_crit": 0.15,
        "mitigatable_devices": frozenset({"left_wheels", "right_wheels", "left_arm", "right_arm", "left_gripper", "right_gripper"}),
        "mitigation_delay_sec": 1.0,
        "max_event_age_sec": 5.0,
        "default_speed_limit": 0.35,
        "safe_stop_speed": 0.0,
    }
    values.update(overrides)
    return GuardianConfig(**values)


def experiment_zero_trust_event_gate() -> dict[str, object]:
    verifier = EventVerifier({"scenario_injector"}, max_event_age_sec=5.0)
    codes: dict[str, str] = {}
    accepted = verifier.verify(make_event(1), 100.0)
    codes["accepted"] = accepted.code.value
    codes["unknown_source"] = verifier.verify(make_event(2, source="evil"), 100.0).code.value
    codes["stale"] = verifier.verify(make_event(3, timestamp=90.0), 100.0).code.value
    codes["future"] = verifier.verify(make_event(4, timestamp=101.0), 100.0).code.value
    codes["replay"] = verifier.verify(make_event(1), 100.0).code.value

    secret = b"innovation-test-secret"
    signature_verifier = EventVerifier(
        {"scenario_injector"},
        max_event_age_sec=5.0,
        signature_secret=secret,
        require_signature=True,
    )
    valid_signature = signature_verifier.verify(signed_event(secret), 100.0)
    invalid_signature = signature_verifier.verify(make_event(2, signature="bad"), 100.0)
    codes["hmac_valid"] = valid_signature.code.value
    codes["hmac_invalid"] = invalid_signature.code.value

    expected = {
        "accepted": VerificationCode.ACCEPTED.value,
        "unknown_source": VerificationCode.UNKNOWN_SOURCE.value,
        "stale": VerificationCode.STALE.value,
        "future": VerificationCode.FUTURE.value,
        "replay": VerificationCode.REPLAY.value,
        "hmac_valid": VerificationCode.ACCEPTED.value,
        "hmac_invalid": VerificationCode.INVALID.value,
    }
    assert codes == expected, codes
    return {
        "name": "zero_trust_event_gate",
        "passed": True,
        "evidence": {"verification_codes": codes, "blocked_events": 5},
    }


def experiment_wave_replanning() -> dict[str, object]:
    cfg = config(
        tau={"left_wheels": 2, "right_wheels": 2, "left_arm": 1, "right_arm": 1},
    )
    engine = RiskEngine(cfg)
    planner = MitigationPlanner(cfg, engine)
    registry = AttackRegistry(cfg.max_event_age_sec)
    # First wave creates a pending arm-isolation plan. A critical wheel attack
    # arrives before activation, so the planner must replace that stale plan.
    registry.upsert(make_event(1, component="left_arm", timestamp=0.0), 0.0)
    registry.upsert(make_event(2, component="right_arm", timestamp=0.0), 0.0)
    first_assessment = engine.evaluate(registry.active_records(), 0.0)
    first_plan = planner.plan(registry.active_records(), first_assessment, 0.0)
    first_decision = SafetySupervisor(cfg.default_speed_limit, cfg.safe_stop_speed).decide(first_assessment, first_plan)

    registry.upsert(make_event(3, component="left_wheels", attack_type="STOP", timestamp=0.5), 0.5)
    second_assessment = engine.evaluate(registry.active_records(), 0.5)
    second_plan = planner.plan(registry.active_records(), second_assessment, 0.5)
    second_decision = SafetySupervisor(cfg.default_speed_limit, cfg.safe_stop_speed).decide(second_assessment, second_plan)

    before = second_assessment.risk
    for component in second_plan.components:
        registry.clear_component(component)
    recovered = engine.evaluate(registry.active_records(), second_plan.activate_at)
    recovery_plan = planner.plan(registry.active_records(), recovered, second_plan.activate_at)
    recovery_decision = SafetySupervisor(cfg.default_speed_limit, cfg.safe_stop_speed).decide(recovered, recovery_plan)

    observations = [
        {"time": 0.0, "active": sorted(first_assessment.active_components), "action": first_plan.action.value, "components": sorted(first_plan.components), "state": first_decision.state.value, "plan_id": first_plan.plan_id, "activate_at": first_plan.activate_at},
        {"time": 0.5, "active": sorted(second_assessment.active_components), "action": second_plan.action.value, "components": sorted(second_plan.components), "state": second_decision.state.value, "plan_id": second_plan.plan_id, "activate_at": second_plan.activate_at},
        {"time": second_plan.activate_at, "active": sorted(recovered.active_components), "action": recovery_plan.action.value, "components": sorted(recovery_plan.components), "state": recovery_decision.state.value, "plan_id": recovery_plan.plan_id, "activate_at": recovery_plan.activate_at},
    ]
    assert first_plan.action == ActionType.ISOLATE_COMPONENT, observations
    assert second_plan.action == ActionType.ISOLATE_COMPONENT, observations
    assert first_plan.plan_id != second_plan.plan_id, observations
    assert "left_wheels" in second_plan.components, observations
    assert second_plan.activate_at == 1.5, observations
    assert recovered.risk < before, (before, recovered.risk)
    assert recovery_plan.action == ActionType.NONE and recovery_decision.state == SafetyState.RESUMABLE, observations
    return {
        "name": "wave_replanning",
        "passed": True,
        "evidence": {
            "waves": 2,
            "replans_before_enforcement": 2,
            "stale_plan_replaced": first_plan.plan_id != second_plan.plan_id,
            "new_critical_component_in_plan": "left_wheels" in second_plan.components,
            "observations": observations,
        },
    }


def experiment_safety_state_machine() -> dict[str, object]:
    cfg = config()
    engine = RiskEngine(cfg)
    planner = MitigationPlanner(cfg, engine)
    supervisor = SafetySupervisor(cfg.default_speed_limit, cfg.safe_stop_speed)
    registry = AttackRegistry(cfg.max_event_age_sec)

    def decide(now: float) -> tuple[SafetyState, bool, float]:
        assessment = engine.evaluate(registry.active_records(), now)
        plan = planner.plan(registry.active_records(), assessment, now)
        decision = supervisor.decide(assessment, plan)
        return decision.state, decision.mission_allowed, decision.speed_limit

    normal = decide(0.0)
    registry.upsert(make_event(1, component="left_arm", timestamp=1.0), 1.0)
    resumable = decide(1.0)
    registry.upsert(make_event(2, component="right_arm", timestamp=1.0), 1.0)
    containing = decide(1.0)
    registry.clear_component("left_arm")
    registry.clear_component("right_arm")
    registry.upsert(make_event(3, component="left_wheels", timestamp=2.0), 2.0)
    cfg_no_wheel_isolation = config(mitigatable_devices=frozenset({"left_arm", "right_arm"}))
    engine_no_wheel = RiskEngine(cfg_no_wheel_isolation)
    planner_no_wheel = MitigationPlanner(cfg_no_wheel_isolation, engine_no_wheel)
    assessment = engine_no_wheel.evaluate(registry.active_records(), 2.0)
    plan = planner_no_wheel.plan(registry.active_records(), assessment, 2.0)
    safe_stop_decision = supervisor.decide(assessment, plan)
    states = {
        "no_attack": {"state": normal[0].value, "mission_allowed": normal[1], "speed_limit": normal[2]},
        "single_noncritical": {"state": resumable[0].value, "mission_allowed": resumable[1], "speed_limit": resumable[2]},
        "containment": {"state": containing[0].value, "mission_allowed": containing[1], "speed_limit": containing[2]},
        "unmitigatable_critical": {"state": safe_stop_decision.state.value, "mission_allowed": safe_stop_decision.mission_allowed, "speed_limit": safe_stop_decision.speed_limit},
    }
    assert normal[0] == SafetyState.NORMAL and normal[1] and normal[2] == cfg.default_speed_limit, states
    assert resumable[0] == SafetyState.RESUMABLE and resumable[1], states
    assert containing[0] == SafetyState.CONTAINING and not containing[1] and containing[2] == 0.15, states
    assert safe_stop_decision.state == SafetyState.SAFE_STOP and not safe_stop_decision.mission_allowed and safe_stop_decision.speed_limit == 0.0, states
    return {"name": "safety_state_machine", "passed": True, "evidence": states}


def experiment_dashboard_and_audit() -> dict[str, object]:
    dashboard = DashboardState(timeline_limit=10)
    dashboard.update_risk(SimpleNamespace(
        timestamp=1.0, state="DEGRADED", risk=0.4, psi=0.8, delta=True, gamma=False,
        active_components=["right_arm"], critical_components=[], reason="threshold",
    ))
    dashboard.update_mitigation(SimpleNamespace(
        timestamp=1.1, plan_id="contain-test", action="ISOLATE_COMPONENT",
        components=["right_arm"], requires_safe_stop=False, reason="isolate component",
    ))
    dashboard.update_safety(SimpleNamespace(
        timestamp=1.2, state="CONTAINING", speed_limit=0.15,
        mission_allowed=False, reason="pending isolation", plan_id="contain-test",
    ))
    snapshot = dashboard.snapshot()
    assert snapshot["risk"]["state"] == "DEGRADED"
    assert snapshot["mitigation"]["plan_id"] == "contain-test"
    assert snapshot["safety"]["speed_limit"] == 0.15
    assert [item["category"] for item in snapshot["timeline"]] == ["safety", "mitigation", "risk"]

    with tempfile.TemporaryDirectory(prefix="guardian-audit-") as directory:
        path = Path(directory) / "audit.jsonl"
        logger = AuditLogger(path)
        logger.emit("event_verification", {"event_id": "innovation-1", "accepted": True})
        logger.emit("mitigation_plan", {"plan_id": "contain-test", "action": "ISOLATE_COMPONENT"})
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert [row["kind"] for row in rows] == ["event_verification", "mitigation_plan"]
    return {
        "name": "dashboard_and_audit",
        "passed": True,
        "evidence": {
            "timeline_categories": [item["category"] for item in snapshot["timeline"]],
            "api_state_keys": sorted(snapshot.keys()),
            "audit_rows": len(rows),
        },
    }


def experiment_cross_layer_fusion() -> dict[str, object]:
    """Validate the new cross-layer safety path without a live ROS graph.

    The experiment keeps each layer observable so a later ROS 2 adapter can
    replace the deterministic inputs one at a time: graph topology, temporal
    policy violations, evidence fusion, speed envelope and recovery gate.
    """
    graph = SecurityGraph(
        [
            GraphNode("nav", "node", criticality=0.4),
            GraphNode("cmd_vel", "topic", criticality=0.7),
            GraphNode("base", "actuator", criticality=1.0),
        ],
        [
            GraphEdge("nav", "cmd_vel", weight=0.9),
            GraphEdge("cmd_vel", "base", weight=0.8),
        ],
    )
    graph_assessment = graph.propagate({"nav": 0.9})

    policy_monitor = TemporalPolicyMonitor(
        [TopicPolicy("/cmd_vel", "nav", min_period_sec=0.05, max_gap_sec=0.5, max_age_sec=0.2)]
    )
    valid = policy_monitor.observe("/cmd_vel", "nav", 10.0, 1, 10.0)
    untrusted = policy_monitor.observe("/cmd_vel", "spoofed_nav", 10.1, 2, 10.1)
    replay = policy_monitor.observe("/cmd_vel", "nav", 10.1, 1, 10.1)
    stale = policy_monitor.observe("/cmd_vel", "nav", 10.1, 2, 10.6)
    violation_codes = {
        "valid": [item.code for item in valid],
        "untrusted": [item.code for item in untrusted],
        "replay": [item.code for item in replay],
        "stale": [item.code for item in stale],
    }

    fusion = EvidenceFusion()
    fused = fusion.evaluate(
        EvidenceBundle(
            event_confidence=0.9,
            source_trust=0.9,
            temporal_violation=0.7,
            graph_risk=graph_assessment.risk_by_node["base"],
            mission_criticality=0.9,
            physical_inconsistency=0.0,
        )
    )
    envelope = SafetyEnvelopeController(default_speed_limit=0.35, braking_acceleration=0.8)
    clear_speed = envelope.compute(risk=0.05, free_distance=2.0, sensor_fresh=True)
    contained_speed = envelope.compute(risk=fused.score, free_distance=2.0, sensor_fresh=True)
    stale_sensor = envelope.compute(risk=fused.score, free_distance=2.0, sensor_fresh=False)

    recovery = RecoveryGate()
    blocked_recovery = recovery.evaluate(
        RecoveryEvidence(True, False, True, True, True, True)
    )
    allowed_recovery = recovery.evaluate(
        RecoveryEvidence(True, True, True, True, True, True)
    )

    evidence = {
        "graph": {
            "risk_by_node": dict(graph_assessment.risk_by_node),
            "critical_nodes": sorted(graph_assessment.critical_nodes),
            "blast_radius": graph_assessment.blast_radius,
        },
        "temporal_policy": violation_codes,
        "fusion": {
            "score": fused.score,
            "level": fused.level,
            "reasons": list(fused.reasons),
        },
        "safety_envelope": {
            "clear_speed": clear_speed.speed_limit,
            "contained_speed": contained_speed.speed_limit,
            "contained_state": contained_speed.state,
            "stale_sensor_state": stale_sensor.state,
        },
        "recovery": {
            "blocked": list(blocked_recovery.missing),
            "allowed": allowed_recovery.allowed,
        },
    }
    assert abs(graph_assessment.risk_by_node["cmd_vel"] - 0.81) < 1e-9, evidence
    assert abs(graph_assessment.risk_by_node["base"] - 0.648) < 1e-9, evidence
    assert graph_assessment.critical_nodes == frozenset({"base"}), evidence
    assert violation_codes == {
        "valid": [],
        "untrusted": ["UNTRUSTED_SOURCE"],
        "replay": ["REPLAY"],
        "stale": ["STALE"],
    }, evidence
    assert fused.level == "CONTAIN" and fused.score > 0.35, evidence
    assert 0.0 < contained_speed.speed_limit < clear_speed.speed_limit, evidence
    assert contained_speed.state == "CONTAINING" and not contained_speed.mission_allowed, evidence
    assert stale_sensor.state == "SAFE_STOP" and stale_sensor.speed_limit == 0.0, evidence
    assert not blocked_recovery.allowed and "graph_stable" in blocked_recovery.missing, evidence
    assert allowed_recovery.allowed, evidence
    return {"name": "cross_layer_fusion", "passed": True, "evidence": evidence}


def experiment_jev_semantic_advisor() -> dict[str, object]:
    """Validate the Jev side-channel with a deterministic provider stub.

    This deliberately does not alter EvidenceFusion or SafetySupervisor. The
    experiment proves the typed response, cache behavior and fail-safe source
    boundary without requiring network access or a real API key.
    """
    calls: list[dict[str, object]] = []

    def transport(endpoint: str, headers: dict[str, str], body: bytes, timeout: float) -> bytes:
        calls.append({"endpoint": endpoint, "timeout": timeout, "body_bytes": len(body)})
        return json.dumps({
            "model": "jev-stub",
            "answers": {
                "attack_type": {
                    "type": "choice",
                    "choice": "unsafe_command",
                    "confidence": 0.9,
                    "probabilities": {"unsafe_command": 0.9, "benign": 0.1},
                },
                "mission_impact": {
                    "type": "choice",
                    "choice": "critical",
                    "confidence": 0.8,
                    "probabilities": {"critical": 0.85, "medium": 0.15},
                },
                "needs_human_review": {"type": "noul", "noul": 1.0},
            },
        }).encode("utf-8")

    advisor = JevSemanticAdvisor(
        JevAdvisorConfig(enabled=True, api_key="offline-stub", cache_ttl_sec=5.0),
        transport=transport,
        clock=lambda: 100.0,
    )
    context = SemanticContext(
        event_id="jev-innovation-1",
        component="nav",
        attack_type="UNSAFE_COMMAND",
        event_confidence=0.9,
        source_verified=True,
        temporal_codes=("REPLAY",),
        graph_risk=0.81,
        mission_criticality=0.9,
        active_components=("nav", "base"),
        safety_state="CONTAINING",
        sequence=1,
        summary="verified command anomaly",
    )
    assessment = advisor.evaluate(context)
    cached = advisor.evaluate(context)
    skipped = advisor.evaluate(SemanticContext(**{**context.__dict__, "source_verified": False}))
    with tempfile.TemporaryDirectory(prefix="guardian-jev-") as directory:
        audit_path = Path(directory) / "audit.jsonl"
        AuditLogger(audit_path).emit("jev_semantic_advice", assessment.audit_payload())
        audit_rows = audit_path.read_text(encoding="utf-8").splitlines()

    evidence = {
        "status": assessment.status.value,
        "cached_status": cached.status.value,
        "unverified_status": skipped.status.value,
        "label": assessment.label,
        "score": assessment.score,
        "confidence": assessment.confidence,
        "review_recommended": assessment.recommends_review(),
        "provider_calls": len(calls),
        "audit_rows": len(audit_rows),
    }
    assert assessment.status == JevAssessmentStatus.OK, evidence
    assert cached.status == JevAssessmentStatus.CACHED, evidence
    assert skipped.status == JevAssessmentStatus.SKIPPED_UNVERIFIED, evidence
    assert assessment.label == "unsafe_command", evidence
    assert assessment.score >= 0.85, evidence
    assert assessment.recommends_review(), evidence
    assert len(calls) == 1, evidence
    assert len(audit_rows) == 1, evidence
    return {"name": "jev_semantic_advisor", "passed": True, "evidence": evidence}


def main() -> int:
    experiments = [
        experiment_zero_trust_event_gate(),
        experiment_wave_replanning(),
        experiment_safety_state_machine(),
        experiment_dashboard_and_audit(),
        experiment_cross_layer_fusion(),
        experiment_jev_semantic_advisor(),
    ]
    report = {"passed": all(item["passed"] for item in experiments), "experiments": experiments}
    output_path = ROOT / "experiments" / "results" / "innovation_validation.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
