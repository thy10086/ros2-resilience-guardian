import pytest
import hashlib
import hmac

from guardian_core import (
    ActionType,
    AttackEvent,
    AttackRegistry,
    EventVerifier,
    GuardianConfig,
    MitigationPlanner,
    RiskEngine,
    SafetyState,
    SafetySupervisor,
)


def event(seq=1, component="left_arm", source="scenario_injector", timestamp=10.0, attack_type="STOP", confidence=1.0):
    return AttackEvent(f"e-{seq}", source, component, attack_type, seq, timestamp, confidence)


def base_config(**kwargs):
    values = dict(
        task="navigate_to_goal", goal="box2",
        tau={"left_arm": 1, "right_arm": 1, "left_wheels": 2},
        theta_base=0.72, theta_crit=0.8, alpha_base=0.2, alpha_crit=0.15,
        mitigatable_devices=frozenset({"left_arm", "right_arm", "left_wheels"}),
    )
    values.update(kwargs)
    return GuardianConfig(**values)


def test_verifier_rejects_unknown_source_and_replay():
    verifier = EventVerifier({"scenario_injector"}, max_event_age_sec=5.0)
    assert verifier.verify(event(), 10.0).accepted
    assert verifier.verify(event(2, source="evil"), 10.0).code.value == "UNKNOWN_SOURCE"
    assert verifier.verify(event(1), 10.0).code.value == "REPLAY"


def test_verifier_can_require_hmac_signature():
    secret = b"test-secret"
    unsigned = event()
    payload = "|".join([
        unsigned.event_id, unsigned.source, unsigned.component, unsigned.attack_type,
        str(unsigned.sequence), f"{unsigned.timestamp:.6f}", f"{unsigned.confidence:.6f}",
    ]).encode()
    signed = AttackEvent(**{**unsigned.__dict__, "signature": hmac.new(secret, payload, hashlib.sha256).hexdigest()})
    verifier = EventVerifier({"scenario_injector"}, 5.0, signature_secret=secret, require_signature=True)
    assert verifier.verify(signed, 10.0).accepted


def test_registry_keeps_multiple_waves_and_expires():
    registry = AttackRegistry(expiry_sec=5.0)
    registry.upsert(event(1, "left_arm", timestamp=10.0), 10.0)
    registry.upsert(event(2, "right_arm", timestamp=10.0), 10.0)
    assert registry.active_components() == frozenset({"left_arm", "right_arm"})
    assert registry.expire(16.0) == ["e-1", "e-2"]


def test_two_noncritical_components_cross_threshold():
    config = base_config()
    engine = RiskEngine(config)
    registry = AttackRegistry()
    registry.upsert(event(1, "left_arm"), 10.0)
    registry.upsert(event(2, "right_arm"), 10.0)
    assessment = engine.evaluate(registry.active_records(), 10.0)
    assert assessment.delta == 1
    assert assessment.psi == pytest.approx(0.670320046, rel=1e-6)
    assert assessment.gamma == 0


def test_repeated_telemetry_for_one_component_is_counted_once():
    config = base_config()
    engine = RiskEngine(config)
    registry = AttackRegistry()
    registry.upsert(event(1, "left_arm"), 10.0)
    registry.upsert(event(2, "left_arm"), 11.0)
    registry.upsert(event(3, "right_arm"), 11.0)
    assessment = engine.evaluate(registry.active_records(), 11.0)
    assert assessment.k_base == pytest.approx(2.0)
    assert assessment.psi == pytest.approx(0.670320046, rel=1e-6)


def test_planner_replans_and_isolates_one_noncritical_component():
    config = base_config()
    engine = RiskEngine(config)
    planner = MitigationPlanner(config, engine)
    registry = AttackRegistry()
    registry.upsert(event(1, "left_arm"), 10.0)
    registry.upsert(event(2, "right_arm"), 10.0)
    assessment = engine.evaluate(registry.active_records(), 10.0)
    plan = planner.plan(registry.active_records(), assessment, 10.0)
    assert plan.action == ActionType.ISOLATE_COMPONENT
    assert len(plan.components) == 1
    assert plan.residual_psi > config.theta_base


def test_planner_safe_stops_when_critical_component_is_not_mitigatable():
    config = base_config(mitigatable_devices=frozenset({"left_arm", "right_arm"}))
    engine = RiskEngine(config)
    planner = MitigationPlanner(config, engine)
    registry = AttackRegistry()
    registry.upsert(event(1, "left_wheels"), 10.0)
    assessment = engine.evaluate(registry.active_records(), 10.0)
    plan = planner.plan(registry.active_records(), assessment, 10.0)
    assert plan.action == ActionType.SAFE_STOP
    decision = SafetySupervisor().decide(assessment, plan)
    assert decision.state == SafetyState.SAFE_STOP
    assert decision.mission_allowed is False


def test_supervisor_contains_before_recovery():
    config = base_config()
    engine = RiskEngine(config)
    planner = MitigationPlanner(config, engine)
    registry = AttackRegistry()
    registry.upsert(event(1, "left_arm"), 10.0)
    registry.upsert(event(2, "right_arm"), 10.0)
    assessment = engine.evaluate(registry.active_records(), 10.0)
    plan = planner.plan(registry.active_records(), assessment, 10.0)
    decision = SafetySupervisor().decide(assessment, plan)
    assert decision.state == SafetyState.CONTAINING
    assert decision.mission_allowed is False
