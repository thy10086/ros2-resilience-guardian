from dataclasses import replace
import json

import pytest

from guardian_core import (
    ActionType,
    AttackEvent,
    ContainmentPolicy,
    GuardianConfig,
    MitigationPlanner,
    RiskEngine,
    SafetyState,
    SafetySupervisor,
)
from guardian_core.config import parse_containment_policies
from guardian_core.models import AttackRecord, MitigationPlan


def config(**changes):
    values = dict(
        task="navigate",
        goal="pallet",
        tau={"wheel": 2, "arm": 1},
        mitigatable_devices=frozenset({"wheel", "arm"}),
        task_phase="DOCK",
    )
    values.update(changes)
    return GuardianConfig(**values)


def record(attack="SPEED", component="arm", source="sensor", event_id="e1"):
    return AttackRecord(AttackEvent(event_id, source, component, attack, 1, 10.0), 10.0, 10.0)


def planned(settings, records):
    engine = RiskEngine(settings)
    assessment = engine.evaluate(records, 10.0)
    return MitigationPlanner(settings, engine).plan(records, assessment, 10.0)


def test_phase_specific_limit_cannot_override_another_attacks_stop():
    settings = config(containment_policies={
        ("SPEED", "DOCK"): ContainmentPolicy(ActionType.LIMIT_SPEED, 0.1, True),
        ("REPLAY", "*"): ContainmentPolicy(ActionType.SAFE_STOP, 0.0, False),
    })
    plan = planned(settings, [record(), record("REPLAY", "wheel", event_id="e2")])
    assert plan.action == ActionType.SAFE_STOP
    assert plan.mission_allowed is False
    assert plan.speed_limit == 0.0


def test_combination_preserves_speed_and_permission_constraints():
    settings = config(containment_policies={
        ("SPEED", "DOCK"): ContainmentPolicy(ActionType.LIMIT_SPEED, 0.2, True),
        ("FAULT", "*"): ContainmentPolicy(ActionType.DEGRADED_RUN, 0.05, False),
    })
    policy = settings.containment_policy_for(["SPEED", "FAULT"])
    assert policy.action == ActionType.LIMIT_SPEED
    assert policy.speed_limit == 0.05
    assert policy.mission_allowed is False


def test_unmatched_attack_still_contributes_default_stop():
    settings = config(
        containment_policies={("SPEED", "DOCK"): ContainmentPolicy(ActionType.LIMIT_SPEED, 0.1, True)},
        default_containment_policy=ContainmentPolicy(ActionType.SAFE_STOP, 0.0, False),
    )
    assert settings.containment_policy_for(["SPEED", "UNKNOWN"]).action == ActionType.SAFE_STOP


@pytest.mark.parametrize("action", [ActionType.NONE, ActionType.SWITCH_CONTROLLER, ActionType.REPLAN_MISSION])
def test_unimplemented_or_noop_containment_actions_are_rejected(action):
    with pytest.raises(ValueError):
        ContainmentPolicy(action, 0.1, False)


@pytest.mark.parametrize("speed", [True, "0.1", None, float("nan"), float("inf"), -0.1])
def test_policy_speed_requires_a_finite_nonnegative_number(speed):
    with pytest.raises(ValueError):
        ContainmentPolicy(ActionType.LIMIT_SPEED, speed, False)


@pytest.mark.parametrize("speed,allowed", [(0.1, False), (0.0, True)])
def test_stop_policy_cannot_allow_motion(speed, allowed):
    with pytest.raises(ValueError):
        ContainmentPolicy(ActionType.SAFE_STOP, speed, allowed)


@pytest.mark.parametrize("speed_json", ['true', '"0.1"'])
def test_policy_json_does_not_coerce_boolean_or_string_speed(speed_json):
    with pytest.raises(ValueError):
        parse_containment_policies(
            '{"default":{"action":"LIMIT_SPEED","speed_limit":'
            + speed_json + ',"mission_allowed":false}}'
        )


@pytest.mark.parametrize("changes", [
    {"mitigation_delay_sec": -1.0},
    {"mitigation_delay_sec": float("nan")},
    {"default_speed_limit": float("inf")},
    {"default_speed_limit": True},
    {"safe_stop_speed": 0.1},
])
def test_runtime_configuration_rejects_unsafe_timing_or_speeds(changes):
    with pytest.raises(ValueError):
        config(**changes)


@pytest.mark.parametrize("action,speed", [
    (ActionType.SAFE_STOP, 0.0),
    (ActionType.LIMIT_SPEED, 0.1),
    (ActionType.DEGRADED_RUN, 0.1),
])
def test_default_nonisolation_policy_is_applied_even_to_low_risk(action, speed):
    settings = config(default_containment_policy=ContainmentPolicy(action, speed, False))
    plan = planned(settings, [record()])
    assert plan.action == action
    assert plan.speed_limit == speed
    assert plan.mission_allowed is False


@pytest.mark.parametrize("records", [[record(component="wheel")], [record(), record(component="wheel", event_id="e2")]])
def test_explicit_isolation_fails_closed_for_unisolatable_attack(records):
    settings = config(
        mitigatable_devices=frozenset({"arm"}),
        containment_policies={("SPEED", "*"): ContainmentPolicy(ActionType.ISOLATE_COMPONENT, 0.1, True)},
    )
    plan = planned(settings, records)
    assert plan.action == ActionType.SAFE_STOP
    assert plan.requires_safe_stop
    assert plan.mission_allowed is False


def test_explicit_isolation_reports_evaluated_residual_risk():
    settings = config(containment_policies={
        ("SPEED", "*"): ContainmentPolicy(ActionType.ISOLATE_COMPONENT, 0.1, False),
    })
    plan = planned(settings, [record()])
    assert plan.components == frozenset({"arm"})
    assert plan.residual_psi == 1.0


def test_replacing_event_with_colliding_text_identity_triggers_replan():
    settings = config()
    engine = RiskEngine(settings)
    planner = MitigationPlanner(settings, engine)
    original = [record(source="sensor:a", event_id="b")]
    planner.plan(original, engine.evaluate(original, 10.0), 10.0)
    replacement = [record(source="sensor", event_id="a:b", component="wheel")]
    assert planner.should_replan(replacement)


def test_safe_stop_takes_precedence_over_activation_delay():
    assessment = RiskEngine(config()).evaluate([record(component="wheel")], 10.0)
    plan = MitigationPlan("stop", ActionType.SAFE_STOP, frozenset(), 10.0, 20.0, "stop", 0.5, True)
    decision = SafetySupervisor().decide(assessment, plan)
    assert decision.state == SafetyState.SAFE_STOP
    assert decision.speed_limit == 0.0
    assert not decision.mission_allowed


def test_zero_default_speed_cannot_be_raised_by_a_plan():
    assessment = RiskEngine(config()).evaluate([record()], 10.0)
    plan = MitigationPlan(
        "limit", ActionType.LIMIT_SPEED, frozenset(), 10.0, 10.0, "limit", 1.0,
        mission_allowed=True, speed_limit=0.1,
    )
    assert SafetySupervisor(default_speed_limit=0.0).decide(assessment, plan).speed_limit == 0.0


def test_missing_mitigation_cannot_authorize_a_violated_invariant():
    assessment = RiskEngine(config()).evaluate([record(component="wheel")], 10.0)
    plan = MitigationPlan("none", ActionType.NONE, frozenset(), 10.0, 10.0, "none", assessment.psi)
    decision = SafetySupervisor().decide(assessment, plan)
    assert decision.state == SafetyState.SAFE_STOP
    assert not decision.mission_allowed


def test_pending_command_keeps_mission_locked():
    assessment = RiskEngine(config()).evaluate([record()], 10.0)
    plan = MitigationPlan(
        "isolate", ActionType.ISOLATE_COMPONENT, frozenset({"arm"}), 10.0, 12.0, "isolate", 1.0,
        mission_allowed=True, speed_limit=0.1,
    )
    supervisor = SafetySupervisor()
    assert not supervisor.decide(assessment, plan).mission_allowed
    assert supervisor.decide(replace(assessment, timestamp=12.0), plan).mission_allowed


@pytest.mark.parametrize("attack", ["FAULT", "default"])
@pytest.mark.parametrize("order", [("default", "*"), ("*", "default")])
def test_conflicting_phase_aliases_are_rejected_in_either_order(attack, order):
    phases = {
        order[0]: {"action": "SAFE_STOP", "speed_limit": 0.0, "mission_allowed": False},
        order[1]: {"action": "LIMIT_SPEED", "speed_limit": 0.1, "mission_allowed": True},
    }
    with pytest.raises(ValueError, match="duplicate"):
        parse_containment_policies(json.dumps({attack: phases}))


def test_duplicate_json_keys_cannot_silently_remove_a_stop():
    payload = (
        '{"FAULT":{"action":"SAFE_STOP","speed_limit":0,"mission_allowed":false},'
        '"FAULT":{"action":"LIMIT_SPEED","speed_limit":0.1,"mission_allowed":true}}'
    )
    with pytest.raises(ValueError, match="duplicate"):
        parse_containment_policies(payload)
