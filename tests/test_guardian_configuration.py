import json
from pathlib import Path

import pytest

from guardian_core import (
    ActionType,
    AttackEvent,
    AttackRegistry,
    ContainmentPolicy,
    GuardianConfig,
    MitigationPlanner,
    RiskEngine,
    SafetyState,
    SafetySupervisor,
)


ROOT = Path(__file__).resolve().parents[1]


def _event(attack_type: str = "UNSAFE_COMMAND", component: str = "left_wheels") -> AttackEvent:
    return AttackEvent(
        "event-1",
        "scenario_injector",
        component,
        attack_type,
        1,
        10.0,
        0.98,
    )


def _config(**kwargs) -> GuardianConfig:
    values = dict(
        task="navigate_to_goal",
        goal="box2",
        task_phase="DOCK_TO_PALLET",
        tau={"left_wheels": 2, "right_arm": 1},
        epsilon={"distance_sensor": 0},
        theta_crit=0.8,
        theta_base=0.72,
        alpha_crit=0.15,
        alpha_base=0.2,
        mitigation_delay_sec=0.0,
        mitigatable_devices=frozenset({"left_wheels", "right_arm"}),
    )
    values.update(kwargs)
    return GuardianConfig(**values)


def test_config_file_is_a_ros_parameter_file_with_policy_defaults():
    import yaml

    document = yaml.safe_load((ROOT / "configs" / "guardian.yaml").read_text(encoding="utf-8"))
    parameters = document["guardian_node"]["ros__parameters"]
    policy = json.loads(parameters["containment_policy_json"])

    assert parameters["default_speed_limit"] == pytest.approx(0.35)
    assert policy["default"]["action"] == "ISOLATE_COMPONENT"
    assert "UNSAFE_COMMAND" not in policy
    profile = json.loads(parameters["security_profile_json"])
    assert profile["resources"]["left_gripper"]["tau"] == 2


def test_policy_selection_prefers_attack_and_task_phase():
    config = _config(
        containment_policies={
            ("*", "*"): ContainmentPolicy(ActionType.SAFE_STOP, 0.0, False),
            ("UNSAFE_COMMAND", "*"): ContainmentPolicy(ActionType.DEGRADED_RUN, 0.2, True),
            ("UNSAFE_COMMAND", "DOCK_TO_PALLET"): ContainmentPolicy(ActionType.LIMIT_SPEED, 0.12, True),
        }
    )

    selected = config.containment_policy_for({"UNSAFE_COMMAND"}, "DOCK_TO_PALLET")

    assert selected.action == ActionType.LIMIT_SPEED
    assert selected.speed_limit == pytest.approx(0.12)
    assert selected.mission_allowed is True


def test_planner_and_supervisor_apply_configured_limit_speed_policy():
    config = _config(
        containment_policies={
            ("UNSAFE_COMMAND", "DOCK_TO_PALLET"): ContainmentPolicy(ActionType.LIMIT_SPEED, 0.12, True),
        }
    )
    registry = AttackRegistry()
    registry.upsert(_event(), 10.0)
    engine = RiskEngine(config)
    planner = MitigationPlanner(config, engine)
    assessment = engine.evaluate(registry.active_records(), 10.0)

    plan = planner.plan(registry.active_records(), assessment, 10.0, phase="DOCK_TO_PALLET")
    decision = SafetySupervisor(config.default_speed_limit, config.safe_stop_speed).decide(assessment, plan)

    assert plan.action == ActionType.LIMIT_SPEED
    assert plan.speed_limit == pytest.approx(0.12)
    assert decision.state == SafetyState.CONTAINING
    assert decision.mission_allowed is True
    assert decision.speed_limit == pytest.approx(0.12)


def test_planner_replans_when_same_event_id_arrives_from_another_source():
    config = _config()
    registry = AttackRegistry()
    registry.upsert(_event("UNSAFE_COMMAND", "left_wheels"), 10.0)
    engine = RiskEngine(config)
    planner = MitigationPlanner(config, engine)
    first_assessment = engine.evaluate(registry.active_records(), 10.0)
    planner.plan(registry.active_records(), first_assessment, 10.0)

    registry.upsert(
        AttackEvent("event-1", "amr_simulator", "right_arm", "UNSAFE_COMMAND", 1, 10.0, 0.91),
        10.0,
    )

    assert planner.should_replan(registry.active_records())


def test_explicit_low_risk_policy_is_applied_before_resilience_shortcut():
    config = _config(
        containment_policies={
            ("SEMANTIC_MISBEHAVIOR", "DOCK_TO_PALLET"): ContainmentPolicy(
                ActionType.ISOLATE_COMPONENT,
                0.15,
                False,
            ),
        }
    )
    registry = AttackRegistry()
    registry.upsert(_event("SEMANTIC_MISBEHAVIOR", "right_arm"), 10.0)
    engine = RiskEngine(config)
    planner = MitigationPlanner(config, engine)
    assessment = engine.evaluate(registry.active_records(), 10.0)

    plan = planner.plan(registry.active_records(), assessment, 10.0, phase="DOCK_TO_PALLET")

    assert assessment.delta == 1 and assessment.gamma == 1
    assert plan.action == ActionType.ISOLATE_COMPONENT
    assert plan.components == frozenset({"right_arm"})


def test_planner_replans_when_task_phase_changes():
    config = _config(
        containment_policies={
            ("UNSAFE_COMMAND", "DOCK_TO_PALLET"): ContainmentPolicy(ActionType.LIMIT_SPEED, 0.12, True),
            ("UNSAFE_COMMAND", "PALLET_STABILIZE"): ContainmentPolicy(ActionType.SAFE_STOP, 0.0, False),
        }
    )
    registry = AttackRegistry()
    registry.upsert(_event("UNSAFE_COMMAND", "left_wheels"), 10.0)
    engine = RiskEngine(config)
    planner = MitigationPlanner(config, engine)
    assessment = engine.evaluate(registry.active_records(), 10.0)
    planner.plan(registry.active_records(), assessment, 10.0, phase="DOCK_TO_PALLET")

    assert planner.should_replan(registry.active_records(), phase="PALLET_STABILIZE")


def test_delayed_plan_is_not_active_before_activate_at():
    config = _config(
        mitigation_delay_sec=2.0,
        containment_policies={
            ("UNSAFE_COMMAND", "DOCK_TO_PALLET"): ContainmentPolicy(ActionType.DEGRADED_RUN, 0.2, True),
        },
    )
    registry = AttackRegistry()
    registry.upsert(_event(), 10.0)
    engine = RiskEngine(config)
    planner = MitigationPlanner(config, engine)
    assessment = engine.evaluate(registry.active_records(), 10.0)
    plan = planner.plan(registry.active_records(), assessment, 10.0, phase="DOCK_TO_PALLET")
    supervisor = SafetySupervisor(config.default_speed_limit, config.safe_stop_speed)

    pending = supervisor.decide(assessment, plan)
    active = supervisor.decide(
        engine.evaluate(registry.active_records(), 12.0),
        plan,
    )

    assert plan.activate_at == pytest.approx(12.0)
    assert pending.mission_allowed is False
    assert pending.speed_limit == pytest.approx(0.15)
    assert active.state == SafetyState.DEGRADED
    assert active.mission_allowed is True
    assert active.speed_limit == pytest.approx(0.2)


def test_safe_stop_policy_overrides_isolation_search():
    config = _config(
        containment_policies={
            ("REPLAY", "*"): ContainmentPolicy(ActionType.SAFE_STOP, 0.0, False),
        }
    )
    registry = AttackRegistry()
    registry.upsert(_event("REPLAY"), 10.0)
    engine = RiskEngine(config)
    planner = MitigationPlanner(config, engine)
    assessment = engine.evaluate(registry.active_records(), 10.0)

    plan = planner.plan(registry.active_records(), assessment, 10.0, phase="DOCK_TO_PALLET")

    assert plan.action == ActionType.SAFE_STOP
    assert plan.requires_safe_stop is True


def test_containment_policy_rejects_non_finite_or_non_boolean_values():
    with pytest.raises(ValueError, match="finite"):
        ContainmentPolicy(ActionType.LIMIT_SPEED, float("nan"), True)
    with pytest.raises(ValueError, match="boolean"):
        ContainmentPolicy(ActionType.LIMIT_SPEED, 0.1, 1)


def test_launch_uses_installed_guardian_yaml_and_exposes_config_argument():
    launch = (ROOT / "ros2_ws" / "src" / "guardian_core" / "launch" / "guardian.launch.py").read_text(
        encoding="utf-8"
    )

    assert "DeclareLaunchArgument" in launch
    assert "config_file" in launch
    assert "parameters=[config_file]" in launch
