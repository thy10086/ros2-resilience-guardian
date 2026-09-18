#!/usr/bin/env python3
"""Run a deterministic, headless demonstration of the new Guardian loop."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ros2_ws" / "src" / "guardian_core"))

from guardian_core import (
    AttackEvent,
    AttackRegistry,
    EventVerifier,
    GuardianConfig,
    MitigationPlanner,
    RiskEngine,
    SafetySupervisor,
)


SCENARIOS = {
    "1": [(0.0, [("left_arm", "UNDERSPEED")]), (5.0, [("left_arm", "UNDERSPEED"), ("right_arm", "UNDERSPEED")])],
    "2a": [(0.0, [("left_arm", "STOP")]), (5.0, [("left_arm", "STOP"), ("right_arm", "STOP")])],
    "2b": [(0.0, [("left_arm", "STOP")]), (5.0, [("left_arm", "STOP"), ("right_arm", "STOP")])],
    "3b": [
        (0.0, [("left_wheels", "STOP")]),
        (10.0, [("left_gripper", "GRIP_WEAK"), ("right_arm", "STOP")]),
        (20.0, [("left_arm", "STOP"), ("right_gripper", "GRIP_WEAK")]),
        (30.0, [("right_wheels", "UNDERSPEED"), ("right_arm", "STOP")]),
        (40.0, [("left_wheels", "STOP"), ("left_gripper", "GRIP_WEAK"), ("right_arm", "STOP")]),
    ],
}


def build_config(scenario: str) -> GuardianConfig:
    if scenario in {"1", "2a", "2b"}:
        return GuardianConfig(
            task="navigate_to_goal", goal="box2",
            tau={"left_arm": 1, "right_arm": 1, "left_wheels": 0, "right_wheels": 0},
            theta_base=0.72, theta_crit=0.8, alpha_base=0.2 if scenario != "1" else 0.04,
            alpha_crit=0.15, mitigatable_devices=frozenset() if scenario == "2a" else frozenset({"left_arm", "right_arm"}),
            mitigation_delay_sec=1.0,
        )
    return GuardianConfig(
        task="navigate_and_pickup", goal="table2",
        tau={"left_wheels": 2, "right_wheels": 2, "left_arm": 2, "right_arm": 1, "left_gripper": 2, "right_gripper": 1},
        theta_base=0.75, theta_crit=0.99, alpha_base=0.05, alpha_crit=0.4,
        mitigatable_devices=frozenset({"left_wheels", "right_wheels", "left_arm", "right_arm", "left_gripper", "right_gripper"}),
        mitigation_delay_sec=1.0,
    )


def run(scenario: str) -> int:
    config = build_config(scenario)
    verifier = EventVerifier(set(config.trusted_sources), config.max_event_age_sec)
    registry = AttackRegistry(config.max_event_age_sec)
    risk_engine = RiskEngine(config)
    planner = MitigationPlanner(config, risk_engine)
    supervisor = SafetySupervisor(config.default_speed_limit, config.safe_stop_speed)
    sequence = 0
    output = []

    for timestamp, attacks in SCENARIOS[scenario]:
        for component, attack_type in attacks:
            sequence += 1
            event = AttackEvent(f"{scenario}-{sequence}", "scenario_injector", component, attack_type, sequence, timestamp)
            result = verifier.verify(event, timestamp)
            if not result.accepted:
                raise RuntimeError(result.reason)
            registry.upsert(event, timestamp)
        assessment = risk_engine.evaluate(registry.active_records(), timestamp)
        plan = planner.plan(registry.active_records(), assessment, timestamp)
        decision = supervisor.decide(assessment, plan)
        row = {"time": timestamp, "active": sorted(assessment.active_components), "psi": round(assessment.psi, 4), "delta": assessment.delta, "gamma": assessment.gamma, "plan": plan.action.value, "components": sorted(plan.components), "state": decision.state.value}
        output.append(row)
        print(json.dumps(row, ensure_ascii=False))

        # Simulate enforcement after the configured delay. A later wave will replan.
        if plan.action.value == "ISOLATE_COMPONENT":
            apply_time = plan.activate_at
            for component in plan.components:
                registry.clear_component(component)
            recovered = risk_engine.evaluate(registry.active_records(), apply_time)
            recovery_plan = planner.plan(registry.active_records(), recovered, apply_time)
            recovery_decision = supervisor.decide(recovered, recovery_plan)
            recovery_row = {"time": apply_time, "active": sorted(recovered.active_components), "psi": round(recovered.psi, 4), "delta": recovered.delta, "gamma": recovered.gamma, "plan": recovery_plan.action.value, "components": sorted(recovery_plan.components), "state": recovery_decision.state.value}
            output.append(recovery_row)
            print(json.dumps(recovery_row, ensure_ascii=False))

    result_path = Path("experiments/results")
    result_path.mkdir(parents=True, exist_ok=True)
    (result_path / f"scenario_{scenario}.json").write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), default="3b")
    args = parser.parse_args()
    raise SystemExit(run(args.scenario))

