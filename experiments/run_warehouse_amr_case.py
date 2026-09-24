#!/usr/bin/env python3
"""Replay a realistic warehouse AMR pallet-transfer security case.

The raw records model the industrial integration boundary. The adapter maps
them to the bounded Guardian replay schema and creates a separate, redacted
semantic summary for Jev. Jev is never used to approve motion or release a
containment decision.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ros2_ws" / "src" / "guardian_core"))

from guardian_core.dashboard_experiments import run_replay  # noqa: E402


CASE_NAME = "仓储 AMR 托盘运输：对接阶段速度指令重放与抓取器异常"

# These are the fields an industrial adapter could receive from ROS 2/DDS,
# a PLC gateway and a safety scanner. They are deliberately kept local to the
# replay fixture; no live topic is published by this script.
RAW_EVENTS: tuple[dict[str, Any], ...] = (
    {
        "at": 0.0,
        "topic": "/cmd_vel",
        "robot_id": "amr-07",
        "mission_phase": "DOCK_TO_PALLET",
        "zone": "A-12-to-P-07",
        "component": "left_wheels",
        "attack_type": "UNSAFE_COMMAND",
        "sequence": 7001,
        "timestamp": 0.0,
        "confidence": 0.98,
        "payload": {"linear_x": 0.62, "angular_z": 0.04, "expected_max": 0.12},
    },
    {
        "at": 0.2,
        "topic": "/cmd_vel",
        "robot_id": "amr-07",
        "mission_phase": "DOCK_TO_PALLET",
        "zone": "A-12-to-P-07",
        "component": "left_wheels",
        "attack_type": "UNSAFE_COMMAND",
        "sequence": 7001,
        "timestamp": 0.2,
        "confidence": 0.98,
        "payload": {"linear_x": 0.62, "angular_z": 0.04, "expected_max": 0.12},
    },
    {
        "at": 0.6,
        "topic": "/cmd_vel",
        "robot_id": "amr-07",
        "mission_phase": "DOCK_TO_PALLET",
        "zone": "A-12-to-P-07",
        "component": "left_wheels",
        "attack_type": "UNSAFE_COMMAND",
        "sequence": 7002,
        "timestamp": 0.6,
        "confidence": 0.96,
        "payload": {"linear_x": 0.58, "angular_z": 0.06, "expected_max": 0.12},
    },
    {
        "at": 1.2,
        "topic": "/gripper/command",
        "robot_id": "amr-07",
        "mission_phase": "PALLET_STABILIZE",
        "zone": "P-07",
        "component": "right_arm",
        "attack_type": "SEMANTIC_MISBEHAVIOR",
        "sequence": 7003,
        "timestamp": 1.2,
        "confidence": 0.91,
        "payload": {"grip_force": 0.0, "expected_min": 35.0, "load_present": True},
    },
)


def guardian_sample() -> dict[str, Any]:
    """Map raw industrial telemetry to the strict offline replay contract."""

    return {
        "schema": "guardian-replay/v1",
        "name": CASE_NAME,
        "profile": "navigation",
        "events": [
            {
                "at": event["at"],
                "event_id": f"amr-07-{event['component']}-{event['sequence']}",
                # scenario_injector identifies the trusted offline adapter;
                # a real deployment would use a DDS/SROS2 authenticated source.
                "source": "scenario_injector",
                "component": event["component"],
                "attack_type": event["attack_type"],
                "sequence": event["sequence"],
                "timestamp": event["timestamp"],
                "confidence": event["confidence"],
            }
            for event in RAW_EVENTS
        ],
    }


def jev_summary() -> dict[str, str]:
    """Return the bounded semantic context sent only after local verification."""

    return {
        "summary": (
            "仓储 AMR amr-07 正在从货架 A-12 搬运托盘到装卸位 P-07，处于低速对接阶段。"
            "Guardian 已验证事件来源和时间关系：/cmd_vel 对应的左轮组件连续收到高频 "
            "UNSAFE_COMMAND，第二条消息重复了 sequence 7001，随后出现 sequence 7002；"
            "托盘抓取器对应的右臂又出现语义行为异常。若继续执行，可能造成对接偏移、"
            "托盘碰撞或货物掉落。请判断攻击类型、任务影响等级，并说明是否需要人工复核。"
        )
    }


def run_case() -> dict[str, Any]:
    report = run_replay(guardian_sample())
    return {
        "scenario": {
            "robot_id": "amr-07",
            "mission": "pallet_transfer",
            "route": "A-12 -> P-07",
            "topics": sorted({event["topic"] for event in RAW_EVENTS}),
            "note": "offline adapter only; no ROS 2 topic is published",
        },
        "raw_events": list(RAW_EVENTS),
        "guardian_replay": report,
        "jev_context": jev_summary(),
        "jev_boundary": "Jev receives only the verified bounded summary; Guardian keeps authority over state, speed and stop.",
    }


def main() -> int:
    result = run_case()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    final = result["guardian_replay"]["final"]
    assert final["safety"]["state"] == "CONTAINING"
    assert final["safety"]["speed_limit"] == 0.15
    assert result["guardian_replay"]["steps"][1]["verification"]["code"] == "REPLAY"
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
