"""Bounded, isolated replay of Guardian decisions; no ROS or provider access."""
from __future__ import annotations

import math
from dataclasses import asdict

from .models import AttackEvent, GuardianConfig
from .planner import MitigationPlanner
from .registry import AttackRegistry
from .risk_engine import RiskEngine
from .supervisor import SafetySupervisor
from .verifier import EventVerifier

SCHEMA = "guardian-replay/v1"
COMPONENTS = {"left_wheels": 2, "right_wheels": 2, "left_arm": 1, "right_arm": 1}
MAX_EVENTS = 64


class ReplayError(ValueError):
    """Invalid experiment data, with a safe user-facing explanation."""


def sample_catalog() -> list[dict]:
    event = dict(event_id="event-1", source="scenario_injector", component="left_wheels",
                 attack_type="STOP", sequence=1, timestamp=10.0, at=10.0, confidence=1.0)
    specs = [
        ("normal", "正常基线", "无攻击：NORMAL，速度上限 0.35 m/s。", "navigation", []),
        ("untrusted", "未知来源拦截", "UNKNOWN_SOURCE：事件拒绝进入风险计算。", "navigation",
         [dict(event, source="unknown_sender")]),
        ("replay", "重复序列拦截", "首次接受，第二次 REPLAY；非关键组件仍在容忍范围。", "navigation",
         [dict(event, component="left_arm"), dict(event, component="left_arm", at=10.1)]),
        ("critical", "关键组件隔离", "ACCEPTED → ISOLATE_COMPONENT → CONTAINING，限制到 0.15 m/s。", "navigation", [event]),
        ("stop", "无隔离能力时停车", "ACCEPTED → SAFE_STOP，任务锁定，速度上限 0。", "no_isolation", [event]),
    ]
    return [dict(id=id_, title=title, expected=expected,
                 sample=dict(schema=SCHEMA, name=title, profile=profile, events=[dict(e) for e in events]))
            for id_, title, expected, profile, events in specs]


def _number(value, field: str, low: float, high: float) -> float:
    if type(value) not in (int, float) or not low <= value <= high or not math.isfinite(value):
        raise ReplayError(f"{field} 必须是 {low:g} 到 {high:g} 的有限数值")
    return float(value)


def _text(value, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 128 or not value.isprintable():
        raise ReplayError(f"{field} 必须是 1–128 字符的可打印文本")
    return value


def _validate(sample) -> tuple[GuardianConfig, list[tuple[float, AttackEvent]]]:
    if not isinstance(sample, dict) or set(sample) - {"schema", "name", "profile", "events"}:
        raise ReplayError("请导入防护样例 JSON；仅支持 schema、name、profile、events 字段")
    if sample.get("schema") != SCHEMA or sample.get("profile") not in ("navigation", "no_isolation"):
        raise ReplayError("schema 应为 guardian-replay/v1；profile 应为 navigation 或 no_isolation")
    _text(sample.get("name"), "name")
    events = sample.get("events")
    if not isinstance(events, list) or len(events) > MAX_EVENTS:
        raise ReplayError("events 必须为最多 64 条事件的数组")
    validated = []
    last_at = 0.0
    fields = {"at", "event_id", "source", "component", "attack_type", "sequence", "timestamp", "confidence"}
    for index, row in enumerate(events):
        prefix = f"events[{index}]"
        if not isinstance(row, dict) or set(row) != fields:
            raise ReplayError(f"{prefix} 字段不完整，请参考下载的样例格式")
        strings = {key: _text(row[key], f"{prefix}.{key}") for key in ("event_id", "source", "component", "attack_type")}
        if strings["component"] not in COMPONENTS:
            raise ReplayError(f"{prefix}.component 不属于当前导航策略：left_wheels/right_wheels/left_arm/right_arm")
        at = _number(row["at"], f"{prefix}.at", 0, 3600)
        if at < last_at:
            raise ReplayError("at 是相对观测时间，必须按非递减顺序排列")
        last_at = at
        timestamp = _number(row["timestamp"], f"{prefix}.timestamp", -60, 3660)
        confidence = _number(row["confidence"], f"{prefix}.confidence", 0, 1)
        sequence = row["sequence"]
        if type(sequence) is not int or not 0 <= sequence <= 1_000_000_000:
            raise ReplayError(f"{prefix}.sequence 必须为非负整数，最大 1000000000")
        validated.append((at, AttackEvent(**strings, sequence=sequence, timestamp=timestamp, confidence=confidence)))
    config = GuardianConfig(task="navigate_to_goal", goal="offline_test", tau=COMPONENTS,
                            theta_crit=.8, theta_base=.72, alpha_crit=.15, alpha_base=.2,
                            mitigatable_devices=frozenset(COMPONENTS) if sample["profile"] == "navigation" else frozenset())
    return config, validated


def run_replay(sample) -> dict:
    """Validate the entire input, then use fresh per-request core instances."""
    config, events = _validate(sample)
    verifier = EventVerifier(set(config.trusted_sources), config.max_event_age_sec)
    registry = AttackRegistry(config.max_event_age_sec)
    engine = RiskEngine(config)
    planner = MitigationPlanner(config, engine)
    supervisor = SafetySupervisor(config.default_speed_limit, config.safe_stop_speed)
    steps = []
    accepted = 0
    for at, event in events or [(0.0, None)]:
        expired = registry.expire(at)
        verification = verifier.verify(event, at) if event else None
        if verification and verification.accepted:
            accepted += 1
            registry.upsert(event, at)
        records = registry.active_records()
        risk = engine.evaluate(records, at)
        # Match GuardianNode.tick: an unchanged attack set keeps its pending plan.
        plan = planner.plan(records, risk, at) if planner.current_plan is None or planner.should_replan(records) else planner.current_plan
        decision = supervisor.decide(risk, plan)
        risk_json = asdict(risk)
        for field in ("active_components", "critical_components"):
            risk_json[field] = sorted(risk_json[field])
        plan_json = {**asdict(plan), "action": plan.action.value, "components": sorted(plan.components)}
        safety_json = {**asdict(decision), "state": decision.state.value}
        steps.append(dict(at=at, event=asdict(event) if event else None,
                          verification={**asdict(verification), "code": verification.code.value} if verification else None,
                          expired_event_ids=expired, risk=risk_json, plan=plan_json, safety=safety_json))
    return dict(mode="offline_replay", actuation="none", schema=SCHEMA, name=sample["name"],
                profile=sample["profile"], summary=dict(total=len(events), accepted=accepted, rejected=len(events)-accepted),
                policy=dict(trusted_sources=sorted(config.trusted_sources), component_criticality=COMPONENTS,
                            max_event_age_sec=config.max_event_age_sec, max_future_skew_sec=.5,
                            theta_crit=config.theta_crit, theta_base=config.theta_base,
                            alpha_crit=config.alpha_crit, alpha_base=config.alpha_base,
                            mitigatable_devices=sorted(config.mitigatable_devices), signature_required=False),
                steps=steps, final=steps[-1])
