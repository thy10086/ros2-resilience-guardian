"""Bounded, isolated replay of Guardian decisions; no ROS or provider access."""
from __future__ import annotations

import json
import math
from dataclasses import asdict
from collections.abc import Callable, Mapping
from typing import Any

from .models import AttackEvent, GuardianConfig
from .planner import MitigationPlanner
from .registry import AttackRegistry
from .risk_engine import RiskEngine
from .supervisor import SafetySupervisor
from .verifier import EventVerifier

SCHEMA = "guardian-replay/v1"
COMPONENTS = {"left_wheels": 2, "right_wheels": 2, "left_arm": 1, "right_arm": 1}
MAX_EVENTS = 64
JEV_HARD_RISK_FLOORS = {
    "UNKNOWN_SOURCE": 0.90,
    "INVALID": 0.95,
    "REPLAY": 0.85,
    "STALE": 0.85,
    "FUTURE": 0.85,
}


class ReplayError(ValueError):
    """Invalid experiment data, with a safe user-facing explanation."""


def sample_catalog() -> list[dict]:
    event = dict(event_id="event-1", source="scenario_injector", component="left_wheels",
                 attack_type="STOP", sequence=1, timestamp=10.0, at=10.0, confidence=1.0)
    warehouse_events = [
        dict(event_id="amr-dock-left-wheel-7001", source="scenario_injector", component="left_wheels",
             attack_type="UNSAFE_COMMAND", sequence=7001, timestamp=0.0, at=0.0, confidence=0.98),
        dict(event_id="amr-dock-left-wheel-7001-replay", source="scenario_injector", component="left_wheels",
             attack_type="UNSAFE_COMMAND", sequence=7001, timestamp=0.2, at=0.2, confidence=0.98),
        dict(event_id="amr-dock-left-wheel-7002", source="scenario_injector", component="left_wheels",
             attack_type="UNSAFE_COMMAND", sequence=7002, timestamp=0.6, at=0.6, confidence=0.96),
        dict(event_id="amr-pallet-gripper-7003", source="scenario_injector", component="right_arm",
             attack_type="SEMANTIC_MISBEHAVIOR", sequence=7003, timestamp=1.2, at=1.2, confidence=0.91),
    ]
    warehouse_summary = (
        "仓储 AMR amr-07 正在从货架 A-12 搬运托盘到装卸位 P-07，处于低速对接阶段。"
        "Guardian 已验证 /cmd_vel 左轮异常 UNSAFE_COMMAND，第二条消息重复 sequence 7001，"
        "随后出现 sequence 7002；/gripper/command 右臂又出现抓取力为零的语义异常。"
        "请判断攻击类型、任务影响等级，并说明是否需要人工复核。"
    )
    specs = [
        ("normal", "正常基线", "无攻击：NORMAL，速度上限 0.35 m/s。", "navigation", []),
        ("untrusted", "未知来源拦截", "UNKNOWN_SOURCE：事件拒绝进入风险计算。", "navigation",
         [dict(event, source="unknown_sender")]),
        ("replay", "重复序列拦截", "首次接受，第二次 REPLAY；非关键组件仍在容忍范围。", "navigation",
         [dict(event, component="left_arm"), dict(event, component="left_arm", at=10.1)]),
        ("critical", "关键组件隔离", "ACCEPTED → ISOLATE_COMPONENT → CONTAINING，限制到 0.15 m/s。", "navigation", [event]),
        ("stop", "无隔离能力时停车", "ACCEPTED → SAFE_STOP，任务锁定，速度上限 0。", "no_isolation", [event]),
    ]
    catalog = [dict(id=id_, title=title, expected=expected,
                    sample=dict(schema=SCHEMA, name=title, profile=profile, events=[dict(e) for e in events]))
               for id_, title, expected, profile, events in specs]
    warehouse_entry = {
        "id": "warehouse_amr",
        "title": "仓储 AMR 托盘运输",
        "expected": "ACCEPTED → REPLAY → ACCEPTED → ACCEPTED；最终 CONTAINING / ISOLATE_COMPONENT / 0.15 m/s",
        "description": "amr-07 从 A-12 搬运托盘到 P-07，模拟对接速度指令、序列重放和抓取器语义异常。",
        "robot": "amr-07",
        "mission": "托盘运输：A-12 → P-07",
        "phase": "低速对接与托盘稳定",
        "topics": ["/cmd_vel", "/gripper/command"],
        "threats": ["速度指令越界", "sequence=7001 重放", "抓取力语义异常"],
        "jev_boundary": "advisory_only",
        "jev_context": {"summary": warehouse_summary},
        "sample": dict(schema=SCHEMA, name="仓储 AMR 托盘运输：对接阶段速度指令重放与抓取器异常",
                       profile="navigation", events=warehouse_events),
    }
    # Keep the existing SAFE_STOP fixture last so research tables retain their
    # stable terminal case while the industrial case appears before it.
    catalog.insert(len(catalog) - 1, warehouse_entry)
    return catalog


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
    assurance_checks = [
        {
            "id": "schema_and_fields",
            "label": "样例结构和字段校验",
            "passed": True,
            "details": f"{len(events)} 条事件通过输入格式校验",
        },
        {
            "id": "event_verification",
            "label": "来源、时间、序列和重放校验",
            "passed": len(steps) == len(events),
            "details": f"{len(steps)}/{len(events)} 条事件经过 Guardian 校验",
        },
        {
            "id": "risk_recalculation",
            "label": "每条事件重新计算风险",
            "passed": all(step.get("risk") is not None for step in steps),
            "details": "每一步都生成风险、活动组件和关键组件结果",
        },
        {
            "id": "mitigation_decision",
            "label": "每一步生成缓解与安全状态",
            "passed": all(step.get("plan") is not None and step.get("safety") is not None for step in steps),
            "details": "每一步都生成缓解计划和安全监督结果",
        },
        {
            "id": "runtime_actuation_feedback",
            "label": "真实 ROS 2/Gazebo 执行器反馈",
            "passed": False,
            "details": "离线回放不会发布 /cmd_vel，也不会验证实际运动",
        },
    ]
    assurance = {
        "mode": "OFFLINE_REPLAY",
        "coverage_score": round(sum(1 for item in assurance_checks if item["passed"]) / len(assurance_checks) * 100, 1),
        "offline_logic_check_score": round(sum(1 for item in assurance_checks if item["passed"]) / len(assurance_checks) * 100, 1),
        "runtime_verified": False,
        "actuation": "none",
        "checks": assurance_checks,
        "missing_controls": ["真实 ROS 2/Gazebo 执行器反馈"],
        "limitations": [
            "当前结果证明 Guardian 的确定性验证、风险、缓解和状态机逻辑，不证明真实机器人已经动作正确。",
            "事件来源为离线 scenario_injector；没有 ROS 2/Gazebo 实际执行、DDS/SROS2 身份认证、网络延迟和传感器噪声证据。",
            "需要在工程仿真或硬件在环中验证限速、隔离、停车距离和恢复门控。",
        ],
    }
    return dict(mode="offline_replay", actuation="none", schema=SCHEMA, name=sample["name"],
                profile=sample["profile"], summary=dict(total=len(events), accepted=accepted, rejected=len(events)-accepted),
                policy=dict(trusted_sources=sorted(config.trusted_sources), component_criticality=COMPONENTS,
                            max_event_age_sec=config.max_event_age_sec, max_future_skew_sec=.5,
                            theta_crit=config.theta_crit, theta_base=config.theta_base,
                            alpha_crit=config.alpha_crit, alpha_base=config.alpha_base,
                            mitigatable_devices=sorted(config.mitigatable_devices), signature_required=False),
                steps=steps, final=steps[-1], assurance=assurance)


def _bounded_score(value: Any, default: float = 0.0) -> float:
    if isinstance(value, bool):
        return default
    try:
        score = float(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return min(1.0, max(0.0, score)) if math.isfinite(score) else default


def _strict_score(value: Any) -> float | None:
    if type(value) not in (int, float) or not math.isfinite(value) or not 0.0 <= value <= 1.0:
        return None
    return float(value)


def _risk_level(score: float) -> str:
    if score >= 0.75:
        return "CRITICAL"
    if score >= 0.50:
        return "HIGH_RISK"
    if score >= 0.25:
        return "CAUTION"
    return "SAFE"


def _jev_context(step: Mapping[str, Any]) -> str:
    event = step.get("event") or {}
    verification = step.get("verification") or {}
    risk = step.get("risk") or {}
    safety = step.get("safety") or {}
    plan = step.get("plan") or {}
    context = {
        "event_id": event.get("event_id", "unknown"),
        "component": event.get("component", "unknown"),
        "attack_type": event.get("attack_type", "unknown"),
        "event_confidence": _bounded_score(event.get("confidence")),
        "source_verified": verification.get("accepted") is True,
        "verification_code": verification.get("code", "UNKNOWN"),
        "verification_reason": verification.get("reason", ""),
        "guardian_risk": _bounded_score(risk.get("risk")),
        "guardian_risk_reason": risk.get("reason", ""),
        "active_components": risk.get("active_components", []),
        "critical_components": risk.get("critical_components", []),
        "safety_state": safety.get("state", "UNKNOWN"),
        "mission_allowed": safety.get("mission_allowed", False),
        "speed_limit": safety.get("speed_limit", 0.0),
        "mitigation_action": plan.get("action", "NONE"),
        "mitigation_components": plan.get("components", []),
        "sequence": event.get("sequence", 0),
        "summary": "Evaluate the safety of this verified industrial robot action using the Guardian evidence.",
    }
    return json.dumps(context, ensure_ascii=False, separators=(",", ":"))


def _jev_payload(response: Any) -> Mapping[str, Any]:
    if isinstance(response, Mapping):
        return response
    payload = getattr(response, "payload", None)
    return payload if isinstance(payload, Mapping) else {}


def _normalize_jev_result(response: Any, event_id: str) -> dict[str, Any]:
    payload = _jev_payload(response)
    raw_assessment = payload.get("assessment")
    assessment = raw_assessment if isinstance(raw_assessment, Mapping) else {}
    status = str(payload.get("status") or assessment.get("status") or "UNAVAILABLE")
    if status == "OK":
        if not assessment:
            return {
                "status": "INVALID",
                "called": True,
                "event_id": event_id,
                "label": "INVALID_ASSESSMENT",
                "risk": None,
                "confidence": None,
                "mission_impact": "unknown",
                "needs_human_review": True,
                "model": "—",
                "reason": "Jev 返回了空的 assessment，无法形成可审计判断",
            }
        score = _strict_score(assessment.get("score"))
        confidence = _strict_score(assessment.get("confidence"))
        if score is None or confidence is None:
            return {
                "status": "INVALID",
                "called": True,
                "event_id": event_id,
                "label": "INVALID_ASSESSMENT",
                "risk": None,
                "confidence": None,
                "mission_impact": "unknown",
                "needs_human_review": True,
                "model": str(assessment.get("model") or "—"),
                "reason": "Jev 返回的风险分或置信度不是 0 到 1 的有限数值",
            }
        return {
            "status": "OK",
            "called": True,
            "event_id": event_id,
            "label": str(assessment.get("label") or "UNKNOWN"),
            "risk": score,
            "confidence": confidence,
            "mission_impact": str(assessment.get("mission_impact") or "unknown"),
            "needs_human_review": assessment.get("needs_human_review") is True,
            "model": str(assessment.get("model") or "—"),
            "reason": str(assessment.get("reason") or "Jev returned a typed assessment"),
        }
    error = payload.get("error")
    error_message = error.get("message") if isinstance(error, Mapping) else None
    return {
        "status": status,
        "called": True,
        "event_id": event_id,
        "label": "UNKNOWN",
        "risk": None,
        "confidence": None,
        "mission_impact": "unknown",
        "needs_human_review": False,
        "model": "—",
        "reason": str(error_message or "Jev did not return a usable assessment"),
    }


def _guardian_hard_floor(step: Mapping[str, Any]) -> float:
    verification = step.get("verification") or {}
    safety = step.get("safety") or {}
    risk = step.get("risk") or {}
    code = str(verification.get("code") or "")
    floor = _bounded_score(risk.get("risk"))
    floor = max(floor, JEV_HARD_RISK_FLOORS.get(code, 0.0))
    if safety.get("state") == "CONTAINING":
        floor = max(floor, 0.80)
    elif safety.get("state") == "SAFE_STOP":
        floor = max(floor, 0.95)
    return min(1.0, floor)


def _score_jev_event(step: Mapping[str, Any], jev: Mapping[str, Any]) -> dict[str, Any]:
    risk = step.get("risk") or {}
    safety = step.get("safety") or {}
    plan = step.get("plan") or {}
    verification = step.get("verification") or {}
    guardian_risk = _bounded_score(risk.get("risk"))
    jev_risk = jev.get("risk")
    jev_risk = _bounded_score(jev_risk) if jev_risk is not None else None
    jev_confidence = _bounded_score(jev.get("confidence"), default=0.0) if jev_risk is not None else None
    confidence_gate = 0.70
    if jev_risk is None:
        semantic_risk = guardian_risk
        fusion_mode = "GUARDIAN_ONLY"
    elif jev_confidence < confidence_gate:
        semantic_risk = max(guardian_risk, jev_risk)
        fusion_mode = "CONSERVATIVE_LOW_CONFIDENCE"
    else:
        semantic_risk = jev_risk
        fusion_mode = "GUARDIAN_60_PERCENT_PLUS_JEV_40_PERCENT"
    weighted_risk = guardian_risk * 0.60 + semantic_risk * 0.40
    hard_floor = _guardian_hard_floor(step)
    composite_risk = max(hard_floor, weighted_risk)
    evidence = [
        f"Guardian {verification.get('code', 'UNKNOWN')}: {risk.get('reason', 'no local reason')}",
        f"Guardian state {safety.get('state', 'UNKNOWN')} with action {plan.get('action', 'NONE')}",
    ]
    if jev.get("status") == "OK":
        evidence.append(
            f"Jev classified {jev.get('label', 'UNKNOWN')} with "
            f"{jev.get('mission_impact', 'unknown')} mission impact at "
            f"{_bounded_score(jev.get('confidence')):.2f} confidence"
        )
        evidence.append(f"Jev reason: {jev.get('reason', 'no semantic reason')}")
        if jev.get("needs_human_review") is True:
            evidence.append("Jev recommends human review before recovery")
    else:
        evidence.append(f"Jev status {jev.get('status', 'UNAVAILABLE')}: {jev.get('reason', 'no result')}")
    if hard_floor > max(guardian_risk, weighted_risk):
        evidence.append(f"Guardian hard floor applied: {hard_floor * 100:.1f}")
    scoring = {
        "guardian_risk": round(guardian_risk, 4),
        "jev_risk": None if jev_risk is None else round(jev_risk, 4),
        "jev_confidence": None if jev_confidence is None else round(jev_confidence, 4),
        "confidence_gate": confidence_gate,
        "fusion_mode": fusion_mode,
        "hard_floor": round(hard_floor, 4),
        "composite_risk": round(composite_risk, 4),
        "risk_score": round(composite_risk * 100, 1),
        "safety_score": round((1.0 - composite_risk) * 100, 1),
        "level": _risk_level(composite_risk),
        "basis": evidence,
    }
    scoring["basis_zh"] = _scoring_basis_zh(step, jev, scoring)
    return scoring


def _scoring_basis_zh(
    step: Mapping[str, Any],
    jev: Mapping[str, Any],
    scoring: Mapping[str, Any],
) -> list[str]:
    verification = step.get("verification") or {}
    risk = step.get("risk") or {}
    safety = step.get("safety") or {}
    plan = step.get("plan") or {}
    code = str(verification.get("code") or "UNKNOWN")
    event = step.get("event") or {}
    sequence = event.get("sequence", "—")
    if code == "ACCEPTED":
        basis = ["Guardian 已接受：来源、时间戳和序列号通过校验"]
    elif code == "REPLAY":
        basis = [f"Guardian 已拒绝：序列号 {sequence} 重复，未进入攻击登记"]
    else:
        basis = [f"Guardian 已拒绝：{verification.get('reason') or code}"]
    basis.append(
        f"本地风险 {float(scoring['guardian_risk']) * 100:.1f} 分；"
        f"状态 {safety.get('state', 'UNKNOWN')}；动作 {plan.get('action', 'NONE')}"
    )
    if jev.get("status") == "OK":
        confidence = float(scoring.get("jev_confidence") or 0.0) * 100
        if confidence < float(scoring["confidence_gate"]) * 100:
            basis.append(
                f"Jev 置信度 {confidence:.1f} 分低于 {float(scoring['confidence_gate']) * 100:.1f} 分门槛，"
                "采用保守融合，不降低 Guardian 风险"
            )
        else:
            basis.append(
                f"Jev 类型为 {jev.get('label', 'UNKNOWN')}，风险 {float(scoring['jev_risk']) * 100:.1f} 分，"
                f"置信度 {confidence:.1f} 分"
            )
    elif jev.get("status") == "SKIPPED_UNVERIFIED":
        basis.append("该事件未通过 Guardian 校验，Jev 未调用，使用本地重放/来源硬规则")
    else:
        basis.append(f"Jev 证据不可用：{jev.get('reason', '无有效返回')}；仅使用 Guardian 结果")
    basis.append(f"事件综合风险 {float(scoring['risk_score']):.1f} 分，安全分 {float(scoring['safety_score']):.1f} 分")
    return basis


def _safety_summary(report: Mapping[str, Any], event_results: list[dict[str, Any]]) -> dict[str, Any]:
    final = report.get("final") or {}
    safety = final.get("safety") or {}
    plan = final.get("plan") or {}
    status_counts = {}
    low_confidence = 0
    invalid_jev = 0
    jev_successes = 0
    local_rejected = 0
    for item in event_results:
        verification_code = str((item.get("guardian") or {}).get("verification_code") or "UNKNOWN")
        status_counts[verification_code] = status_counts.get(verification_code, 0) + 1
        if verification_code != "ACCEPTED":
            local_rejected += 1
        jev = item.get("jev") or {}
        if jev.get("status") == "OK":
            jev_successes += 1
            confidence = _strict_score(jev.get("confidence"))
            if confidence is not None and confidence < 0.70:
                low_confidence += 1
        elif jev.get("status") == "INVALID":
            invalid_jev += 1

    runtime_verified = False
    state = str(safety.get("state") or "UNKNOWN")
    if not event_results:
        decision = "证据不足，不能判定为安全"
    elif state == "SAFE_STOP":
        decision = "保持安全停车，完成整改并人工确认后才能恢复"
    elif state == "CONTAINING":
        decision = "保持任务锁定，整改后复核"
    elif state == "RESUMABLE":
        decision = "限制运行，完成复核后再恢复任务"
    elif local_rejected:
        decision = "存在被 Guardian 拒绝的未验证事件，不能据此判定为安全；人工复核后再继续"
    else:
        decision = "可以继续仿真，但上线前仍需复核"
    return {
        "decision": decision,
        "state": state,
        "mission_allowed": safety.get("mission_allowed") is True,
        "speed_limit": safety.get("speed_limit"),
        "action": plan.get("action", "NONE"),
        "runtime_verified": runtime_verified,
        "evidence": {
            "total_events": len(event_results),
            "accepted_events": status_counts.get("ACCEPTED", 0),
            "locally_rejected": local_rejected,
            "jev_successes": jev_successes,
            "low_confidence_events": low_confidence,
            "invalid_jev_events": invalid_jev,
            "verification_codes": status_counts,
        },
        "limitations": "未执行 ROS 2/Gazebo，未验证真实执行器动作",
    }


def run_replay_with_jev(sample, jev_call: Callable[[str], Any]) -> dict:
    """Run Guardian replay, then attach bounded per-event Jev evidence."""

    report = run_replay(sample)
    event_results = []
    calls = 0
    for step in report["steps"]:
        event = step.get("event")
        if not event:
            continue
        verification = step.get("verification") or {}
        event_id = str(event.get("event_id") or "unknown")
        if verification.get("accepted") is not True:
            jev = {
                "status": "SKIPPED_UNVERIFIED",
                "called": False,
                "event_id": event_id,
                "label": "UNVERIFIED_EVENT",
                "risk": None,
                "confidence": None,
                "mission_impact": "unknown",
                "needs_human_review": True,
                "model": "local-guardian",
                "reason": f"{verification.get('code', 'UNKNOWN')} was blocked before Jev",
            }
        else:
            calls += 1
            try:
                jev = _normalize_jev_result(jev_call(_jev_context(step)), event_id)
            except Exception as error:  # pragma: no cover - defensive provider boundary
                jev = {
                    "status": "UNAVAILABLE",
                    "called": True,
                    "event_id": event_id,
                    "label": "UNKNOWN",
                    "risk": None,
                    "confidence": None,
                    "mission_impact": "unknown",
                    "needs_human_review": True,
                    "model": "—",
                    "reason": f"Jev call failed: {type(error).__name__}",
                }
        event_results.append({
            "at": step.get("at", 0.0),
            "event": event,
            "guardian": {
                "verification_code": verification.get("code", "UNKNOWN"),
                "verification_reason": verification.get("reason", ""),
                "risk": step.get("risk", {}),
                "plan": step.get("plan", {}),
                "safety": step.get("safety", {}),
            },
            "jev": jev,
            "scoring": _score_jev_event(step, jev),
        })

    scores = [item["scoring"]["composite_risk"] for item in event_results]
    max_risk = max(scores, default=None)
    mean_risk = (sum(scores) / len(scores)) if scores else None
    event_hard_floor = max(
        (float(item["scoring"].get("hard_floor") or 0.0) for item in event_results),
        default=None,
    )
    weighted_risk = (0.70 * max_risk + 0.30 * mean_risk) if scores else None
    aggregate_risk = (
        max(weighted_risk, event_hard_floor or 0.0)
        if weighted_risk is not None
        else None
    )
    statuses = {item["jev"]["status"] for item in event_results}
    locally_rejected = sum(
        1 for item in event_results
        if (item.get("guardian") or {}).get("verification_code") != "ACCEPTED"
    )
    evaluation_status = (
        "INSUFFICIENT_EVIDENCE" if not event_results
        else "LOCAL_ONLY" if locally_rejected and calls == 0 and statuses == {"SKIPPED_UNVERIFIED"}
        else "PARTIAL" if locally_rejected or not statuses.issubset({"OK"})
        else "OK"
    )
    aggregate_basis = [
        "综合风险 = 最高事件风险 × 70% + 所有事件平均风险 × 30%",
        "聚合结果不得低于所有事件中最高的 Guardian hard floor",
        "Jev 置信度低于 70 分时采用保守融合，不允许降低 Guardian 风险",
        f"Jev calls={calls}; local-only events={sum(item['jev']['status'] == 'SKIPPED_UNVERIFIED' for item in event_results)}",
    ]
    if event_hard_floor is not None:
        aggregate_basis.append(f"最高 Guardian hard floor={event_hard_floor * 100:.1f}")
    safety_summary = _safety_summary(report, event_results)
    return {
        **report,
        "mode": "offline_replay_with_jev",
        "jev_evaluation": {
            "status": evaluation_status,
            "method": "guardian_60_percent_plus_jev_40_percent",
            "calls": calls,
            "events": event_results,
            "aggregate": {
                "risk_score": None if aggregate_risk is None else round(aggregate_risk * 100, 1),
                "safety_score": None if aggregate_risk is None else round((1.0 - aggregate_risk) * 100, 1),
                "level": "INSUFFICIENT_EVIDENCE" if aggregate_risk is None else _risk_level(aggregate_risk),
                "max_event_risk": None if max_risk is None else round(max_risk * 100, 1),
                "mean_event_risk": None if mean_risk is None else round(mean_risk * 100, 1),
                "basis": aggregate_basis,
            },
        },
        "safety_summary": safety_summary,
    }
