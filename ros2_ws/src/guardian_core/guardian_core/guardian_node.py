from __future__ import annotations

from typing import Iterable

import rclpy
from rclpy.node import Node

from guardian_interfaces.msg import AttackEvent as AttackEventMsg, MitigationCommand, RiskState, SafetyStatus

from .audit import AuditLogger
from .models import AttackEvent, GuardianConfig
from .planner import MitigationPlanner
from .registry import AttackRegistry
from .risk_engine import RiskEngine
from .supervisor import SafetySupervisor
from .verifier import EventVerifier


class GuardianNode(Node):
    def __init__(self) -> None:
        super().__init__("guardian_node")
        self.declare_parameter("task", "navigate_to_goal")
        self.declare_parameter("goal", "box2")
        self.declare_parameter("max_event_age_sec", 5.0)
        self.declare_parameter("mitigation_delay_sec", 1.0)
        self.declare_parameter("default_speed_limit", 0.35)
        self.declare_parameter("require_signature", False)
        self.declare_parameter("signature_secret", "")
        self.declare_parameter("audit_path", "")

        config = GuardianConfig(
            task=str(self.get_parameter("task").value),
            goal=str(self.get_parameter("goal").value),
            tau={"left_wheels": 2, "right_wheels": 2, "left_arm": 1, "right_arm": 1, "left_gripper": 2, "right_gripper": 1},
            epsilon={"distance_sensor": 0},
            theta_crit=0.8,
            theta_base=0.72,
            alpha_crit=0.15,
            alpha_base=0.2,
            max_event_age_sec=float(self.get_parameter("max_event_age_sec").value),
            mitigation_delay_sec=float(self.get_parameter("mitigation_delay_sec").value),
            default_speed_limit=float(self.get_parameter("default_speed_limit").value),
            mitigatable_devices=frozenset({"left_wheels", "right_wheels", "left_arm", "right_arm", "left_gripper", "right_gripper"}),
        )
        signature_secret = str(self.get_parameter("signature_secret").value).encode("utf-8") or None
        self.verifier = EventVerifier(
            set(config.trusted_sources), config.max_event_age_sec,
            signature_secret=signature_secret,
            require_signature=bool(self.get_parameter("require_signature").value),
        )
        self.registry = AttackRegistry(config.max_event_age_sec)
        self.risk_engine = RiskEngine(config)
        self.planner = MitigationPlanner(config, self.risk_engine)
        self.supervisor = SafetySupervisor(config.default_speed_limit, config.safe_stop_speed)
        audit_path = str(self.get_parameter("audit_path").value)
        self.audit = AuditLogger(audit_path or None)
        self._last_signature: tuple[str, ...] = ()

        self.create_subscription(AttackEventMsg, "guardian/attack_events", self.on_attack_event, 20)
        self.risk_pub = self.create_publisher(RiskState, "guardian/risk_state", 20)
        self.command_pub = self.create_publisher(MitigationCommand, "guardian/mitigation_command", 20)
        self.status_pub = self.create_publisher(SafetyStatus, "guardian/safety_status", 20)
        self.create_timer(0.1, self.tick)

    def now_seconds(self) -> float:
        return self.get_clock().now().nanoseconds / 1e9

    def on_attack_event(self, message: AttackEvent) -> None:
        now = self.now_seconds()
        event = AttackEvent(
            event_id=message.event_id,
            source=message.source,
            component=message.component,
            attack_type=message.attack_type,
            sequence=int(message.sequence),
            timestamp=float(message.timestamp),
            confidence=float(message.confidence),
            signature=message.signature,
        )
        result = self.verifier.verify(event, now)
        self.audit.emit("event_verification", {"event_id": event.event_id, "code": result.code.value, "accepted": result.accepted, "reason": result.reason})
        if result.accepted:
            self.registry.upsert(event, now)

    def tick(self) -> None:
        now = self.now_seconds()
        self.registry.expire(now)
        records = self.registry.active_records()
        assessment = self.risk_engine.evaluate(records, now)
        signature = tuple(sorted(f"{record.event.event_id}:{record.event.sequence}" for record in records))
        if signature != self._last_signature or self.planner.current_plan is None:
            self._last_signature = signature
            plan = self.planner.plan(records, assessment, now)
            self.audit.emit("mitigation_plan", {"plan_id": plan.plan_id, "action": plan.action.value, "components": sorted(plan.components), "reason": plan.reason})
        else:
            plan = self.planner.current_plan
        decision = self.supervisor.decide(assessment, plan)
        self.publish(assessment, plan, decision)

    def publish(self, assessment, plan, decision) -> None:
        risk = RiskState()
        risk.timestamp = assessment.timestamp
        risk.state = decision.state.value
        risk.risk = float(assessment.risk)
        risk.psi = float(assessment.psi)
        risk.delta = bool(assessment.delta)
        risk.gamma = bool(assessment.gamma)
        risk.active_components = sorted(assessment.active_components)
        risk.critical_components = sorted(assessment.critical_components)
        risk.reason = assessment.reason
        self.risk_pub.publish(risk)

        command = MitigationCommand()
        command.timestamp = assessment.timestamp
        command.plan_id = plan.plan_id
        command.action = plan.action.value
        command.components = sorted(plan.components)
        command.requires_safe_stop = plan.requires_safe_stop
        command.reason = plan.reason
        self.command_pub.publish(command)

        status = SafetyStatus()
        status.timestamp = decision.timestamp
        status.state = decision.state.value
        status.speed_limit = float(decision.speed_limit)
        status.mission_allowed = decision.mission_allowed
        status.reason = decision.reason
        status.plan_id = decision.plan_id or ""
        self.status_pub.publish(status)


def main(args: Iterable[str] | None = None) -> None:
    rclpy.init(args=args)
    node = GuardianNode()
    try:
        rclpy.spin(node)
    finally:
        node.destroy_node()
        rclpy.shutdown()

