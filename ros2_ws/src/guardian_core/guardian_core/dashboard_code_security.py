"""Bounded, read-only inspection of industrial ROS 2 Python source code.

The inspector intentionally treats source as data. It never imports, executes,
launches, or sends the submitted code to ROS 2 or an external provider.
"""

from __future__ import annotations

import ast
import math
import os
import re
from dataclasses import dataclass

CODE_SECURITY_SCHEMA = "guardian-code-security/v1"
PROFILE = "conveyor_robot_arm"
MAX_SOURCE_BYTES = 64 * 1024
MAX_FILENAME_CHARS = 128

CONTROL_TOPICS = ("/cmd_vel", "/joint_trajectory", "/gripper/command")
GAZEBO_CONTROL_TOPIC_RE = re.compile(r"^/model/[^/]+/cmd_vel$")
SECRET_NAME_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:api[_-]?key|password|passwd|token|secret|credential)(?![A-Za-z0-9_])",
    re.IGNORECASE,
)
STRING_LITERAL_RE = re.compile(r"""(["'])(?:\\.|(?!\1).)*\1""")

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class CodeSecurityError(ValueError):
    """Invalid or unsupported source inspection input."""


@dataclass(frozen=True)
class _Finding:
    rule_id: str
    severity: str
    title: str
    line: int
    evidence: str
    recommendation: str
    guardian_action: str

    def as_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "line": self.line,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "guardian_action": self.guardian_action,
        }


class _SourceVisitor(ast.NodeVisitor):
    def __init__(self, source_lines: list[str]) -> None:
        self.source_lines = source_lines
        self.topics: set[str] = set()
        self.findings: list[_Finding] = []

    def _line(self, node: ast.AST) -> int:
        return max(1, int(getattr(node, "lineno", 1)))

    def _evidence(self, line: int, *, redact: bool = False) -> str:
        text = self.source_lines[line - 1].strip() if line <= len(self.source_lines) else ""
        if redact:
            text = STRING_LITERAL_RE.sub("<redacted>", text)
            return SECRET_NAME_RE.sub("<secret>", text)[:240]
        return text[:240]

    def _add(self, node: ast.AST, rule_id: str, severity: str, title: str,
             recommendation: str, guardian_action: str, *, redact: bool = False) -> None:
        line = self._line(node)
        self.findings.append(_Finding(
            rule_id=rule_id,
            severity=severity,
            title=title,
            line=line,
            evidence=self._evidence(line, redact=redact),
            recommendation=recommendation,
            guardian_action=guardian_action,
        ))

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        name = _call_name(node.func)
        dynamic_name = node.func.id if isinstance(node.func, ast.Name) else ""
        if dynamic_name in {"eval", "exec", "compile", "__import__"}:
            self._add(
                node,
                "DYN-001",
                "critical",
                "动态执行外部输入",
                "删除动态执行；使用固定的消息字段和显式白名单分支。",
                "SAFE_STOP",
            )
        elif name in {"os.system", "os.popen", "subprocess.run", "subprocess.Popen", "subprocess.call"}:
            self._add(
                node,
                "DYN-002",
                "high",
                "回调路径可启动外部进程",
                "将外部进程移出控制回调，并通过受限服务接口和固定参数调用。",
                "ISOLATE_COMPONENT",
            )

        if name.endswith("create_publisher") and node.args:
            topic = _string_value(node.args[1] if len(node.args) > 1 else node.args[0])
            if topic in CONTROL_TOPICS or (topic and GAZEBO_CONTROL_TOPIC_RE.fullmatch(topic)):
                self.topics.add(topic)
        if name in {"time.sleep", "sleep"}:
            self._add(
                node,
                "CALL-001",
                "medium",
                "控制回调包含阻塞等待",
                "将等待改为定时器或状态机，避免阻塞安全反馈和心跳。",
                "REVIEW_REQUIRED",
            )
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        for alias in node.names:
            if alias.name == "subprocess":
                self._add(
                    node,
                    "DYN-002",
                    "high",
                    "导入外部进程执行模块",
                    "移除 subprocess；控制节点不应从回调路径启动外部命令。",
                    "ISOLATE_COMPONENT",
                )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        if node.module == "subprocess":
            self._add(
                node,
                "DYN-002",
                "high",
                "导入外部进程执行模块",
                "移除 subprocess；控制节点不应从回调路径启动外部命令。",
                "ISOLATE_COMPONENT",
            )
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        target_names = [_target_name(target) for target in node.targets]
        if any(name and SECRET_NAME_RE.search(name) for name in target_names):
            if not _is_environment_lookup(node.value):
                self._add(
                    node,
                    "SEC-001",
                    "high",
                    "疑似硬编码凭据或访问令牌",
                    "改用受限凭据存储或 os.getenv，并避免在控制代码中保存密钥。",
                    "ISOLATE_COMPONENT",
                    redact=True,
                )
        self.generic_visit(node)


class _ControlPathAnalyzer(ast.NodeVisitor):
    """Recognize bounded local guard/clamp patterns, not whole-program safety."""

    def __init__(self, source_lines: list[str]) -> None:
        self.source_lines = source_lines
        self.topics: set[str] = set()
        self.publishers: dict[str, str] = {}
        self.publish_calls: list[dict[str, object]] = []
        self.unresolved_calls = 0
        self.has_rclpy_init = False
        self.has_rclpy_spin = False
        self.has_rclpy_shutdown = False

    @property
    def runtime_entrypoint(self) -> bool:
        return self.has_rclpy_init and self.has_rclpy_spin and self.has_rclpy_shutdown

    def _line(self, node: ast.AST) -> int:
        return max(1, int(getattr(node, "lineno", 1)))

    @staticmethod
    def _safe_branch(test: ast.AST, truth: bool) -> bool:
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            return _ControlPathAnalyzer._safe_branch(test.operand, not truth)
        if isinstance(test, ast.BoolOp):
            evidence = [_ControlPathAnalyzer._safe_branch(value, truth) for value in test.values]
            return any(evidence) if isinstance(test.op, ast.And) == truth else all(evidence)
        if isinstance(test, (ast.Name, ast.Attribute)):
            name = _target_name(test).lower()
            return (truth and name in {"mission_allowed", "safety_ok", "permit", "motion_allowed"}
                    or not truth and name in {"estop", "e_stop", "safe_stop", "emergency_stop"})
        return False

    @staticmethod
    def _clamp(value: ast.AST, target: str) -> bool:
        # Recognize symmetric min/max on the same message field. Helpers remain unverified.
        if not isinstance(value, ast.Call) or len(value.args) != 2 or value.keywords:
            return False
        outer = _call_name(value.func)
        bound, inner = value.args
        if outer not in {"min", "max"} or not isinstance(inner, ast.Call) or len(inner.args) != 2 or inner.keywords:
            return False
        if _call_name(inner.func) != ("min" if outer == "max" else "max"):
            return False
        lower, upper = (bound, inner.args[0]) if outer == "max" else (inner.args[0], bound)
        if _call_name(inner.args[1]) != target:
            return False
        if not isinstance(lower, ast.UnaryOp) or not isinstance(lower.op, ast.USub):
            return False
        if ast.dump(lower.operand) != ast.dump(upper):
            return False
        if isinstance(upper, ast.Constant):
            return type(upper.value) in (int, float) and math.isfinite(upper.value) and upper.value > 0
        return isinstance(upper, (ast.Name, ast.Attribute)) and _target_name(upper) in {
            "speed_limit", "max_speed", "velocity_limit",
        }

    def _declarations(self, node: ast.AST) -> dict[str, str]:
        publishers = {}
        for item in ast.walk(node):
            if not isinstance(item, ast.Assign) or not isinstance(item.value, ast.Call):
                continue
            call = item.value
            if not _call_name(call.func).endswith(".create_publisher"):
                continue
            topic_node = call.args[1] if len(call.args) > 1 else next(
                (kw.value for kw in call.keywords if kw.arg == "topic"), None)
            topic = _string_value(topic_node)
            for target in item.targets:
                publishers[_call_name(target)] = topic or ""
            if topic in CONTROL_TOPICS or (topic and GAZEBO_CONTROL_TOPIC_RE.fullmatch(topic)):
                self.topics.add(topic)
        return publishers

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        previous = self.publishers
        self.publishers = self._declarations(node)
        for statement in node.body:
            self.visit(statement)
        self.publishers = previous

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        previous = self.publishers
        self.publishers = {**previous, **self._declarations(node)}
        self._block(node.body, False, set())
        self.publishers = previous

    visit_AsyncFunctionDef = visit_FunctionDef

    def _calls(self, node: ast.AST, guarded: bool, limited: set[str]) -> None:
        for call in ast.walk(node):
            if not isinstance(call, ast.Call):
                continue
            name = _call_name(call.func)
            self.has_rclpy_init |= name == "rclpy.init"
            self.has_rclpy_spin |= name == "rclpy.spin"
            self.has_rclpy_shutdown |= name == "rclpy.shutdown"
            if not isinstance(call.func, ast.Attribute) or call.func.attr != "publish":
                continue
            topic = self.publishers.get(_call_name(call.func.value), "")
            if not topic:
                self.unresolved_calls += 1
                continue
            if topic not in CONTROL_TOPICS and not GAZEBO_CONTROL_TOPIC_RE.fullmatch(topic):
                continue
            argument = _call_name(call.args[0]) if call.args else ""
            self.publish_calls.append({
                "topic": topic, "line": call.lineno, "guarded": guarded,
                "limited": bool(argument and argument + ".linear.x" in limited),
            })

    def _block(self, statements: list[ast.stmt], guarded: bool, limited: set[str]):
        limited = set(limited)
        for statement in statements:
            if isinstance(statement, ast.If):
                self._calls(statement.test, guarded, limited)
                left = self._block(statement.body, guarded or self._safe_branch(statement.test, True), limited)
                right = self._block(statement.orelse, guarded or self._safe_branch(statement.test, False), limited)
                surviving = [branch for branch in (left, right) if branch is not None]
                if not surviving:
                    return None
                guarded = all(branch[0] for branch in surviving)
                limited = set.intersection(*(branch[1] for branch in surviving))
            elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self.visit(statement)
            elif isinstance(statement, (ast.For, ast.While, ast.Try, ast.With, ast.AsyncWith, ast.AsyncFor, ast.Match)):
                # Unsupported control flow cannot contribute guard evidence.
                self._calls(statement, False, set())
                guarded, limited = False, set()
            else:
                self._calls(statement, guarded, limited)
                if isinstance(statement, (ast.Return, ast.Raise)):
                    return None
                if isinstance(statement, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                    targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                    for target_node in targets:
                        target = _call_name(target_node)
                        limited = {field for field in limited if not (field == target or field.startswith(target + "."))}
                        if _target_name(target_node) in {"estop", "mission_allowed", "permit", "safety_ok"}:
                            guarded = False
                        if target.endswith(".linear.x") and self._clamp(statement.value, target):
                            limited.add(target)
        return guarded, limited


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _string_value(node: ast.AST) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _target_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _is_environment_lookup(node: ast.AST) -> bool:
    return isinstance(node, ast.Call) and _call_name(node.func) in {"os.getenv", "getenv"}


def _validate_source(source: str, filename: str, profile: str) -> None:
    if not isinstance(source, str) or not source.strip():
        raise CodeSecurityError("source 必须是非空文本")
    if len(source.encode("utf-8")) > MAX_SOURCE_BYTES:
        raise CodeSecurityError("source 不能超过 64 KiB")
    if not isinstance(filename, str) or not filename.strip() or len(filename) > MAX_FILENAME_CHARS:
        raise CodeSecurityError("filename 必须是 1–128 个字符")
    if os.path.basename(filename) != filename or "\x00" in filename:
        raise CodeSecurityError("filename 只能是单级文件名")
    if profile != PROFILE:
        raise CodeSecurityError(f"profile 必须为 {PROFILE}")


def _finding(rule_id: str, severity: str, title: str, line: int, evidence: str,
             recommendation: str, guardian_action: str) -> _Finding:
    return _Finding(rule_id, severity, title, line, evidence, recommendation, guardian_action)


def _dedupe_findings(findings: list[_Finding]) -> list[_Finding]:
    seen: set[tuple[str, int, str]] = set()
    result: list[_Finding] = []
    for item in findings:
        key = (item.rule_id, item.line, item.evidence)
        if key not in seen:
            result.append(item)
            seen.add(key)
    return sorted(result, key=lambda item: (_SEVERITY_ORDER[item.severity], item.line, item.rule_id))


def _guardian_mapping(findings: list[_Finding]) -> dict[str, str]:
    severities = {item.severity for item in findings}
    if "critical" in severities:
        return {
            "state": "SAFE_STOP",
            "action": "SAFE_STOP",
            "reason": "存在必须阻断部署的关键代码风险。",
        }
    if "high" in severities:
        return {
            "state": "CONTAINING",
            "action": "ISOLATE_COMPONENT",
            "reason": "存在执行器边界或凭据风险，需隔离并人工复核。",
        }
    if "medium" in severities:
        return {
            "state": "RESUMABLE",
            "action": "REVIEW_REQUIRED",
            "reason": "存在需要在上线前复核的控制路径风险。",
        }
    return {
        "state": "NORMAL",
        "action": "NONE",
        "reason": "未发现当前规则覆盖的高风险模式。",
    }


def _parse_findings(source: str) -> tuple[list[str], list[str], list[_Finding], _ControlPathAnalyzer | None]:
    lines = source.splitlines()
    try:
        tree = ast.parse(source)
    except SyntaxError as error:
        line = max(1, int(error.lineno or 1))
        evidence = lines[line - 1].strip()[:240] if line <= len(lines) else ""
        return lines, [], [_finding(
            "PARSE-001",
            "critical",
            "源代码无法解析",
            line,
            evidence,
            "修复语法错误后再进行部署检查。",
            "SAFE_STOP",
        )], None

    visitor = _SourceVisitor(lines)
    visitor.visit(tree)
    control = _ControlPathAnalyzer(lines)
    control.visit(tree)
    topics = sorted(control.topics or visitor.topics)
    publish_calls = control.publish_calls
    if topics and not all(item["guarded"] for item in publish_calls):
        visitor.findings.append(_finding(
            "ACT-002",
            "high",
            "执行器发布缺少逐路径急停或许可门控",
            1,
            ", ".join(topics),
            "让 Guardian SafetyStatus 或等价安全许可成为每个执行器发布的前置条件。",
            "ISOLATE_COMPONENT",
        ))
    drive_topics = {topic for topic in topics if topic.endswith("/cmd_vel")}
    drive_calls = [item for item in publish_calls if item["topic"] in drive_topics]
    if drive_topics and (not drive_calls or not all(item["limited"] for item in drive_calls)):
        visitor.findings.append(_finding(
            "ACT-001",
            "high",
            "速度控制路径缺少可验证限幅",
            1,
            ", ".join(sorted(drive_topics)),
            "在发布前对线速度进行明确限幅，并将上限与安全状态绑定。",
            "ISOLATE_COMPONENT",
        ))
    return lines, topics, _dedupe_findings(visitor.findings), control


def _assurance_report(
    source: str,
    topics: list[str],
    findings: list[_Finding],
    control: _ControlPathAnalyzer | None,
) -> dict[str, object]:
    parsed = control is not None
    publish_calls = control.publish_calls if control else []
    guarded_calls = [item for item in publish_calls if item["guarded"]]
    drive_calls = [item for item in publish_calls if str(item["topic"]).endswith("/cmd_vel")]
    limited_drive_calls = [item for item in drive_calls if item["limited"]]
    checks = [
        {
            "id": "python_syntax",
            "label": "Python 语法可解析",
            "passed": parsed,
            "details": "AST 解析完成" if parsed else "语法解析失败",
        },
        {
            "id": "actuator_topic_discovery",
            "label": "执行器主题可识别",
            "passed": bool(topics),
            "details": "、".join(topics) if topics else "未识别到当前规则覆盖的执行器主题",
        },
        {
            "id": "publish_path_guarded",
            "label": "每条发布路径都有安全门控",
            "passed": bool(publish_calls) and len(guarded_calls) == len(publish_calls),
            "details": f"{len(guarded_calls)}/{len(publish_calls)} 条发布路径通过",
        },
        {
            "id": "velocity_boundary",
            "label": "速度控制路径具有限幅",
            "passed": bool(drive_calls) and len(limited_drive_calls) == len(drive_calls),
            "details": (
                f"{len(limited_drive_calls)}/{len(drive_calls)} 条 /cmd_vel 路径通过"
                if drive_calls else "没有可验证的 /cmd_vel 速度控制路径"
            ),
        },
        {
            "id": "ros2_runtime_entrypoint",
            "label": "ROS 2 启动入口",
            "passed": bool(control and control.runtime_entrypoint),
            "details": "检测到 rclpy.init/spin/shutdown" if control and control.runtime_entrypoint else "未检测到完整 rclpy.init/spin/shutdown",
        },
    ]
    missing_controls = [item["label"] for item in checks if not item["passed"]]
    passed = sum(1 for item in checks if item["passed"])
    coverage_score = round(passed / len(checks) * 100, 1)
    return {
        "mode": "STATIC_ONLY",
        "coverage_score": coverage_score,
        "runtime_verified": False,
        "source_executed": False,
        "checks": checks,
        "missing_controls": missing_controls,
        "limitations": [
            "只完成 Python AST 和有限文本规则检查，未启动 ROS 2/Gazebo。",
            "未验证 DDS/SROS2 身份、真实传感器输入、控制器时序和物理碰撞结果。",
            "通过检查不等于工业安全认证；上线前仍需仿真闭环、硬件在环和人工复核。",
        ],
        "finding_count": len(findings),
        "topics_checked": topics,
        "publish_paths": [
            {
                "topic": item["topic"],
                "line": item["line"],
                "guarded": item["guarded"],
                "limited": item["limited"],
            }
            for item in publish_calls
        ],
        "executable_source_bytes": len(source.encode("utf-8")),
    }


def inspect_source(source: str, *, filename: str = "uploaded.py", profile: str = PROFILE) -> dict[str, object]:
    """Inspect a bounded ROS 2 Python source string without executing it."""
    _validate_source(source, filename, profile)
    _lines, topics, findings, control = _parse_findings(source)
    assurance = _assurance_report(source, topics, findings, control)
    checks = {item["id"]: item["passed"] for item in assurance["checks"]}
    core_evidence_missing = (
        not checks.get("python_syntax", False)
        or not checks.get("actuator_topic_discovery", False)
        or not checks.get("publish_path_guarded", False)
        or ("/cmd_vel" in topics and not checks.get("velocity_boundary", False))
    )
    summary = {name: sum(item.severity == name for item in findings) for name in ("critical", "high", "medium", "low")}
    summary["total"] = len(findings)
    summary["verdict"] = (
        "BLOCKED"
        if summary["critical"]
        else "REVIEW"
        if summary["high"] or summary["medium"] or core_evidence_missing
        else "PASS"
    )
    return {
        "schema": CODE_SECURITY_SCHEMA,
        "filename": filename,
        "profile": profile,
        "topics": topics,
        "summary": summary,
        "guardian_mapping": _guardian_mapping(findings),
        "findings": [item.as_dict() for item in findings],
        "assurance": assurance,
        "execution": "not_executed",
    }


SAFE_CONVEYOR_SOURCE = '''\
import os
from geometry_msgs.msg import Twist
from rclpy.node import Node


class SafeCell(Node):
    def __init__(self):
        super().__init__("safe_cell")
        self.speed_limit = 0.20
        self.estop = False
        self.drive_pub = self.create_publisher(Twist, "/cmd_vel", 10)
        self.arm_pub = self.create_publisher(object, "/joint_trajectory", 10)
        self.gripper_pub = self.create_publisher(object, "/gripper/command", 10)

    def publish_drive(self, command):
        if self.estop:
            return
        command.linear.x = max(-self.speed_limit, min(self.speed_limit, command.linear.x))
        self.drive_pub.publish(command)

    def publish_gripper(self, command):
        if self.estop:
            return
        self.gripper_pub.publish(command)
'''


UNSAFE_CONVEYOR_SOURCE = '''\
import subprocess
from rclpy.node import Node


class UnsafeCell(Node):
    def __init__(self):
        super().__init__("unsafe_cell")
        self.drive_pub = self.create_publisher(object, "/cmd_vel", 10)
        self.arm_pub = self.create_publisher(object, "/joint_trajectory", 10)
        self.password = "factory-admin-password"

    def callback(self, msg):
        eval(msg.command)
        self.drive_pub.publish(msg)
'''

GAZEBO_AMR_UNSAFE_SOURCE = '''\
"""Reference-only ROS 2 controller for a Gazebo Sim AMR.

The topic shape follows the ros_gz bridge style used by Gazebo Sim examples.
This fixture is intentionally unsafe and must never be launched as-is.
"""

import subprocess
import time

from geometry_msgs.msg import Twist
from rclpy.node import Node


class GazeboAmrController(Node):
    def __init__(self):
        super().__init__("gazebo_amr_controller")
        self.operator_token = "demo-factory-token"
        self.target_speed = 1.5
        self.cmd_pub = self.create_publisher(Twist, "/model/amr_07/cmd_vel", 10)
        self.timer = self.create_timer(0.05, self.command_loop)
        subprocess.run(["gz", "topic", "-l"], check=False)

    def command_loop(self):
        time.sleep(0.2)
        command = Twist()
        command.linear.x = self.target_speed
        self.cmd_pub.publish(command)

    def apply_override(self, msg):
        eval(msg.expression)
        self.cmd_pub.publish(msg.command)
'''


def sample_catalog() -> list[dict[str, object]]:
    return [
        {
            "id": "safe_conveyor",
            "title": "安全输送线与机械臂控制节点",
            "description": "包含速度限幅、急停门控和三个典型工业 ROS 2 执行器话题。",
            "profile": PROFILE,
            "topics": list(CONTROL_TOPICS),
            "source": SAFE_CONVEYOR_SOURCE,
        },
        {
            "id": "unsafe_conveyor",
            "title": "待整改的输送线控制节点",
            "description": "包含动态执行、硬编码凭据和未受保护的执行器发布路径。",
            "profile": PROFILE,
            "topics": ["/cmd_vel", "/joint_trajectory"],
            "source": UNSAFE_CONVEYOR_SOURCE,
        },
        {
            "id": "gazebo_amr_unsafe",
            "title": "Gazebo Sim AMR 差速驱动风险控制节点",
            "description": "参考 ros_gz 桥接主题形态的可检查源码；包含无速度边界、无急停门控、阻塞调用、动态执行和硬编码令牌。",
            "profile": PROFILE,
            "topics": ["/model/amr_07/cmd_vel"],
            "source": GAZEBO_AMR_UNSAFE_SOURCE,
        },
    ]
