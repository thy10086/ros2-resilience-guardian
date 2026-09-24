"""Bounded, read-only inspection of industrial ROS 2 Python source code.

The inspector intentionally treats source as data. It never imports, executes,
launches, or sends the submitted code to ROS 2 or an external provider.
"""

from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass

CODE_SECURITY_SCHEMA = "guardian-code-security/v1"
PROFILE = "conveyor_robot_arm"
MAX_SOURCE_BYTES = 64 * 1024
MAX_FILENAME_CHARS = 128

CONTROL_TOPICS = ("/cmd_vel", "/joint_trajectory", "/gripper/command")
SECRET_NAME_RE = re.compile(r"(?:api[_-]?key|password|passwd|token|secret|credential)", re.IGNORECASE)
STRING_LITERAL_RE = re.compile(r"""(["'])(?:\\.|(?!\1).)*\1""")
SAFETY_BOUNDARY_RE = re.compile(
    r"(?:speed[_-]?limit|max[_-]?speed|joint[_-]?limit|clamp|SAFE_STOP|safe[_-]?stop|"
    r"emergency|e[_-]?stop|estop|mission[_-]?allowed|safety[_-]?status)",
    re.IGNORECASE,
)

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
        if name in {"eval", "exec", "compile", "__import__"}:
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
            if topic in CONTROL_TOPICS:
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


def _parse_findings(source: str) -> tuple[list[str], list[str], list[_Finding]]:
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
        )]

    visitor = _SourceVisitor(lines)
    visitor.visit(tree)
    if visitor.topics and not SAFETY_BOUNDARY_RE.search(source):
        visitor.findings.append(_finding(
            "ACT-001",
            "high",
            "执行器发布缺少可识别的安全边界",
            1,
            ", ".join(sorted(visitor.topics)),
            "在发布前校验速度/关节限位、急停状态和任务许可。",
            "ISOLATE_COMPONENT",
        ))
    if visitor.topics and not re.search(r"(?:publish|timer|callback).*(?:SAFE_STOP|safe_stop|estop|emergency|safety|mission_allowed)", source, re.IGNORECASE | re.DOTALL):
        visitor.findings.append(_finding(
            "ACT-002",
            "high",
            "执行器路径缺少显式停车或许可门控",
            1,
            ", ".join(sorted(visitor.topics)),
            "让 Guardian SafetyStatus 或等价安全许可成为执行器发布的前置条件。",
            "ISOLATE_COMPONENT",
        ))
    return lines, sorted(visitor.topics), _dedupe_findings(visitor.findings)


def inspect_source(source: str, *, filename: str = "uploaded.py", profile: str = PROFILE) -> dict[str, object]:
    """Inspect a bounded ROS 2 Python source string without executing it."""
    _validate_source(source, filename, profile)
    _lines, topics, findings = _parse_findings(source)
    summary = {name: sum(item.severity == name for item in findings) for name in ("critical", "high", "medium", "low")}
    summary["total"] = len(findings)
    summary["verdict"] = "BLOCKED" if summary["critical"] else "REVIEW" if summary["high"] or summary["medium"] else "PASS"
    return {
        "schema": CODE_SECURITY_SCHEMA,
        "filename": filename,
        "profile": profile,
        "topics": topics,
        "summary": summary,
        "guardian_mapping": _guardian_mapping(findings),
        "findings": [item.as_dict() for item in findings],
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
    ]
