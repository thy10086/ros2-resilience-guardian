"""Bounded, read-only ROS 2 code and control-path graph analysis."""

from __future__ import annotations

import ast
from collections import defaultdict, deque
from pathlib import PurePosixPath
import re
from typing import Any

from .dashboard_code_security import CodeSecurityError, inspect_source


GRAPH_SCHEMA = "ros-security-graph/v1"
MAX_FILES = 128
MAX_FILE_BYTES = 64 * 1024
MAX_TOTAL_BYTES = 512 * 1024
MAX_PATHS = 64
MAX_FINDINGS = 256
MAX_LABEL_CHARS = 160

CONTROL_TOPICS = {
    "/cmd_vel": ("actuator", "high"),
    "/joint_trajectory": ("actuator", "high"),
    "/gripper/command": ("actuator", "high"),
}
CONTROL_TOPIC_PATTERN = re.compile(r"^/model/[^/]+/cmd_vel$")
TOPIC_TOKENS = tuple(CONTROL_TOPICS) + ("/clock",)
PERMISSION_MARKERS = (
    "permission",
    "permissions",
    "profile_id",
    "adapter_id",
    "security_context",
    "sros",
    "dds",
)
PYTHON_SUFFIXES = {".py", ".pyi"}
CONFIG_SUFFIXES = {".yaml", ".yml", ".xml", ".sdf", ".urdf", ".json", ".toml"}
UNSUPPORTED_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp"}
GUARD_NAMES = {"estop", "e_stop", "safe_stop", "emergency_stop", "mission_allowed", "safety_ok", "permit"}
LIMIT_NAMES = {"speed_limit", "max_speed", "velocity_limit", "max_velocity"}

_RULE_MAP = {
    "PARSE-001": ("GRAPH-PARSE-001", "critical"),
    "DYN-001": ("GRAPH-DYN-001", "critical"),
    "DYN-002": ("GRAPH-DYN-002", "high"),
    "ACT-001": ("GRAPH-ACT-002", "high"),
    "ACT-002": ("GRAPH-ACT-001", "high"),
    "CALL-001": ("GRAPH-FEEDBACK-001", "medium"),
    "SEC-001": ("GRAPH-TRUST-001", "critical"),
}
_ACTION_ORDER = {"NONE": 0, "REVIEW_REQUIRED": 1, "ISOLATE_COMPONENT": 2, "SAFE_STOP": 3}
_SEVERITY_ORDER = {"low": 3, "medium": 2, "high": 1, "critical": 0}


class GraphSecurityError(ValueError):
    """Raised when a graph request is malformed or exceeds a hard bound."""


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _string_value(node: ast.AST | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _target_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _safe_text(value: object, limit: int = MAX_LABEL_CHARS) -> str:
    return str(value).replace("\x00", "")[:limit]


def _valid_filename(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 256 or "\x00" in value:
        raise GraphSecurityError("filename must be a non-empty relative path")
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        raise GraphSecurityError("filename must be relative")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise GraphSecurityError("filename contains an unsafe path segment")
    return str(path)


def _topic_kind(topic: str) -> tuple[str, str]:
    if topic in CONTROL_TOPICS:
        return CONTROL_TOPICS[topic]
    if CONTROL_TOPIC_PATTERN.fullmatch(topic):
        return "actuator", "high"
    return "topic", "medium"


def _topic_from_call(call: ast.Call, method: str) -> str | None:
    index = 1 if method in {"create_publisher", "create_subscription"} else 0
    if len(call.args) > index:
        return _string_value(call.args[index])
    for keyword in call.keywords:
        if keyword.arg in {"topic", "topic_name"}:
            return _string_value(keyword.value)
    return None


def _publisher_target(call: ast.Call) -> str:
    if isinstance(call.func, ast.Attribute):
        return _target_name(call.func.value)
    return ""


def _node(node_id: str, kind: str, label: str, *, filename: str = "", line: int = 1,
          criticality: str = "low", trust_zone: str = "unknown",
          provenance: str = "EXTRACTED") -> dict[str, object]:
    return {
        "id": node_id,
        "kind": kind,
        "label": _safe_text(label),
        "file": filename,
        "line": int(line or 1),
        "trust_zone": trust_zone,
        "criticality": criticality,
        "provenance": provenance,
    }


def _edge(source: str, target: str, kind: str, *, filename: str = "", line: int = 1,
          confidence: float = 1.0, provenance: str = "EXTRACTED",
          relevance: str = "structure") -> dict[str, object]:
    return {
        "id": f"edge:{source}->{kind}->{target}",
        "source": source,
        "target": target,
        "kind": kind,
        "file": filename,
        "line": int(line or 1),
        "confidence": max(0.0, min(1.0, float(confidence))),
        "provenance": provenance,
        "security_relevance": relevance,
    }


class _PythonGraphVisitor(ast.NodeVisitor):
    def __init__(self, filename: str, source: str, nodes: dict[str, dict[str, object]],
                 edges: dict[str, dict[str, object]]) -> None:
        self.filename = filename
        self.source = source
        self.lines = source.splitlines()
        self.nodes = nodes
        self.edges = edges
        self.parents: list[str] = [f"file:{filename}"]
        self.publisher_topics: dict[str, str] = {}
        self.function_topics: dict[str, set[str]] = defaultdict(set)
        self.security_nodes: set[str] = set()

    def _add_node(self, item: dict[str, object]) -> None:
        self.nodes.setdefault(str(item["id"]), item)

    def _add_edge(self, item: dict[str, object]) -> None:
        self.edges.setdefault(str(item["id"]), item)

    def _current(self) -> str:
        return self.parents[-1]

    def _source_line(self, line: int) -> str:
        return self.lines[line - 1] if 0 < line <= len(self.lines) else ""

    def _has_security_evidence(self, node: ast.AST) -> bool:
        start = max(1, int(getattr(node, "lineno", 1)))
        end = max(start, int(getattr(node, "end_lineno", start)))
        text = "\n".join(self.lines[start - 1:end]).lower()
        return any(name in text for name in GUARD_NAMES | LIMIT_NAMES)

    def _register_topic(self, topic: str, line: int) -> str:
        kind, criticality = _topic_kind(topic)
        topic_id = f"topic:{topic}"
        self._add_node(_node(
            topic_id, kind, topic, filename=self.filename, line=line,
            criticality=criticality, provenance="EXTRACTED",
        ))
        return topic_id

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        class_id = f"class:{self.filename}:{node.lineno}:{node.name}"
        self._add_node(_node(class_id, "class", node.name, filename=self.filename, line=node.lineno))
        self._add_edge(_edge(self._current(), class_id, "contains", filename=self.filename, line=node.lineno))
        self.parents.append(class_id)
        self.generic_visit(node)
        self.parents.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        function_id = f"function:{self.filename}:{node.lineno}:{node.name}"
        self._add_node(_node(function_id, "function", node.name, filename=self.filename, line=node.lineno))
        self._add_edge(_edge(self._current(), function_id, "contains", filename=self.filename, line=node.lineno))
        if self._has_security_evidence(node):
            guard_id = f"security:{self.filename}:{node.lineno}:{node.name}"
            self._add_node(_node(
                guard_id, "trust_zone", "safety gate evidence", filename=self.filename,
                line=node.lineno, criticality="high", trust_zone="guardian",
            ))
            self._add_edge(_edge(
                function_id, guard_id, "protected_by", filename=self.filename,
                line=node.lineno, relevance="safety_evidence",
            ))
            self.security_nodes.add(guard_id)
        self.parents.append(function_id)
        self.generic_visit(node)
        self.parents.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Call):
            method = _call_name(node.value.func).split(".")[-1]
            if method == "create_publisher":
                topic = _topic_from_call(node.value, method)
                if topic:
                    for target in node.targets:
                        name = _target_name(target)
                        if name:
                            self.publisher_topics[name] = topic
                    publisher_id = f"publisher:{self.filename}:{node.lineno}:{topic}"
                    self._add_node(_node(
                        publisher_id, "publisher", topic, filename=self.filename,
                        line=node.lineno, criticality=_topic_kind(topic)[1],
                    ))
                    self._add_edge(_edge(
                        self._current(), publisher_id, "contains", filename=self.filename,
                        line=node.lineno, relevance="control_path",
                    ))
                    topic_id = self._register_topic(topic, node.lineno)
                    self._add_edge(_edge(
                        publisher_id, topic_id, "publishes", filename=self.filename,
                        line=node.lineno, relevance="control_path",
                    ))
            elif method == "create_subscription":
                topic = _topic_from_call(node.value, method)
                if topic:
                    subscriber_id = f"subscriber:{self.filename}:{node.lineno}:{topic}"
                    self._add_node(_node(
                        subscriber_id, "subscriber", topic, filename=self.filename,
                        line=node.lineno, criticality=_topic_kind(topic)[1],
                    ))
                    self._add_edge(_edge(
                        self._current(), subscriber_id, "contains", filename=self.filename,
                        line=node.lineno, relevance="control_path",
                    ))
                    topic_id = self._register_topic(topic, node.lineno)
                    self._add_edge(_edge(
                        subscriber_id, topic_id, "subscribes", filename=self.filename,
                        line=node.lineno, relevance="control_path",
                    ))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node.func)
        method = name.split(".")[-1]
        if method == "publish" and isinstance(node.func, ast.Attribute):
            target = _target_name(node.func.value)
            topic = self.publisher_topics.get(target)
            if topic:
                topic_id = self._register_topic(topic, node.lineno)
                self._add_edge(_edge(
                    self._current(), topic_id, "publishes", filename=self.filename,
                    line=node.lineno, relevance="control_path",
                ))
                self.function_topics[self._current()].add(topic)
        self.generic_visit(node)


def _map_finding(item: dict[str, object], filename: str, topic_ids: list[str]) -> dict[str, object]:
    raw_rule = str(item.get("rule_id", "GRAPH-PARSE-001"))
    rule_id, default_severity = _RULE_MAP.get(raw_rule, (f"GRAPH-{raw_rule}", str(item.get("severity", "medium"))))
    action = str(item.get("guardian_action", "REVIEW_REQUIRED"))
    path_node_ids = [f"file:{filename}", *topic_ids]
    return {
        "rule_id": rule_id,
        "severity": str(item.get("severity", default_severity)),
        "title": _safe_text(item.get("title", "security finding")),
        "file": filename,
        "line": int(item.get("line", 1) or 1),
        "evidence": _safe_text(item.get("evidence", "")),
        "recommendation": _safe_text(item.get("recommendation", "")),
        "guardian_action": action,
        "path_node_ids": path_node_ids,
        "path_edge_ids": [],
        "confidence": 1.0,
        "provenance": "EXTRACTED",
    }


def _validate_files(files: object) -> list[dict[str, str]]:
    if not isinstance(files, list) or not files or len(files) > MAX_FILES:
        raise GraphSecurityError(f"files must contain 1-{MAX_FILES} items")
    result: list[dict[str, str]] = []
    seen: set[str] = set()
    total_bytes = 0
    for item in files:
        if not isinstance(item, dict) or set(item) != {"filename", "source"}:
            raise GraphSecurityError("each file must contain only filename and source")
        filename = _valid_filename(item["filename"])
        source = item["source"]
        if not isinstance(source, str) or not source.strip():
            raise GraphSecurityError("source must be non-empty text")
        if filename in seen:
            raise GraphSecurityError("duplicate filename")
        seen.add(filename)
        size = len(source.encode("utf-8"))
        if size > MAX_FILE_BYTES:
            raise GraphSecurityError(f"{filename} exceeds the per-file limit")
        total_bytes += size
        if total_bytes > MAX_TOTAL_BYTES:
            raise GraphSecurityError("total source exceeds the request limit")
        result.append({"filename": filename, "source": source})
    return sorted(result, key=lambda item: item["filename"])


def _scan_config(filename: str, source: str, nodes: dict[str, dict[str, object]],
                 edges: dict[str, dict[str, object]]) -> list[str]:
    file_id = f"file:{filename}"
    topic_ids: list[str] = []
    for topic in TOPIC_TOKENS:
        if topic not in source:
            continue
        topic_id = f"topic:{topic}"
        kind, criticality = _topic_kind(topic)
        nodes.setdefault(topic_id, _node(
            topic_id, kind, topic, filename=filename, line=1,
            criticality=criticality, provenance="INFERRED",
        ))
        edges.setdefault(str(_edge(
            file_id, topic_id, "contains", filename=filename, line=1,
            confidence=0.6, provenance="INFERRED", relevance="control_path",
        )["id"]), _edge(
            file_id, topic_id, "contains", filename=filename, line=1,
            confidence=0.6, provenance="INFERRED", relevance="control_path",
        ))
        topic_ids.append(topic_id)
    marker_lines = [
        index for index, line in enumerate(source.splitlines(), start=1)
        if any(marker in line.lower() for marker in PERMISSION_MARKERS)
    ]
    if marker_lines:
        profile_id = f"security_profile:{filename}"
        nodes.setdefault(profile_id, _node(
            profile_id,
            "security_profile",
            "permission summary",
            filename=filename,
            line=marker_lines[0],
            criticality="high",
            provenance="EXTRACTED",
        ))
        edges.setdefault(str(_edge(
            file_id,
            profile_id,
            "contains",
            filename=filename,
            line=marker_lines[0],
            relevance="security_boundary",
        )["id"]), _edge(
            file_id,
            profile_id,
            "contains",
            filename=filename,
            line=marker_lines[0],
            relevance="security_boundary",
        ))
        for topic_id in topic_ids:
            permission_edge = _edge(
                profile_id,
                topic_id,
                "declares_permission",
                filename=filename,
                line=marker_lines[0],
                confidence=0.8,
                relevance="security_boundary",
            )
            edges.setdefault(str(permission_edge["id"]), permission_edge)
    return topic_ids


def _permission_finding(filename: str, topic_ids: list[str]) -> dict[str, object]:
    return {
        "rule_id": "GRAPH-PERM-001",
        "severity": "medium",
        "title": "高关键度 ROS 资源缺少可验证权限摘要",
        "file": filename,
        "line": 1,
        "evidence": "控制主题已识别，但未发现 profile_id、adapter_id、SROS2/DDS 或 permission marker",
        "recommendation": "提供可审计的 SROS2/DDS 权限或 Guardian security profile 摘要。",
        "guardian_action": "REVIEW_REQUIRED",
        "path_node_ids": [f"file:{filename}", *topic_ids],
        "path_edge_ids": [],
        "confidence": 0.8,
        "provenance": "INFERRED",
    }


def _find_paths(edges: list[dict[str, object]], findings: list[dict[str, object]]) -> list[dict[str, object]]:
    adjacency: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for item in edges:
        adjacency[str(item["source"])].append((str(item["target"]), str(item["id"])))
    paths: list[dict[str, object]] = []
    for finding in findings:
        start_nodes = list(dict.fromkeys(str(item) for item in finding["path_node_ids"]))
        targets = {node_id for node_id in start_nodes if node_id.startswith("topic:")}
        if not targets:
            continue
        for start in start_nodes:
            queue: deque[tuple[str, list[str], list[str]]] = deque([(start, [start], [])])
            visited = {start}
            while queue and len(paths) < MAX_PATHS:
                current, node_ids, edge_ids = queue.popleft()
                if current in targets and len(node_ids) > 1:
                    paths.append({
                        "finding_rule_id": finding["rule_id"],
                        "node_ids": node_ids,
                        "edge_ids": edge_ids,
                        "confidence": finding["confidence"],
                        "provenance": finding["provenance"],
                    })
                    break
                for target, edge_id in adjacency.get(current, []):
                    if target in visited or len(node_ids) >= 12:
                        continue
                    visited.add(target)
                    queue.append((target, [*node_ids, target], [*edge_ids, edge_id]))
    return paths[:MAX_PATHS]


def _summary(findings: list[dict[str, object]], unsupported: list[str]) -> dict[str, object]:
    counts = {name: sum(item["severity"] == name for item in findings) for name in ("critical", "high", "medium", "low")}
    counts["total"] = len(findings)
    if counts["critical"] or unsupported:
        verdict = "BLOCKED"
    elif counts["high"] or counts["medium"]:
        verdict = "REVIEW"
    else:
        verdict = "PASS"
    action = max(
        (str(item["guardian_action"]) for item in findings),
        key=lambda value: _ACTION_ORDER.get(value, 1),
        default="NONE",
    )
    counts["verdict"] = verdict
    counts["guardian_action"] = action
    return counts


def inspect_project(files: object, *, profile: str = "ros2_generic") -> dict[str, object]:
    """Analyze a bounded batch of ROS 2 source/config files without executing it."""
    normalized = _validate_files(files)
    if not isinstance(profile, str) or not profile or len(profile) > 64 or "\x00" in profile:
        raise GraphSecurityError("profile must be a bounded text identifier")

    nodes: dict[str, dict[str, object]] = {}
    edges: dict[str, dict[str, object]] = {}
    findings: list[dict[str, object]] = []
    unsupported_files: list[str] = []
    for item in normalized:
        filename = item["filename"]
        source = item["source"]
        file_id = f"file:{filename}"
        nodes[file_id] = _node(file_id, "file", filename, filename=filename, line=1)
        suffix = PurePosixPath(filename).suffix.lower()
        if suffix in PYTHON_SUFFIXES or filename.endswith(".launch.py"):
            try:
                tree = ast.parse(source, filename=filename)
            except SyntaxError as error:
                line = max(1, int(error.lineno or 1))
                findings.append({
                    "rule_id": "GRAPH-PARSE-001",
                    "severity": "critical",
                    "title": "Python source cannot be parsed",
                    "file": filename,
                    "line": line,
                    "evidence": _safe_text(source.splitlines()[line - 1] if source.splitlines() and line <= len(source.splitlines()) else ""),
                    "recommendation": "Fix syntax errors before deployment review.",
                    "guardian_action": "SAFE_STOP",
                    "path_node_ids": [file_id],
                    "path_edge_ids": [],
                    "confidence": 1.0,
                    "provenance": "EXTRACTED",
                })
                continue
            visitor = _PythonGraphVisitor(filename, source, nodes, edges)
            visitor.visit(tree)
            try:
                single_report = inspect_source(
                    source,
                    filename=PurePosixPath(filename).name,
                    profile="conveyor_robot_arm",
                )
            except CodeSecurityError as error:
                findings.append({
                    "rule_id": "GRAPH-PARSE-001",
                    "severity": "critical",
                    "title": "Source validation failed",
                    "file": filename,
                    "line": 1,
                    "evidence": _safe_text(str(error)),
                    "recommendation": "Review the source boundary and file metadata.",
                    "guardian_action": "SAFE_STOP",
                    "path_node_ids": [file_id],
                    "path_edge_ids": [],
                    "confidence": 1.0,
                    "provenance": "EXTRACTED",
                })
                continue
            topic_ids = sorted(node_id for node_id, node in nodes.items()
                               if node["kind"] in {"topic", "actuator"} and node["file"] == filename)
            for raw_finding in single_report.get("findings", []):
                if isinstance(raw_finding, dict):
                    findings.append(_map_finding(raw_finding, filename, topic_ids))
        elif suffix in CONFIG_SUFFIXES:
            topic_ids = _scan_config(filename, source, nodes, edges)
            if topic_ids and not any(
                marker in source.lower() for marker in PERMISSION_MARKERS
            ):
                findings.append(_permission_finding(filename, topic_ids))
        elif suffix in UNSUPPORTED_SUFFIXES or suffix:
            unsupported_files.append(filename)
            nodes[file_id]["provenance"] = "UNSUPPORTED"
            findings.append({
                "rule_id": "GRAPH-PARSE-001",
                "severity": "critical",
                "title": "Control file language is unsupported by the static analyzer",
                "file": filename,
                "line": 1,
                "evidence": f"{filename} requires a dedicated parser",
                "recommendation": "Add a verified parser or complete manual review before deployment.",
                "guardian_action": "SAFE_STOP",
                "path_node_ids": [file_id],
                "path_edge_ids": [],
                "confidence": 1.0,
                "provenance": "UNSUPPORTED",
            })

    if len(findings) > MAX_FINDINGS:
        findings = findings[:MAX_FINDINGS]
    for finding in findings:
        finding["path_edge_ids"] = [
            item["id"] for item in edges.values()
            if item["source"] in finding["path_node_ids"] or item["target"] in finding["path_node_ids"]
        ][:16]
    edge_list = sorted(edges.values(), key=lambda item: str(item["id"]))
    paths = _find_paths(edge_list, findings)
    return {
        "schema": GRAPH_SCHEMA,
        "profile": profile,
        "files": [item["filename"] for item in normalized],
        "nodes": sorted(nodes.values(), key=lambda item: str(item["id"])),
        "edges": edge_list,
        "findings": sorted(
            findings,
            key=lambda item: (_SEVERITY_ORDER.get(str(item["severity"]), 9), str(item["file"]), int(item["line"])),
        ),
        "paths": paths,
        "unsupported_files": sorted(set(unsupported_files)),
        "summary": _summary(findings, unsupported_files),
        "assurance": {
            "mode": "STATIC_ONLY",
            "runtime_verified": False,
            "source_executed": False,
            "coverage_score": round(
                max(0.0, 100.0 * (len(normalized) - len(unsupported_files)) / len(normalized)),
                1,
            ),
            "limitations": [
                "Only bounded Python AST and literal ROS resource extraction is performed.",
                "Unsupported source languages are never treated as safe.",
                "No ROS 2 process, DDS graph, hardware, or physical actuator is started.",
            ],
        },
        "execution": "not_executed",
    }


SAFE_SAMPLE = {
    "id": "safe_controller",
    "title": "安全 ROS 2 速度控制节点",
    "description": "带急停门控和速度限幅的 /cmd_vel 发布路径。",
    "files": [{
        "filename": "safe_controller.py",
        "source": """from geometry_msgs.msg import Twist
from rclpy.node import Node

class SafeController(Node):
    def __init__(self):
        super().__init__("safe_controller")
        self.estop = False
        self.speed_limit = 0.20
        self.drive_pub = self.create_publisher(Twist, "/cmd_vel", 10)

    def publish_drive(self, command):
        if self.estop:
            return
        command.linear.x = max(-self.speed_limit, min(self.speed_limit, command.linear.x))
        self.drive_pub.publish(command)
""",
    }],
}

UNSAFE_SAMPLE = {
    "id": "unsafe_controller",
    "title": "待整改 ROS 2 控制节点",
    "description": "包含动态执行、外部进程和未限幅执行器发布。",
    "files": [{
        "filename": "unsafe_controller.py",
        "source": """import subprocess
from rclpy.node import Node

class UnsafeController(Node):
    def __init__(self):
        super().__init__("unsafe_controller")
        self.drive_pub = self.create_publisher(object, "/cmd_vel", 10)

    def callback(self, message):
        eval(message.command)
        subprocess.run(["sh", "-c", message.command])
        self.drive_pub.publish(message)
""",
    }],
}


def sample_catalog() -> list[dict[str, object]]:
    return [SAFE_SAMPLE, UNSAFE_SAMPLE]


__all__ = ["GRAPH_SCHEMA", "GraphSecurityError", "inspect_project", "sample_catalog"]
