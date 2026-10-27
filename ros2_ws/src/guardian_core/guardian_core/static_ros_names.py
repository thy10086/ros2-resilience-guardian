"""Limited source-only ROS name evidence, without claiming launch resolution.

Literal constructor namespaces are handled locally. External launch/CLI remaps,
private names and dynamic constructor arguments need runtime context.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
import re


ALLOW_GUARDS = frozenset({"mission_allowed", "safety_ok", "permit", "motion_allowed"})
STOP_GUARDS = frozenset({"estop", "e_stop", "safe_stop", "emergency_stop"})
GUARD_NAMES = ALLOW_GUARDS | STOP_GUARDS
_CONTROL_SUFFIXES = ("cmd_vel", "joint_trajectory", "gripper/command")
_VALID_NAME = re.compile(r"/?[A-Za-z_][A-Za-z_0-9]*(?:/[A-Za-z_][A-Za-z_0-9]*)*")


def is_control_topic(topic: str) -> bool:
    """Identify control candidates while retaining their distinct full names."""
    return any(topic == suffix or topic.endswith("/" + suffix) for suffix in _CONTROL_SUFFIXES)


@dataclass(frozen=True)
class NameContext:
    namespace: str | None = "/"
    remapped: bool = False
    explicit_namespace: bool = False


def context_for_scope(scope: ast.AST, inherited: NameContext = NameContext()) -> NameContext:
    """Extract only local Node/super constructor keywords, never evaluate code."""
    namespaces: set[str | None] = set()
    explicit_namespace = False
    remapped = inherited.remapped
    if isinstance(scope, ast.Module):
        # rclpy.init(args=...) may live in main() and affect every node.
        remapped |= any(
            isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
            and isinstance(call.func.value, ast.Name) and call.func.value.id == "rclpy"
            and call.func.attr == "init"
            and any(keyword.arg in {"args", None} for keyword in call.keywords)
            for call in ast.walk(scope)
        )
    pending = [scope]
    while pending:
        call = pending.pop()
        # A module or outer class must not inherit another node's namespace.
        pending.extend(child for child in ast.iter_child_nodes(call)
                       if not isinstance(child, ast.ClassDef)
                       and not (isinstance(scope, ast.Module) and isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))))
        if not isinstance(call, ast.Call):
            continue
        method = call.func.attr if isinstance(call.func, ast.Attribute) else getattr(call.func, "id", "")
        if method not in {"__init__", "Node", "create_node", "init"}:
            continue
        if method != "init" and not any(keyword.arg == "namespace" for keyword in call.keywords):
            # Without receiver-to-node dataflow, mixed constructors must remain
            # ambiguous. A default-root node is a namespace candidate too.
            namespaces.add("/")
        for keyword in call.keywords:
            if keyword.arg == "namespace":
                explicit_namespace = True
                value = keyword.value.value if isinstance(keyword.value, ast.Constant) else None
                if isinstance(value, str) and (not value or value == "/" or _VALID_NAME.fullmatch(value)):
                    namespaces.add("/" + value.strip("/") if value.strip("/") else "/")
                else:
                    namespaces.add(None)
            elif keyword.arg in {"cli_args", "arguments", "remappings", "args"}:
                # Even literal remapping lists require ROS rule ordering/context.
                remapped = True
            elif keyword.arg is None:
                remapped = True
    if not namespaces:
        return NameContext(inherited.namespace, remapped, inherited.explicit_namespace)
    namespace = next(iter(namespaces)) if len(namespaces) == 1 else None
    return NameContext(namespace, remapped, explicit_namespace)


def resolve_topic(original: str, context: NameContext) -> dict[str, object]:
    """Return a source-derived endpoint plus explicit assumptions and gaps."""
    resolved = None
    status = "UNRESOLVED"
    if not context.remapped and _VALID_NAME.fullmatch(original):
        if original.startswith("/"):
            resolved, status = original, "ABSOLUTE_SOURCE_NAME"
        elif context.namespace is not None:
            resolved = context.namespace.rstrip("/") + "/" + original
            status = "LITERAL_NAMESPACE" if context.explicit_namespace else "ROOT_NAMESPACE_ASSUMED"
    return {
        "topic": resolved or original,
        "original_topic": original,
        "resolved_topic": resolved,
        "name_resolution": status,
    }
