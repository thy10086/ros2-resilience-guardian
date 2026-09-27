"""Bounded robot-controller sandbox and evidence-producing simulation.

The module deliberately supports a small controller contract instead of
pretending that arbitrary ROS 2 nodes can be safely imported into the
Dashboard. Python controllers run in a Linux user/mount/PID/network namespace
when Docker is not available. SDF/URDF is parsed as data and uses a built-in
controller; XML never loads user plugins or external resources.
"""

from __future__ import annotations

import ast
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import tempfile
import textwrap
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


SANDBOX_SCHEMA = "guardian-sandbox/v1"
MAX_PYTHON_BYTES = 64 * 1024
MAX_XML_BYTES = 128 * 1024
MAX_FILENAME_CHARS = 128
MAX_DURATION_SEC = 8.0
MIN_DURATION_SEC = 0.2
STEP_SEC = 0.1
MAX_TRACE_POINTS = 120
MAX_LOG_BYTES = 16 * 1024
_DEFAULT_OBSTACLE = {"x": 1.25, "y": 0.0, "half_x": 0.25, "half_y": 0.5}

_ALLOWED_PYTHON_MODULES = {"math", "json"}
_BLOCKED_IMPORTS = {
    "asyncio",
    "ctypes",
    "importlib",
    "multiprocessing",
    "os",
    "pathlib",
    "psutil",
    "requests",
    "rclpy",
    "socket",
    "subprocess",
    "sys",
    "threading",
    "time",
}
_BLOCKED_CALLS = {"__import__", "compile", "eval", "exec", "input", "open"}
_EXTERNAL_URI_RE = re.compile(r"(?:file|http|https|model|package):", re.IGNORECASE)
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class SandboxInputError(ValueError):
    """Raised when an input cannot be handled by the bounded sandbox contract."""


def _finite(value: Any, fallback: float = 0.0) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return fallback
    return number if math.isfinite(number) else fallback


def _filename(filename: str) -> str:
    if not isinstance(filename, str) or not filename.strip() or len(filename) > MAX_FILENAME_CHARS:
        raise SandboxInputError("filename 必须是 1–128 个字符")
    if os.path.basename(filename) != filename or "\x00" in filename:
        raise SandboxInputError("filename 只能是单级文件名")
    return filename


def _kind(filename: str, kind: str | None) -> str:
    suffix = Path(filename).suffix.lower()
    selected = str(kind or "").strip().lower()
    if not selected:
        selected = "python" if suffix == ".py" else "sdf" if suffix in {".sdf", ".world"} else "urdf" if suffix == ".urdf" else ""
    if selected in {"py", "python"}:
        selected = "python"
    if selected not in {"python", "sdf", "urdf"}:
        raise SandboxInputError("只支持 Python 控制器、SDF 或 URDF 文件")
    if selected == "python" and suffix not in {".py", ""}:
        raise SandboxInputError("Python 控制器文件必须使用 .py")
    if selected == "sdf" and suffix not in {".sdf", ".world", ".xml", ""}:
        raise SandboxInputError("SDF 场景文件必须使用 .sdf、.world 或 .xml")
    if selected == "urdf" and suffix not in {".urdf", ".xml", ""}:
        raise SandboxInputError("URDF 文件必须使用 .urdf 或 .xml")
    return selected


class _PythonContractVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.function_names: set[str] = set()

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        for alias in node.names:
            root = alias.name.split(".", 1)[0]
            if root not in _ALLOWED_PYTHON_MODULES:
                raise SandboxInputError(f"不允许导入模块：{root}")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        root = (node.module or "").split(".", 1)[0]
        if root not in _ALLOWED_PYTHON_MODULES:
            raise SandboxInputError(f"不允许导入模块：{root or '未知模块'}")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        if isinstance(node.func, ast.Name) and node.func.id in _BLOCKED_CALLS:
            raise SandboxInputError(f"不允许调用：{node.func.id}")
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:  # noqa: N802
        if node.attr.startswith("__") or node.attr.endswith("__"):
            raise SandboxInputError("不允许使用对象内部反射属性")
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:  # noqa: N802
        if node.id.startswith("__") or node.id in {"globals", "locals", "vars", "dir"}:
            raise SandboxInputError("不允许使用运行时反射接口")
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self.function_names.add(node.name)
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef


def _validate_python(source: str) -> None:
    try:
        tree = ast.parse(source)
    except SyntaxError as error:
        raise SandboxInputError(f"Python 语法错误：第 {error.lineno or 1} 行") from error
    visitor = _PythonContractVisitor()
    visitor.visit(tree)
    if not {"control", "step"} & visitor.function_names:
        raise SandboxInputError("Python 文件必须定义 control(state) 或 step(state)")


def _xml_local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()


def _parse_numbers(text: str | None, count: int, defaults: tuple[float, ...]) -> tuple[float, ...]:
    values = []
    for item in (text or "").replace(",", " ").split():
        try:
            value = float(item)
        except ValueError:
            continue
        if math.isfinite(value):
            values.append(value)
    return tuple(values[:count]) + defaults[len(values[:count]):]


def _parse_xml(source: str, kind: str) -> dict[str, Any]:
    if "<!DOCTYPE" in source.upper() or "<!ENTITY" in source.upper():
        raise SandboxInputError("XML 禁止使用 DOCTYPE 或外部实体")
    if _EXTERNAL_URI_RE.search(source):
        raise SandboxInputError("XML 禁止引用外部 URI")
    try:
        root = ET.fromstring(source)
    except ET.ParseError as error:
        raise SandboxInputError(f"XML 语法错误：{error}") from error
    root_name = _xml_local(root.tag)
    expected = "sdf" if kind == "sdf" else "robot"
    if root_name != expected:
        raise SandboxInputError(f"{kind.upper()} 根节点必须是 <{expected}>")

    forbidden = {"plugin", "include"}
    for element in root.iter():
        name = _xml_local(element.tag)
        if name in forbidden:
            raise SandboxInputError(f"XML 不允许使用 <{name}>")
        for value in element.attrib.values():
            if _EXTERNAL_URI_RE.search(value):
                raise SandboxInputError("XML 属性禁止引用外部 URI")

    obstacles: list[dict[str, float]] = []
    for model in root.iter():
        if _xml_local(model.tag) != "model":
            continue
        pose = next((child for child in model.iter() if _xml_local(child.tag) == "pose"), None)
        px, py, *_ = _parse_numbers(pose.text if pose is not None else None, 2, (0.0, 0.0))
        for box in model.iter():
            if _xml_local(box.tag) != "box":
                continue
            size = next((child for child in box if _xml_local(child.tag) == "size"), None)
            sx, sy, *_ = _parse_numbers(size.text if size is not None else None, 2, (0.5, 0.5))
            obstacles.append({
                "x": px,
                "y": py,
                "half_x": max(0.05, abs(sx) / 2.0),
                "half_y": max(0.05, abs(sy) / 2.0),
            })

    return {
        "root": root_name,
        "version": root.attrib.get("version"),
        "obstacles": obstacles,
        "obstacle_count": len(obstacles),
        "model_count": sum(1 for element in root.iter() if _xml_local(element.tag) == "model"),
    }


def inspect_sandbox_input(source: str, *, filename: str = "uploaded.py", kind: str | None = None) -> dict[str, Any]:
    """Validate input without executing uploaded code."""
    if not isinstance(source, str) or not source.strip():
        raise SandboxInputError("source 必须是非空文本")
    name = _filename(filename)
    selected = _kind(name, kind)
    encoded = source.encode("utf-8")
    max_bytes = MAX_PYTHON_BYTES if selected == "python" else MAX_XML_BYTES
    if len(encoded) > max_bytes:
        raise SandboxInputError(f"{selected} 文件不能超过 {max_bytes // 1024} KiB")
    if selected == "python":
        _validate_python(source)
        model = {
            "root": None,
            "version": None,
            "obstacles": [dict(_DEFAULT_OBSTACLE)],
            "obstacle_count": 1,
            "model_count": 0,
        }
    else:
        model = _parse_xml(source, selected)
    return {"filename": name, "kind": selected, "bytes": len(encoded), "model": model}


def _docker_image_available() -> bool:
    docker = shutil.which("docker")
    image = os.getenv("GUARDIAN_SANDBOX_IMAGE", "").strip()
    if not docker or not image:
        return False
    try:
        info = subprocess.run([docker, "info"], capture_output=True, timeout=1.5, check=False)
        inspect = subprocess.run([docker, "image", "inspect", image], capture_output=True, timeout=1.5, check=False)
    except (OSError, subprocess.SubprocessError):
        return False
    return info.returncode == 0 and inspect.returncode == 0


def sandbox_runtime_status() -> dict[str, Any]:
    """Return the provider that can run the fixed controller harness."""
    if _docker_image_available():
        return {
            "provider": "docker",
            "available": True,
            "isolated": True,
            "network_disabled": True,
            "boundary": "容器隔离：非 root、只读根文件系统、无网络、丢弃能力、资源受限。",
        }
    unshare = shutil.which("unshare")
    if unshare:
        try:
            probe = subprocess.run(
                [unshare, "--user", "--map-root-user", "--mount", "--pid", "--fork", "--net", "true"],
                capture_output=True,
                timeout=1.5,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            probe = None
        if probe is not None and probe.returncode == 0:
            return {
                "provider": "unshare-userns",
                "available": True,
                "isolated": True,
                "network_disabled": True,
                "boundary": "WSL 用户/挂载/PID/网络命名空间；无完整 VM/rootfs 边界，适合本地工程测试，不是恶意多租户隔离。",
            }
    return {
        "provider": "none",
        "available": False,
        "isolated": False,
        "network_disabled": True,
        "reason": "Docker 镜像不可用且 Linux 用户命名空间不可用；为避免在 Dashboard 进程执行源码，本次运行已失败关闭。",
        "boundary": "未执行源码",
    }


def _runner_source() -> str:
    return textwrap.dedent(
        r"""
        import builtins as _builtins
        import contextlib
        import io
        import json
        import math
        import resource
        import sys
        import traceback

        resource.setrlimit(resource.RLIMIT_CPU, (4, 4))
        resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_FSIZE, (32 * 1024, 32 * 1024))
        resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
        resource.setrlimit(resource.RLIMIT_NPROC, (16, 16))

        source_path, config_path = sys.argv[1], sys.argv[2]
        source = open(source_path, "r", encoding="utf-8").read()
        config = json.load(open(config_path, "r", encoding="utf-8"))
        allowed_modules = {"math", "json"}
        original_import = _builtins.__import__

        def safe_import(name, globals=None, locals=None, fromlist=(), level=0):
            root = name.split(".", 1)[0]
            if root not in allowed_modules:
                raise ImportError("module is not available in the controller sandbox")
            return original_import(name, globals, locals, fromlist, level)

        names = (
            "abs", "all", "any", "bool", "dict", "enumerate", "float", "int",
            "isinstance", "len", "list", "max", "min", "print", "range",
            "round", "set", "sorted", "str", "sum", "tuple", "type", "zip",
        )
        safe_builtins = {name: getattr(_builtins, name) for name in names}
        safe_builtins["__import__"] = safe_import
        namespace = {"__name__": "guardian_controller", "__builtins__": safe_builtins}
        class LimitedOutput:
            def __init__(self, limit):
                self.limit = limit
                self.parts = []
                self.size = 0

            def write(self, value):
                text = str(value)
                remaining = max(0, self.limit - self.size)
                if remaining:
                    self.parts.append(text[:remaining])
                    self.size += min(len(text), remaining)
                return len(text)

            def flush(self):
                return None

            def getvalue(self):
                return "".join(self.parts)

        output = LimitedOutput(16384)
        result = {"ok": False, "trace": [], "logs": "", "error": None}

        try:
            exec(compile(source, config["filename"], "exec"), namespace, namespace)
            controller = namespace.get("control") or namespace.get("step")
            if not callable(controller):
                raise RuntimeError("control(state) or step(state) is required")
            dt = float(config["dt"])
            duration = float(config["duration"])
            obstacles = list(config.get("obstacles") or [])
            x = 0.0
            y = 0.0
            elapsed = 0.0
            safety_limit = float(config.get("safety_limit", 0.35))
            robot_radius = 0.25
            collision_steps = 0
            overspeed_steps = 0
            min_distance = None
            max_requested = 0.0
            max_applied = 0.0
            steps = int(math.ceil(duration / dt))

            for _ in range(steps):
                obstacle_distance = 999.0
                if obstacles:
                    obstacle_distance = min(
                        max(0.0, item["x"] - item["half_x"] - robot_radius - x)
                        for item in obstacles
                    )
                state = {
                    "t": round(elapsed, 4),
                    "x": round(x, 4),
                    "y": round(y, 4),
                    "distance_to_obstacle": round(obstacle_distance, 4),
                    "safety_limit": safety_limit,
                    "estop": False,
                    "mission_allowed": True,
                }
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                    command = controller(dict(state))
                if not isinstance(command, dict):
                    raise RuntimeError("controller must return a dict")
                requested = float(command.get("linear_x", 0.0))
                angular = float(command.get("angular_z", 0.0))
                if not math.isfinite(requested) or not math.isfinite(angular):
                    raise RuntimeError("controller returned a non-finite command")
                requested = max(-3.0, min(3.0, requested))
                applied = max(-safety_limit, min(safety_limit, requested))
                if abs(requested) > safety_limit + 1e-9:
                    overspeed_steps += 1
                max_requested = max(max_requested, abs(requested))
                max_applied = max(max_applied, abs(applied))
                x += applied * dt
                elapsed += dt
                distance_after = 999.0
                if obstacles:
                    distance_after = min(
                        max(0.0, item["x"] - item["half_x"] - robot_radius - x)
                        for item in obstacles
                    )
                collision = bool(obstacles and distance_after <= 1e-9)
                if collision:
                    collision_steps += 1
                min_distance = distance_after if min_distance is None else min(min_distance, distance_after)
                result["trace"].append({
                    "t": round(elapsed, 4),
                    "x": round(x, 4),
                    "y": round(y, 4),
                    "requested_speed": round(requested, 4),
                    "applied_speed": round(applied, 4),
                    "safety_limit": round(safety_limit, 4),
                    "distance_to_obstacle": round(distance_after, 4),
                    "collision": collision,
                })
                if collision:
                    break
            result["metrics"] = {
                "steps": len(result["trace"]),
                "duration_sec": round(elapsed, 4),
                "max_requested_speed": round(max_requested, 4),
                "max_applied_speed": round(max_applied, 4),
                "safety_limit": round(safety_limit, 4),
                "overspeed_steps": overspeed_steps,
                "collision_steps": collision_steps,
                "min_obstacle_distance": None if min_distance is None else round(min_distance, 4),
            }
            result["ok"] = True
        except BaseException as error:
            result["error"] = {
                "type": type(error).__name__,
                "message": str(error)[:240],
                "traceback": traceback.format_exc(limit=3)[-1200:],
            }
        result["logs"] = output.getvalue()[:16384]
        print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
        """
    )


def _run_python_isolated(source: str, filename: str, model: dict[str, Any], duration: float, runtime: dict[str, Any]) -> dict[str, Any]:
    provider = runtime["provider"]
    with tempfile.TemporaryDirectory(prefix="guardian-sandbox-") as directory:
        work = Path(directory)
        source_path = work / "controller.py"
        runner_path = work / "runner.py"
        config_path = work / "config.json"
        source_path.write_text(source, encoding="utf-8")
        runner_path.write_text(_runner_source(), encoding="utf-8")
        config_path.write_text(json.dumps({
            "filename": filename,
            "duration": duration,
            "dt": STEP_SEC,
            "safety_limit": 0.35,
            "obstacles": model.get("obstacles", []),
        }), encoding="utf-8")
        if provider == "docker":
            image = os.environ["GUARDIAN_SANDBOX_IMAGE"]
            command = [
                "docker", "run", "--rm", "--network=none", "--read-only",
                "--cap-drop=ALL", "--security-opt=no-new-privileges",
                "--pids-limit=32", "--memory=256m", "--cpus=0.5",
                "-v", f"{work}:/work:ro", "-w", "/work", image,
                "python3", "/work/runner.py", "/work/controller.py", "/work/config.json",
            ]
        else:
            command = [
                "unshare", "--user", "--map-root-user", "--mount", "--pid",
                "--fork", "--mount-proc", "--net", "--",
                "/usr/bin/python3", str(runner_path), str(source_path), str(config_path),
            ]
        try:
            completed = subprocess.run(
                command,
                cwd=directory,
                env={"PATH": os.getenv("PATH", "/usr/bin:/bin"), "HOME": directory, "LANG": "C.UTF-8"},
                capture_output=True,
                text=True,
                timeout=max(3.0, duration + 3.0),
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            return {"timed_out": True, "stdout": (error.stdout or "")[-MAX_LOG_BYTES:], "stderr": (error.stderr or "")[-MAX_LOG_BYTES:]}
        except OSError as error:
            return {"launch_error": str(error)[:240]}
        stdout = (completed.stdout or "")[-MAX_LOG_BYTES:]
        stderr = (completed.stderr or "")[-MAX_LOG_BYTES:]
        if completed.returncode != 0:
            return {"launch_error": f"隔离执行器退出码 {completed.returncode}", "stdout": stdout, "stderr": stderr}
        try:
            return json.loads(stdout.strip().splitlines()[-1])
        except (json.JSONDecodeError, IndexError):
            return {"launch_error": "隔离执行器没有返回有效的仿真报告", "stdout": stdout, "stderr": stderr}


def _gz_validation(source: str) -> dict[str, Any]:
    gz = shutil.which("gz")
    if not gz:
        return {"available": False, "checked": False, "passed": None, "message": "未发现 gz 命令"}
    with tempfile.NamedTemporaryFile("w", suffix=".sdf", encoding="utf-8", delete=False) as handle:
        handle.write(source)
        path = handle.name
    try:
        completed = subprocess.run(
            [gz, "sdf", "--check", path],
            capture_output=True,
            text=True,
            timeout=3.0,
            check=False,
        )
        message = (completed.stderr or completed.stdout or "").strip()[:500]
        return {"available": True, "checked": True, "passed": completed.returncode == 0, "message": message or "gz sdf 校验完成"}
    except (OSError, subprocess.SubprocessError) as error:
        return {"available": True, "checked": True, "passed": False, "message": str(error)[:500]}
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _builtin_trace(model: dict[str, Any], duration: float) -> dict[str, Any]:
    obstacles = list(model.get("obstacles") or [])
    x = 0.0
    elapsed = 0.0
    speed_limit = 0.35
    trace: list[dict[str, Any]] = []
    overspeed_steps = 0
    collision_steps = 0
    min_distance = None
    for _ in range(int(math.ceil(duration / STEP_SEC))):
        distance = min(
            (max(0.0, item["x"] - item["half_x"] - 0.25 - x) for item in obstacles),
            default=999.0,
        )
        requested = 0.22 if distance > 0.65 else 0.0
        applied = min(requested, speed_limit)
        x += applied * STEP_SEC
        elapsed += STEP_SEC
        distance_after = min(
            (max(0.0, item["x"] - item["half_x"] - 0.25 - x) for item in obstacles),
            default=999.0,
        )
        collision = bool(obstacles and distance_after <= 1e-9)
        collision_steps += int(collision)
        min_distance = distance_after if min_distance is None else min(min_distance, distance_after)
        trace.append({
            "t": round(elapsed, 4),
            "x": round(x, 4),
            "y": 0.0,
            "requested_speed": requested,
            "applied_speed": applied,
            "safety_limit": speed_limit,
            "distance_to_obstacle": round(distance_after, 4),
            "collision": collision,
        })
        if collision:
            break
    return {
        "trace": trace,
        "metrics": {
            "steps": len(trace),
            "duration_sec": round(elapsed, 4),
            "max_requested_speed": 0.22 if trace else 0.0,
            "max_applied_speed": 0.22 if trace else 0.0,
            "safety_limit": speed_limit,
            "overspeed_steps": overspeed_steps,
            "collision_steps": collision_steps,
            "min_obstacle_distance": None if min_distance is None else round(min_distance, 4),
        },
    }


def _risk_report(
    *,
    source: str,
    filename: str,
    kind: str,
    execution_mode: str,
    model: dict[str, Any],
    sandbox: dict[str, Any],
    trace: list[dict[str, Any]],
    metrics: dict[str, Any],
    runtime_error: dict[str, Any] | None = None,
    timed_out: bool = False,
    logs: str = "",
    validation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    events: list[dict[str, Any]] = []
    if runtime_error:
        events.append({
            "type": "RUNTIME_ERROR",
            "severity": "critical",
            "at": 0.0,
            "title": "控制器运行时异常",
            "evidence": runtime_error.get("message", "未知运行时异常"),
        })
    if timed_out:
        events.append({
            "type": "TIMEOUT",
            "severity": "critical",
            "at": round(_finite(metrics.get("duration_sec")), 3),
            "title": "控制器超过执行时限",
            "evidence": "沙箱已终止超时进程，未回退到宿主机执行。",
        })
    overspeed = int(metrics.get("overspeed_steps", 0) or 0)
    collision = int(metrics.get("collision_steps", 0) or 0)
    if overspeed:
        events.append({
            "type": "OVERSPEED_COMMAND",
            "severity": "high",
            "at": 0.0,
            "title": "控制器请求速度超过安全上限",
            "evidence": f"{overspeed} 个控制周期超过 {_finite(metrics.get('safety_limit'), 0.35):.2f} m/s；施加速度已被安全边界截断。",
        })
    if collision:
        events.append({
            "type": "COLLISION",
            "severity": "critical",
            "at": next((item["t"] for item in trace if item.get("collision")), 0.0),
            "title": "固定场景检测到碰撞",
            "evidence": f"障碍物净距达到 0，共 {collision} 个周期。",
        })
    minimum = metrics.get("min_obstacle_distance")
    if minimum is not None and not collision and _finite(minimum, 999.0) < 0.20:
        events.append({
            "type": "NEAR_COLLISION",
            "severity": "high",
            "at": trace[-1]["t"] if trace else 0.0,
            "title": "机器人进入近碰撞距离",
            "evidence": f"最小障碍净距 {_finite(minimum):.3f} m。",
        })
    if not trace and not runtime_error and not timed_out:
        events.append({
            "type": "NO_CONTROL_OUTPUT",
            "severity": "medium",
            "at": 0.0,
            "title": "没有产生控制轨迹",
            "evidence": "控制器没有完成任何有效控制周期。",
        })

    risk = 0
    if runtime_error or timed_out:
        risk = 100
    else:
        risk = max(risk, 95 if collision else 0)
        risk = max(risk, 65 if overspeed else 0)
        risk = max(risk, 55 if minimum is not None and _finite(minimum, 999.0) < 0.20 else 0)
        risk = max(risk, 35 if not trace else 0)
    risk = min(100, int(risk))
    verdict = "BLOCKED" if risk >= 90 else "REVIEW" if risk >= 50 else "PASS"
    summary = (
        "固定步长仿真中观察到碰撞或执行异常，当前控制器必须阻断。"
        if verdict == "BLOCKED"
        else "固定步长仿真中观察到超速或近碰撞证据，整改并人工复核后再测试。"
        if verdict == "REVIEW"
        else "当前固定场景未观察到碰撞、超速或执行异常，可进入更高保真仿真。"
    )
    return {
        "schema": SANDBOX_SCHEMA,
        "status": "COMPLETED" if not runtime_error and not timed_out else "FAILED",
        "filename": filename,
        "input_kind": kind,
        "execution_mode": execution_mode,
        "source_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
        "source_executed": kind == "python" and not runtime_error and bool(trace),
        "engine": "guardian-kinematic-v1",
        "engine_description": "固定步长二维运动模型；用于工程前筛查，不等同于 Gazebo 物理认证。",
        "model": {
            "obstacle_count": int(model.get("obstacle_count", 0)),
            "model_count": int(model.get("model_count", 0)),
            "xml_root": model.get("root"),
            "xml_version": model.get("version"),
        },
        "sandbox": sandbox,
        "metrics": metrics,
        "trace": trace[:MAX_TRACE_POINTS],
        "events": sorted(events, key=lambda item: (item["at"], _SEVERITY_ORDER.get(item["severity"], 9))),
        "logs": logs[:MAX_LOG_BYTES],
        "validation": validation or {},
        "verdict": verdict,
        "risk_score": risk,
        "safety_score": 100 - risk,
        "summary_zh": summary,
        "jev_context": {
            "kind": "sandbox_simulation_evidence",
            "input_kind": kind,
            "execution_mode": execution_mode,
            "engine": "guardian-kinematic-v1",
            "verdict": verdict,
            "risk_score": risk,
            "safety_score": 100 - risk,
            "metrics": metrics,
            "events": [
                {
                    "type": item["type"],
                    "severity": item["severity"],
                    "at": item["at"],
                    "evidence": item["evidence"],
                }
                for item in events[:16]
            ],
            "source_executed": kind == "python" and not runtime_error and bool(trace),
            "source_sent_to_jev": False,
        },
    }


def run_sandbox(
    source: str,
    *,
    filename: str = "uploaded.py",
    kind: str | None = None,
    duration_sec: float = 4.0,
) -> dict[str, Any]:
    """Run the bounded controller contract or the built-in XML controller."""
    inspected = inspect_sandbox_input(source, filename=filename, kind=kind)
    selected = inspected["kind"]
    duration = max(MIN_DURATION_SEC, min(MAX_DURATION_SEC, _finite(duration_sec, 4.0)))
    model = inspected["model"]
    if selected != "python":
        validation = _gz_validation(source) if selected == "sdf" else {"checked": False, "message": "URDF 作为模型数据解析，未加载外部插件"}
        builtin = _builtin_trace(model, duration)
        return _risk_report(
            source=source,
            filename=inspected["filename"],
            kind=selected,
            execution_mode="builtin_controller",
            model=model,
            sandbox={
                "provider": "not_applicable",
                "available": True,
                "isolated": False,
                "network_disabled": True,
                "boundary": "XML 只作为模型数据解析；未执行 XML 中的插件或外部引用。",
            },
            trace=builtin["trace"],
            metrics=builtin["metrics"],
            validation=validation,
        )

    runtime = sandbox_runtime_status()
    if not runtime["available"]:
        metrics = {
            "steps": 0,
            "duration_sec": 0.0,
            "max_requested_speed": 0.0,
            "max_applied_speed": 0.0,
            "safety_limit": 0.35,
            "overspeed_steps": 0,
            "collision_steps": 0,
            "min_obstacle_distance": None,
        }
        report = _risk_report(
            source=source,
            filename=inspected["filename"],
            kind=selected,
            execution_mode="isolated_controller_contract",
            model=model,
            sandbox=runtime,
            trace=[],
            metrics=metrics,
            runtime_error={"message": runtime["reason"]},
        )
        report["status"] = "UNAVAILABLE"
        report["source_executed"] = False
        report["verdict"] = "BLOCKED"
        report["risk_score"] = 100
        report["safety_score"] = 0
        report["summary_zh"] = "隔离执行器不可用，系统没有在 Dashboard 进程中执行上传代码。"
        return report

    child = _run_python_isolated(source, inspected["filename"], model, duration, runtime)
    metrics = child.get("metrics") if isinstance(child.get("metrics"), dict) else {
        "steps": 0,
        "duration_sec": 0.0,
        "max_requested_speed": 0.0,
        "max_applied_speed": 0.0,
        "safety_limit": 0.35,
        "overspeed_steps": 0,
        "collision_steps": 0,
        "min_obstacle_distance": None,
    }
    timed_out = bool(child.get("timed_out"))
    runtime_error = child.get("error") if isinstance(child.get("error"), dict) else None
    if child.get("launch_error"):
        runtime_error = {"message": child["launch_error"]}
    return _risk_report(
        source=source,
        filename=inspected["filename"],
        kind=selected,
        execution_mode="isolated_controller_contract",
        model=model,
        sandbox=runtime,
        trace=child.get("trace") if isinstance(child.get("trace"), list) else [],
        metrics=metrics,
        runtime_error=runtime_error,
        timed_out=timed_out,
        logs=str(child.get("logs") or child.get("stderr") or ""),
    )


def sample_catalog() -> list[dict[str, Any]]:
    safe = """\
import math

def control(state):
    if state["estop"] or not state["mission_allowed"]:
        return {"linear_x": 0.0, "angular_z": 0.0}
    if state["distance_to_obstacle"] < 0.65:
        return {"linear_x": 0.0, "angular_z": 0.0}
    return {"linear_x": min(0.25, state["safety_limit"]), "angular_z": 0.0}
"""
    unsafe = """\
def control(state):
    # Intentionally unsafe: ignores the safety envelope and obstacle distance.
    return {"linear_x": 1.4, "angular_z": 0.0}
"""
    sdf = """\
<?xml version="1.0"?>
<sdf version="1.9">
  <world name="warehouse_sandbox">
    <model name="pallet_rack">
      <pose>1.25 0 0.5 0 0 0</pose>
      <link name="rack_link">
        <collision name="rack_collision">
          <geometry><box><size>0.5 1.0 1.0</size></box></geometry>
        </collision>
      </link>
    </model>
  </world>
</sdf>
"""
    return [
        {
            "id": "safe_controller",
            "title": "安全 AMR 控制器（可运行 Python）",
            "kind": "python",
            "filename": "safe_controller.py",
            "description": "按障碍净距停车，并遵守 0.35 m/s 安全上限。",
            "source": safe,
        },
        {
            "id": "unsafe_controller",
            "title": "危险 AMR 控制器（可运行 Python）",
            "kind": "python",
            "filename": "unsafe_controller.py",
            "description": "持续请求 1.4 m/s，忽略障碍距离；用于观察超速与碰撞证据。",
            "source": unsafe,
        },
        {
            "id": "warehouse_obstacle_sdf",
            "title": "仓储货架障碍场景（SDF 模型）",
            "kind": "sdf",
            "filename": "warehouse_obstacle.sdf",
            "description": "SDF 只做模型解析和 Gazebo SDF 校验，使用内置安全控制器运行固定步长实验。",
            "source": sdf,
        },
    ]


__all__ = [
    "SANDBOX_SCHEMA",
    "SandboxInputError",
    "inspect_sandbox_input",
    "run_sandbox",
    "sandbox_runtime_status",
    "sample_catalog",
]
