"""Run only fixed registered scenarios in a bounded Linux worker process."""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile
import time

from .catalog import require_test_id


ROOT = Path(__file__).resolve().parents[2]
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_FRAMES = 2000
_SOURCES = (
    "experiments/agent_review/catalog.py", "experiments/agent_review/worker.py",
    "experiments/agent_review/runner.py", "experiments/recovery_scenarios.py",
    "ros2_ws/src/guardian_core/guardian_core/bound_recovery.py",
    "ros2_ws/src/guardian_core/guardian_core/recovery_protocol.py",
    "ros2_ws/src/guardian_core/guardian_core/recovery_feedback.py",
    "ros2_ws/src/guardian_core/guardian_core/independent_observation.py",
    "ros2_ws/src/guardian_core/guardian_core/evidence_ledger.py",
    "ros2_ws/src/guardian_core/guardian_core/predictive_envelope.py",
)


def _source_manifest():
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in _SOURCES}


def _cancelled(cancel):
    if cancel is None:
        return False
    if hasattr(cancel, "is_set"):
        return bool(cancel.is_set())
    if callable(cancel):
        return bool(cancel())
    raise TypeError("cancel must be an event or callable")


def _collect_process(proc, *, timeout_sec, cancel):
    """Bound both pipes while supervising a process already started by its owner.

    Production workers cannot fork, exec, or leave their supervisor's process
    group after seccomp setup. Killing and waiting this PID handles local test
    deadlines; the outer coordinator can kill its whole group on run cancellation.
    """
    deadline = time.monotonic() + timeout_sec
    output = {"stdout": bytearray(), "stderr": bytearray()}
    selector = selectors.DefaultSelector()
    status = "COMPLETE"
    try:
        for name in output:
            stream = getattr(proc, name)
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        while selector.get_map() or proc.poll() is None:
            if _cancelled(cancel):
                status = "CANCELLED"
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                status = "TIMEOUT"
                break
            for key, _ in selector.select(min(.02, remaining)):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                available = MAX_OUTPUT_BYTES - sum(len(value) for value in output.values())
                output[key.data].extend(chunk[:available])
                if len(chunk) > available:
                    status = "OUTPUT_LIMIT"
                    break
            if status != "COMPLETE":
                break
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait()
        selector.close()
        for name in output:
            getattr(proc, name).close()
    return {"status": status, "returncode": proc.returncode,
        **{name: bytes(value) for name, value in output.items()}}


def _load_json(text):
    def unique_pairs(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate JSON key")
            value[key] = item
        return value

    def invalid_constant(value):
        raise ValueError("non-finite JSON number")

    return json.loads(text, object_pairs_hook=unique_pairs, parse_constant=invalid_constant)


def _failure(test_id, status, detail, manifest=None):
    return {"test_id": test_id, "status": status, "detail": detail,
        "frames": [], "witnesses": {}, "validity": "ERROR",
        "assertion_result": "NOT_EVALUATED", "assertion_failures": [],
        "source_manifest": manifest or {}, "isolation": {"mode": "unavailable"}}


def run_registered_test(test_id, *, timeout_sec=2.0, cancel=None):
    require_test_id(test_id)
    if (type(timeout_sec) not in (int, float) or not math.isfinite(timeout_sec)
            or not 0 < timeout_sec <= 2.):
        raise ValueError("timeout_sec must be finite and in (0, 2]")
    started = time.monotonic()
    if _cancelled(cancel):
        return _failure(test_id, "CANCELLED", "cancelled before dispatch")
    if sys.platform != "linux":
        return _failure(test_id, "UNAVAILABLE", "Linux seccomp isolation is required")
    try:
        manifest = _source_manifest()
    except OSError:
        return _failure(test_id, "UNAVAILABLE", "required source snapshot is unavailable")
    if time.monotonic() - started >= timeout_sec:
        return _failure(test_id, "TIMEOUT", "deadline reached before dispatch", manifest)
    try:
        with tempfile.TemporaryDirectory(prefix="guardian-agent-review-") as directory:
            # Neither inherited environment values nor external import paths are used.
            environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8", "TMPDIR": directory}
            argv = [sys.executable, "-I", "-B", str(ROOT / "experiments/agent_review/worker.py")]
            proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, cwd=directory, env=environment, close_fds=True)
            try:
                proc.stdin.write(json.dumps({"test_id": test_id}).encode("utf-8"))
                proc.stdin.close()
                collected = _collect_process(proc,
                    timeout_sec=max(0., timeout_sec - (time.monotonic() - started)), cancel=cancel)
            finally:
                if proc.poll() is None:
                    proc.kill()
                proc.wait()
    except OSError as exc:
        return _failure(test_id, "UNAVAILABLE", f"worker startup failed: {type(exc).__name__}", manifest)
    if collected["status"] != "COMPLETE":
        return _failure(test_id, collected["status"], "worker terminated and reaped", manifest)
    if _cancelled(cancel):
        return _failure(test_id, "CANCELLED", "cancelled before result acceptance", manifest)
    try:
        unchanged = _source_manifest() == manifest
    except OSError:
        unchanged = False
    if not unchanged:
        return _failure(test_id, "STALE_CONTEXT", "source changed during execution", manifest)
    try:
        result = _load_json(collected["stdout"].decode("utf-8"))
        if (type(result) is not dict or result.get("test_id") != test_id
                or result.get("source_manifest") != manifest):
            raise ValueError("worker identity or source binding mismatch")
        if result.get("status") == "UNAVAILABLE":
            return result
        if collected["returncode"] != 0 or result.get("status") != "COMPLETE":
            raise ValueError("worker failed")
        if type(result.get("frames")) is not list or len(result["frames"]) > MAX_FRAMES:
            raise ValueError("invalid frame count")
        # Parent-side validation uses the actual raw frames, never the worker's
        # claim that an assertion passed. The outer review also runs SafetyOracle.
        from .catalog import validate_case
        validated = validate_case(test_id, result["frames"], result["witnesses"]["events"])
        if any(result.get(name) != value for name, value in validated.items()):
            raise ValueError("worker assertion mismatch")
        return result
    except (ValueError, UnicodeError, TypeError, KeyError) as exc:
        return _failure(test_id, "ERROR", f"invalid worker result: {type(exc).__name__}", manifest)
