"""Private fixed Linux entrypoint; never accepts source, modules, or paths."""
from __future__ import annotations

import errno
import json
import os
from pathlib import Path
import resource
import socket
import sys


ROOT = Path(__file__).resolve().parents[2]
# Startup paths are calculated only from this installed entrypoint. -I ignores
# PYTHONPATH and the temporary working directory is never added to import paths.
sys.path[:0] = [str(ROOT), str(ROOT / "ros2_ws/src/guardian_core")]

from experiments.agent_review.catalog import require_test_id, run_case
from experiments.agent_review.runner import _load_json, _source_manifest


def _isolate():
    if sys.platform != "linux":
        raise RuntimeError("Linux seccomp isolation is required")
    import pyseccomp

    limits = ((resource.RLIMIT_CPU, 1), (resource.RLIMIT_AS, 256 * 1024 * 1024),
        (resource.RLIMIT_FSIZE, 2 * 1024 * 1024), (resource.RLIMIT_NOFILE, 32),
        (resource.RLIMIT_NPROC, 0), (resource.RLIMIT_CORE, 0))
    for kind, maximum in limits:
        resource.setrlimit(kind, (maximum, maximum))
    denied = ("socket", "socketpair", "socketcall", "connect", "bind", "listen", "accept", "accept4",
        "sendto", "sendmsg", "sendmmsg", "recvfrom", "recvmsg", "recvmmsg", "shutdown",
        "setsockopt", "getsockopt", "getpeername", "getsockname", "io_uring_setup",
        "io_uring_enter", "io_uring_register", "fork", "vfork", "clone", "clone3", "execve",
        "execveat", "setsid", "setpgid")
    policy = pyseccomp.SyscallFilter(pyseccomp.ALLOW)
    applied = []
    for name in denied:
        number = pyseccomp.resolve_syscall(pyseccomp.Arch.NATIVE, name)
        if number != -1:
            policy.add_rule(pyseccomp.ERRNO(errno.EPERM), name)
            applied.append(name)
    if "socket" not in applied or "execve" not in applied or "clone" not in applied:
        raise RuntimeError("required seccomp rules are unavailable")
    policy.load()
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except OSError as exc:
        socket_errno = exc.errno
        if socket_errno not in (errno.EPERM, errno.EACCES):
            raise RuntimeError("network denial was not verified") from exc
    else:
        probe.close()
        raise RuntimeError("network denial was not established")
    allowed_names = {"PATH", "LANG", "LC_ALL", "TMPDIR"}
    if set(os.environ) - allowed_names:
        raise RuntimeError("unexpected inherited environment")
    temporary = Path.cwd() == Path(os.environ["TMPDIR"]) and Path.cwd() != ROOT
    if not temporary:
        raise RuntimeError("temporary working directory is required")
    return {"mode": "linux_seccomp_fixed_worker", "network_denied": True,
        "socket_errno": socket_errno, "credentials_absent": True,
        "environment_names": sorted(os.environ), "cwd_is_temporary": temporary,
        "limits_applied": True, "denied_syscalls": applied,
        "scope": "fixed repository scenarios; no arbitrary or hostile code execution"}


def main():
    manifest = _source_manifest()
    test_id = None
    try:
        raw = sys.stdin.buffer.read(1025)
        if len(raw) > 1024:
            raise ValueError("request exceeds limit")
        request = _load_json(raw.decode("utf-8"))
        if type(request) is not dict or set(request) != {"test_id"}:
            raise ValueError("invalid request schema")
        test_id = require_test_id(request["test_id"])
        isolation = _isolate()
    except Exception as exc:
        print(json.dumps({"test_id": test_id, "status": "UNAVAILABLE",
            "detail": f"isolation or request unavailable: {type(exc).__name__}", "frames": [],
            "witnesses": {}, "validity": "ERROR", "assertion_result": "NOT_EVALUATED",
            "assertion_failures": [], "source_manifest": manifest,
            "isolation": {"mode": "unavailable"}}, allow_nan=False))
        return 1
    result = run_case(test_id)
    result.update(status="COMPLETE", source_manifest=manifest, isolation=isolation, worker_pid=os.getpid())
    print(json.dumps(result, allow_nan=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
