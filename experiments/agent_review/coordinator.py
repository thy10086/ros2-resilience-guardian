"""Fixed, supervised offline coordinator entry. Not a general code runner."""
import errno
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / "ros2_ws/src/guardian_core")]


def main():
    # Restrict network even in the orchestrator. Worker adds stronger process and
    # resource restrictions. Fail closed if the kernel/binding is unavailable.
    import pyseccomp as seccomp
    policy = seccomp.SyscallFilter(defaction=seccomp.ALLOW)
    for syscall in ("socket", "socketpair", "connect", "bind", "listen", "accept", "accept4", "sendto", "sendmsg", "recvfrom", "recvmsg", "io_uring_setup"):
        policy.add_rule(seccomp.ERRNO(errno.EPERM), syscall)
    policy.load()
    from experiments.agent_review.contracts import strict_loads
    from experiments.agent_review.orchestration import _run_graph
    raw = sys.stdin.buffer.read(2 * 1024 * 1024 + 128 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024 + 128 * 1024:
        raise ValueError("input limit exceeded")
    data = strict_loads(raw.decode())
    def emit(record):
        print(json.dumps(record, ensure_ascii=False, allow_nan=False, separators=(",", ":")), flush=True)
    # This inherited pipe carries only role JSON, never the API Key. Network
    # syscalls remain denied in this process and all registered test workers.
    response_pipe = open(int(sys.argv[1]), "rb", buffering=0)
    def complete(role, context):
        emit({"kind": "provider_request", "role": role, "context": context})
        raw = response_pipe.readline(64 * 1024 + 1)
        if len(raw) > 64 * 1024 or not raw.endswith(b"\n"):
            raise ValueError("invalid provider broker reply")
        reply = strict_loads(raw.decode())
        if reply.get("ok") is not True:
            raise ValueError("模型接口不可用、拒绝或输出无效；未回退脚本模式")
        return reply["output"]
    report = _run_graph(data["payload"], data["fixture"], data["timeout_sec"], emit,
                        complete=complete if data.get("mode") == "llm" else None)
    emit({"kind": "final", "report": report})


if __name__ == "__main__":
    main()
