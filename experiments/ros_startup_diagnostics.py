"""ROS test startup diagnostics with explicitly allowlisted environment fields."""
from pathlib import Path
import time

ENV_FIELDS = {"ROS_DOMAIN_ID", "ROS_LOCALHOST_ONLY", "RMW_IMPLEMENTATION", "FASTRTPS_DEFAULT_PROFILES_FILE"}


def read_process_environment(pid, *, proc_root=Path("/proc")):
    try:
        entries = (proc_root / str(pid) / "environ").read_bytes().split(b"\0")
    except OSError:
        return {}
    result = {}
    for entry in entries:
        key, separator, value = entry.partition(b"=")
        name = key.decode("utf-8", errors="replace")
        if separator and name in ENV_FIELDS:
            result[name] = value.decode("utf-8", errors="replace")
    return result


class StartupDiagnostics:
    def __init__(self, expected_domain, *, started_at=None):
        self.expected_domain = int(expected_domain)
        self.started_at = time.monotonic() if started_at is None else started_at
        self.first_seen = {}

    def mark(self, name, *, now=None):
        self.first_seen.setdefault(name, round((time.monotonic() if now is None else now) - self.started_at, 4))

    def snapshot(self, node, process_ids):
        domain = node.context.get_domain_id()
        return {"expected_domain": self.expected_domain, "probe_domain": domain,
            "domain_match": domain == self.expected_domain,
            "first_seen_sec": dict(self.first_seen),
            "node_count": len(node.get_node_names_and_namespaces()),
            "topics": sorted(name for name, _ in node.get_topic_names_and_types()),
            "processes": [{"pid": pid, "environment": read_process_environment(pid)} for pid in process_ids]}
