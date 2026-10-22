from pathlib import Path
import sys
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "experiments"))
from ros_startup_diagnostics import StartupDiagnostics, read_process_environment


def test_process_environment_is_allowlisted(tmp_path):
    directory = tmp_path / "42"
    directory.mkdir()
    (directory / "environ").write_bytes(b"ROS_DOMAIN_ID=180\0GUARDIAN_FEEDBACK_SECRET=hidden\0ROS_LOCALHOST_ONLY=1\0OTHER=hidden\0")
    assert read_process_environment(42, proc_root=tmp_path) == {
        "ROS_DOMAIN_ID": "180", "ROS_LOCALHOST_ONLY": "1"}
    assert read_process_environment(999, proc_root=tmp_path) == {}


def test_readiness_records_first_occurrence_and_domain_mismatch():
    diagnostics = StartupDiagnostics("180", started_at=10.0)
    diagnostics.mark("safety_status", now=11.0)
    diagnostics.mark("safety_status", now=12.0)
    node = SimpleNamespace(context=SimpleNamespace(get_domain_id=lambda: 181),
        get_node_names_and_namespaces=lambda: [("probe", "/")],
        get_topic_names_and_types=lambda: [("guardian/safety_status", ["type"])])
    report = diagnostics.snapshot(node, [])
    assert report["first_seen_sec"]["safety_status"] == 1.0
    assert report["domain_match"] is False
    assert report["node_count"] == 1
