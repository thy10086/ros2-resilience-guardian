"""Audit identity and verdicts must survive a real JSONL import."""
import hashlib
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "experiments"))
from guardian_core.dashboard_recovery import MAX_TRACE_BYTES
from guardian_core.recovery_feedback import RecoveryFrame


def parked_frames():
    return [RecoveryFrame(i * .05, "stabilize", "SAFE_STOP", "healthy", True,
        False, False, "g", "p", "l", 1, 1, False, 0, 0).to_dict()
        for i in range(65)]


@pytest.fixture
def ros_installation():
    packages = pytest.importorskip("ament_index_python.packages")
    try:
        packages.get_package_prefix("guardian_core")
    except packages.PackageNotFoundError:
        pytest.skip("ROS capture requires the installed guardian_core package")


def test_mixed_audit_reuses_oracle_and_hashes_exact_bytes(tmp_path):
    from inspect_recovery_audit import inspect_audit
    path = tmp_path / "audit.jsonl"
    rows = [{"kind": "risk", "source_authenticated": True}]
    rows += [{"kind": "recovery_trace", **f} for f in parked_frames()]
    raw = "\n".join(json.dumps(row) for row in rows).encode() + b"\n"
    path.write_bytes(raw)
    report = inspect_audit(path, source_kind="self_ros_dds")
    assert report["analysis"]["violation_codes"] == ["recovery_stalled"]
    assert report["analysis"]["frame_count"] == 65
    assert report["source"]["sha256"] == hashlib.sha256(raw).hexdigest()
    assert report["source"]["ignored_rows"] == 1
    assert not report["source"]["authenticated"]
    assert not report["physical_safety_validated"]
    assert report["analysis"]["actuation"] == "none"


def test_trace_envelope_cannot_supply_its_own_trust_claim(tmp_path):
    from inspect_recovery_audit import inspect_audit
    path = tmp_path / "trace.json"
    path.write_text(json.dumps({"frames": parked_frames(),
        "physical_safety_validated": True, "source_authenticated": True}))
    result = inspect_audit(path)
    assert not result["physical_safety_validated"]
    assert not result["source"]["authenticated"]
    assert result["analysis"]["violation_codes"] == ["recovery_stalled"]


@pytest.mark.parametrize("raw", [
    b'{"kind":"risk"}\nnot-json\n',
    b'{"kind":"risk","kind":"recovery_trace"}\n',
    b'{"frames":[{"now":NaN}]}',
    b'{"kind":"risk"}\n',
])
def test_malformed_or_empty_trace_is_not_silently_accepted(tmp_path, raw):
    from inspect_recovery_audit import inspect_audit
    path = tmp_path / "bad.jsonl"
    path.write_bytes(raw)
    with pytest.raises(ValueError):
        inspect_audit(path)


def test_bounded_read_and_expected_identity_are_enforced(tmp_path):
    from inspect_recovery_audit import inspect_audit
    path = tmp_path / "audit.json"
    path.write_text(json.dumps(parked_frames()))
    with pytest.raises(ValueError, match="SHA"):
        inspect_audit(path, expected_sha256="0" * 64)
    path.write_bytes(b" " * (MAX_TRACE_BYTES + 1))
    with pytest.raises(ValueError, match="size"):
        inspect_audit(path)


def test_capture_retains_exact_audit_and_verified_source_snapshots(tmp_path, ros_installation):
    from recovery_ros_artifacts import begin_capture, retain_capture
    directory = begin_capture(ROOT, tmp_path / "new", domain="190")
    raw_path = tmp_path / "live.jsonl"
    raw_path.write_text(json.dumps({"frames": parked_frames()[:3]}))
    report = retain_capture(directory, raw_path)
    assert (directory / "audit.jsonl").read_bytes() == raw_path.read_bytes()
    assert report["source_freeze_verified"]
    assert report["analysis"]["frame_count"] == 3
    protocol = json.loads((directory / "capture_protocol.json").read_text())
    assert protocol["domain"] == "190"
    assert not protocol["external_dataset"] and not protocol["physical_safety_validated"]
    assert all(Path(value).is_file() for value in protocol["source_snapshots"].values())
    assert set(protocol["runtime"]["entrypoints"]) == {"guardian_node", "amr_simulator", "recovery_observer"}
    for source, digest in protocol["runtime"]["source_sha256"].items():
        assert Path(source).is_file()
        assert digest in protocol["source_sha256"].values()


def test_capture_rejects_overwrite_and_modified_snapshot(tmp_path, ros_installation):
    from recovery_ros_artifacts import begin_capture, retain_capture
    with pytest.raises(FileExistsError):
        begin_capture(ROOT, tmp_path, domain="190")
    directory = begin_capture(ROOT, tmp_path / "new", domain="190")
    protocol = json.loads((directory / "capture_protocol.json").read_text())
    Path(next(iter(protocol["source_snapshots"].values()))).write_text("changed")
    raw_path = tmp_path / "live.jsonl"
    raw_path.write_text(json.dumps({"frames": parked_frames()[:3]}))
    with pytest.raises(ValueError, match="source"):
        retain_capture(directory, raw_path)


def test_clock_order_is_checked_without_sorting_input(tmp_path):
    from inspect_recovery_audit import inspect_audit
    frames = parked_frames()[:2]
    frames.reverse()
    path = tmp_path / "trace.json"
    path.write_text(json.dumps(frames))
    assert "invalid_clock" in inspect_audit(path)["analysis"]["violation_codes"]


def test_cli_cannot_overwrite_saved_report(tmp_path, monkeypatch):
    from inspect_recovery_audit import main
    source, output = tmp_path / "input.json", tmp_path / "report.json"
    source.write_text(json.dumps(parked_frames()[:2]))
    output.write_text("previous report")
    monkeypatch.setattr(sys, "argv", ["inspect", "--input", str(source), "--output", str(output)])
    with pytest.raises(SystemExit) as error:
        main()
    assert error.value.code == 2
    assert output.read_text() == "previous report"


def test_rotated_audit_is_preserved_but_not_claimed_complete(tmp_path, ros_installation):
    from recovery_ros_artifacts import begin_capture, retain_capture
    directory = begin_capture(ROOT, tmp_path / "new", domain="190")
    raw_path = tmp_path / "live.jsonl"
    raw_path.write_text(json.dumps({"frames": parked_frames()[:2]}))
    older = raw_path.with_name(raw_path.name + ".1")
    older.write_text("older audit bytes")
    with pytest.raises(ValueError, match="rotated"):
        retain_capture(directory, raw_path)
    assert (directory / "audit.jsonl.1").read_bytes() == older.read_bytes()
    assert not (directory / "inspection.json").exists()
