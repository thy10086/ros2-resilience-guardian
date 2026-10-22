"""Optional durable evidence for the existing launch_testing DDS acceptance."""
import hashlib
import json
from pathlib import Path
import shlex
import subprocess

from inspect_recovery_audit import inspect_audit

CORE = "ros2_ws/src/guardian_core/guardian_core"
SOURCES = [f"{CORE}/{name}.py" for name in ("guardian_node", "bound_recovery",
    "recovery_protocol", "recovery_feedback", "independent_observation", "amr_simulator",
    "recovery_observer", "audit")]
SOURCES.extend(("experiments/independent_observation_launch_test.py",
    "experiments/recovery_ros_artifacts.py", "experiments/inspect_recovery_audit.py",
    f"{CORE}/dashboard_recovery.py"))


def resolve_runtime(root, frozen):
    from ament_index_python.packages import get_package_prefix
    prefix = Path(get_package_prefix("guardian_core"))
    names = [Path(name).stem for name in SOURCES if name.startswith(CORE + "/")]
    entries, entry_hashes, resolved, interpreter = {}, {}, {}, None
    for name in ("guardian_node", "amr_simulator", "recovery_observer"):
        entry = prefix / "lib/guardian_core" / name
        command = shlex.split(entry.read_text(encoding="utf-8").splitlines()[0].removeprefix("#!"))
        key = (tuple(command), str(entry.parent))
        entries[name] = str(entry)
        entry_hashes[str(entry)] = hashlib.sha256(entry.read_bytes()).hexdigest()
        if key == interpreter:
            continue
        script = ("import importlib.util,json,sys; sys.path[0]=sys.argv[1]; "
            "print(json.dumps({name:importlib.util.find_spec('guardian_core.'+name).origin "
            "for name in json.loads(sys.argv[2])}))")
        actual = json.loads(subprocess.check_output([*command, "-c", script,
            str(entry.parent), json.dumps(names)], cwd=root, text=True, timeout=10))
        for module, origin in actual.items():
            path = Path(origin).resolve()
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            expected = str(root / CORE / (module + ".py"))
            if digest != frozen[expected]:
                raise ValueError(f"installed ROS source differs from workspace: {module}")
            resolved[str(path)] = digest
        interpreter = key
    return {"package_prefix": str(prefix), "entrypoints": entries,
        "entrypoint_sha256": entry_hashes, "source_sha256": resolved,
        "resolution": "entrypoint interpreter and inherited environment before launch"}


def begin_capture(root, directory, *, domain):
    root, directory = Path(root).resolve(), Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=False)
    hashes, snapshots = {}, {}
    for name in SOURCES:
        source = root / name
        raw = source.read_bytes()
        snapshot = directory / "source_snapshot" / name
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        snapshot.write_bytes(raw)
        hashes[str(source)] = hashlib.sha256(raw).hexdigest()
        snapshots[str(source)] = str(snapshot)
    protocol = {"schema": "guardian-ros-audit-capture/v1", "domain": str(domain),
        "localhost_only": True, "process_count": 3, "source_sha256": hashes,
        "source_snapshots": snapshots, "external_dataset": False,
        "physical_safety_validated": False, "sensor_source": "software AMR model",
        "capture_boundary": "all launch children stopped before final audit snapshot",
        "runtime": resolve_runtime(root, hashes)}
    (directory / "capture_protocol.json").write_text(json.dumps(protocol, indent=2), encoding="utf-8")
    return directory


def retain_capture(directory, audit_path):
    directory = Path(directory)
    # Preserve evidence before checking it, including evidence from failed runs.
    raw = Path(audit_path).read_bytes()
    destination = directory / "audit.jsonl"
    with destination.open("xb") as stream:
        stream.write(raw)
    rotations = [Path(audit_path).with_name(Path(audit_path).name + f".{index}")
        for index in range(1, 4)]
    present = [path for path in rotations if path.is_file()]
    for path in present:
        with (directory / ("audit.jsonl" + path.suffix)).open("xb") as stream:
            stream.write(path.read_bytes())
    if present:
        raise ValueError("rotated audit cannot establish one complete bounded trace")
    protocol = json.loads((directory / "capture_protocol.json").read_text(encoding="utf-8"))
    for source, digest in protocol["source_sha256"].items():
        snapshot = protocol["source_snapshots"][source]
        if any(hashlib.sha256(Path(name).read_bytes()).hexdigest() != digest for name in (source, snapshot)):
            raise ValueError(f"ROS capture source changed: {source}")
    for source, digest in {**protocol["runtime"]["source_sha256"],
            **protocol["runtime"]["entrypoint_sha256"]}.items():
        if hashlib.sha256(Path(source).read_bytes()).hexdigest() != digest:
            raise ValueError(f"installed ROS source changed: {source}")
    report = inspect_audit(destination, source_kind="self_ros_dds",
        expected_sha256=hashlib.sha256(raw).hexdigest())
    report["source_freeze_verified"] = True
    report["runtime_freeze_verified"] = True
    report["capture_protocol"] = str(directory / "capture_protocol.json")
    report["acceptance_report"] = str(directory / "acceptance.json") if (directory / "acceptance.json").is_file() else None
    with (directory / "inspection.json").open("x", encoding="utf-8") as stream:
        json.dump(report, stream, ensure_ascii=False, allow_nan=False, indent=2)
    return report
