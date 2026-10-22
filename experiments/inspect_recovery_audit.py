"""Bounded JSON/JSONL audit import using the existing read-only trace checker."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ros2_ws/src/guardian_core"))
from guardian_core.dashboard_recovery import MAX_TRACE_BYTES, inspect_recovery_trace

SOURCE_KINDS = ("user_supplied", "self_ros_dds")


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def reject_constant(value):
    raise ValueError(f"nonfinite JSON constant: {value}")


def decode_json(value):
    return json.loads(value, object_pairs_hook=unique_object, parse_constant=reject_constant)


def inspect_audit(path, *, source_kind="user_supplied", expected_sha256=None):
    if source_kind not in SOURCE_KINDS:
        raise ValueError("unsupported source kind")
    path = Path(path).resolve()
    with path.open("rb") as stream:
        raw = stream.read(MAX_TRACE_BYTES + 1)
    if len(raw) > MAX_TRACE_BYTES:
        raise ValueError("audit size exceeds bounded input limit")
    digest = hashlib.sha256(raw).hexdigest()
    if expected_sha256 is not None and (
            not isinstance(expected_sha256, str)
            or not re.fullmatch("[0-9a-fA-F]{64}", expected_sha256)
            or digest != expected_sha256.lower()):
        raise ValueError("audit SHA256 identity mismatch")
    text = raw.decode("utf-8")
    try:
        value = decode_json(text)
    except json.JSONDecodeError:
        value = [decode_json(line) for line in text.splitlines() if line.strip()]
        input_format = "jsonl"
    else:
        input_format = "json"
    if isinstance(value, dict) and "frames" in value:
        frames, ignored, rows = value["frames"], 0, len(value["frames"]) if isinstance(value["frames"], list) else 0
    else:
        if isinstance(value, dict):
            value = [value]
        if not isinstance(value, list):
            raise ValueError("audit must be a frame array, trace envelope or JSONL objects")
        rows, ignored = len(value), 0
        if input_format == "jsonl" or any(isinstance(row, dict) and "kind" in row for row in value):
            frames = []
            for row in value:
                if not isinstance(row, dict) or not isinstance(row.get("kind"), str):
                    raise ValueError("JSONL audit row requires a kind")
                if row["kind"] == "recovery_trace":
                    frames.append({key: item for key, item in row.items() if key != "kind"})
                else:
                    ignored += 1
        else:
            frames = value
    analysis = inspect_recovery_trace({"frames": frames})
    return {"schema": "guardian-recovery-audit-inspection/v1",
        "source": {"path": str(path), "kind": source_kind, "format": input_format,
            "sha256": digest, "bytes": len(raw), "rows": rows, "ignored_rows": ignored,
            "authenticated": False},
        "analysis": analysis, "physical_safety_validated": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--source-kind", choices=SOURCE_KINDS, default="user_supplied")
    parser.add_argument("--expected-sha256")
    args = parser.parse_args()
    try:
        report = inspect_audit(args.input, source_kind=args.source_kind,
            expected_sha256=args.expected_sha256)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, ensure_ascii=False, allow_nan=False, indent=2)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps({"verdict": report["analysis"]["verdict"],
        "frames": report["analysis"]["frame_count"], "sha256": report["source"]["sha256"],
        "output": str(args.output)}, ensure_ascii=False))
    return int(bool(report["analysis"]["violation_count"]))


if __name__ == "__main__":
    raise SystemExit(main())
