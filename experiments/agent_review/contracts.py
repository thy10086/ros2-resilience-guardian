"""Strict data contracts for the offline Guardian model review.

Source text and submitted frames are data. Neither their contents nor a model
response can select executable code, authenticate a source, or change roles.
"""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re
from uuid import uuid4

from guardian_core.dashboard_recovery import MAX_TRACE_BYTES, inspect_recovery_trace
from guardian_core.ros_graph_security import inspect_project


REPO_ROOT = Path(__file__).resolve().parents[2]
TEST_IDS = ("healthy_resume", "ttl_gap", "graph_change", "policy_change", "epoch_change", "proof_replay")
SAMPLE_ID = "guardian_recovery_virtual_model"
SCHEMA = "guardian-agent-review-evidence/v1"
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_EVIDENCE = 384
_CORE = "ros2_ws/src/guardian_core/guardian_core/"
_REQUIRED_SOURCES = (
    "experiments/recovery_scenarios.py",
    "experiments/requirements-agent-review.txt",
    "docs/artex_ros2_agent_prompts.md",
    *(_CORE + name for name in (
        "__init__.py", "bound_recovery.py", "recovery_protocol.py", "recovery_feedback.py",
        "recovery_graph.py", "independent_observation.py", "evidence_ledger.py",
        "predictive_envelope.py", "dashboard_recovery.py", "dashboard_code_security.py",
        "ros_graph_security.py",
    )),
)
_OPTIONAL_SOURCES = ("experiments/run_agent_review.py",)
_PROPOSAL_FIELDS = {"goal_id", "test_id", "evidence_refs", "reason"}
_BUNDLE_FIELDS = {"schema", "input_digest", "context_digest", "evidence", "summary", "target", "source_manifest"}


def _json_value(value, depth=0):
    if depth > 128:
        raise ValueError("JSON nesting exceeds the limit")
    if value is None or type(value) in (bool, int):
        return
    if type(value) is str:
        value.encode("utf-8")
        return
    if type(value) is float and math.isfinite(value):
        return
    if type(value) is list:
        for item in value:
            _json_value(item, depth + 1)
        return
    if type(value) is dict and all(type(key) is str for key in value):
        for key in value:
            key.encode("utf-8")
        for item in value.values():
            _json_value(item, depth + 1)
        return
    raise ValueError("only finite JSON values and string object keys are accepted")


def _canonical(value):
    _json_value(value)
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True,
            separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (UnicodeError, OverflowError, RecursionError) as error:
        raise ValueError("invalid canonical JSON") from error


def digest(value):
    """SHA256 of strict canonical UTF-8 JSON; this identifies data, not trust."""
    return hashlib.sha256(_canonical(value)).hexdigest()


def strict_loads(text):
    """Decode bounded JSON, rejecting duplicate keys and nonfinite numbers."""
    if type(text) not in (str, bytes):
        raise ValueError("JSON input must be text or UTF-8 bytes")
    try:
        if type(text) is bytes:
            text = text.decode("utf-8")
        if len(text.encode("utf-8")) > MAX_JSON_BYTES:
            raise ValueError("JSON input exceeds the byte limit")

        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate JSON object key")
                result[key] = value
            return result

        def reject_constant(_value):
            raise ValueError("JSON numbers must be finite")

        value = json.loads(text, object_pairs_hook=unique, parse_constant=reject_constant)
        _json_value(value)
        return value
    except (UnicodeError, OverflowError, RecursionError) as error:
        raise ValueError("invalid JSON input") from error


def source_manifest():
    """Hash reviewed sources using repository-relative paths only.

    New review modules are discovered each time, so adding a catalog, worker,
    runner, coordinator, orchestration or prompts invalidates older snapshots.
    No caller-supplied path is read.
    """
    root = REPO_ROOT.resolve()
    paths = set(_REQUIRED_SOURCES)
    paths.update(path.relative_to(root).as_posix()
        for path in (root / "experiments/agent_review").glob("*.py"))
    paths.update(path for path in _OPTIONAL_SOURCES if (root / path).is_file())
    result = {}
    for relative in sorted(paths):
        path = (root / relative).resolve(strict=True)
        if not path.is_relative_to(root) or not path.is_file():
            raise ValueError("source manifest path must remain within the repository")
        result[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def verify_sources(manifest):
    """Return False for changed, missing, added, or malformed source bindings."""
    if type(manifest) is not dict or not manifest:
        return False
    if any(type(path) is not str or type(sha) is not str
            or re.fullmatch(r"[0-9a-f]{64}", sha) is None for path, sha in manifest.items()):
        return False
    try:
        # Compare to the complete server-selected scope; never open manifest paths.
        return manifest == source_manifest()
    except (OSError, ValueError):
        return False


def _safe_files(files):
    if type(files) is not list:
        raise ValueError("files must be a list")
    normalized = []
    for item in files:
        if type(item) is not dict or set(item) != {"filename", "source"}:
            raise ValueError("file fields must be filename and source")
        name = item["filename"]
        if type(name) is not str:
            raise ValueError("filename must be a relative path")
        name = name.replace("\\", "/")
        if (not name or name.startswith("/") or re.match(r"^[A-Za-z]:", name)
                or any(part in {"", ".", ".."} for part in name.split("/"))):
            raise ValueError("filename must be a normalized relative path")
        normalized.append({"filename": str(PurePosixPath(name)), "source": item["source"]})
    # The existing graph analyzer enforces file count, byte bounds and uniqueness.
    report = inspect_project(normalized)
    return sorted(normalized, key=lambda item: item["filename"]), report


def _static_evidence(files, report):
    records = [{"kind": "source_file", "file": item["filename"],
        "source_digest": hashlib.sha256(item["source"].encode("utf-8")).hexdigest(),
        "provenance": "UNSUPPORTED" if item["filename"] in report["unsupported_files"] else "EXTRACTED",
        "verification_kind": "STATIC_REVIEW", "authenticated": False}
        for item in files]
    records.extend({"kind": "static_finding", "rule_id": item["rule_id"],
        "severity": item["severity"], "file": item["file"], "line": item["line"],
        "provenance": item["provenance"], "verification_kind": "STATIC_REVIEW",
        "authenticated": False} for item in report["findings"])
    return records


def _bundle_identity(bundle):
    return {key: value for key, value in bundle.items() if key != "context_digest"} | {
        "evidence": [{key: value for key, value in item.items() if key != "id"}
            for item in bundle["evidence"]]}


def _evidence_id(context, index, item):
    return "evidence:" + digest({"context_digest": context, "index": index, "record": item})


def make_bundle(payload):
    """Recompute local evidence from exactly one raw files/frames/sample input."""
    if type(payload) is not dict or len(payload) != 1 or not set(payload) <= {"files", "frames", "sample"}:
        raise ValueError("provide exactly one of files, frames or sample")
    _json_value(payload)
    sources = source_manifest()
    kind = next(iter(payload))
    summary = {"input_kind": kind,
        "source_kind": "project_owned_model" if kind == "sample" else "user_supplied",
        "registered_tests_executed": False,
        "authenticated": False, "source_executed": False,
        "limitations": [
            "Source digests identify bytes and do not authenticate their origin.",
            "Registered executions target only the project's virtual Guardian recovery model.",
            "Uploaded program behavior and physical safety are not established by model tests.",
        ]}
    if kind == "files":
        files, report = _safe_files(payload["files"])
        normalized_input = {"files": files}
        records = _static_evidence(files, report)
        summary["static"] = {"profile": report["profile"], "counts": report["summary"],
            "file_count": len(files), "unsupported_file_count": len(report["unsupported_files"]),
            "unsupported_files": report["unsupported_files"], "assurance": report["assurance"],
            "source_executed": False, "runtime_verified": False,
            "verification_kind": "STATIC_REVIEW"}
        summary["limitations"].append("Static extraction is a review lead, not a runtime finding.")
    elif kind == "frames":
        if len(_canonical(payload)) > MAX_TRACE_BYTES:
            raise ValueError("submitted trace exceeds the byte limit")
        report = inspect_recovery_trace(payload)
        normalized_input = payload
        records = [{"kind": "submitted_trace", "frame_count": report["frame_count"],
            "provenance": "USER_SUPPLIED", "verification_kind": "TRACE_RECHECK", "authenticated": False}]
        records.extend({"kind": "trace_violation", "code": item["code"],
            "frame_index": item["frame_index"], "provenance": "USER_SUPPLIED",
            "verification_kind": "TRACE_RECHECK", "authenticated": False}
            for item in report["violations"])
        summary["trace"] = {key: report[key] for key in (
            "verdict", "frame_count", "coverage", "violation_codes", "violation_count",
            "violations_truncated", "liveness_gaps", "oracle_config", "limitations")}
        summary["trace"]["verification_kind"] = "TRACE_RECHECK"
        summary["trace"]["new_execution"] = False
        summary["limitations"].append("Only the original submitted trace was rechecked; no new trigger was executed.")
    else:
        if payload["sample"] != SAMPLE_ID:
            raise ValueError("unknown sample")
        normalized_input = payload
        records = [{"kind": "model_definition", "sample": SAMPLE_ID,
            "provenance": "PROJECT_OWNED_MODEL", "verification_kind": "MODEL_DECLARATION",
            "authenticated": False}]
        summary["sample"] = "Project-owned virtual recovery model; no registered test has run yet."
    summary["evidence_total"] = len(records)
    summary["evidence_truncated"] = len(records) > MAX_EVIDENCE
    target = {"kind": SAMPLE_ID, "variant": "full", "actuation": "none",
        "uploaded_source_executed": False, "physical_robot_verified": False}
    bundle = {"schema": SCHEMA, "input_digest": digest(normalized_input),
        "summary": summary, "target": target, "source_manifest": sources,
        "evidence": records[:MAX_EVIDENCE]}
    context = digest(bundle)
    bundle["context_digest"] = context
    bundle["evidence"] = [{"id": _evidence_id(context, index, item), **item}
        for index, item in enumerate(bundle["evidence"])]
    if not verify_sources(sources):
        raise ValueError("source context changed while collecting evidence")
    return bundle


def _validate_bundle(bundle):
    if type(bundle) is not dict or set(bundle) != _BUNDLE_FIELDS:
        raise ValueError("invalid evidence bundle")
    _json_value(bundle)
    if (bundle["schema"] != SCHEMA or type(bundle["evidence"]) is not list
            or not 1 <= len(bundle["evidence"]) <= MAX_EVIDENCE
            or any(type(record) is not dict for record in bundle["evidence"])):
        raise ValueError("invalid evidence bundle")
    if digest(_bundle_identity(bundle)) != bundle["context_digest"]:
        raise ValueError("evidence bundle digest does not match")
    ids = []
    for index, record in enumerate(bundle["evidence"]):
        if type(record) is not dict or "id" not in record or record.get("authenticated") is not False:
            raise ValueError("invalid or authenticated evidence claim")
        content = {key: value for key, value in record.items() if key != "id"}
        if record["id"] != _evidence_id(bundle["context_digest"], index, content):
            raise ValueError("invalid evidence identity")
        ids.append(record["id"])
    if not verify_sources(bundle["source_manifest"]):
        raise ValueError("source context has changed")
    return set(ids)


def approve_plan(role, proposals, bundle, goal_ids, seen=()):
    """Authorize a bounded planner proposal; execution identity is host-owned."""
    if role != "planner":
        raise ValueError("only planner may propose test intents")
    if type(proposals) is not list or len(proposals) > len(TEST_IDS):
        raise ValueError("a plan may contain at most six test intents")
    if (type(goal_ids) not in (list, tuple) or not 1 <= len(goal_ids) <= 6
            or any(type(goal) is not str or not goal or len(goal) > 128 for goal in goal_ids)
            or len(set(goal_ids)) != len(goal_ids)):
        raise ValueError("invalid goal scope")
    if (type(seen) not in (list, tuple, set, frozenset)
            or any(type(test) is not str or test not in TEST_IDS for test in seen)
            or len(set(seen)) != len(seen)):
        raise ValueError("invalid prior test scope")
    evidence_ids = _validate_bundle(bundle)
    used = set(seen)
    approved = []
    for proposal in proposals:
        if type(proposal) is not dict or set(proposal) != _PROPOSAL_FIELDS:
            raise ValueError("proposal fields must be goal_id, test_id, evidence_refs and reason")
        _json_value(proposal)
        goal, test, refs, reason = (proposal[key] for key in ("goal_id", "test_id", "evidence_refs", "reason"))
        if type(goal) is not str or goal not in goal_ids:
            raise ValueError("unknown goal")
        if type(test) is not str or test not in TEST_IDS or test in used:
            raise ValueError("unknown or repeated registered test")
        if (type(refs) is not list or not 1 <= len(refs) <= 8
                or any(type(ref) is not str or ref not in evidence_ids for ref in refs)
                or len(set(refs)) != len(refs)):
            raise ValueError("evidence references must be unique references from the current bundle")
        if type(reason) is not str or not reason.strip() or len(reason) > 512:
            raise ValueError("reason must contain 1-512 characters")
        used.add(test)
        approved.append({"goal_id": goal, "test_id": test, "evidence_refs": list(refs), "reason": reason})
    plan_digest = digest({"context_digest": bundle["context_digest"], "proposals": approved})
    return [{**proposal, "intent_id": "intent:" + uuid4().hex,
        "context_digest": bundle["context_digest"], "plan_digest": plan_digest}
        for proposal in approved]


__all__ = ["TEST_IDS", "SAMPLE_ID", "digest", "strict_loads", "source_manifest",
    "verify_sources", "make_bundle", "approve_plan"]
