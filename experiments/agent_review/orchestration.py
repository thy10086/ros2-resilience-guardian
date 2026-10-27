"""Supervised LangGraph review with a parent-side, bounded model broker.

Fixture and live modes share contracts. Coordinator and test workers retain
network denial; only the supervising parent receives the operator's API Key.
"""
from __future__ import annotations

import json
import math
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile
import threading
import time
from typing import Annotated, TypedDict
import operator

from .contracts import approve_plan, digest, make_bundle, select_evidence, strict_loads, verify_sources
from .prompts import ROLES, role_prompt

MAX_INPUT = 2 * 1024 * 1024
MAX_OUTPUT = 32 * 1024 * 1024


class FixtureProvider:
    """Bounded JSON reply overrides for offline contract tests; no callables."""

    def __init__(self, replies=None):
        replies = {} if replies is None else replies
        if not isinstance(replies, dict) or set(replies) - set(ROLES):
            raise ValueError("fixture roles are fixed")
        raw = json.dumps(replies, ensure_ascii=False, allow_nan=False).encode()
        if len(raw) > 64 * 1024:
            raise ValueError("fixture replies too large")
        self.replies = strict_loads(raw.decode())


def _empty(status="INCOMPLETE", reason=""):
    return {"schema": "guardian-agent-review/v1", "provider_mode": "fixture",
        "model_reasoning": False, "actuation": "none", "external_calls": 0,
        "execution_status": status, "detection": "NOT_RUN", "model_detection": "NOT_RUN", "reason": reason,
        "target": {"kind": "guardian_recovery_virtual_model", "uploaded_source_executed": False},
        "role_events": [], "executions": [], "findings": [], "reviews": [], "intents": [],
        "limitations": ["固定角色脚本应答，非真实模型研判。", "仅测试自有Guardian虚拟恢复模型；不执行上传源码，不证明物理安全。"]}


def _bounded_payload(payload):
    try:
        raw = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode()
    except (TypeError, ValueError, RecursionError, UnicodeError) as exc:
        raise ValueError("input must be finite JSON") from exc
    if len(raw) > MAX_INPUT or not isinstance(payload, dict) or len(payload) != 1:
        raise ValueError("expected one bounded input kind")
    if set(payload) not in ({"sample"}, {"files"}, {"frames"}):
        raise ValueError("unsupported input fields")
    return raw


def run_review(payload, *, timeout_sec=30.0, cancel=None, provider=None, python_executable=None):
    """Supervise the fixed graph; only the parent may contact a configured model."""
    from .provider import OpenAICompatibleProvider
    _bounded_payload(payload)
    live = type(provider) is OpenAICompatibleProvider
    if type(timeout_sec) not in (int, float) or not math.isfinite(timeout_sec) or not 0 < timeout_sec <= (180 if live else 30):
        raise ValueError("timeout exceeds provider budget")
    if provider is not None and type(provider) not in (FixtureProvider, OpenAICompatibleProvider):
        raise ValueError("unsupported provider")
    mode = "llm" if live else "fixture"
    def annotate(result):
        result["provider_mode"] = mode
        if live:
            result["external_calls"] = provider.calls - initial_calls
            result["model_reasoning"] = any(e["mode"] == "llm" for e in result["role_events"])
            result["provider_usage"] = dict(provider.usage)
            result["provider_usage"]["cost"] = "not_calculated"
            result["provider_model"] = provider.redact(provider.model)
            result["limitations"] = ["真实接口模式；模型解释不覆盖程序判据。",
                "仅测试自有Guardian虚拟恢复模型；上传源码不执行，不证明物理安全。"]
        return provider.redact(result) if live else result
    initial_calls = provider.calls if live else 0
    if cancel is not None and cancel.is_set():
        return annotate(_empty("CANCELLED", "cancelled before start"))
    if sys.platform != "linux":
        return annotate(_empty("UNAVAILABLE", "Linux seccomp research environment required"))
    request = {"payload": payload, "fixture": {} if live else (provider or FixtureProvider()).replies,
               "timeout_sec": float(timeout_sec), "mode": mode}
    started = time.monotonic()
    checkpoint = _empty()
    final = None
    reason = ""
    raw_output = bytearray()
    pending = bytearray()
    errors = bytearray()
    env = {"PATH": os.defpath, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
           "PYTHONNOUSERSITE": "1", "LANGSMITH_TRACING": "false", "LANGCHAIN_TRACING_V2": "false"}
    script = Path(__file__).with_name("coordinator.py")
    with tempfile.TemporaryDirectory(prefix="guardian-agent-review-") as workdir:
        try:
            reply_read, reply_write = os.pipe()
        except OSError:
            return annotate(_empty("UNAVAILABLE", "coordinator pipe unavailable"))
        response_pipe = None
        try:
            response_pipe = os.fdopen(reply_write, "wb", buffering=0)
            proc = subprocess.Popen([python_executable or sys.executable, "-I", str(script), str(reply_read)], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=workdir, env=env,
                start_new_session=True, pass_fds=(reply_read,))
        except (OSError, ValueError):
            os.close(reply_read)
            if response_pipe is not None:
                response_pipe.close()
            else:
                os.close(reply_write)
            return annotate(_empty("UNAVAILABLE", "coordinator could not be started"))
        os.close(reply_read)
        pending_call = None
        broker_calls = 0
        try:
            # Input is bounded, but use a writer thread so a blocked reader cannot
            # prevent the supervisor from enforcing cancellation/deadline.
            def write_request():
                try:
                    proc.stdin.write(json.dumps(request, ensure_ascii=False, allow_nan=False).encode())
                    proc.stdin.close()
                except (BrokenPipeError, OSError, ValueError):
                    pass
            writer = threading.Thread(target=write_request, daemon=True)
            writer.start()
            with selectors.DefaultSelector() as selector:
                selector.register(proc.stdout, selectors.EVENT_READ, "out")
                selector.register(proc.stderr, selectors.EVENT_READ, "err")
                while selector.get_map() or proc.poll() is None:
                    if cancel is not None and cancel.is_set():
                        reason = "cancelled"
                        break
                    if time.monotonic() - started >= timeout_sec:
                        reason = "deadline exceeded"
                        break
                    if pending_call is not None and pending_call["ready"].is_set():
                        response_pipe.write(json.dumps(pending_call["response"], ensure_ascii=False).encode() + b"\n")
                        pending_call = None
                    for key, _ in selector.select(.02):
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        if key.data == "err":
                            errors.extend(chunk)
                            if len(errors) > 65536:
                                reason = "stderr limit exceeded"
                                break
                        else:
                            raw_output.extend(chunk)
                            if len(raw_output) > MAX_OUTPUT:
                                reason = "report limit exceeded"
                                break
                            pending.extend(chunk)
                            while b"\n" in pending:
                                line, _, remainder = pending.partition(b"\n")
                                pending = bytearray(remainder)
                                record = strict_loads(line.decode())
                                if record.get("kind") == "checkpoint":
                                    checkpoint = record["report"]
                                elif record.get("kind") == "final":
                                    final = record["report"]
                                elif record.get("kind") == "provider_request":
                                    if not live or pending_call is not None or broker_calls >= 16:
                                        raise ValueError("invalid provider request or exhausted budget")
                                    broker_calls += 1
                                    call = {"ready": threading.Event()}
                                    pending_call = call
                                    def invoke(record=record, call=call):
                                        try:
                                            output = provider.complete(record["role"], record["context"])
                                            call["response"] = {"ok": True, "output": output}
                                        except Exception:
                                            # Provider body, URL and credentials never enter child/report errors.
                                            call["response"] = {"ok": False, "error": "模型接口不可用、拒绝或输出无效；未回退脚本模式"}
                                        finally:
                                            call["ready"].set()
                                    call["thread"] = threading.Thread(target=invoke, daemon=True)
                                    call["thread"].start()
                    if reason:
                        break
            if reason:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            proc.wait(timeout=2)
            writer.join(timeout=.2)
            if cancel is not None and cancel.is_set():
                reason = "cancelled"
            if final is not None and proc.returncode == 0 and not reason:
                result = final
                if "source_manifest" in result and not verify_sources(result["source_manifest"]):
                    result["execution_status"] = "STALE_CONTEXT"
                    result["reason"] = "source changed before result acceptance"
            else:
                result = checkpoint
                result["execution_status"] = "CANCELLED" if reason == "cancelled" else "INCOMPLETE"
                result["reason"] = reason or "coordinator unavailable or terminated"
                if errors and not result["executions"]:
                    result["execution_status"] = "UNAVAILABLE"
        except (ValueError, OSError, subprocess.TimeoutExpired):
            result = checkpoint
            result["execution_status"] = "INCOMPLETE"
            result["reason"] = "invalid or interrupted coordinator output"
        finally:
            if live and pending_call is not None:
                provider.cancel()
                pending_call["thread"].join(timeout=2)
            # Descendant workers stay in this group. Clean up even if coordinator
            # already exited: process.poll() alone says nothing about descendants.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait(timeout=2)
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                stream.close()
            response_pipe.close()
    result["elapsed_sec"] = time.monotonic() - started
    return annotate(result)


def replay_assessment(finding, replay_findings, *, comparable):
    if not comparable:
        return "INCONCLUSIVE"
    key = (finding["test_id"], finding["rule"], finding["frame_index"])
    return "REPRODUCED" if any((f["test_id"], f["rule"], f["frame_index"]) == key
        for f in replay_findings) else "NOT_REPRODUCED"


def _findings(execution):
    rows = [{"rule": "oracle:" + row["code"], "frame_index": row["frame_index"],
             "origin": "SAFETY_ORACLE"} for row in execution["oracle"]["violations"]]
    for failure in execution.get("assertion_failures", []):
        rows.append({"rule": "scenario:" + failure["code"],
                     "frame_index": failure["frame_index"] if failure["frame_index"] is not None else max(0, execution["frame_count"] - 1),
                     "origin": "SCENARIO_ASSERTION"})
    for row in rows:
        row.update(test_id=execution["test_id"], intent_id=execution["intent_id"],
            artifact_refs=[execution["artifact_id"]], verification_kind="REEXECUTION")
        row["finding_id"] = "finding-" + digest(row)[:24]
    return rows


class _State(TypedDict, total=False):
    intents: list
    intent: dict
    done: Annotated[list, operator.add]


def _run_graph(payload, replies, timeout_sec, emit, complete=None):
    """Coordinator only. Never called with arbitrary executable provider code."""
    from langgraph.graph import StateGraph, START, END
    from langgraph.types import Send
    from guardian_core.dashboard_recovery import inspect_recovery_trace
    from .runner import run_registered_test
    from .contracts import TEST_IDS
    from importlib.metadata import version

    report = _empty()
    report["dependencies"] = {name: version(name) for name in ("langgraph", "pyseccomp")}
    report["python_version"] = sys.version.split()[0]
    bundle = make_bundle(payload)
    report.update(context_digest=bundle["context_digest"], target=bundle["target"],
        input_summary=bundle["summary"], source_manifest=bundle["source_manifest"],
        evidence=bundle["evidence"], run_id="run-" + os.urandom(12).hex())
    report["execution_target"] = bundle["target"]
    report["targets"] = [{"kind": "guardian_recovery_virtual_model", "detection": "NOT_RUN"}]
    static_review_required = False
    if "static" in bundle["summary"]:
        submitted = bundle["summary"]["static"]
        original_artifact = "submitted-source-" + bundle["input_digest"]
        report["static_detection"] = submitted["counts"]["verdict"]
        report["target"] = {"kind": "submitted_source_static", "uploaded_source_executed": False,
                            "authenticated": False, "runtime_verified": False}
        report["submitted_source"] = {**submitted, "artifact_id": original_artifact,
                                      "input_digest": bundle["input_digest"]}
        report["targets"].append({**report["target"], "detection": report["static_detection"]})
        static_review_required = bool(submitted["counts"]["total"]
            or submitted["unsupported_file_count"] or bundle["summary"]["evidence_truncated"]
            or report["static_detection"] != "PASS")
        if static_review_required:
            report["detection"] = "STATIC_REVIEW_REQUIRED"
        for evidence in bundle["evidence"]:
            if evidence["kind"] != "static_finding":
                continue
            row = {"test_id": None, "intent_id": None, "rule": "static:" + evidence["rule_id"],
                "severity": evidence["severity"], "file": evidence["file"], "line": evidence["line"],
                "provenance": evidence["provenance"], "origin": "STATIC_ANALYZER",
                "verification_kind": "STATIC_REVIEW", "artifact_refs": [original_artifact],
                "evidence_refs": [evidence["id"]], "authenticated": False, "runtime_verified": False}
            row["finding_id"] = "finding-" + digest(row)[:24]
            report["findings"].append(row)
    if "trace" in bundle["summary"]:
        submitted = bundle["summary"]["trace"]
        original_artifact = "submitted-trace-" + digest(payload["frames"])
        report["target"] = {"kind": "submitted_recovery_trace", "uploaded_source_executed": False,
                            "authenticated": False, "new_execution": False}
        report["submitted_trace"] = {**submitted, "artifact_id": original_artifact,
                                     "trace_digest": digest(payload["frames"])}
        report["targets"].append({"kind": "submitted_recovery_trace", "detection": submitted["verdict"]})
        report["detection"] = submitted["verdict"]
        for evidence in bundle["evidence"]:
            if evidence["kind"] != "trace_violation":
                continue
            row = {"test_id": None, "intent_id": None, "rule": "oracle:" + evidence["code"],
                "frame_index": evidence["frame_index"], "origin": "SAFETY_ORACLE",
                "verification_kind": "TRACE_RECHECK", "artifact_refs": [original_artifact],
                "evidence_refs": [evidence["id"]], "authenticated": False}
            row["finding_id"] = "finding-" + digest(row)[:24]
            report["findings"].append(row)
    lock = threading.RLock()
    deadline = time.monotonic() + timeout_sec
    calls, executions = 0, 0
    claimed = set()
    goals = []
    visible_evidence = select_evidence(bundle)
    visible_ids = [e["id"] for e in visible_evidence]
    report["evidence_selection"] = {"strategy": "risk_and_kind/v1", "selected_ids": visible_ids,
        "total": len(bundle["evidence"]), "additional_read_tool": False}

    def gaps(value):
        if not isinstance(value, list) or len(value) > 8 or any(not isinstance(item, str) or len(item) > 512 for item in value):
            raise ValueError("invalid bounded gaps")

    def check():
        if time.monotonic() >= deadline:
            raise RuntimeError("deadline exceeded")
        if not verify_sources(bundle["source_manifest"]):
            report["execution_status"] = "STALE_CONTEXT"
            raise RuntimeError("source context changed")

    def snapshot():
        with lock:
            emit({"kind": "checkpoint", "report": json.loads(json.dumps(report, allow_nan=False))})

    # Preserve deterministic input findings even if planning/provider later fails.
    snapshot()

    def role(name, data, default):
        nonlocal calls
        with lock:
            check()
            if calls >= 16:
                raise RuntimeError("role budget exhausted")
            calls += 1
            from .catalog import SCENARIOS
            context = {"role": name, "context_digest": bundle["context_digest"],
                "evidence_total": len(bundle["evidence"]),
                "evidence_in_message": min(8, len(bundle["evidence"])),
                "evidence_truncated": len(bundle["evidence"]) > 8 or bundle["summary"]["evidence_truncated"],
                "budget": {"role_calls_remaining": 16 - calls, "max_executions": 12,
                           "remaining_sec": max(0, deadline - time.monotonic())},
                "test_catalog": [{"test_id": key, "fixed_actions": list(value),
                                  "target": "guardian_recovery_virtual_model"}
                                 for key, value in SCENARIOS.items()],
                "evidence_selection": report["evidence_selection"],
                "evidence": [{k: v for k, v in e.items() if k not in {"filename", "file", "path", "source"}}
                             for e in visible_evidence], "task": data}
            if name == "reviewer":
                # Findings and comparisons in this batch are the reviewer's entire
                # scope. Do not repeat unrelated evidence or execution summaries.
                context.pop("evidence")
                context.pop("test_catalog")
                context["evidence_selection"] = {"strategy": "review_batch/v1",
                    "selected_ids": [r for f in data["findings"] for r in f.get("evidence_refs", [])],
                    "additional_read_tool": False}
            def public_data(value):
                if isinstance(value, dict):
                    return {key: public_data(item) for key, item in value.items()
                            if key not in {"filename", "file", "path", "source", "unsupported_files"}}
                if isinstance(value, list):
                    return [public_data(item) for item in value]
                return value
            context = public_data(context)
            input_bytes = len(json.dumps(context, ensure_ascii=False).encode())
            if name == "reviewer" and input_bytes >= 16384:
                raise ValueError("review batch input too large")
            output = complete(name, context) if complete is not None else replies.get(name, default)
            encoded = json.dumps(output, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode()
            if len(encoded) > (2048 if name == "reviewer" else 16384):
                raise ValueError("role response too large")
            output = strict_loads(encoded.decode())
            report["role_events"].append({"role": name, "mode": "llm" if complete is not None else "fixture", "ordinal": calls,
                "prompt_sha256": role_prompt(name)["sha256"], "input_digest": digest(data),
                "prompt_version": role_prompt(name)["version"],
                "output_digest": digest(output), "input_bytes": input_bytes,
                "output_bytes": len(encoded), "evidence_refs": context["evidence_selection"]["selected_ids"]})
            return output

    def goals_node(state):
        refs = visible_ids
        out = role("goals", bundle["summary"], {"goals": [{"summary": "核对自有恢复模型的许可与上下文边界", "evidence_refs": refs}], "gaps": []})
        if not isinstance(out, dict) or set(out) != {"goals", "gaps"} or not isinstance(out["goals"], list) or not 1 <= len(out["goals"]) <= 6:
            raise ValueError("invalid goals response")
        gaps(out["gaps"])
        for row in out["goals"]:
            if not isinstance(row, dict) or set(row) != {"summary", "evidence_refs"} or not isinstance(row["summary"], str) or not 1 <= len(row["summary"]) <= 512:
                raise ValueError("invalid goal")
            if not isinstance(row["evidence_refs"], list) or not 1 <= len(row["evidence_refs"]) <= 8 or any(r not in refs for r in row["evidence_refs"]):
                raise ValueError("invalid goal reference")
            goals.append({**row, "goal_id": "goal-" + digest([report["run_id"], row])[:24]})
        report["goals"] = goals
        report["goal_gaps"] = out["gaps"]
        return {}

    def planner_node(state):
        default = {"intents": [{"goal_id": goals[0]["goal_id"], "test_id": test_id,
            "evidence_refs": goals[0]["evidence_refs"], "reason": "检查注册恢复边界"} for test_id in TEST_IDS],
            "stop_reason": "注册目录范围内选测", "gaps": []}
        out = role("planner", {"goals": goals, "test_ids": list(TEST_IDS)}, default)
        if not isinstance(out, dict) or set(out) != {"intents", "stop_reason", "gaps"}:
            raise ValueError("invalid planner response")
        gaps(out["gaps"])
        if not isinstance(out["stop_reason"], str) or len(out["stop_reason"]) > 512:
            raise ValueError("invalid planner stop reason")
        proposed = out["intents"]
        if not isinstance(proposed, list):
            raise ValueError("invalid intent list")
        if any(not isinstance(row, dict) or not isinstance(row.get("evidence_refs"), list)
                or any(ref not in visible_ids for ref in row["evidence_refs"]) for row in proposed):
            raise ValueError("planner reference was not visible")
        # Validate before inserting the mandatory normal control.
        approved = approve_plan("planner", proposed, bundle, [g["goal_id"] for g in goals])
        if not any(i["test_id"] == "healthy_resume" for i in approved):
            normal = {"goal_id": goals[0]["goal_id"], "test_id": "healthy_resume",
                      "evidence_refs": goals[0]["evidence_refs"], "reason": "程序要求的正常对照"}
            approved = approve_plan("planner", proposed + [normal], bundle, [g["goal_id"] for g in goals])
        report["intents"] = approved
        report["planner_gaps"] = out["gaps"]
        report["planner_stop_reason"] = out["stop_reason"]
        report["plan_digest"] = approved[0]["plan_digest"]
        snapshot()
        return {"intents": approved}

    def dispatch(state):
        return [Send("worker", {"intent": i}) for i in state["intents"]] or "reviewer"

    def execute(intent, *, replay=False):
        nonlocal executions
        with lock:
            check()
            if executions >= 12:
                raise RuntimeError("test execution budget exhausted")
            executions += 1
        result = run_registered_test(intent["test_id"], timeout_sec=min(2.0, max(.001, deadline - time.monotonic())))
        with lock:
            check()
        if result.get("status") != "COMPLETE" or not result.get("frames"):
            raise RuntimeError("registered worker unavailable")
        oracle = inspect_recovery_trace({"frames": result["frames"]})
        row = dict(result)
        row.update(oracle=oracle, frame_count=oracle["frame_count"], intent_id=intent["intent_id"],
            target_kind="guardian_recovery_virtual_model",
            context_digest=bundle["context_digest"], plan_digest=report["plan_digest"],
            trace_digest=digest(result["frames"]), artifact_digest=digest(result),
            artifact_id="artifact-" + digest([report["run_id"], intent["intent_id"], replay, result])[:24])
        return row

    def worker_node(state):
        intent = state["intent"]
        with lock:
            if intent["intent_id"] in claimed:
                raise ValueError("intent already claimed")
            claimed.add(intent["intent_id"])
        out = role("worker", intent, {"intent_id": intent["intent_id"]})
        if out != {"intent_id": intent["intent_id"]}:
            raise ValueError("worker cannot change assigned intent or tool")
        row = execute(intent)
        with lock:
            report["executions"].append(row)
            report["findings"].extend(_findings(row))
            report["model_detection"] = "VIOLATIONS" if any(
                f["verification_kind"] == "REEXECUTION" for f in report["findings"]) else "NO_VIOLATIONS"
            report["targets"][0]["detection"] = report["model_detection"]
            report["detection"] = ("VIOLATIONS" if any(f["verification_kind"] in
                {"REEXECUTION", "TRACE_RECHECK"} for f in report["findings"])
                else "STATIC_REVIEW_REQUIRED" if static_review_required else "NO_VIOLATIONS")
            snapshot()
        return {"done": [intent["intent_id"]]}

    def reviewer_node(state):
        comparisons = {f["finding_id"]: "INCONCLUSIVE" for f in report["findings"]
                       if f["verification_kind"] != "REEXECUTION"}
        replay_artifacts = []
        for intent in report["intents"]:
            related = [f for f in report["findings"] if f["intent_id"] == intent["intent_id"]]
            if not related:
                continue
            original = next(e for e in report["executions"] if e["intent_id"] == intent["intent_id"])
            rerun = execute(intent, replay=True)
            replay_artifacts.append(rerun)
            comparable = original["validity"] == rerun["validity"] == "VALID"
            for finding in related:
                comparisons[finding["finding_id"]] = replay_assessment(finding, _findings(rerun), comparable=comparable)
        report["replays"] = replay_artifacts
        def execution_summary(row):
            summary = {key: row[key] for key in ("test_id", "intent_id", "artifact_id",
                "artifact_digest", "trace_digest", "context_digest", "plan_digest",
                "target_kind", "frame_count", "validity", "assertion_result")}
            summary["oracle"] = {key: row["oracle"][key] for key in
                ("verdict", "violation_count", "violation_codes", "coverage", "liveness_gaps")}
            summary["assertion_failures"] = row["assertion_failures"]
            summary["witness_summary"] = {key: len(value) if isinstance(value, list) else value
                for key, value in row["witnesses"].items()}
            summary["isolation"] = row["isolation"]
            return summary
        review_context = {"target": report["target"], "targets": report["targets"],
            "context_digest": bundle["context_digest"], "plan_digest": report["plan_digest"],
            "source_manifest_digest": digest(bundle["source_manifest"]),
            "source_snapshot_unchanged": verify_sources(bundle["source_manifest"]),
            "intents": report["intents"],
            "executions": [execution_summary(row) for row in report["executions"]],
            "replays": [execution_summary(row) for row in replay_artifacts],
            "limitations": bundle["summary"]["limitations"]}
        expected = [{"finding_id": f["finding_id"], "intent_id": f["intent_id"],
            "artifact_refs": f["artifact_refs"], "assessment": comparisons[f["finding_id"]],
            "counterevidence": ("固定模型重复执行逐规则/帧对比，不推断上传程序" if f["verification_kind"] == "REEXECUTION"
                                else "静态分析线索与抽取缺口保留；上传源码未运行，未确认运行时风险"
                                if f["verification_kind"] == "STATIC_REVIEW"
                                else "原始提交数据的确定性重算，保留违规；未在目标上重新触发"),
            "missing": "" if f["verification_kind"] == "REEXECUTION" else "无目标重新执行证据"}
            for f in report["findings"]]
        report["review_pending_ids"] = [row["finding_id"] for row in expected]
        # Eight batches cover 128 findings while 2 planning + 6 worker + 8 review
        # calls fit the unchanged 16-call ceiling. Short local indices avoid
        # retransmitting long immutable IDs in the 2048-token provider response.
        for start in range(0, max(1, len(expected)), 16):
            batch = report["findings"][start:start + 16]
            trusted_rows = expected[start:start + 16]
            batch_intents = {f["intent_id"] for f in batch if f["intent_id"] is not None}
            context = dict(review_context)
            if batch:
                context.update(intents=[row for row in report["intents"] if row["intent_id"] in batch_intents],
                    executions=[execution_summary(row) for row in report["executions"] if row["intent_id"] in batch_intents],
                    replays=[execution_summary(row) for row in replay_artifacts if row["intent_id"] in batch_intents])
            default = {"reviews": [{"i": index, "a": row["assessment"],
                "c": "逐规则帧重执行" if finding["verification_kind"] == "REEXECUTION" else "原始数据复核",
                "m": "" if finding["verification_kind"] == "REEXECUTION" else "无运行证据"}
                for index, (finding, row) in enumerate(zip(batch, trusted_rows))]}
            out = role("reviewer", {"findings": batch,
                "comparisons": {f["finding_id"]: comparisons[f["finding_id"]] for f in batch},
                "batch": {"offset": start, "count": len(batch), "total": len(expected)},
                "review_context": context}, default)
            if (not isinstance(out, dict) or set(out) != {"reviews"}
                    or not isinstance(out["reviews"], list) or len(out["reviews"]) != len(trusted_rows)):
                raise ValueError("invalid reviewer response")
            validated, seen = [], set()
            expected_by_id = {row["finding_id"]: row for row in trusted_rows}
            for row in out["reviews"]:
                if not isinstance(row, dict):
                    raise ValueError("invalid review fields")
                if set(row) == {"i", "a", "c", "m"}:
                    index = row["i"]
                    if type(index) is not int or not 0 <= index < len(trusted_rows):
                        raise ValueError("unbound or forged review")
                    trusted = trusted_rows[index]
                    if (any(type(row[key]) is not str for key in ("c", "m"))
                            or len(row["c"]) + len(row["m"]) > 16):
                        raise ValueError("review text invalid")
                    if row["a"] != trusted["assessment"]:
                        raise ValueError("unbound or forged review")
                    row = {**trusted, "counterevidence": row["c"], "missing": row["m"]}
                elif set(row) == {"finding_id", "intent_id", "artifact_refs", "assessment", "counterevidence", "missing"}:
                    # Older clients' full rows use exactly the same binding and
                    # byte checks. New prompts and fixtures use compact rows.
                    trusted = expected_by_id.get(row["finding_id"])
                    if trusted is None or any(row[k] != trusted[k] for k in ("intent_id", "artifact_refs", "assessment")):
                        raise ValueError("unbound or forged review")
                    if any(type(row[k]) is not str or len(row[k]) > 512 for k in ("counterevidence", "missing")):
                        raise ValueError("review text invalid")
                else:
                    raise ValueError("invalid review fields")
                if row["finding_id"] in seen:
                    raise ValueError("unbound or forged review")
                seen.add(row["finding_id"])
                validated.append(row)
            report["reviews"].extend(validated)
            report["review_pending_ids"] = report["review_pending_ids"][len(validated):]
            snapshot()
        return {}

    graph = StateGraph(_State)
    graph.add_node("goals", goals_node)
    graph.add_node("planner", planner_node)
    graph.add_node("worker", worker_node)
    graph.add_node("reviewer", reviewer_node)
    graph.add_edge(START, "goals")
    graph.add_edge("goals", "planner")
    graph.add_conditional_edges("planner", dispatch, ["worker", "reviewer"])
    graph.add_edge("worker", "reviewer")
    graph.add_edge("reviewer", END)
    try:
        graph.compile().invoke({}, {"max_concurrency": 3, "recursion_limit": 32})
        check()
        report["execution_status"] = "COMPLETE" if all(
            e["validity"] == "VALID" for e in report["executions"]) else "INCOMPLETE"
        report["role_calls"] = calls
        report["scenario_executions"] = executions
        report["expectations"] = "FAIL" if any(e["assertion_result"] == "FAIL" for e in report["executions"]) else "PASS"
    except (ValueError, RuntimeError, KeyError, TypeError) as exc:
        if report["execution_status"] != "STALE_CONTEXT":
            report["execution_status"] = "INCOMPLETE"
        report["reason"] = str(exc)[:512]
        # Barrier shutdown waits for bounded worker executions, retaining findings.
        report["role_calls"] = calls
        report["scenario_executions"] = executions
        reviewed = {row["finding_id"] for row in report["reviews"]}
        report["review_pending_ids"] = [row["finding_id"] for row in report["findings"] if row["finding_id"] not in reviewed]
    return report
