"""Session-owned, bounded live review jobs. Credentials live only in active calls."""
from __future__ import annotations

from collections import OrderedDict
import hashlib
import json
import math
from pathlib import Path
import subprocess
import sys
from threading import Event, RLock, Thread
from uuid import uuid4

MAX_REQUEST_BYTES = 2 * 1024 * 1024
MAX_REPORT_BYTES = 4 * 1024 * 1024
MAX_HISTORY_BYTES = 32 * 1024 * 1024


class AgentRequestError(ValueError):
    def __init__(self, code, message, status=400):
        super().__init__(message)
        self.code, self.status = code, status

    def payload(self):
        return {"status": "UNAVAILABLE" if self.status == 503 else "INVALID_REQUEST",
            "error": {"code": self.code, "message": str(self)}}


def strict_request(raw):
    """Reject duplicate keys, nonfinite values, nesting abuse and oversized JSON."""
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    def finite(value, depth=0):
        if depth > 128 or (type(value) is float and not math.isfinite(value)):
            raise ValueError("invalid JSON value")
        if type(value) is dict:
            for item in value.values():
                finite(item, depth + 1)
        elif type(value) is list:
            for item in value:
                finite(item, depth + 1)

    try:
        if len(raw) > MAX_REQUEST_BYTES:
            raise ValueError("size limit")
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")))
        finite(value)
        if type(value) is not dict:
            raise ValueError("object required")
        return value
    except (UnicodeError, ValueError, RecursionError):
        raise AgentRequestError("invalid_agent_request", "请求须为不超过 2 MiB 的严格 JSON 对象") from None


def _load_runtime():
    """Load only the fixed repository and isolated executable; no client paths."""
    root = Path(__file__).resolve().parents[4]
    python = root / "output/agent-review-venv/bin/python"
    try:
        if (sys.platform != "linux" or not python.is_file()
                or not (root / "experiments/agent_review/orchestration.py").is_file()):
            raise OSError("missing fixed runtime")
        subprocess.run([str(python), "-I", "-c", "import langgraph, pyseccomp"],
            check=True, timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
        if str(root) not in sys.path:
            sys.path.insert(0, str(root))
        from experiments.agent_review.provider import OpenAICompatibleProvider
        from experiments.agent_review.orchestration import run_review
        from experiments.agent_review.contracts import make_bundle
        return OpenAICompatibleProvider, run_review, make_bundle, str(python)
    except (OSError, subprocess.SubprocessError, ImportError):
        raise AgentRequestError("runtime_unavailable",
            "需要 Linux 与项目固定 agent-review-venv（LangGraph、pyseccomp）；未运行替代脚本", 503) from None


def _fields(payload, fields):
    if type(payload) is not dict or set(payload) != set(fields):
        raise AgentRequestError("invalid_agent_request", "请求字段不完整或含未支持字段")


class AgentReviewJobs:
    def __init__(self):
        self._lock = RLock()
        self._jobs = OrderedDict()
        self._active = None

    @staticmethod
    def _owner(token):
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def models(self, payload):
        _fields(payload, {"base_url", "api_key"})
        Provider, _, _, _ = _load_runtime()
        try:
            provider = Provider(**payload, timeout_sec=15)
        except (TypeError, ValueError):
            raise AgentRequestError("invalid_agent_config", "请填写有效 URL 与 API Key") from None
        try:
            return {"status": "OK", "models": provider.list_models(),
                "mode": "llm", "limitations": ["协议接通不代表实际模型质量。"]}
        except Exception:
            raise AgentRequestError("provider_unavailable", "模型列表读取失败；请检查接口，或手动填写模型名", 503) from None

    def start(self, payload, token, validate_owner):
        # Admission and logout revocation share this lock. Route authentication
        # alone is insufficient: fixed-runtime preparation may outlive logout.
        with self._lock:
            self._require_owner(validate_owner)
        _fields(payload, {"base_url", "api_key", "model", "input"})
        if type(payload["model"]) is not str or not payload["model"].strip():
            raise AgentRequestError("invalid_agent_config", "请读取或填写模型名")
        Provider, run_review, make_bundle, python = _load_runtime()
        try:
            provider = Provider(base_url=payload["base_url"], api_key=payload["api_key"],
                model=payload["model"], timeout_sec=15)
            make_bundle(payload["input"])
        except (TypeError, ValueError, OSError):
            raise AgentRequestError("invalid_agent_request", "模型配置或 files / frames / sample 输入无效") from None
        with self._lock:
            self._require_owner(validate_owner)
            if self._active is not None:
                raise AgentRequestError("agent_job_busy", "已有分析任务运行，请等待完成或取消", 409)
            job_id = uuid4().hex
            cancel = Event()
            self._jobs[job_id] = {"owner": self._owner(token), "cancel": cancel,
                "public": {"job_id": job_id, "status": "RUNNING", "mode": "llm"}, "bytes": 0}
            self._active = job_id
            self._prune_locked()
            thread = Thread(target=self._work,
                args=(job_id, payload["input"], provider, run_review, python), daemon=True,
                name="guardian-agent-review")
            thread.start()
            return {"job_id": job_id, "status": "RUNNING", "mode": "llm"}

    @staticmethod
    def _require_owner(validate_owner):
        if not validate_owner():
            raise AgentRequestError("auth_required", "登录已过期，请重新登录", 401)

    def _work(self, job_id, payload, provider, run_review, python):
        with self._lock:
            cancel = self._jobs[job_id]["cancel"]
        try:
            report = run_review(payload, provider=provider, timeout_sec=180,
                cancel=cancel, python_executable=python)
            # The provider redacts model replies. Final defense also covers future runners.
            raw = json.dumps(provider.redact(report), ensure_ascii=False, allow_nan=False)
            if len(raw.encode("utf-8")) > MAX_REPORT_BYTES:
                raise ValueError("report limit")
            report = json.loads(raw)
            execution_status = report.get("execution_status", report.get("status"))
            status = "CANCELLED" if cancel.is_set() or execution_status == "CANCELLED" else (
                "COMPLETED" if execution_status in {"COMPLETE", "OK"} else "FAILED")
            public = {"job_id": job_id, "status": status, "mode": "llm", "report": report}
        except Exception:
            public = {"job_id": job_id, "status": "CANCELLED" if cancel.is_set() else "FAILED",
                "mode": "llm", "error": {"code": "agent_review_failed",
                    "message": "分析失败或超过报告限制；未使用离线替代结果"}}
        finally:
            # Do not retain the request, provider, credential or raw input in history.
            payload = provider = run_review = None
        with self._lock:
            record = self._jobs[job_id]
            record["public"] = public
            record["bytes"] = len(json.dumps(public, ensure_ascii=False).encode("utf-8"))
            record.pop("cancel", None)
            self._active = None
            self._prune_locked()

    def _prune_locked(self):
        while len(self._jobs) > 8 or sum(row["bytes"] for row in self._jobs.values()) > MAX_HISTORY_BYTES:
            oldest = next(key for key in self._jobs if key != self._active)
            self._jobs.pop(oldest)

    def get(self, job_id, token):
        with self._lock:
            row = self._owned(job_id, token)
            return json.loads(json.dumps(row["public"]))

    def _owned(self, job_id, token):
        row = self._jobs.get(job_id) if type(job_id) is str else None
        if row is None or row["owner"] != self._owner(token):
            raise AgentRequestError("agent_job_not_found", "任务不存在或不属于当前会话", 404)
        return row

    def cancel(self, payload, token):
        _fields(payload, {"job_id"})
        with self._lock:
            row = self._owned(payload["job_id"], token)
            if "cancel" in row:
                row["cancel"].set()
                row["public"]["status"] = "CANCELLING"
            return dict(row["public"])

    def logout(self, token, revoke_owner):
        if not token:
            return
        with self._lock:
            # Revoke while holding the admission lock, including sessions with
            # no registered job yet. No raw token or revocation history is kept.
            revoke_owner()
            for row in self._jobs.values():
                if row["owner"] == self._owner(token) and "cancel" in row:
                    row["cancel"].set()
                    row["public"]["status"] = "CANCELLING"

    def close(self):
        with self._lock:
            for row in self._jobs.values():
                if "cancel" in row:
                    row["cancel"].set()
