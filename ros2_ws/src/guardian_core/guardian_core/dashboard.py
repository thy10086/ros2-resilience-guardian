"""ROS 2 to HTTP bridge for the local Guardian security dashboard."""

from __future__ import annotations

import json
import mimetypes
import os
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import Iterable
from urllib.parse import unquote, urlparse

import rclpy
from rclpy.node import Node

from guardian_interfaces.msg import MitigationCommand, RiskState, SafetyStatus
from std_msgs.msg import String

from .dashboard_state import DashboardState
from .dashboard_experiments import ReplayError, run_replay, run_replay_with_jev, sample_catalog
from .dashboard_code_security import (
    CODE_SECURITY_SCHEMA,
    CodeSecurityError,
    inspect_source,
    sample_catalog as code_security_sample_catalog,
)
from .dashboard_research import run_research_suite
from .dashboard_jev import (
    DEFAULT_TIMEOUT_SEC,
    DEFAULT_ENDPOINT,
    JevDashboardService,
    JevRequestError,
    MAX_REQUEST_BYTES,
    parse_api_key_request,
    parse_request,
)
from .dashboard_auth import DashboardAuth
from .dashboard_credentials import CredentialStoreError
from .dataset_security import DatasetSecurityError, scan_dataset
from .dataset_upload import DatasetUploadError, stage_multipart_upload
from .sandbox_simulation import (
    SANDBOX_SCHEMA,
    SandboxInputError,
    run_sandbox,
    sandbox_runtime_status,
    sample_catalog as sandbox_sample_catalog,
)

MAX_SIMULATION_REQUEST_BYTES = 4096
MAX_CODE_SECURITY_REQUEST_BYTES = 72 * 1024
MAX_SANDBOX_REQUEST_BYTES = 148 * 1024
MAX_CODE_SECURITY_JEV_FINDINGS = 32
MAX_JEV_EVALUATION_EVENTS = 16
SIMULATION_ATTACK_TYPES = {"speed_abuse", "replay", "gripper_fault"}
SIMULATION_ACTIONS = {"start", "stop", "reset", "attack"}


def _frontend_dir() -> Path:
    configured = os.getenv("GUARDIAN_FRONTEND_DIR")
    if configured:
        return Path(configured).expanduser().resolve()
    source_dir = Path(__file__).resolve().parent / "frontend"
    if source_dir.is_dir():
        return source_dir
    for prefix in os.getenv("AMENT_PREFIX_PATH", "").split(os.pathsep):
        candidate = Path(prefix) / "share" / "guardian_core" / "frontend"
        if candidate.is_dir():
            return candidate
    return source_dir


class DashboardHandler(BaseHTTPRequestHandler):
    """Serve the static dashboard and a JSON state endpoint."""

    server_version = "GuardianDashboard/0.1"

    @property
    def dashboard_server(self) -> "DashboardHTTPServer":
        return self.server  # type: ignore[return-value]

    def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        try:
            self._get()
        except CredentialStoreError:
            self._credential_error()

    def _credential_error(self) -> None:
        self._json({"error": {"code": "credential_store_unavailable", "message": str(CredentialStoreError())}}, status=503)

    def _get(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/health":
            self._json({"status": "ok", "service": "guardian_dashboard"})
            return
        if parsed.path == "/api/state":
            if not self._require_auth():
                return
            self._json(self.dashboard_server.state.snapshot())
            return
        if parsed.path == "/api/session":
            token = self._session_token()
            if self.dashboard_server.auth.validate(token):
                self._json({"authenticated": True, "username": self.dashboard_server.auth.username})
            else:
                self._json({"authenticated": False, "error": {"code": "auth_required", "message": "Login required"}}, status=401)
            return
        if parsed.path == "/api/jev/key":
            if not self._require_auth():
                return
            self._jev_key_status()
            return
        if parsed.path == "/api/experiments/samples":
            if not self._require_auth():
                return
            self._experiment_samples()
            return
        if parsed.path == "/api/code-security/samples":
            if not self._require_auth():
                return
            self._code_security_samples()
            return
        if parsed.path == "/api/sandbox/samples":
            if not self._require_auth():
                return
            self._sandbox_samples()
            return
        if parsed.path == "/api/research/suite":
            if not self._require_auth():
                return
            self._research_suite()
            return
        self._static(parsed.path)

    def do_POST(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        try:
            self._post()
        except CredentialStoreError:
            self._credential_error()

    def _post(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/login":
            self._login()
            return
        if parsed.path == "/api/logout":
            self.dashboard_server.auth.logout(self._session_token())
            self._json({"authenticated": False}, headers={"Set-Cookie": self._clear_cookie()})
            return
        if parsed.path == "/api/jev/key":
            if not self._require_auth():
                return
            self._save_jev_key()
            return
        if parsed.path == "/api/jev/key/clear":
            if not self._require_auth():
                return
            self.dashboard_server.auth.clear_jev_key(self._session_token())
            self._json({"saved": False})
            return
        if parsed.path == "/api/jev/test":
            if not self._require_auth():
                return
            self._jev_test()
            return
        if parsed.path == "/api/experiments/replay":
            if not self._require_auth():
                return
            self._experiment_replay()
            return
        if parsed.path == "/api/experiments/jev-evaluate":
            if not self._require_auth():
                return
            self._experiment_jev_evaluate()
            return
        if parsed.path == "/api/code-security/inspect":
            if not self._require_auth():
                return
            self._code_security_inspect()
            return
        if parsed.path == "/api/code-security/jev-evaluate":
            if not self._require_auth():
                return
            self._code_security_jev_evaluate()
            return
        if parsed.path == "/api/sandbox/run":
            if not self._require_auth():
                return
            self._sandbox_run()
            return
        if parsed.path == "/api/dataset-security/scan":
            if not self._require_auth():
                return
            self._dataset_scan()
            return
        if parsed.path == "/api/simulation/control":
            if not self._require_auth():
                return
            self._simulation_control()
            return
        self.send_error(404)

    def _json(self, payload: object, *, status: int = 200, headers: dict[str, str] | None = None) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _session_token(self) -> str | None:
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except (TypeError, ValueError):
            return None
        morsel = cookie.get("guardian_session")
        return morsel.value if morsel is not None else None

    def _require_auth(self) -> bool:
        if self.dashboard_server.auth.validate(self._session_token()):
            return True
        self._json({"authenticated": False, "error": {"code": "auth_required", "message": "Login required"}}, status=401)
        return False

    @staticmethod
    def _clear_cookie() -> str:
        return "guardian_session=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict"

    def _login(self) -> None:
        content_length = self.headers.get("Content-Length")
        try:
            length = int(content_length or "-1")
        except (TypeError, ValueError):
            length = -1
        if length < 0 or length > 4096:
            self._json({"authenticated": False, "error": {"code": "invalid_login_request", "message": "Login request is invalid"}}, status=400)
            return
        try:
            payload = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            payload = None
        username = payload.get("username") if isinstance(payload, dict) else None
        password = payload.get("password") if isinstance(payload, dict) else None
        token = self.dashboard_server.auth.login(username, password)
        if token is None:
            self._json({"authenticated": False, "error": {"code": "invalid_credentials", "message": "用户名或密码错误"}}, status=401)
            return
        cookie = f"guardian_session={token}; Max-Age={int(self.dashboard_server.auth.ttl_sec)}; Path=/; HttpOnly; SameSite=Strict"
        self._json({"authenticated": True, "username": self.dashboard_server.auth.username}, headers={"Set-Cookie": cookie})

    def _jev_test(self) -> None:
        content_length = self.headers.get("Content-Length")
        if content_length is None:
            self._json(
                {
                    "status": "INVALID_REQUEST",
                    "connected": False,
                    "error": {"code": "missing_content_length", "message": "Request body is required"},
                },
                status=400,
            )
            return
        try:
            length = int(content_length)
        except (TypeError, ValueError):
            length = -1
        if length < 0:
            self._json(
                {
                    "status": "INVALID_REQUEST",
                    "connected": False,
                    "error": {"code": "invalid_content_length", "message": "Request body length is invalid"},
                },
                status=400,
            )
            return
        if length > MAX_REQUEST_BYTES:
            self._json(
                {
                    "status": "INVALID_REQUEST",
                    "connected": False,
                    "error": {"code": "request_too_large", "message": "Request body is too large"},
                },
                status=413,
            )
            return
        raw = self.rfile.read(length)
        if len(raw) != length:
            self._json(
                {
                    "status": "INVALID_REQUEST",
                    "connected": False,
                    "error": {"code": "incomplete_body", "message": "Request body is incomplete"},
                },
                status=400,
            )
            return
        try:
            api_key, state = parse_request(raw, allow_missing_api_key=True)
        except JevRequestError as error:
            self._json(
                {
                    "status": "INVALID_REQUEST",
                    "connected": False,
                    "error": {"code": error.code, "message": error.message},
                },
                status=error.http_status,
            )
            return
        if api_key is None:
            api_key = self.dashboard_server.auth.get_jev_key(self._session_token())
            if api_key is None:
                self._json(
                    {
                        "status": "INVALID_REQUEST",
                        "connected": False,
                        "error": {"code": "missing_api_key", "message": "Enter a Jev API key or save one on this device"},
                    },
                    status=400,
                )
                return
        try:
            response = self.dashboard_server.jev_service.test(api_key, state)
        except Exception:
            # Keep an unexpected provider/client failure bounded and free of
            # request data; the browser can render the same failure state.
            self._json(
                {
                    "status": "UNAVAILABLE",
                    "connected": False,
                    "error": {"code": "provider_unavailable", "message": "Jev service is unavailable"},
                },
                status=502,
            )
            return
        self._json(response.payload, status=response.http_status)

    def _jev_key_status(self) -> None:
        self._json({"saved": self.dashboard_server.auth.has_jev_key(self._session_token())})

    def _save_jev_key(self) -> None:
        content_length = self.headers.get("Content-Length")
        try:
            length = int(content_length or "-1")
        except (TypeError, ValueError):
            length = -1
        if length < 0 or length > MAX_REQUEST_BYTES:
            self._json({"saved": False, "error": {"code": "invalid_key_request", "message": "Key request is invalid"}}, status=400)
            return
        try:
            api_key = parse_api_key_request(self.rfile.read(length))
        except JevRequestError as error:
            self._json({"saved": False, "error": {"code": error.code, "message": error.message}}, status=error.http_status)
            return
        if not self.dashboard_server.auth.remember_jev_key(self._session_token(), api_key):
            self._json({"saved": False, "error": {"code": "auth_required", "message": "Login required"}}, status=401)
            return
        self._json({"saved": True})

    def _experiment_samples(self) -> None:
        self._json({"schema": "guardian-replay/v1", "samples": sample_catalog()})

    def _code_security_samples(self) -> None:
        self._json({"schema": CODE_SECURITY_SCHEMA, "samples": code_security_sample_catalog()})

    def _sandbox_samples(self) -> None:
        self._json({
            "schema": SANDBOX_SCHEMA,
            "samples": sandbox_sample_catalog(),
            "runtime": sandbox_runtime_status(),
        })

    def _research_suite(self) -> None:
        self._json(run_research_suite())

    def _experiment_replay(self) -> None:
        content_length = self.headers.get("Content-Length")
        try:
            length = int(content_length or "-1")
        except (TypeError, ValueError):
            length = -1
        if length < 0:
            self._json(
                {"status": "INVALID_REQUEST", "error": {"code": "invalid_content_length", "message": "Request body length is invalid"}},
                status=400,
            )
            return
        if length > MAX_REQUEST_BYTES:
            self._json(
                {"status": "INVALID_REQUEST", "error": {"code": "request_too_large", "message": "Request body is too large"}},
                status=413,
            )
            return
        raw = self.rfile.read(length)
        if len(raw) != length:
            self._json(
                {"status": "INVALID_REQUEST", "error": {"code": "incomplete_body", "message": "Request body is incomplete"}},
                status=400,
            )
            return
        try:
            sample = json.loads(raw.decode("utf-8"))
            report = run_replay(sample)
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._json(
                {"status": "INVALID_REQUEST", "error": {"code": "invalid_json", "message": "样例必须是有效 JSON"}},
                status=400,
            )
            return
        except ReplayError as error:
            self._json(
                {"status": "INVALID_REQUEST", "error": {"code": "invalid_sample", "message": str(error)}},
                status=400,
            )
            return
        self._json({"status": "OK", "report": report})

    def _experiment_jev_evaluate(self) -> None:
        content_length = self.headers.get("Content-Length")
        try:
            length = int(content_length or "-1")
        except (TypeError, ValueError):
            length = -1
        if length < 0:
            self._json(
                {"status": "INVALID_REQUEST", "error": {"code": "invalid_content_length", "message": "Request body length is invalid"}},
                status=400,
            )
            return
        if length > MAX_REQUEST_BYTES:
            self._json(
                {"status": "INVALID_REQUEST", "error": {"code": "request_too_large", "message": "Request body is too large"}},
                status=413,
            )
            return
        raw = self.rfile.read(length)
        if len(raw) != length:
            self._json(
                {"status": "INVALID_REQUEST", "error": {"code": "incomplete_body", "message": "Request body is incomplete"}},
                status=400,
            )
            return
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._json(
                {"status": "INVALID_REQUEST", "error": {"code": "invalid_json", "message": "请求体必须是有效 JSON"}},
                status=400,
            )
            return
        if not isinstance(payload, dict) or set(payload) - {"sample", "api_key"}:
            self._json(
                {"status": "INVALID_REQUEST", "error": {"code": "invalid_jev_request", "message": "请求体只支持 sample 和可选 api_key"}},
                status=400,
            )
            return
        sample = payload.get("sample")
        if not isinstance(sample, dict) or not isinstance(sample.get("events"), list):
            self._json(
                {"status": "INVALID_REQUEST", "error": {"code": "missing_sample", "message": "请求体必须包含防护样例 sample"}},
                status=400,
            )
            return
        if len(sample["events"]) > MAX_JEV_EVALUATION_EVENTS:
            self._json(
                {
                    "status": "INVALID_REQUEST",
                    "error": {
                        "code": "jev_event_budget_exceeded",
                        "message": f"单次 Jev 综合评价最多处理 {MAX_JEV_EVALUATION_EVENTS} 条事件",
                    },
                },
                status=400,
            )
            return
        try:
            api_key = None
            if "api_key" in payload:
                api_key = parse_api_key_request(json.dumps({"api_key": payload["api_key"]}).encode("utf-8"))
            if api_key is None:
                api_key = self.dashboard_server.auth.get_jev_key(self._session_token())
            if api_key is None:
                self._json(
                    {
                        "status": "INVALID_REQUEST",
                        "error": {"code": "missing_api_key", "message": "请先保存 Jev Key，或在 Jev 页面输入 Key"},
                    },
                    status=400,
                )
                return
            report = run_replay_with_jev(
                sample,
                lambda state: self.dashboard_server.jev_service.test(api_key, state).payload,
            )
        except ReplayError as error:
            self._json(
                {"status": "INVALID_REQUEST", "error": {"code": "invalid_sample", "message": str(error)}},
                status=400,
            )
            return
        except JevRequestError as error:
            self._json(
                {"status": "INVALID_REQUEST", "error": {"code": error.code, "message": error.message}},
                status=error.http_status,
            )
            return
        self._json({"status": "OK", "report": report})

    def _code_security_inspect(self) -> None:
        content_length = self.headers.get("Content-Length")
        try:
            length = int(content_length or "-1")
        except (TypeError, ValueError):
            length = -1
        if length < 0:
            self._json(
                {"status": "INVALID_REQUEST", "error": {"code": "invalid_code_security_request", "message": "请求体长度无效"}},
                status=400,
            )
            return
        if length > MAX_CODE_SECURITY_REQUEST_BYTES:
            self._json(
                {"status": "INVALID_REQUEST", "error": {"code": "code_security_request_too_large", "message": "代码文件不能超过 64 KiB"}},
                status=413,
            )
            return
        raw = self.rfile.read(length)
        if len(raw) != length:
            self._json(
                {"status": "INVALID_REQUEST", "error": {"code": "invalid_code_security_request", "message": "请求体不完整"}},
                status=400,
            )
            return
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._json(
                {"status": "INVALID_REQUEST", "error": {"code": "invalid_code_security_request", "message": "请求体必须是有效 JSON"}},
                status=400,
            )
            return
        if not isinstance(payload, dict) or set(payload) - {"source", "filename", "profile"}:
            self._json(
                {"status": "INVALID_REQUEST", "error": {"code": "invalid_code_security_request", "message": "仅支持 source、filename、profile 字段"}},
                status=400,
            )
            return
        try:
            report = inspect_source(
                payload.get("source"),
                filename=payload.get("filename", "uploaded.py"),
                profile=payload.get("profile", "conveyor_robot_arm"),
            )
        except CodeSecurityError as error:
            self._json(
                {"status": "INVALID_REQUEST", "error": {"code": "invalid_code_security_request", "message": str(error)}},
                status=400,
            )
            return
        self._json({"status": "OK", "report": report})

    def _sandbox_run(self) -> None:
        content_length = self.headers.get("Content-Length")
        try:
            length = int(content_length or "-1")
        except (TypeError, ValueError):
            length = -1
        if length < 0:
            self._json(
                {"status": "INVALID_REQUEST", "error": {"code": "invalid_sandbox_request", "message": "请求体长度无效"}},
                status=400,
            )
            return
        if length > MAX_SANDBOX_REQUEST_BYTES:
            self._json(
                {"status": "INVALID_REQUEST", "error": {"code": "sandbox_request_too_large", "message": "沙箱输入不能超过 128 KiB"}},
                status=413,
            )
            return
        raw = self.rfile.read(length)
        if len(raw) != length:
            self._json(
                {"status": "INVALID_REQUEST", "error": {"code": "invalid_sandbox_request", "message": "请求体不完整"}},
                status=400,
            )
            return
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._json(
                {"status": "INVALID_REQUEST", "error": {"code": "invalid_sandbox_request", "message": "请求体必须是有效 JSON"}},
                status=400,
            )
            return
        if not isinstance(payload, dict) or set(payload) - {"source", "filename", "kind", "duration_sec", "api_key"}:
            self._json(
                {"status": "INVALID_REQUEST", "error": {"code": "invalid_sandbox_request", "message": "仅支持 source、filename、kind、duration_sec、api_key 字段"}},
                status=400,
            )
            return

        try:
            report = run_sandbox(
                payload.get("source"),
                filename=payload.get("filename", "uploaded.py"),
                kind=payload.get("kind"),
                duration_sec=payload.get("duration_sec", 4.0),
            )
        except SandboxInputError as error:
            self._json(
                {"status": "INVALID_REQUEST", "error": {"code": "invalid_sandbox_input", "message": str(error)}},
                status=400,
            )
            return

        api_key = None
        try:
            if payload.get("api_key") is not None:
                api_key = parse_api_key_request(json.dumps({"api_key": payload.get("api_key")}).encode("utf-8"))
            if api_key is None:
                api_key = self.dashboard_server.auth.get_jev_key(self._session_token())
        except JevRequestError as error:
            self._json(
                {"status": "INVALID_REQUEST", "error": {"code": error.code, "message": error.message}},
                status=error.http_status,
            )
            return

        report["jev"] = {
            "status": "LOCAL_ONLY",
            "connected": False,
            "called": False,
            "source_sent_to_jev": False,
            "assessment": None,
            "error": {"code": "missing_api_key", "message": "未提供 Jev Key，仅展示本地仿真证据"},
        }
        if api_key:
            try:
                jev_response = self.dashboard_server.jev_service.test(
                    api_key,
                    json.dumps(report["jev_context"], ensure_ascii=False, separators=(",", ":")),
                )
                jev_payload = jev_response.payload if isinstance(jev_response.payload, dict) else {}
                report["jev"] = {
                    "status": jev_payload.get("status", "UNAVAILABLE"),
                    "connected": jev_payload.get("connected") is True,
                    "called": True,
                    "source_sent_to_jev": False,
                    "assessment": jev_payload.get("assessment"),
                    "error": jev_payload.get("error"),
                }
            except Exception:
                report["jev"] = {
                    "status": "UNAVAILABLE",
                    "connected": False,
                    "called": True,
                    "source_sent_to_jev": False,
                    "assessment": None,
                    "error": {"code": "provider_unavailable", "message": "Jev 服务暂不可用，本地仿真证据仍然有效"},
                }
        self._json({"status": "OK", "report": report})

    def _dataset_scan(self) -> None:
        try:
            content_length = int(self.headers.get("Content-Length", "-1"))
        except (TypeError, ValueError):
            content_length = -1
        try:
            with stage_multipart_upload(
                self.rfile,
                self.headers.get("Content-Type", ""),
                content_length,
            ) as batch:
                report = scan_dataset(batch.root, display_name=batch.label)
                upload = {
                    "files_total": batch.files_total,
                    "bytes_total": batch.bytes_total,
                    "label": batch.label,
                }
        except DatasetUploadError as error:
            self._json(
                {"status": "INVALID_REQUEST", "error": {"code": error.code, "message": str(error)}},
                status=error.status,
            )
            return
        except DatasetSecurityError as error:
            self._json(
                {"status": "INVALID_REQUEST", "error": {"code": "dataset_unavailable", "message": str(error)}},
                status=400,
            )
            return
        self._json({"status": "OK", "report": report, "upload": upload})

    @staticmethod
    def _code_security_jev_context(report: dict[str, object], filename: str, profile: str) -> str:
        summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
        mapping = report.get("guardian_mapping") if isinstance(report.get("guardian_mapping"), dict) else {}
        assurance = report.get("assurance") if isinstance(report.get("assurance"), dict) else {}
        findings = report.get("findings") if isinstance(report.get("findings"), list) else []
        bounded_findings = []
        for finding in findings[:MAX_CODE_SECURITY_JEV_FINDINGS]:
            if not isinstance(finding, dict):
                continue
            bounded_findings.append({
                "rule_id": finding.get("rule_id"),
                "severity": finding.get("severity"),
                "title": finding.get("title"),
                "line": finding.get("line"),
                "guardian_action": finding.get("guardian_action"),
            })
        return json.dumps(
            {
                "kind": "industrial_code_security",
                "filename": filename,
                "profile": profile,
                "verdict": summary.get("verdict"),
                "counts": {
                    name: summary.get(name, 0)
                    for name in ("critical", "high", "medium", "low", "total")
                },
                "topics": report.get("topics", []),
                "guardian_mapping": {
                    "state": mapping.get("state"),
                    "action": mapping.get("action"),
                },
                "evidence_boundary": assurance.get("mode", "STATIC_ONLY"),
                "execution": report.get("execution", "not_executed"),
                "assurance": {
                    "mode": assurance.get("mode", "STATIC_ONLY"),
                    "coverage_score": assurance.get("coverage_score"),
                    "runtime_verified": assurance.get("runtime_verified") is True,
                    "source_executed": assurance.get("source_executed") is True,
                    "missing_controls": assurance.get("missing_controls", []),
                },
                "findings": bounded_findings,
                "source_sent_to_jev": False,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )

    def _code_security_jev_evaluate(self) -> None:
        content_length = self.headers.get("Content-Length")
        try:
            length = int(content_length or "-1")
        except (TypeError, ValueError):
            length = -1
        if length < 0:
            self._json(
                {"status": "INVALID_REQUEST", "error": {"code": "invalid_code_security_request", "message": "请求体长度无效"}},
                status=400,
            )
            return
        if length > MAX_CODE_SECURITY_REQUEST_BYTES:
            self._json(
                {"status": "INVALID_REQUEST", "error": {"code": "code_security_request_too_large", "message": "代码文件不能超过 64 KiB"}},
                status=413,
            )
            return
        raw = self.rfile.read(length)
        if len(raw) != length:
            self._json(
                {"status": "INVALID_REQUEST", "error": {"code": "invalid_code_security_request", "message": "请求体不完整"}},
                status=400,
            )
            return
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._json(
                {"status": "INVALID_REQUEST", "error": {"code": "invalid_code_security_request", "message": "请求体必须是有效 JSON"}},
                status=400,
            )
            return
        if not isinstance(payload, dict) or set(payload) - {"source", "filename", "profile", "api_key"}:
            self._json(
                {"status": "INVALID_REQUEST", "error": {"code": "invalid_code_security_request", "message": "仅支持 source、filename、profile、api_key 字段"}},
                status=400,
            )
            return

        filename = payload.get("filename", "uploaded.py")
        profile = payload.get("profile", "conveyor_robot_arm")
        try:
            report = inspect_source(payload.get("source"), filename=filename, profile=profile)
            api_key = None
            if "api_key" in payload:
                api_key = parse_api_key_request(json.dumps({"api_key": payload["api_key"]}).encode("utf-8"))
            if api_key is None:
                api_key = self.dashboard_server.auth.get_jev_key(self._session_token())
            if api_key is None:
                self._json(
                    {
                        "status": "INVALID_REQUEST",
                        "error": {"code": "missing_api_key", "message": "请先保存 Jev Key，或在 Jev 页面输入 Key"},
                    },
                    status=400,
                )
                return
            jev_response = self.dashboard_server.jev_service.test(
                api_key,
                self._code_security_jev_context(report, filename, profile),
            )
        except CodeSecurityError as error:
            self._json(
                {"status": "INVALID_REQUEST", "error": {"code": "invalid_code_security_request", "message": str(error)}},
                status=400,
            )
            return
        except JevRequestError as error:
            self._json(
                {"status": "INVALID_REQUEST", "error": {"code": error.code, "message": error.message}},
                status=error.http_status,
            )
            return
        except Exception:
            self._json(
                {
                    "status": "OK",
                    "report": report,
                    "jev": {
                        "status": "UNAVAILABLE",
                        "connected": False,
                        "called": True,
                        "source_sent_to_jev": False,
                        "assessment": None,
                        "error": {"code": "provider_unavailable", "message": "Jev 服务暂不可用"},
                    },
                }
            )
            return

        jev_payload = jev_response.payload if isinstance(jev_response.payload, dict) else {}
        self._json(
            {
                "status": "OK",
                "report": report,
                "jev": {
                    "status": jev_payload.get("status", "UNAVAILABLE"),
                    "connected": jev_payload.get("connected") is True,
                    "called": True,
                    "source_sent_to_jev": False,
                    "assessment": jev_payload.get("assessment"),
                    "error": jev_payload.get("error"),
                },
            }
        )

    def _simulation_control(self) -> None:
        content_length = self.headers.get("Content-Length")
        try:
            length = int(content_length or "-1")
        except (TypeError, ValueError):
            length = -1
        if length < 0 or length > MAX_SIMULATION_REQUEST_BYTES:
            self._json({"status": "INVALID_REQUEST", "error": {"code": "invalid_simulation_command", "message": "仿真控制请求无效"}}, status=400)
            return
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._json({"status": "INVALID_REQUEST", "error": {"code": "invalid_simulation_command", "message": "仿真控制请求必须是 JSON"}}, status=400)
            return
        if not isinstance(payload, dict) or set(payload) - {"action", "type"} or payload.get("action") not in SIMULATION_ACTIONS:
            self._json({"status": "INVALID_REQUEST", "error": {"code": "invalid_simulation_command", "message": "action 必须是 start、stop、reset 或 attack"}}, status=400)
            return
        action = payload["action"]
        command = {"action": action}
        if action == "attack":
            if payload.get("type") not in SIMULATION_ATTACK_TYPES:
                self._json({"status": "INVALID_REQUEST", "error": {"code": "invalid_simulation_command", "message": "type 必须是 speed_abuse、replay 或 gripper_fault"}}, status=400)
                return
            command["type"] = payload["type"]
        callback = self.dashboard_server.simulation_control
        if callback is None:
            self._json({"status": "UNAVAILABLE", "error": {"code": "simulation_unavailable", "message": "ROS 2 仿真节点尚未启动"}}, status=503)
            return
        try:
            callback(command)
        except Exception:
            self._json({"status": "UNAVAILABLE", "error": {"code": "simulation_unavailable", "message": "ROS 2 仿真控制不可用"}}, status=503)
            return
        self._json({"status": "SENT", "command": command})

    def _static(self, request_path: str) -> None:
        relative = unquote(request_path.lstrip("/")) or "index.html"
        root = self.dashboard_server.frontend_dir
        candidate = (root / relative).resolve()
        if root != candidate and root not in candidate.parents:
            self.send_error(404)
            return
        if not candidate.is_file():
            self.send_error(404)
            return
        body = candidate.read_bytes()
        content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8" if content_type.startswith("text/") else content_type)
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


class DashboardHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        address: tuple[str, int],
        state: DashboardState,
        frontend_dir: Path,
        jev_service: JevDashboardService | None = None,
        auth: DashboardAuth | None = None,
        simulation_control=None,
    ) -> None:
        super().__init__(address, DashboardHandler)
        self.state = state
        self.frontend_dir = frontend_dir
        self.jev_service = jev_service or JevDashboardService()
        self.auth = auth or DashboardAuth.from_environment()
        self.simulation_control = simulation_control


class DashboardNode(Node):
    def __init__(self) -> None:
        super().__init__("guardian_dashboard")
        self.declare_parameter("host", "127.0.0.1")
        self.declare_parameter("port", 8080)
        self.declare_parameter("timeline_limit", 100)
        self.declare_parameter("frontend_dir", "")
        self.declare_parameter("jev_endpoint", os.getenv("JEV_ENDPOINT", DEFAULT_ENDPOINT))
        self.declare_parameter("jev_model", os.getenv("JEV_MODEL", "jev-latest"))
        self.declare_parameter("jev_timeout_sec", os.getenv("JEV_TIMEOUT_SEC", str(DEFAULT_TIMEOUT_SEC)))

        self.state = DashboardState(int(self.get_parameter("timeline_limit").value))
        frontend_parameter = str(self.get_parameter("frontend_dir").value)
        frontend_dir = Path(frontend_parameter).expanduser().resolve() if frontend_parameter else _frontend_dir()
        if not frontend_dir.is_dir():
            raise RuntimeError(f"Dashboard frontend directory does not exist: {frontend_dir}")
        host = str(self.get_parameter("host").value)
        port = int(self.get_parameter("port").value)
        try:
            jev_service = JevDashboardService(
                endpoint=str(self.get_parameter("jev_endpoint").value),
                model=str(self.get_parameter("jev_model").value),
                timeout_sec=float(self.get_parameter("jev_timeout_sec").value),
            )
        except (TypeError, ValueError) as error:
            self.get_logger().warning(f"Invalid Jev dashboard configuration; using defaults: {error}")
            jev_service = JevDashboardService()
        self.http_server = DashboardHTTPServer((host, port), self.state, frontend_dir, jev_service=jev_service, auth=DashboardAuth.from_environment())
        self.http_thread = Thread(target=self.http_server.serve_forever, name="guardian-dashboard-http", daemon=True)
        self.http_thread.start()

        self.create_subscription(RiskState, "guardian/risk_state", self.state.update_risk, 20)
        self.create_subscription(MitigationCommand, "guardian/mitigation_command", self.state.update_mitigation, 20)
        self.create_subscription(SafetyStatus, "guardian/safety_status", self.state.update_safety, 20)
        self.sim_control_pub = self.create_publisher(String, "/amr_07/sim_control", 20)
        self.create_subscription(String, "guardian/sim_state", self.state.update_simulation, 20)
        self.http_server.simulation_control = self.publish_simulation_control
        self.get_logger().info(f"Guardian dashboard available at http://{host}:{port}")

    def publish_simulation_control(self, command: dict) -> None:
        self.sim_control_pub.publish(String(data=json.dumps(command, ensure_ascii=False)))

    def destroy_node(self) -> bool:
        self.http_server.shutdown()
        self.http_server.server_close()
        self.http_thread.join(timeout=2.0)
        return super().destroy_node()


def main(args: Iterable[str] | None = None) -> None:
    rclpy.init(args=args)
    node = DashboardNode()
    try:
        rclpy.spin(node)
    except KeyboardInterrupt:
        pass
    finally:
        node.destroy_node()
        if rclpy.ok():
            rclpy.shutdown()
