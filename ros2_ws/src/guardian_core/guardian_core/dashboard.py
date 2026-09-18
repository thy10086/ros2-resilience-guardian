"""ROS 2 to HTTP bridge for the local Guardian security dashboard."""

from __future__ import annotations

import json
import mimetypes
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import Iterable
from urllib.parse import unquote, urlparse

import rclpy
from rclpy.node import Node

from guardian_interfaces.msg import MitigationCommand, RiskState, SafetyStatus

from .dashboard_state import DashboardState


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
        parsed = urlparse(self.path)
        if parsed.path == "/api/health":
            self._json({"status": "ok", "service": "guardian_dashboard"})
            return
        if parsed.path == "/api/state":
            self._json(self.dashboard_server.state.snapshot())
            return
        self._static(parsed.path)

    def _json(self, payload: object) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

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

    def __init__(self, address: tuple[str, int], state: DashboardState, frontend_dir: Path) -> None:
        super().__init__(address, DashboardHandler)
        self.state = state
        self.frontend_dir = frontend_dir


class DashboardNode(Node):
    def __init__(self) -> None:
        super().__init__("guardian_dashboard")
        self.declare_parameter("host", "127.0.0.1")
        self.declare_parameter("port", 8080)
        self.declare_parameter("timeline_limit", 100)
        self.declare_parameter("frontend_dir", "")

        self.state = DashboardState(int(self.get_parameter("timeline_limit").value))
        frontend_parameter = str(self.get_parameter("frontend_dir").value)
        frontend_dir = Path(frontend_parameter).expanduser().resolve() if frontend_parameter else _frontend_dir()
        if not frontend_dir.is_dir():
            raise RuntimeError(f"Dashboard frontend directory does not exist: {frontend_dir}")
        host = str(self.get_parameter("host").value)
        port = int(self.get_parameter("port").value)
        self.http_server = DashboardHTTPServer((host, port), self.state, frontend_dir)
        self.http_thread = Thread(target=self.http_server.serve_forever, name="guardian-dashboard-http", daemon=True)
        self.http_thread.start()

        self.create_subscription(RiskState, "guardian/risk_state", self.state.update_risk, 20)
        self.create_subscription(MitigationCommand, "guardian/mitigation_command", self.state.update_mitigation, 20)
        self.create_subscription(SafetyStatus, "guardian/safety_status", self.state.update_safety, 20)
        self.get_logger().info(f"Guardian dashboard available at http://{host}:{port}")

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
    finally:
        node.destroy_node()
        rclpy.shutdown()

