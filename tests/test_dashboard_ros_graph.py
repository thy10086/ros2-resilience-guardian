from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from guardian_core.dashboard import DashboardHTTPServer
from guardian_core.dashboard_auth import DashboardAuth
from guardian_core.dashboard_state import DashboardState


ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "ros2_ws" / "src" / "guardian_core" / "guardian_core" / "frontend"


def request_json(url: str, *, data: bytes | None = None, headers: dict[str, str] | None = None):
    request = urllib.request.Request(
        url,
        data=data,
        headers=headers or {},
        method="POST" if data is not None else "GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=2) as response:
            return response.status, dict(response.headers), json.loads(response.read())
    except urllib.error.HTTPError as error:
        body = error.read()
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            payload = {"raw": body.decode("utf-8", errors="replace")}
        return error.code, dict(error.headers), payload


@pytest.fixture()
def server():
    auth = DashboardAuth(username="admin", password="admin", ttl_sec=60.0)
    http = DashboardHTTPServer(("127.0.0.1", 0), DashboardState(), FRONTEND, auth=auth)
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{http.server_port}"
    finally:
        http.shutdown()
        http.server_close()
        thread.join(timeout=2)


def login(server: str) -> str:
    status, headers, payload = request_json(
        f"{server}/api/login",
        data=b'{"username":"admin","password":"admin"}',
        headers={"Content-Type": "application/json"},
    )
    assert status == 200
    assert payload["authenticated"] is True
    return headers["Set-Cookie"].split(";", 1)[0]


def test_ros_graph_samples_require_login_and_return_bounded_catalog(server):
    status, _, payload = request_json(f"{server}/api/ros-graph/samples")
    assert status == 401
    assert payload["error"]["code"] == "auth_required"

    cookie = login(server)
    status, _, payload = request_json(
        f"{server}/api/ros-graph/samples",
        headers={"Cookie": cookie},
    )
    assert status == 200
    assert payload["schema"] == "ros-security-graph/v1"
    assert payload["samples"]
    assert all(isinstance(sample.get("files"), list) for sample in payload["samples"])


def test_ros_graph_inspect_returns_graph_without_executing_source(server, tmp_path):
    marker = tmp_path / "should-not-exist"
    source = f"""
import os
from rclpy.node import Node

class Controller(Node):
    def __init__(self):
        super().__init__("controller")
        self.pub = self.create_publisher(object, "/cmd_vel", 10)

    def publish(self, command):
        os.system("touch {marker}")
        self.pub.publish(command)
"""
    cookie = login(server)
    body = json.dumps({
        "files": [{"filename": "controller.py", "source": source}],
    }).encode()
    status, _, payload = request_json(
        f"{server}/api/ros-graph/inspect",
        data=body,
        headers={"Cookie": cookie, "Content-Type": "application/json"},
    )
    assert status == 200
    report = payload["report"]
    assert report["schema"] == "ros-security-graph/v1"
    assert report["execution"] == "not_executed"
    assert report["nodes"]
    assert report["edges"]
    assert report["findings"]
    assert marker.exists() is False


def test_ros_graph_inspect_rejects_extra_fields_and_oversized_batches(server):
    cookie = login(server)
    extra_body = json.dumps({
        "files": [{"filename": "controller.py", "source": "x = 1"}],
        "execute": True,
    }).encode()
    status, _, payload = request_json(
        f"{server}/api/ros-graph/inspect",
        data=extra_body,
        headers={"Cookie": cookie, "Content-Type": "application/json"},
    )
    assert status == 400
    assert payload["error"]["code"] == "invalid_ros_graph_request"

    oversized_body = json.dumps({
        "files": [{"filename": "controller.py", "source": "x" * (600 * 1024)}],
    }).encode()
    status, _, payload = request_json(
        f"{server}/api/ros-graph/inspect",
        data=oversized_body,
        headers={"Cookie": cookie, "Content-Type": "application/json"},
    )
    assert status == 413
    assert payload["error"]["code"] == "ros_graph_request_too_large"
