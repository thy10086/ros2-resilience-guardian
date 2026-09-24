"""Contract tests for bounded industrial ROS 2 source inspection."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from guardian_core.dashboard import DashboardHTTPServer
from guardian_core.dashboard_auth import DashboardAuth
from guardian_core.dashboard_code_security import (
    CODE_SECURITY_SCHEMA,
    CodeSecurityError,
    inspect_source,
    sample_catalog,
)
from guardian_core.dashboard_state import DashboardState


ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "ros2_ws" / "src" / "guardian_core" / "guardian_core" / "frontend"


def request_json(url: str, *, data: bytes | None = None, headers: dict[str, str] | None = None):
    request = urllib.request.Request(url, data=data, headers=headers or {}, method="POST" if data is not None else "GET")
    try:
        with urllib.request.urlopen(request, timeout=2) as response:
            return response.status, dict(response.headers), json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers), json.loads(error.read())


@pytest.fixture()
def server():
    http = DashboardHTTPServer(
        ("127.0.0.1", 0),
        DashboardState(),
        FRONTEND,
        auth=DashboardAuth(username="admin", password="admin", ttl_sec=60),
    )
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{http.server_port}"
    finally:
        http.shutdown()
        http.server_close()
        thread.join(timeout=2)


def login(server: str) -> str:
    status, headers, _ = request_json(
        f"{server}/api/login",
        data=b'{"username":"admin","password":"admin"}',
        headers={"Content-Type": "application/json"},
    )
    assert status == 200
    return headers["Set-Cookie"].split(";", 1)[0]


def test_unsafe_industrial_source_maps_to_guardian_containment():
    source = """
import subprocess
from rclpy.node import Node

class Line(Node):
    def __init__(self):
        super().__init__("line")
        self.pub = self.create_publisher(Twist, "/cmd_vel", 10)
        self.password = "factory-admin-password"

    def callback(self, msg):
        eval(msg.command)
        self.pub.publish(msg)
"""
    report = inspect_source(source, filename="unsafe_line.py")
    assert report["schema"] == CODE_SECURITY_SCHEMA
    assert report["profile"] == "conveyor_robot_arm"
    assert "/cmd_vel" in report["topics"]
    rule_ids = {item["rule_id"] for item in report["findings"]}
    assert {"DYN-001", "SEC-001", "ACT-001", "ACT-002"} <= rule_ids
    assert report["summary"]["critical"] >= 1
    assert report["guardian_mapping"]["state"] == "SAFE_STOP"
    assert "factory-admin-password" not in json.dumps(report, ensure_ascii=False)
    assert "factory-admin" not in json.dumps(report, ensure_ascii=False)
    assert report["guardian_mapping"]["action"] == "SAFE_STOP"


def test_bounded_source_has_no_critical_findings():
    sample = next(item for item in sample_catalog() if item["id"] == "safe_conveyor")
    report = inspect_source(sample["source"], filename="safe_conveyor.py")
    assert report["summary"]["critical"] == 0
    assert report["summary"]["high"] == 0
    assert report["guardian_mapping"]["state"] in {"NORMAL", "REVIEW"}
    assert {"/cmd_vel", "/joint_trajectory", "/gripper/command"} <= set(report["topics"])


def test_checked_in_industrial_fixtures_match_the_builtin_profile():
    safe = (ROOT / "experiments" / "industrial_conveyor_arm_safe.py").read_text(encoding="utf-8")
    unsafe = (ROOT / "experiments" / "industrial_conveyor_arm_unsafe.py").read_text(encoding="utf-8")
    assert inspect_source(safe, filename="industrial_conveyor_arm_safe.py")["summary"]["verdict"] == "PASS"
    assert inspect_source(unsafe, filename="industrial_conveyor_arm_unsafe.py")["summary"]["verdict"] == "BLOCKED"


def test_syntax_error_is_a_bounded_blocking_finding():
    report = inspect_source("def broken(:\n  pass\n", filename="broken.py")
    assert report["summary"]["critical"] == 1
    assert report["findings"][0]["rule_id"] == "PARSE-001"
    assert report["guardian_mapping"]["state"] == "SAFE_STOP"


@pytest.mark.parametrize("value", ["", "x" * 65537])
def test_source_size_is_bounded(value):
    with pytest.raises(CodeSecurityError):
        inspect_source(value)


def test_code_security_http_contract_is_authenticated_and_bounded(server):
    status, _, payload = request_json(f"{server}/api/code-security/samples")
    assert status == 401
    assert payload["error"]["code"] == "auth_required"

    cookie = login(server)
    status, _, payload = request_json(f"{server}/api/code-security/samples", headers={"Cookie": cookie})
    assert status == 200
    assert payload["schema"] == CODE_SECURITY_SCHEMA
    assert {item["id"] for item in payload["samples"]} >= {"safe_conveyor", "unsafe_conveyor"}

    source = next(item for item in payload["samples"] if item["id"] == "unsafe_conveyor")["source"]
    status, _, payload = request_json(
        f"{server}/api/code-security/inspect",
        data=json.dumps({"source": source, "filename": "unsafe.py"}).encode(),
        headers={"Cookie": cookie, "Content-Type": "application/json"},
    )
    assert status == 200
    assert payload["status"] == "OK"
    assert payload["report"]["guardian_mapping"]["state"] == "SAFE_STOP"

    status, _, payload = request_json(
        f"{server}/api/code-security/inspect",
        data=b'{"source": "x", "extra": true}',
        headers={"Cookie": cookie, "Content-Type": "application/json"},
    )
    assert status == 400
    assert payload["error"]["code"] == "invalid_code_security_request"


def test_frontend_exposes_code_security_workspace():
    html = (FRONTEND / "index.html").read_text(encoding="utf-8")
    script = (FRONTEND / "app.js").read_text(encoding="utf-8")
    assert "工业代码安全检查" in html
    assert "code-security" in html
    assert "/api/code-security/inspect" in script
