"""Contract tests for bounded industrial ROS 2 source inspection."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace

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
    assert report["assurance"]["mode"] == "STATIC_ONLY"
    assert report["assurance"]["runtime_verified"] is False
    assert report["assurance"]["coverage_score"] >= 60
    assert any(item["id"] == "publish_path_guarded" and item["passed"] for item in report["assurance"]["checks"])


def test_model_eval_method_is_not_treated_as_dynamic_execution():
    report = inspect_source(
        """
class Model:
    def eval(self):
        return self

model = Model()
model.eval()
policy.eval()
model.to("cpu").eval()
reward_model.to(device).eval()
""",
        filename="model_eval.py",
    )
    assert "DYN-001" not in {item["rule_id"] for item in report["findings"]}


def test_attribute_named_eval_is_not_treated_as_dynamic_execution():
    report = inspect_source(
        """
class Evaluator:
    def eval(self, value):
        return value

evaluator = Evaluator()
evaluator.eval(untrusted_input)
""",
        filename="attribute_eval.py",
    )
    assert "DYN-001" not in {item["rule_id"] for item in report["findings"]}


def test_bare_eval_call_remains_a_dynamic_execution_finding():
    report = inspect_source(
        """
untrusted_input = "robot_command"
eval(untrusted_input)
""",
        filename="bare_eval.py",
    )
    assert "DYN-001" in {item["rule_id"] for item in report["findings"]}


def test_secret_rule_uses_identifier_boundaries():
    report = inspect_source(
        """
tokenizer = "byte_pair"
fast_tokenizer = tokenizer
api_key = "factory-key"
""",
        filename="identifier_names.py",
    )
    findings = [item for item in report["findings"] if item["rule_id"] == "SEC-001"]
    assert len(findings) == 1
    assert findings[0]["line"] == 4


def test_safety_keywords_in_comments_do_not_count_as_actuator_gates():
    source = """
# estop and SAFE_STOP are documented here, but never checked in the callback.
from rclpy.node import Node

class CommentOnlyGate(Node):
    def __init__(self):
        super().__init__("comment_only_gate")
        self.pub = self.create_publisher(object, "/cmd_vel", 10)

    def callback(self, msg):
        self.pub.publish(msg)
"""
    report = inspect_source(source, filename="comment_only_gate.py")
    rule_ids = {item["rule_id"] for item in report["findings"]}
    assert "ACT-001" in rule_ids
    assert "ACT-002" in rule_ids
    assert any(item["id"] == "publish_path_guarded" and not item["passed"]
               for item in report["assurance"]["checks"])


def control_source(body):
    import textwrap
    return '''from rclpy.node import Node
from geometry_msgs.msg import Twist
class Controller(Node):
    def __init__(self):
        self.speed_limit = 0.2
        self.pub = self.create_publisher(Twist, "/cmd_vel", 10)
    def callback(self, cmd):
''' + textwrap.indent(textwrap.dedent(body).strip(), "        ") + "\n"


@pytest.mark.parametrize("body", [
    'if "estop":\n    return\nself.pub.publish(cmd)',
    'if not self.estop:\n    return\nself.pub.publish(cmd)',
    'if self.estop:\n    if self.debug:\n        return\nself.pub.publish(cmd)',
    'if self.debug:\n    if self.estop:\n        return\nself.pub.publish(cmd)',
    'self.pub.publish(cmd)\nif self.estop:\n    return',
])
def test_wrong_or_conditional_guards_do_not_clear_publish_finding(body):
    report = inspect_source(control_source(body))
    assert "ACT-002" in {f["rule_id"] for f in report["findings"]}


@pytest.mark.parametrize("body", [
    'if self.estop:\n    return\nself.pub.publish(cmd)',
    'if not self.mission_allowed:\n    return\nself.pub.publish(cmd)',
    'if self.mission_allowed:\n    self.pub.publish(cmd)',
    'if not self.estop:\n    self.pub.publish(cmd)',
])
def test_supported_guard_direction_covers_only_its_publish_path(body):
    report = inspect_source(control_source(body))
    assert "ACT-002" not in {f["rule_id"] for f in report["findings"]}


@pytest.mark.parametrize("body", [
    'cmd.linear.x = 1.5\nself.pub.publish(cmd)',
    'speed_limit = 0.2\nself.pub.publish(cmd)',
    'cmd.linear.x = min(self.speed_limit, cmd.linear.x)\nself.pub.publish(cmd)',
    'other.linear.x = max(-self.speed_limit, min(self.speed_limit, other.linear.x))\nself.pub.publish(cmd)',
    'cmd.linear.x = max(-self.speed_limit, min(self.speed_limit, cmd.linear.x))\ncmd.linear.x = 2.0\nself.pub.publish(cmd)',
    'if self.debug:\n    cmd.linear.x = max(-self.speed_limit, min(self.speed_limit, cmd.linear.x))\nself.pub.publish(cmd)',
])
def test_assignment_or_unrelated_clamp_does_not_count_as_velocity_bound(body):
    report = inspect_source(control_source(body))
    assert "ACT-001" in {f["rule_id"] for f in report["findings"]}


def test_supported_guard_and_clamp_report_real_publish_line():
    source = control_source('''
        if self.estop:
            return
        cmd.linear.x = max(-self.speed_limit, min(self.speed_limit, cmd.linear.x))
        self.pub.publish(cmd)
    ''')
    report = inspect_source(source)
    assert not {"ACT-001", "ACT-002"} & {f["rule_id"] for f in report["findings"]}
    path = report["assurance"]["publish_paths"][0]
    assert path["line"] == 11
    assert path["guarded"] is True and path["limited"] is True


def test_same_publisher_name_in_another_class_cannot_hide_an_unsafe_path():
    source = control_source('self.pub.publish(cmd)') + '''
class Telemetry:
    def __init__(self):
        self.pub = self.create_publisher(object, "/telemetry", 10)
    def callback(self, msg):
        self.pub.publish(msg)
'''
    report = inspect_source(source)
    assert {"ACT-001", "ACT-002"} <= {f["rule_id"] for f in report["findings"]}


@pytest.mark.parametrize("source", ["print('hello')", "def broken(:\n pass"])
def test_insufficient_source_evidence_never_claims_velocity_coverage(source):
    report = inspect_source(source)
    check = next(c for c in report["assurance"]["checks"] if c["id"] == "velocity_boundary")
    assert check["passed"] is False
    assert report["assurance"]["runtime_verified"] is False
    assert report["summary"]["verdict"] != "PASS"


def test_checked_in_industrial_fixtures_match_the_builtin_profile():
    safe = (ROOT / "experiments" / "industrial_conveyor_arm_safe.py").read_text(encoding="utf-8")
    unsafe = (ROOT / "experiments" / "industrial_conveyor_arm_unsafe.py").read_text(encoding="utf-8")
    assert inspect_source(safe, filename="industrial_conveyor_arm_safe.py")["summary"]["verdict"] == "PASS"
    assert inspect_source(unsafe, filename="industrial_conveyor_arm_unsafe.py")["summary"]["verdict"] == "BLOCKED"


def test_gazebo_ros2_amr_fixture_is_available_as_a_builtin_source_sample():
    sample = next(item for item in sample_catalog() if item["id"] == "gazebo_amr_unsafe")
    source = sample["source"]
    fixture = (ROOT / "experiments" / "gazebo_ros2_amr_controller_unsafe.py").read_text(encoding="utf-8")

    assert sample["profile"] == "conveyor_robot_arm"
    assert "Gazebo" in sample["title"]
    assert "/model/amr_07/cmd_vel" in source
    assert "ros_gz" in source
    assert source == fixture

    report = inspect_source(source, filename="gazebo_ros2_amr_controller_unsafe.py")
    assert report["summary"]["critical"] >= 1
    assert report["guardian_mapping"]["state"] == "SAFE_STOP"
    assert "/model/amr_07/cmd_vel" in report["topics"]
    assert "ROS 2 启动入口" in report["assurance"]["missing_controls"]
    assert "未启动 ROS 2/Gazebo" in " ".join(report["assurance"]["limitations"])


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
    assert {item["id"] for item in payload["samples"]} >= {"safe_conveyor", "unsafe_conveyor", "gazebo_amr_unsafe"}

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


def test_code_security_jev_endpoint_uses_saved_key_and_sends_summary_without_source():
    calls = []

    class FakeJevService:
        def test(self, api_key, state):
            calls.append((api_key, state))
            return SimpleNamespace(
                http_status=200,
                payload={
                    "status": "OK",
                    "connected": True,
                    "assessment": {
                        "status": "OK",
                        "label": "unsafe_command",
                        "score": 0.94,
                        "confidence": 0.91,
                        "mission_impact": "critical",
                        "needs_human_review": True,
                        "model": "jev-code-test",
                        "reason": "static findings indicate an unsafe actuator path",
                    },
                },
            )

    auth = DashboardAuth(username="admin", password="admin", ttl_sec=60)
    http = DashboardHTTPServer(
        ("127.0.0.1", 0),
        DashboardState(),
        FRONTEND,
        jev_service=FakeJevService(),
        auth=auth,
    )
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{http.server_port}"
        cookie = login(base)
        status, _, payload = request_json(
            f"{base}/api/jev/key",
            data=b'{"api_key":"saved-code-jev-key"}',
            headers={"Cookie": cookie, "Content-Type": "application/json"},
        )
        assert status == 200
        source = next(item for item in sample_catalog() if item["id"] == "gazebo_amr_unsafe")["source"]
        status, _, payload = request_json(
            f"{base}/api/code-security/jev-evaluate",
            data=json.dumps({
                "source": source,
                "filename": "gazebo_ros2_amr_controller_unsafe.py",
                "profile": "conveyor_robot_arm",
            }).encode(),
            headers={"Cookie": cookie, "Content-Type": "application/json"},
        )
        assert status == 200
        assert payload["status"] == "OK"
        assert payload["report"]["summary"]["verdict"] == "BLOCKED"
        assert payload["jev"]["assessment"]["confidence"] == 0.91
        assert payload["jev"]["source_sent_to_jev"] is False
        assert len(calls) == 1
        assert calls[0][0] == "saved-code-jev-key"
        context = json.loads(calls[0][1])
        assert context["kind"] == "industrial_code_security"
        assert context["filename"] == "gazebo_ros2_amr_controller_unsafe.py"
        assert "source" not in context
        assert "findings" in context
        assert context["findings"][0]["rule_id"] == "DYN-001"
        assert context["evidence_boundary"] == "STATIC_ONLY"
        assert context["execution"] == "not_executed"
        assert context["assurance"]["mode"] == "STATIC_ONLY"
        assert context["assurance"]["runtime_verified"] is False
        assert context["assurance"]["source_executed"] is False
    finally:
        http.shutdown()
        http.server_close()
        thread.join(timeout=2)


def test_code_security_jev_endpoint_requires_a_saved_or_typed_key(server):
    source = next(item for item in sample_catalog() if item["id"] == "unsafe_conveyor")["source"]
    cookie = login(server)
    status, _, payload = request_json(
        f"{server}/api/code-security/jev-evaluate",
        data=json.dumps({
            "source": source,
            "filename": "unsafe.py",
            "profile": "conveyor_robot_arm",
        }).encode(),
        headers={"Cookie": cookie, "Content-Type": "application/json"},
    )
    assert status == 400
    assert payload["error"]["code"] == "missing_api_key"


def test_frontend_exposes_code_security_workspace():
    html = (FRONTEND / "index.html").read_text(encoding="utf-8")
    script = (FRONTEND / "app.js").read_text(encoding="utf-8")
    assert "工业代码安全检查" in html
    assert "code-security" in html
    assert "/api/code-security/inspect" in script
    assert "/api/code-security/jev-evaluate" in script
    assert 'id="code-security-jev-run"' in html
    assert 'id="code-security-jev-result"' in html
    assert 'id="code-security-jev-confidence"' in html
