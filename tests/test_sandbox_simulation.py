from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

import guardian_core.sandbox_simulation as sandbox_simulation
from guardian_core.dashboard import DashboardHTTPServer
from guardian_core.dashboard_auth import DashboardAuth
from guardian_core.dashboard_state import DashboardState
from guardian_core.sandbox_simulation import (
    SANDBOX_SCHEMA,
    SandboxInputError,
    inspect_sandbox_input,
    run_sandbox,
    sample_catalog,
)

from tests.test_dashboard_experiments import request_json


ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "ros2_ws" / "src" / "guardian_core" / "guardian_core" / "frontend"


SAFE_CONTROLLER = """
import math

def control(state):
    if state["estop"] or not state["mission_allowed"]:
        return {"linear_x": 0.0, "angular_z": 0.0}
    if state["distance_to_obstacle"] < 0.65:
        return {"linear_x": 0.0, "angular_z": 0.0}
    return {"linear_x": min(0.25, state["safety_limit"]), "angular_z": 0.0}
"""


UNSAFE_CONTROLLER = """
def control(state):
    return {"linear_x": 1.4, "angular_z": 0.0}
"""


MINIMAL_SDF = """<?xml version="1.0"?>
<sdf version="1.9">
  <world name="sandbox">
    <model name="obstacle">
      <pose>1.25 0 0.5 0 0 0</pose>
      <link name="link">
        <collision name="collision">
          <geometry><box><size>0.5 1.0 1.0</size></box></geometry>
        </collision>
      </link>
    </model>
  </world>
</sdf>
"""


def test_python_input_contract_rejects_host_capabilities():
    with pytest.raises(SandboxInputError, match="不允许"):
        inspect_sandbox_input("import os\n\ndef control(state):\n return {}", filename="bad.py")

    with pytest.raises(SandboxInputError, match="control"):
        inspect_sandbox_input("value = 1", filename="bad.py")

    with pytest.raises(SandboxInputError, match="反射"):
        inspect_sandbox_input(
            "def control(state):\n return ().__class__\n",
            filename="reflection.py",
        )


def test_xml_input_contract_rejects_external_features():
    with pytest.raises(SandboxInputError, match="DOCTYPE"):
        inspect_sandbox_input("<!DOCTYPE sdf><sdf/>", filename="bad.sdf")

    with pytest.raises(SandboxInputError, match="plugin"):
        inspect_sandbox_input("<sdf><world><plugin filename=\"x\"/></world></sdf>", filename="bad.sdf")


def test_sample_catalog_contains_runnable_python_and_sdf_cases():
    samples = {item["id"]: item for item in sample_catalog()}
    assert {"safe_controller", "unsafe_controller", "warehouse_obstacle_sdf"} <= set(samples)
    assert samples["safe_controller"]["kind"] == "python"
    assert samples["warehouse_obstacle_sdf"]["kind"] == "sdf"


@pytest.mark.skipif(
    not (Path("/usr/bin/unshare").exists() or Path("/usr/bin/docker").exists()),
    reason="没有可用的隔离执行器",
)
def test_safe_python_controller_produces_trace_and_safe_evidence():
    report = run_sandbox(SAFE_CONTROLLER, filename="safe_controller.py", kind="python", duration_sec=2.0)
    if report["status"] == "UNAVAILABLE":
        pytest.skip(report["sandbox"]["reason"])
    assert report["schema"] == SANDBOX_SCHEMA
    assert report["sandbox"]["isolated"] is True
    assert report["source_executed"] is True
    assert report["trace"]
    assert report["metrics"]["steps"] > 0
    assert report["metrics"]["collision_steps"] == 0
    assert report["verdict"] in {"PASS", "REVIEW"}


@pytest.mark.skipif(
    not (Path("/usr/bin/unshare").exists() or Path("/usr/bin/docker").exists()),
    reason="没有可用的隔离执行器",
)
def test_unsafe_python_controller_exposes_runtime_measurements():
    report = run_sandbox(UNSAFE_CONTROLLER, filename="unsafe_controller.py", kind="python", duration_sec=2.0)
    if report["status"] == "UNAVAILABLE":
        pytest.skip(report["sandbox"]["reason"])
    assert report["source_executed"] is True
    assert report["metrics"]["max_requested_speed"] > report["metrics"]["safety_limit"]
    assert report["metrics"]["overspeed_steps"] > 0
    assert any(event["type"] == "OVERSPEED_COMMAND" for event in report["events"])
    assert report["verdict"] in {"REVIEW", "BLOCKED"}


def test_sdf_case_reports_model_validation_and_builtin_controller():
    report = run_sandbox(MINIMAL_SDF, filename="warehouse.sdf", kind="sdf", duration_sec=2.0)
    assert report["input_kind"] == "sdf"
    assert report["source_executed"] is False
    assert report["execution_mode"] == "builtin_controller"
    assert report["model"]["obstacle_count"] == 1
    assert report["trace"]
    assert report["metrics"]["min_obstacle_distance"] is not None
    assert report["sandbox"]["isolated"] is False


def test_sandbox_jev_context_contains_measurements_but_not_source():
    report = run_sandbox(SAFE_CONTROLLER, filename="safe.py", kind="python", duration_sec=0.5)
    context = json.dumps(report["jev_context"], ensure_ascii=False)
    assert "safe_controller" not in context
    assert "source" not in report["jev_context"]
    assert "metrics" in report["jev_context"]


def test_python_sandbox_fails_closed_when_no_isolation_provider(monkeypatch):
    monkeypatch.setattr(
        sandbox_simulation,
        "sandbox_runtime_status",
        lambda: {
            "provider": "none",
            "available": False,
            "isolated": False,
            "network_disabled": True,
            "reason": "test unavailable",
            "boundary": "未执行源码",
        },
    )
    report = sandbox_simulation.run_sandbox(
        SAFE_CONTROLLER,
        filename="safe.py",
        kind="python",
        duration_sec=0.5,
    )
    assert report["status"] == "UNAVAILABLE"
    assert report["source_executed"] is False
    assert report["sandbox"]["provider"] == "none"


def test_sandbox_http_endpoint_is_authenticated_and_bounded():
    http = DashboardHTTPServer(
        ("127.0.0.1", 0),
        DashboardState(),
        FRONTEND,
        auth=DashboardAuth(username="admin", password="admin", ttl_sec=60),
    )
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{http.server_port}"
        status, _, payload = request_json(f"{base}/api/sandbox/samples")
        assert status == 401
        assert payload["error"]["code"] == "auth_required"
        status, headers, _ = request_json(
            f"{base}/api/login",
            data=b'{"username":"admin","password":"admin"}',
            headers={"Content-Type": "application/json"},
        )
        assert status == 200
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        status, _, payload = request_json(
            f"{base}/api/sandbox/samples",
            headers={"Cookie": cookie},
        )
        assert status == 200
        assert payload["schema"] == SANDBOX_SCHEMA
        status, _, payload = request_json(
            f"{base}/api/sandbox/run",
            data=json.dumps({
                "source": SAFE_CONTROLLER,
                "filename": "safe.py",
                "kind": "python",
                "duration_sec": 0.5,
            }).encode(),
            headers={"Cookie": cookie, "Content-Type": "application/json"},
        )
        assert status == 200
        assert payload["status"] in {"OK", "UNAVAILABLE"}
        assert payload["report"]["schema"] == SANDBOX_SCHEMA
    finally:
        http.shutdown()
        http.server_close()
        thread.join(timeout=2)
