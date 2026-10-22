from types import SimpleNamespace

import hashlib
import hmac
import json

import pytest

from guardian_core import feedback_auth


@pytest.mark.parametrize("kind,sign,verify,data", [
    ("mitigation_command", feedback_auth.sign_command, feedback_auth.verify_command,
        dict(profile_id="amr-default", command_epoch=1, transmission_id=1,
            adapter_id="default-actuator", plan_id="none", action="NONE",
            components=[], requires_safe_stop=False)),
    ("safety_status", feedback_auth.sign_status, feedback_auth.verify_status,
        dict(profile_id="amr-default", command_epoch=1, transmission_id=1,
            adapter_id="default-actuator", plan_id="none", state="NORMAL",
            speed_limit=0.25, mission_allowed=True)),
])
def test_motion_authorization_rejects_legacy_signatures_and_binds_time(kind, sign, verify, data):
    legacy_payload = json.dumps({"kind": kind, **data}, ensure_ascii=True,
        sort_keys=True, separators=(",", ":")).encode("ascii")
    legacy_signature = hmac.new(b"test-secret", legacy_payload, hashlib.sha256).hexdigest()
    assert not verify(b"test-secret", legacy_signature, timestamp=10.0, **data)
    assert not verify(b"test-secret", legacy_signature, **data)
    signature = sign(b"test-secret", timestamp=10.0, **data)
    assert verify(b"test-secret", signature, timestamp=10.0, **data)
    assert not verify(b"test-secret", signature, timestamp=10.1, **data)


def fields():
    return dict(timestamp=1.0, profile_id="amr-default", adapter_id="default-actuator",
        command_epoch=2, transmission_id=4, observation_sequence=8,
        actual_speed=0.0, free_distance=5.0, sensor_fresh=True, attack_active=False,
        commands_cleared=True, probe_success=True)


def test_recovery_telemetry_authenticates_every_safety_field():
    data = fields()
    signature = feedback_auth.sign_recovery_telemetry(b"secret", **data)
    assert feedback_auth.verify_recovery_telemetry(b"secret", signature, **data)
    for key, value in data.items():
        changed = dict(data)
        changed[key] = not value if type(value) is bool else (
            value + 1 if type(value) in (int, float) else value + "x")
        assert not feedback_auth.verify_recovery_telemetry(b"secret", signature, **changed)
    assert not feedback_auth.verify_recovery_telemetry(None, signature, **data)
    assert not feedback_auth.verify_recovery_telemetry(b"wrong", signature, **data)


def test_native_ros_graph_fingerprint_changes_with_endpoint_restart():
    from guardian_core.recovery_graph import recovery_graph_fingerprint
    class Graph:
        gid = 1
        def get_publishers_info_by_topic(self, topic):
            name = "amr_simulator" if topic.endswith("recovery_telemetry") else "guardian_node"
            return [SimpleNamespace(node_name=name, node_namespace="/", topic_type="test/msg/T",
                endpoint_gid=[self.gid] * 16)]
        def get_subscriptions_info_by_topic(self, topic):
            name = "guardian_node" if topic.endswith("recovery_telemetry") else "amr_simulator"
            return [SimpleNamespace(node_name=name, node_namespace="/", topic_type="test/msg/T",
                endpoint_gid=[3] * 16)]
        def resolve_topic_name(self, topic):
            return "/" + topic
    graph = Graph()
    before = recovery_graph_fingerprint(graph)
    assert before
    graph.gid = 2
    assert recovery_graph_fingerprint(graph) != before
    graph.get_publishers_info_by_topic = lambda topic: []
    assert recovery_graph_fingerprint(graph) == ""
