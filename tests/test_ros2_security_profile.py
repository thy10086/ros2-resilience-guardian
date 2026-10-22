import json

import pytest

from guardian_core.security_profile import parse_security_profile


def test_profile_supports_non_vehicle_ros2_resources():
    profile = parse_security_profile(json.dumps({
        "profile_id": "manipulator-runtime",
        "adapter_id": "ros2-control-adapter",
        "trusted_sources": ["controller_monitor"],
        "resources": {
            "joint_1_controller": {"tau": 2, "epsilon": 0, "mitigatable": True},
            "wrench_sensor": {"tau": 0, "epsilon": 1, "mitigatable": False},
        },
    }))

    assert profile.profile_id == "manipulator-runtime"
    assert profile.adapter_id == "ros2-control-adapter"
    assert profile.trusted_sources == frozenset({"controller_monitor"})
    assert profile.tau == {"joint_1_controller": 2, "wrench_sensor": 0}
    assert profile.epsilon == {"joint_1_controller": 0, "wrench_sensor": 1}
    assert profile.mitigatable_devices == frozenset({"joint_1_controller"})


def test_profile_rejects_duplicate_nested_keys():
    payload = (
        '{"profile_id":"p","adapter_id":"a","trusted_sources":["s"],'
        '"resources":{"joint":{"tau":1,"tau":2,"epsilon":0,"mitigatable":true}}}'
    )

    with pytest.raises(ValueError, match="duplicate security profile key"):
        parse_security_profile(payload)


@pytest.mark.parametrize("payload", [
    '{"profile_id":"p","adapter_id":"a","trusted_sources":[],"resources":{"joint":{"tau":1,"epsilon":0,"mitigatable":true}}}',
    '{"profile_id":"p","adapter_id":"a","trusted_sources":["s"],"resources":{"joint":{"tau":-1,"epsilon":0,"mitigatable":true}}}',
    '{"profile_id":"p","adapter_id":"a","trusted_sources":["s"],"resources":{"joint":{"tau":1,"epsilon":0,"mitigatable":"yes"}}}',
])
def test_profile_rejects_unsafe_shape(payload):
    with pytest.raises(ValueError):
        parse_security_profile(payload)
