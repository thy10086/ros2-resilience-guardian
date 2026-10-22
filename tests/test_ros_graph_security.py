import pytest

from guardian_core.ros_graph_security import GraphSecurityError, inspect_project, sample_catalog


SAFE_CONTROLLER = """
import rclpy
from geometry_msgs.msg import Twist
from rclpy.node import Node

class SafeController(Node):
    def __init__(self):
        super().__init__("safe_controller")
        self.estop = False
        self.speed_limit = 0.20
        self.drive_pub = self.create_publisher(Twist, "/cmd_vel", 10)

    def publish_drive(self, command):
        if self.estop:
            return
        command.linear.x = max(-self.speed_limit, min(self.speed_limit, command.linear.x))
        self.drive_pub.publish(command)

def main():
    rclpy.init()
    rclpy.spin(SafeController())
    rclpy.shutdown()
"""


UNSAFE_CONTROLLER = """
import subprocess
from rclpy.node import Node

class UnsafeController(Node):
    def __init__(self):
        super().__init__("unsafe_controller")
        self.drive_pub = self.create_publisher(object, "/cmd_vel", 10)

    def callback(self, message):
        eval(message.command)
        subprocess.run(["sh", "-c", message.command])
        self.drive_pub.publish(message)
"""


def test_safe_python_controller_builds_publisher_and_guard_edges():
    report = inspect_project([{"filename": "controller.py", "source": SAFE_CONTROLLER}])

    assert report["schema"] == "ros-security-graph/v1"
    assert "topic:/cmd_vel" in {item["id"] for item in report["nodes"]}
    assert any(edge["kind"] == "publishes" for edge in report["edges"])
    assert report["summary"]["verdict"] == "PASS"
    assert report["assurance"]["source_executed"] is False


def test_unsafe_control_path_reports_dynamic_execution_and_unbounded_velocity():
    report = inspect_project([{"filename": "unsafe.py", "source": UNSAFE_CONTROLLER}])

    rule_ids = {item["rule_id"] for item in report["findings"]}
    assert "GRAPH-DYN-001" in rule_ids
    assert "GRAPH-ACT-002" in rule_ids
    assert report["summary"]["verdict"] == "BLOCKED"
    assert report["paths"]
    assert all(path["node_ids"] for path in report["paths"])


def test_unsupported_cpp_is_visible_and_not_passed():
    report = inspect_project([{
        "filename": "controller.cpp",
        "source": "publisher_->publish(command);",
    }])

    assert report["unsupported_files"] == ["controller.cpp"]
    assert report["summary"]["verdict"] == "BLOCKED"
    assert any(item["provenance"] == "UNSUPPORTED" for item in report["nodes"])


@pytest.mark.parametrize("files", [
    [{"filename": "../unsafe.py", "source": "x = 1"}],
    [{"filename": "/tmp/unsafe.py", "source": "x = 1"}],
    [{"filename": "unsafe.py\x00", "source": "x = 1"}],
])
def test_graph_input_rejects_unsafe_paths(files):
    with pytest.raises(GraphSecurityError):
        inspect_project(files)


def test_graph_input_rejects_duplicate_files_and_total_budget():
    with pytest.raises(GraphSecurityError):
        inspect_project([
            {"filename": "same.py", "source": "x = 1"},
            {"filename": "same.py", "source": "x = 2"},
        ])

    with pytest.raises(GraphSecurityError):
        inspect_project([
            {"filename": f"file-{index}.py", "source": "x" * 5000}
            for index in range(110)
        ])


def test_samples_include_safe_and_unsafe_multifile_cases():
    samples = sample_catalog()

    assert {item["id"] for item in samples} >= {"safe_controller", "unsafe_controller"}
    assert all(isinstance(item["files"], list) and item["files"] for item in samples)


def test_control_config_without_permission_summary_requires_review():
    report = inspect_project([{
        "filename": "configs/guardian.yaml",
        "source": "controller_topic: /cmd_vel\n",
    }])

    finding = next(item for item in report["findings"] if item["rule_id"] == "GRAPH-PERM-001")
    assert finding["guardian_action"] == "REVIEW_REQUIRED"
    assert finding["severity"] == "medium"
    assert report["summary"]["verdict"] == "REVIEW"


def test_control_config_with_permission_summary_is_not_flagged_for_permission():
    report = inspect_project([{
        "filename": "configs/guardian.yaml",
        "source": (
            "profile_id: manipulator-runtime\n"
            "adapter_id: ros2-control-adapter\n"
            "permissions: allow /cmd_vel\n"
            "controller_topic: /cmd_vel\n"
        ),
    }])

    assert "GRAPH-PERM-001" not in {item["rule_id"] for item in report["findings"]}
