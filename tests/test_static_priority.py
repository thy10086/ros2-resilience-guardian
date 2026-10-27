"""Regression cases for static control-name, guard-write and corpus boundaries."""

import pytest

from guardian_core.dashboard_code_security import inspect_source
from guardian_core.dataset_security import DatasetSecurityError, catalog_dataset, scan_dataset
from guardian_core.ros_graph_security import inspect_project


def controller(topic="cmd_vel", *, namespace="", guard="estop", write=""):
    return f'''
import rclpy
from rclpy.node import Node
class Drive(Node):
    def __init__(self):
        super().__init__("drive"{namespace})
        self.pub = self.create_publisher(object, {topic!r}, 10)
    def send(self, msg):
        if self.{guard}:
            return
        {write or 'pass'}
        msg.linear.x = max(-0.2, min(0.2, msg.linear.x))
        self.pub.publish(msg)
def main():
    rclpy.init()
    rclpy.spin(Drive())
    rclpy.shutdown()
'''


def test_relative_control_name_builds_root_control_path_and_risk():
    source = controller().replace("        if self.estop:\n            return\n", "")
    report = inspect_source(source)
    assert report["topics"] == ["/cmd_vel"]
    path, = report["assurance"]["publish_paths"]
    assert path["topic"] == "/cmd_vel"
    assert path["original_topic"] == "cmd_vel"
    assert path["guarded"] is False
    graph = inspect_project([{"filename": "drive.py", "source": source}])
    assert any(n["id"] == "topic:/cmd_vel" and n["kind"] == "actuator" for n in graph["nodes"])
    assert "GRAPH-ACT-001" in {f["rule_id"] for f in graph["findings"]}
    assert graph["summary"]["verdict"] == "REVIEW"


def test_module_level_relative_publisher_keeps_control_path():
    report = inspect_source('''
from rclpy.node import Node
node = Node("drive")
pub = node.create_publisher(object, "cmd_vel", 10)
pub.publish(command)
''')
    assert report["topics"] == ["/cmd_vel"]
    path, = report["assurance"]["publish_paths"]
    assert path["guarded"] is False
    assert "ACT-002" in {f["rule_id"] for f in report["findings"]}


def test_literal_namespace_resolves_separate_control_endpoint():
    source = controller(namespace=', namespace="/robot_7"')
    report = inspect_source(source)
    assert report["topics"] == ["/robot_7/cmd_vel"]
    path, = report["assurance"]["publish_paths"]
    assert path["original_topic"] == "cmd_vel"
    assert path["resolved_topic"] == "/robot_7/cmd_vel"
    graph = inspect_project([{"filename": "drive.py", "source": source}])
    ids = {n["id"] for n in graph["nodes"]}
    assert "topic:/robot_7/cmd_vel" in ids
    assert "topic:/cmd_vel" not in ids


def test_namespaces_do_not_leak_between_independent_node_classes():
    source = controller().replace("class Drive", "class RootDrive")
    source += controller(namespace=', namespace="/robot_7"').replace("class Drive", "class RobotDrive")
    report = inspect_source(source)
    assert report["topics"] == ["/cmd_vel", "/robot_7/cmd_vel"]
    graph = inspect_project([{"filename": "drive.py", "source": source}])
    assert {"topic:/cmd_vel", "topic:/robot_7/cmd_vel"} <= {n["id"] for n in graph["nodes"]}


def test_factory_namespace_does_not_change_an_independent_root_controller():
    source = controller() + '''
def factory():
    return Node("other", namespace="/other")
'''
    report = inspect_source(source)
    assert report["topics"] == ["/cmd_vel"]
    graph = inspect_project([{"filename": "drive.py", "source": source}])
    assert "topic:/cmd_vel" in {n["id"] for n in graph["nodes"]}


def test_dynamic_publisher_topic_marks_extraction_gap_in_every_consumer(tmp_path):
    source = controller().replace(
        '        self.pub = self.create_publisher(object, \'cmd_vel\', 10)',
        '        self.pub = self.create_publisher(object, "cmd_vel", 10)\n'
        '        self.other = self.create_publisher(object, selected_topic, 10)',
    ).replace('        self.pub.publish(msg)', '        self.pub.publish(msg)\n        self.other.publish(msg)')
    report = inspect_source(source)
    assert report["summary"]["verdict"] == "REVIEW"
    gap, = report["assurance"]["name_resolution_gaps"]
    assert gap["original_topic"] is None
    assert gap["topic_expression"] == "selected_topic"
    assert gap["resolved_topic"] is None
    assert any(f["rule_id"] == "NAME-001" for f in report["findings"])
    graph = inspect_project([{"filename": "drive.py", "source": source}])
    assert graph["summary"]["verdict"] == "REVIEW"
    assert any(f["rule_id"] == "GRAPH-NAME-001" for f in graph["findings"])
    (tmp_path / "drive.py").write_text(source, encoding="utf-8")
    assert scan_dataset(tmp_path)["summary"]["verdict"] == "REVIEW"


def test_create_node_namespace_expands_relative_publisher():
    source = '''
import rclpy
node = rclpy.create_node("drive", namespace="/robot")
pub = node.create_publisher(object, "cmd_vel", 10)
pub.publish(command)
'''
    report = inspect_source(source)
    assert report["topics"] == ["/robot/cmd_vel"]
    path, = report["assurance"]["publish_paths"]
    assert path["resolved_topic"] == "/robot/cmd_vel"
    graph = inspect_project([{"filename": "drive.py", "source": source}])
    assert "topic:/robot/cmd_vel" in {n["id"] for n in graph["nodes"]}
    assert "topic:/cmd_vel" not in {n["id"] for n in graph["nodes"]}


@pytest.mark.parametrize("constructor", ["Node", "rclpy.create_node"])
def test_mixed_node_namespaces_without_receiver_binding_are_unresolved(constructor):
    source = f'''
import rclpy
from rclpy.node import Node
root = {constructor}("root")
other = {constructor}("other", namespace="/other")
pub = root.create_publisher(object, "cmd_vel", 10)
pub.publish(command)
'''
    report = inspect_source(source)
    path, = report["assurance"]["publish_paths"]
    assert path["resolved_topic"] is None
    assert path["name_resolution"] == "UNRESOLVED"
    assert report["summary"]["verdict"] == "REVIEW"
    assert any(f["rule_id"] == "NAME-001" for f in report["findings"])
    graph = inspect_project([{"filename": "drive.py", "source": source}])
    assert "topic:/other/cmd_vel" not in {n["id"] for n in graph["nodes"]}
    assert graph["summary"]["verdict"] == "REVIEW"


def test_unresolved_namespace_is_visible_to_dataset_finding_consumer(tmp_path):
    (tmp_path / "drive.py").write_text(controller(namespace=', namespace=robot_namespace'), encoding="utf-8")
    report = scan_dataset(tmp_path)
    assert report["summary"]["verdict"] == "REVIEW"
    assert any(f["rule_id"] == "NAME-001" for f in report["findings"])


def test_private_control_name_is_a_candidate_with_explicit_resolution_gap():
    report = inspect_source(controller(topic="~/cmd_vel"))
    path, = report["assurance"]["publish_paths"]
    assert path["original_topic"] == "~/cmd_vel"
    assert path["resolved_topic"] is None
    assert report["summary"]["verdict"] == "REVIEW"


def test_graph_config_keeps_namespaced_endpoint_instead_of_root_substring():
    graph = inspect_project([{
        "filename": "robot.yaml", "source": "controller_topic: /robot_7/cmd_vel\n",
    }])
    ids = {n["id"] for n in graph["nodes"]}
    assert "topic:/robot_7/cmd_vel" in ids
    assert "topic:/cmd_vel" not in ids
    assert any(f["rule_id"] == "GRAPH-PERM-001" for f in graph["findings"])


@pytest.mark.parametrize("extra", [', namespace=robot_namespace', ', cli_args=arguments'])
def test_dynamic_name_context_keeps_candidate_path_and_resolution_gap(extra):
    source = controller(namespace=extra)
    report = inspect_source(source)
    path, = report["assurance"]["publish_paths"]
    assert path["original_topic"] == "cmd_vel"
    assert path["resolved_topic"] is None
    assert path["name_resolution"] == "UNRESOLVED"
    assert report["assurance"]["name_resolution_gaps"]
    assert report["summary"]["verdict"] == "REVIEW"
    graph = inspect_project([{"filename": "drive.py", "source": source}])
    assert graph["summary"]["verdict"] == "REVIEW"
    assert "topic:/cmd_vel" not in {n["id"] for n in graph["nodes"]}


@pytest.mark.parametrize("guard, value", [
    ("estop", "True"), ("e_stop", "True"), ("safe_stop", "True"),
    ("emergency_stop", "True"), ("mission_allowed", "False"),
    ("safety_ok", "False"), ("permit", "False"), ("motion_allowed", "False"),
])
@pytest.mark.parametrize("form", ["self.{guard} = {value}", "self.{guard}: bool = {value}", "self.{guard} |= {value}"])
def test_every_recognized_guard_write_invalidates_path(guard, value, form):
    source = controller(topic="/cmd_vel", guard=guard,
                        write=form.format(guard=guard, value=value))
    if guard in {"mission_allowed", "safety_ok", "permit", "motion_allowed"}:
        source = source.replace(f"if self.{guard}:", f"if not self.{guard}:")
    report = inspect_source(source)
    path, = report["assurance"]["publish_paths"]
    assert path["guarded"] is False
    assert "ACT-002" in {f["rule_id"] for f in report["findings"]}


@pytest.mark.parametrize("scanner", [scan_dataset, catalog_dataset])
def test_local_dataset_rejects_symlink_root(tmp_path, scanner):
    real = tmp_path / "real"
    real.mkdir()
    (real / "drive.py").write_text("x = 1", encoding="utf-8")
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)
    with pytest.raises(DatasetSecurityError):
        scanner(linked)


@pytest.mark.parametrize("scanner", [scan_dataset, catalog_dataset])
@pytest.mark.parametrize("filename", ["drive.py", "manifest.json", "model.png"])
def test_local_dataset_rejects_file_symlink_before_opening(tmp_path, scanner, filename):
    root = tmp_path / "corpus"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("eval('untrusted')", encoding="utf-8")
    (root / filename).symlink_to(outside)
    with pytest.raises(DatasetSecurityError):
        scanner(root)
