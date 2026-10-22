import os
import time

import rclpy
from sensor_msgs.msg import LaserScan
from guardian_core.recovery_observer import RecoveryObserverNode


def test_standard_float32_scan_and_odometry_create_valid_independent_sample(monkeypatch):
    from nav_msgs.msg import Odometry
    monkeypatch.setenv("ROS_DOMAIN_ID", str(170 + os.getpid() % 30))
    monkeypatch.setenv("ROS_LOCALHOST_ONLY", "1")
    monkeypatch.setenv("GUARDIAN_FEEDBACK_SECRET", "adapter-key")
    monkeypatch.setenv("GUARDIAN_OBSERVATION_SECRET", "observer-key")
    rclpy.init()
    node = RecoveryObserverNode()
    try:
        stamp = node.get_clock().now().to_msg()
        odom = Odometry()
        odom.header.stamp = stamp
        odom.header.frame_id, odom.child_frame_id = "map", "base_link"
        scan = LaserScan()
        scan.header.stamp = stamp
        scan.header.frame_id = "base_scan"
        scan.angle_min, scan.angle_increment = -0.3, 0.3
        scan.range_min, scan.range_max = 0.05, 20.0
        scan.ranges = [15.0] * 3
        node.on_odometry(odom)
        node.on_scan(scan)
        sample = node.buffer.evaluate(now_ros=node.now_ros(), now=__import__("time").monotonic())
        assert sample is not None
        assert sample.free_distance == 15.0
    finally:
        node.destroy_node()
        rclpy.shutdown()


def test_signed_command_epoch_discards_old_sensor_samples(monkeypatch):
    from guardian_interfaces.msg import MitigationCommand
    from guardian_core.feedback_auth import sign_command
    from nav_msgs.msg import Odometry
    monkeypatch.setenv("ROS_DOMAIN_ID", str(170 + os.getpid() % 30))
    monkeypatch.setenv("ROS_LOCALHOST_ONLY", "1")
    monkeypatch.setenv("GUARDIAN_FEEDBACK_SECRET", "adapter-key")
    monkeypatch.setenv("GUARDIAN_OBSERVATION_SECRET", "observer-key")
    rclpy.init()
    node = RecoveryObserverNode()
    try:
        stamp = node.get_clock().now().to_msg()
        odom = Odometry()
        odom.header.stamp, odom.header.frame_id, odom.child_frame_id = stamp, "map", "base_link"
        scan = LaserScan()
        scan.header.stamp, scan.header.frame_id = stamp, "base_scan"
        scan.angle_min, scan.angle_increment = -0.3, 0.3
        scan.range_min, scan.range_max, scan.ranges = 0.05, 20.0, [2.0] * 3
        node.on_odometry(odom)
        node.on_scan(scan)
        assert node.buffer.evaluate(now_ros=node.now_ros(), now=time.monotonic()) is not None
        fields = dict(timestamp=node.now_ros(), profile_id="amr-default", command_epoch=1, transmission_id=1,
            adapter_id="default-actuator", plan_id="stop", action="SAFE_STOP",
            components=[], requires_safe_stop=True)
        message = MitigationCommand(**fields)
        message.signature = "forged"
        node.on_command(message)
        assert node._command_received is None
        message.signature = sign_command(b"adapter-key", **fields)
        node.on_command(message)
        assert node.buffer.evaluate(now_ros=node.now_ros(), now=time.monotonic()) is None
        node.on_odometry(odom)
        node.on_scan(scan)
        assert node.buffer.evaluate(now_ros=node.now_ros(), now=time.monotonic()) is None
        stamp = node.get_clock().now().to_msg()
        odom.header.stamp = scan.header.stamp = stamp
        node.on_odometry(odom)
        node.on_scan(scan)
        assert node.buffer.evaluate(now_ros=node.now_ros(), now=time.monotonic()) is not None
    finally:
        node.destroy_node()
        rclpy.shutdown()


def test_expired_command_with_fresh_sensors_publishes_invalid_report(monkeypatch):
    from guardian_interfaces.msg import IndependentObservation, MitigationCommand
    from guardian_core.feedback_auth import sign_command
    from nav_msgs.msg import Odometry
    from rclpy.executors import SingleThreadedExecutor
    monkeypatch.setenv("ROS_DOMAIN_ID", str(170 + os.getpid() % 30))
    monkeypatch.setenv("ROS_LOCALHOST_ONLY", "1")
    monkeypatch.setenv("GUARDIAN_FEEDBACK_SECRET", "adapter-key")
    monkeypatch.setenv("GUARDIAN_OBSERVATION_SECRET", "observer-key")
    rclpy.init()
    node = RecoveryObserverNode()
    probe = rclpy.create_node("observer_report_test")
    executor = SingleThreadedExecutor()
    executor.add_node(node)
    executor.add_node(probe)
    reports = []
    probe.create_subscription(IndependentObservation, "guardian/independent_observation", reports.append, 20)
    try:
        fields = dict(timestamp=node.now_ros(), profile_id="amr-default", command_epoch=1, transmission_id=1,
            adapter_id="default-actuator", plan_id="stop", action="SAFE_STOP",
            components=[], requires_safe_stop=True)
        message = MitigationCommand(**fields)
        message.signature = sign_command(b"adapter-key", **fields)
        node.on_command(message)
        deadline = time.monotonic() + 0.6
        while time.monotonic() < deadline:
            executor.spin_once(timeout_sec=0.02)
        stamp = node.get_clock().now().to_msg()
        odom = Odometry()
        odom.header.stamp, odom.header.frame_id, odom.child_frame_id = stamp, "map", "base_link"
        scan = LaserScan()
        scan.header.stamp, scan.header.frame_id = stamp, "base_scan"
        scan.angle_min, scan.angle_increment = -0.3, 0.3
        scan.range_min, scan.range_max, scan.ranges = 0.05, 20.0, [2.0] * 3
        node.on_odometry(odom)
        node.on_scan(scan)
        assert node.buffer.evaluate(now_ros=node.now_ros(), now=time.monotonic()) is not None
        reports.clear()
        node.tick()
        deadline = time.monotonic() + 2
        while not reports and time.monotonic() < deadline:
            executor.spin_once(timeout_sec=0.02)
        assert reports and not reports[-1].valid
    finally:
        executor.remove_node(probe)
        executor.remove_node(node)
        probe.destroy_node()
        node.destroy_node()
        executor.shutdown()
        rclpy.shutdown()


def test_sensor_endpoint_restart_changes_native_graph_identity(monkeypatch):
    from std_msgs.msg import String
    from guardian_core.amr_simulator import AmrSimulatorNode
    monkeypatch.setenv("ROS_DOMAIN_ID", str(170 + os.getpid() % 30))
    monkeypatch.setenv("ROS_LOCALHOST_ONLY", "1")
    monkeypatch.setenv("GUARDIAN_FEEDBACK_SECRET", "adapter-key")
    rclpy.init()
    node = AmrSimulatorNode()
    try:
        def identities():
            odom = node.get_publishers_info_by_topic("/amr_07/odom")
            scan = node.get_publishers_info_by_topic("/amr_07/scan")
            return (bytes(odom[0].endpoint_gid), bytes(scan[0].endpoint_gid)) if len(odom) == len(scan) == 1 else None
        deadline = time.monotonic() + 2
        while identities() is None and time.monotonic() < deadline:
            rclpy.spin_once(node, timeout_sec=0.02)
        before = identities()
        assert before is not None
        node.on_control(String(data='{"action":"sensor_fault","mode":"restart_endpoints"}'))
        deadline = time.monotonic() + 2
        while (identities() is None or identities() == before) and time.monotonic() < deadline:
            rclpy.spin_once(node, timeout_sec=0.02)
        assert identities() is not None and identities() != before
    finally:
        node.destroy_node()
        rclpy.shutdown()
