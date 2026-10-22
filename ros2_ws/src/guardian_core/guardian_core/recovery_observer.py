"""Independent computation over standard ROS sensor messages."""
import os
import math
import secrets
import time

import rclpy
from rclpy.executors import ExternalShutdownException
from rclpy.node import Node
from rclpy.qos import qos_profile_sensor_data
from nav_msgs.msg import Odometry
from sensor_msgs.msg import LaserScan
from guardian_interfaces.msg import IndependentObservation, MitigationCommand

from .feedback_auth import INDEPENDENT_OBSERVATION_FIELDS, sign_independent_observation, verify_command
from .independent_observation import SensorObservationBuffer


def stamp_seconds(stamp):
    return stamp.sec + stamp.nanosec / 1e9


class RecoveryObserverNode(Node):
    def __init__(self):
        super().__init__("recovery_observer")
        self._feedback_secret = os.getenv("GUARDIAN_FEEDBACK_SECRET", "").encode() or None
        self._observation_secret = os.getenv("GUARDIAN_OBSERVATION_SECRET", "").encode() or None
        self.buffer = SensorObservationBuffer()
        self._epoch = self._transmission = self._sequence = 0
        self._session = secrets.token_hex(16)
        self._command_received = None
        self._configuration_valid = bool(self._feedback_secret and self._observation_secret
            and self._feedback_secret != self._observation_secret)
        self.publisher = self.create_publisher(IndependentObservation, "guardian/independent_observation", 20)
        self.create_subscription(Odometry, "/amr_07/odom", self.on_odometry, qos_profile_sensor_data)
        self.create_subscription(LaserScan, "/amr_07/scan", self.on_scan, qos_profile_sensor_data)
        self.create_subscription(MitigationCommand, "guardian/mitigation_command", self.on_command, 20)
        self.create_timer(0.05, self.tick)

    def now_ros(self):
        return self.get_clock().now().nanoseconds / 1e9

    def on_command(self, message):
        fields = {key: getattr(message, key) for key in (
            "timestamp", "profile_id", "command_epoch", "transmission_id", "adapter_id", "plan_id",
            "action", "components", "requires_safe_stop")}
        if (not verify_command(self._feedback_secret, message.signature, **fields)
                or message.profile_id != "amr-default" or message.adapter_id != "default-actuator"
                or message.command_epoch < self._epoch or message.transmission_id <= self._transmission):
            return
        source_age = self.now_ros() - message.timestamp
        if not math.isfinite(source_age) or not 0 <= source_age < 0.5:
            return
        if message.command_epoch != self._epoch:
            self.buffer.reset(now_ros=self.now_ros())
        self._epoch, self._transmission = message.command_epoch, message.transmission_id
        self._command_received = time.monotonic() - source_age

    def on_odometry(self, message):
        linear, angular = message.twist.twist.linear, message.twist.twist.angular
        self.buffer.observe_odometry(stamp=stamp_seconds(message.header.stamp),
            received_at=time.monotonic(), now_ros=self.now_ros(), frame=message.header.frame_id,
            child_frame=message.child_frame_id, linear=(linear.x, linear.y, linear.z),
            angular=(angular.x, angular.y, angular.z))

    def on_scan(self, message):
        self.buffer.observe_scan(stamp=stamp_seconds(message.header.stamp),
            received_at=time.monotonic(), now_ros=self.now_ros(), frame=message.header.frame_id,
            angle_min=message.angle_min, angle_increment=message.angle_increment,
            range_min=message.range_min, range_max=message.range_max, ranges=message.ranges)

    def tick(self):
        now, now_ros = time.monotonic(), self.now_ros()
        sample = self.buffer.evaluate(now_ros=now_ros, now=now)
        command_fresh = self._command_received is not None and 0 <= now - self._command_received <= 0.5
        valid = bool(self._configuration_valid and sample is not None and command_fresh)
        self._sequence += 1
        message = IndependentObservation(timestamp=now_ros, observer_id="recovery-observer", observer_session=self._session,
            profile_id="amr-default", command_epoch=self._epoch, transmission_id=self._transmission,
            observation_sequence=self._sequence, odom_timestamp=sample.odom_at if sample else 0.0,
            scan_timestamp=sample.scan_at if sample else 0.0, actual_speed=sample.speed if sample else 0.0,
            free_distance=sample.free_distance if sample else 0.0, valid=valid)
        fields = {key: getattr(message, key) for key in INDEPENDENT_OBSERVATION_FIELDS}
        if self._configuration_valid:
            message.signature = sign_independent_observation(self._observation_secret, **fields)
        self.publisher.publish(message)


def main(args=None):
    rclpy.init(args=args)
    node = RecoveryObserverNode()
    try:
        rclpy.spin(node)
    except (KeyboardInterrupt, ExternalShutdownException):
        pass
    except RuntimeError:
        # SIGINT can close the ROS context while rclpy converts a taken
        # message. Errors with a live context remain real failures.
        if rclpy.ok():
            raise
    finally:
        if rclpy.ok():
            node.destroy_node()
            # SIGINT may close the context after the ok() check. Use rclpy's
            # lock-protected idempotent cleanup rather than a second shutdown.
            rclpy.try_shutdown()
