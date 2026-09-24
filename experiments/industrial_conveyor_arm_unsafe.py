"""Intentionally unsafe ROS 2 fixture for the industrial code checker.

This file must never be launched. It contains representative findings:
dynamic execution, a hard-coded credential, and unguarded actuator publishing.
"""

import subprocess

from rclpy.node import Node


class UnsafeCell(Node):
    def __init__(self):
        super().__init__("unsafe_cell")
        self.drive_pub = self.create_publisher(object, "/cmd_vel", 10)
        self.arm_pub = self.create_publisher(object, "/joint_trajectory", 10)
        self.password = "factory-admin-password"

    def callback(self, msg):
        eval(msg.command)
        self.drive_pub.publish(msg)
