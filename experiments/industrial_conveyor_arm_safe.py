"""Reference-only ROS 2 control sample for the industrial code checker.

This file is an inspection fixture. It is not launched by the project.
"""

from geometry_msgs.msg import Twist
from rclpy.node import Node


class SafeCell(Node):
    def __init__(self):
        super().__init__("safe_cell")
        self.speed_limit = 0.20
        self.estop = False
        self.drive_pub = self.create_publisher(Twist, "/cmd_vel", 10)
        self.arm_pub = self.create_publisher(object, "/joint_trajectory", 10)
        self.gripper_pub = self.create_publisher(object, "/gripper/command", 10)

    def publish_drive(self, command):
        if self.estop:
            return
        command.linear.x = max(-self.speed_limit, min(self.speed_limit, command.linear.x))
        self.drive_pub.publish(command)

    def publish_gripper(self, command):
        if self.estop:
            return
        self.gripper_pub.publish(command)
