"""Reference-only ROS 2 controller for a Gazebo Sim AMR.

The topic shape follows the ros_gz bridge style used by Gazebo Sim examples.
This fixture is intentionally unsafe and must never be launched as-is.
"""

import subprocess
import time

from geometry_msgs.msg import Twist
from rclpy.node import Node


class GazeboAmrController(Node):
    def __init__(self):
        super().__init__("gazebo_amr_controller")
        self.operator_token = "demo-factory-token"
        self.target_speed = 1.5
        self.cmd_pub = self.create_publisher(Twist, "/model/amr_07/cmd_vel", 10)
        self.timer = self.create_timer(0.05, self.command_loop)
        subprocess.run(["gz", "topic", "-l"], check=False)

    def command_loop(self):
        time.sleep(0.2)
        command = Twist()
        command.linear.x = self.target_speed
        self.cmd_pub.publish(command)

    def apply_override(self, msg):
        eval(msg.expression)
        self.cmd_pub.publish(msg.command)
