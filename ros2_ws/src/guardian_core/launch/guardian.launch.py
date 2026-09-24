from launch import LaunchDescription
from launch_ros.actions import Node


def generate_launch_description():
    return LaunchDescription([
        Node(
            package="guardian_core",
            executable="guardian_node",
            name="guardian_node",
            output="screen",
            parameters=[{
                "task": "navigate_to_goal",
                "goal": "box2",
                "max_event_age_sec": 5.0,
                "mitigation_delay_sec": 1.0,
                "default_speed_limit": 0.35,
            }],
        ),
        Node(
            package="guardian_core",
            executable="guardian_dashboard",
            name="guardian_dashboard",
            output="screen",
            parameters=[{
                "host": "127.0.0.1",
                "port": 8080,
            }],
        ),
        Node(
            package="guardian_core",
            executable="amr_simulator",
            name="amr_simulator",
            output="screen",
        ),
    ])
