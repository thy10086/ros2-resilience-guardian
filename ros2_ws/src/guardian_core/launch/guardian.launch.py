from pathlib import Path

from launch import LaunchDescription
from launch.actions import DeclareLaunchArgument
from launch.substitutions import LaunchConfiguration
from ament_index_python.packages import get_package_share_directory
from launch_ros.actions import Node


def generate_launch_description():
    installed_config = Path(get_package_share_directory("guardian_core")) / "config" / "guardian.yaml"
    config_file = LaunchConfiguration("config_file")
    return LaunchDescription([
        DeclareLaunchArgument("config_file", default_value=str(installed_config)),
        Node(
            package="guardian_core",
            executable="guardian_node",
            name="guardian_node",
            output="screen",
            parameters=[config_file],
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
