"""Three-process recovery demo; keys must be supplied by the operator."""
from launch import LaunchDescription
from launch_ros.actions import Node


def generate_launch_description():
    return LaunchDescription([
        Node(package="guardian_core", executable="guardian_node", output="screen",
            parameters=[{"evidence_bound_recovery": True, "independent_observation_required": True,
                "startup_feedback_grace_sec": 5.0}]),
        Node(package="guardian_core", executable="amr_simulator", output="screen",
            additional_env={"GUARDIAN_OBSERVATION_SECRET": ""}),
        Node(package="guardian_core", executable="recovery_observer", output="screen"),
    ])
