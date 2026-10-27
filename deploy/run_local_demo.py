"""Compose the existing nodes for an explicit localhost software demonstration.

This mode uses one executor and a new in-memory control key for each launch.
It is separate from multiprocess launch/DDS validation and hardware deployment.
"""
import argparse
import os
from pathlib import Path
import secrets


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--domain", type=int, default=42)
    parser.add_argument("--port", type=int, default=8080)
    options = parser.parse_args()
    if not 0 <= options.domain <= 232 or not 1024 <= options.port <= 65535:
        parser.error("domain must be 0–232 and port must be 1024–65535")
    config = Path(options.config).resolve()
    if not config.is_file():
        parser.error("configuration file is missing")
    os.environ["ROS_LOCALHOST_ONLY"] = "1"
    os.environ["ROS_DOMAIN_ID"] = str(options.domain)
    os.environ["GUARDIAN_FEEDBACK_SECRET"] = secrets.token_hex(32)
    os.environ["GUARDIAN_DASHBOARD_ALLOW_DEFAULT_CREDENTIALS"] = "1"
    os.environ.setdefault("GUARDIAN_DASHBOARD_USER", "admin")
    # Both software nodes sign incidents and control feedback with this launch's
    # fresh key; an unrelated inherited event key cannot split the demo identity.
    os.environ["GUARDIAN_EVENT_SECRET"] = os.environ["GUARDIAN_FEEDBACK_SECRET"]
    import rclpy
    from rclpy.executors import SingleThreadedExecutor, ExternalShutdownException
    from guardian_core.guardian_node import GuardianNode
    from guardian_core.amr_simulator import AmrSimulatorNode
    from guardian_core.dashboard import DashboardNode

    rclpy.init(args=["--ros-args", "--params-file", str(config),
        "-p", "guardian_dashboard:host:=127.0.0.1",
        "-p", f"guardian_dashboard:port:={options.port}",
        "-p", "guardian_dashboard:allow_remote:=false"])
    nodes = []
    executor = SingleThreadedExecutor()
    try:
        for cls in (GuardianNode, AmrSimulatorNode, DashboardNode):
            node = cls()
            nodes.append(node)
            executor.add_node(node)
        executor.spin()
    except (KeyboardInterrupt, ExternalShutdownException):
        pass
    finally:
        executor.shutdown()
        for node in reversed(nodes):
            node.destroy_node()
        if rclpy.ok():
            rclpy.shutdown()


if __name__ == "__main__":
    main()
