"""Extract relevant live endpoints using ROS 2's existing graph discovery APIs."""
import hashlib
import json


CONTROL_TOPICS = {
    "guardian/mitigation_command": ("guardian_node", "amr_simulator"),
    "guardian/safety_status": ("guardian_node", "amr_simulator"),
    "guardian/recovery_telemetry": ("amr_simulator", "guardian_node"),
}


def recovery_graph_fingerprint(node, independent=False) -> str:
    """Missing/extra publishers fail closed; subscriber changes alter context.

    Names and GIDs are observational identity, not an authentication mechanism.
    Message authentication and production DDS permissions are separate layers.
    """
    endpoints = []
    try:
        topics = dict(CONTROL_TOPICS)
        if independent:
            topics.update({
                "guardian/independent_observation": ("recovery_observer", "guardian_node"),
                "/amr_07/odom": ("amr_simulator", "recovery_observer"),
                "/amr_07/scan": ("amr_simulator", "recovery_observer"),
            })
        for topic, (publisher, subscriber) in topics.items():
            resolved = node.resolve_topic_name(topic)
            pubs = node.get_publishers_info_by_topic(resolved)
            subs = node.get_subscriptions_info_by_topic(resolved)
            if len(pubs) != 1 or pubs[0].node_name != publisher:
                return ""
            if not any(item.node_name == subscriber for item in subs):
                return ""
            if independent and topic == "guardian/mitigation_command" and not any(
                    item.node_name == "recovery_observer" for item in subs):
                return ""
            for direction, items in (("pub", pubs), ("sub", subs)):
                for item in items:
                    endpoints.append((resolved, direction, item.node_namespace,
                        item.node_name, item.topic_type, bytes(item.endpoint_gid).hex()))
        encoded = json.dumps(sorted(endpoints), separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()
    except (RuntimeError, ValueError, TypeError, AttributeError):
        return ""
