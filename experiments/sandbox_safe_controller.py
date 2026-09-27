"""Guardian sandbox controller contract.

This is intentionally not a ROS 2 node. The sandbox supplies a bounded state
dictionary and accepts a bounded command dictionary from control(state).
"""

import math


def control(state):
    if state["estop"] or not state["mission_allowed"]:
        return {"linear_x": 0.0, "angular_z": 0.0}
    if state["distance_to_obstacle"] < 0.65:
        return {"linear_x": 0.0, "angular_z": 0.0}
    return {"linear_x": min(0.25, state["safety_limit"]), "angular_z": 0.0}
