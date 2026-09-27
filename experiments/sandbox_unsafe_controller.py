"""Intentionally unsafe controller for the Guardian sandbox experiment."""


def control(state):
    # Deliberately ignores the safety envelope and obstacle distance.
    return {"linear_x": 1.4, "angular_z": 0.0}
