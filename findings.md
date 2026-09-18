# Findings

## Repository facts

- The project already has a ROS 2 Jazzy `guardian_node` publishing risk,
  mitigation, and safety messages.
- `.env` is intentionally tracked and contains safe defaults only; secret event
  keys remain commented out.
- The repository is on `main` with commit `0b6cbc5` and has no GitHub remote.

## Open-source references checked on 2026-09-18

- `rajavardhan28/IDS_ROS2`: ROS 2 intrusion-detection reference.
- `seergiromero/ROS2-Intrusion-Detection`: ROS 2 IDS experiments.
- `giacomozanatta/sros2-policy-clustering`: SROS 2 policy-management reference.
- `iotsrg/awesome-ros-security`: curated ROS security references.

The references provide useful detection and policy ideas but do not provide the
same mission-aware closed loop with risk scoring, mitigation planning, safety
states, and a local dashboard.

## Credential constraint

The existing SSH key is not authorized by GitHub (`Permission denied (publickey)`).
Pushing requires either adding its public key to the user's GitHub account or
providing a Personal Access Token for a one-time HTTPS push. Secrets must never
be committed or printed.
