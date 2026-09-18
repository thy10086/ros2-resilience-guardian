# ROS 2 security deployment notes

The core Guardian can require an HMAC signature by setting the ROS parameter:

```bash
ros2 run guardian_core guardian_node --ros-args \
  -p require_signature:=true \
  -p signature_secret:="$GUARDIAN_EVENT_SECRET"
```

The secret must be supplied out of band in a deployment secret store. Do not commit a real secret to this repository; the tracked `.env` only contains safe defaults.

For DDS Security / SROS 2, create a local keystore and enclave on the deployment machine:

```bash
ros2 security create_keystore ~/guardian_keystore
ros2 security create_enclave ~/guardian_keystore /guardian_node
```

Then issue permissions for the enclave to subscribe to `guardian/attack_events` and publish the three Guardian outputs. The exact governance policy depends on the DDS vendor and deployment topology, so generated keystores are intentionally excluded from Git.

A production adapter should also enforce the published `guardian/safety_status` at the robot control boundary. The current repository keeps that boundary separate from the task controller so it can be tested independently.
