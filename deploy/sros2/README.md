# SROS2 Deployment Boundary

The systemd template enables DDS-Security enforcement and points ROS 2 at a
per-user keystore. It does not generate certificates or grant permissions
automatically.

Before connecting a real robot:

1. Create a dedicated keystore for this deployment.
2. Create separate enclaves for Guardian, each enforcement adapter, sensor/event
   sources, and the dashboard.
3. Grant Guardian subscription/publish rights only to the topics it needs.
4. Grant an adapter subscription rights to `guardian/mitigation_command` and
   `guardian/safety_status`, and publish rights to `guardian/mitigation_ack`.
5. Deny arbitrary nodes from publishing those control and feedback topics.
6. Test unauthorized publishers, stale certificates, certificate rotation and
   two robots sharing one DDS domain before enabling hardware.

The HMAC fields in the Guardian messages provide an application-level
integrity check, but they do not replace DDS identity, access control,
certificate lifecycle or an independent hardware safety channel.
