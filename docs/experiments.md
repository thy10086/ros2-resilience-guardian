# Experiment protocol

Use the original RobResilience scenarios as a baseline and run the new core engine with the same tau/epsilon and alpha/theta values.

Metrics:

- event verification latency and rejection reason;
- detection-to-containment latency;
- mitigation planning latency;
- recovery time;
- mission completion or explicit safe-stop reason;
- false stop rate under non-critical attacks;
- residual risk after mitigation;
- number of stale/replayed/unauthorized events blocked.

The new scenario 3b driver sends five waves and forces a re-plan whenever the event set changes. This directly targets the original implementation's stale mitigation-plan failure mode.
