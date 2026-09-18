# Guardian design notes

## Trust boundaries

1. Attack publishers are untrusted until `EventVerifier` accepts an event.
2. `AttackRegistry` is the source of truth for active verified events; it does not overwrite all history on every message.
3. `RiskEngine` is a pure function of mission context and verified records. It preserves the paper's δ/ψ/γ metrics and adds bounded persistence/confidence risk.
4. `MitigationPlanner` recomputes a plan when event identity or sequence changes. A future ROS 2 adapter must cancel a pending plan when the signature changes.
5. `SafetySupervisor` is the final policy boundary. It can deny mission continuation even if a task controller reports `DONE`.

## Mission invariants

- A critical active component makes `delta=0`.
- `gamma=1` requires the appropriate threshold to be met.
- Mission continuation requires both `delta=1` and `gamma=1`.
- A plan that cannot restore those invariants produces `SAFE_STOP`.

## ROS 2 deployment

The `guardian_node` subscribes to `guardian/attack_events` and publishes three independent outputs. A real adapter should connect `guardian/mitigation_command` to ROS 2 Lifecycle transitions, topic ACLs, controller switching and a hardware-independent stop interface. The core package does not directly call Webots or hardware APIs; this is intentional isolation.
