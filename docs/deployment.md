# ROS 2 Deployment

This repository supports two isolated ROS 2 build targets:

| Target | Ubuntu | ROS 2 |
| --- | --- | --- |
| `humble` | 22.04 | Humble Hawksbill |
| `jazzy` | 24.04 | Jazzy Jalisco |

The targets must use separate build artifacts. The helper writes them to:

```text
build/<distro>/
install/<distro>/
log/<distro>/
```

This prevents build products from one ROS ABI and Python environment being
reused by the other.

## Helper

From the repository root:

```bash
bash deploy/run_guardian.sh build --distro humble
bash deploy/run_guardian.sh test --distro humble
bash deploy/run_guardian.sh dashboard --distro humble
bash deploy/run_guardian.sh core --distro humble
bash deploy/run_guardian.sh simulator --distro humble
bash deploy/run_guardian.sh all --distro humble
```

Use `--workspace /absolute/path/to/ros2-resilience-guardian` when the helper
is called from another directory. If `--workspace` is omitted, the helper
uses the repository containing the script.

`--distro auto` is the default. It selects a supported value from
`ROS_DISTRO`, or from exactly one installed `/opt/ros/humble` or
`/opt/ros/jazzy` setup. It fails when both are installed and no explicit
choice is available, or when `ROS_DISTRO` is unsupported.

For tests, `GUARDIAN_ROS_ROOT` can point at a fake or alternate ROS root.
This is only a testability hook; normal installations use `/opt/ros`.

The `build` command runs `colcon build --symlink-install` in `ros2_ws`.
The `test` command sources the selected ROS and matching workspace install,
then runs only `python3 -m pytest tests`. It does not run files under
`testdata/`.

The node commands use the shared absolute
`configs/guardian.yaml` parameter file. Direct nodes use:

```bash
ros2 run guardian_core <node> --ros-args --params-file /absolute/path/configs/guardian.yaml
```

The `all` command uses the launch interface with only the documented launch
argument:

```bash
ros2 launch guardian_core guardian.launch.py \
  config_file:=/absolute/path/configs/guardian.yaml
```

The launch argument and the YAML node parameter contract are implemented by
the main ROS package. This deployment layer does not add a `port` launch
argument.

The Dashboard binds to localhost by default and refuses non-loopback hosts.
Remote binding requires an explicit `allow_remote=true` parameter and should
only sit behind a TLS reverse proxy with a configured non-default password.
Requests have bounded body sizes, a finite socket timeout and a global worker
budget; login failures are rate-limited.

## Runtime Safety Contract

- Startup precedence is YAML defaults followed by ROS parameter overrides.
  Guardian-owned parameters other than `task_phase` are read-only after
  startup: a runtime update is rejected rather than acknowledged without
  updating the engine. Correct startup values and restart to change them.
- `task_phase` is read on every Guardian tick and participates in replanning.
  It is not automatically synchronized with simulator telemetry. The mission
  controller must set it through the Guardian parameter service.
- Resolve each attack independently in this order: `(attack, phase)`,
  `(attack, *)`, `(*, phase)`, `(*, *)`, then `default`. The JSON phase name
  `default` means `*`. Combine resolved policies using the strictest action
  (`SAFE_STOP > ISOLATE_COMPONENT > LIMIT_SPEED > DEGRADED_RUN`), minimum
  speed, and logical AND of mission permissions. A specific rule for one
  attack cannot cancel another attack's stop or restriction.
- Only these four containment actions are configurable. `NONE`,
  `SWITCH_CONTROLLER`, and `REPLAN_MISSION` are rejected because they do not
  provide a supported containment operation. Speeds must be finite,
  nonnegative JSON numbers, not booleans or numeric strings. A stop policy
  requires zero speed and `mission_allowed=false`.
- An explicit isolation policy isolates the attacked components only if all
  are eligible and the evaluated residual satisfies mission invariants.
  Otherwise the planner stops. The implicit default isolation policy keeps
  the existing risk-triggered minimal-subset search; low-risk events with no
  explicit match can remain resumable. Default stop, speed-limit, and degraded
  policies are applied even to low-risk active events.
- A pending mitigation locks the mission and publishes `SAFE_STOP` with no
  isolation components. Only at `activate_at` does the command topic carry the
  actual isolation/limit/degraded action. A stop is never delayed. This models
  command activation, not physical actuator acknowledgement.
- Every command carries a monotonically increasing semantic `command_epoch` and
  a new `transmission_id` on every publication. The enforcement adapter must
  echo `profile_id`/`adapter_id`, epoch, transmission, plan, action and
  component set on `guardian/mitigation_ack`, together with a strictly
  increasing `feedback_sequence`, `accepted=true` and `active=true`. For a
  stop command it must also set `safe_stop_confirmed=true`. Old, duplicate,
  out-of-order or differently identified feedback cannot refresh the watchdog.
  The watchdog uses a steady monotonic clock, so paused or jumped ROS
  simulation time cannot suppress a timeout. Missing, stale, or mismatched
  feedback trips the watchdog; it latches `SAFE_STOP` until the process is
  restarted. The simulator publishes this acknowledgement contract, but does
  not prove physical actuator motion.
- Startup and reset are fail-closed. The simulator starts with motion disabled
  and accepts no command until a current command and matching safety status have
  both arrived. A first command may bootstrap from a later epoch when earlier
  DDS samples were lost; after bootstrap, epoch jumps and same-epoch conflicts
  remain a local `SAFE_STOP`. The deployed YAML allows a bounded
  `startup_feedback_grace_sec` for discovery delay, but it never permits motion
  without a matching signed status.
- The implicit isolation search has a hard `max_planner_candidates` budget
  (default 128). If the bounded search cannot prove a safe containment plan
  within that budget, Guardian publishes `SAFE_STOP` instead of blocking the
  real-time loop on an exponential enumeration.
- `security_profile_json` is the device-neutral ROS 2 profile boundary. It
  defines `profile_id`, the enforcement `adapter_id`, trusted event sources,
  and resource criticality/isolatability. Resource names are not restricted
  to vehicles: they may be joints, sensors, planners, bridges, end effectors,
  flight controllers or industrial IO. An unknown or non-isolatable attacked
  resource is handled conservatively and cannot be silently resumed.
- `SafetyStatus` carries `profile_id`, adapter identity, command epoch and
  transmission identity. An enforcement adapter must ignore older status and
  must not allow motion unless the accepted command and safety status refer to
  the same identity. Old `mission_allowed=true` or a higher speed limit cannot
  overwrite a newer containment state.
- Invalid policy JSON keeps publishing zero-speed `SAFE_STOP`, including when
  there are no attacks. Empty strings, duplicate JSON keys, and colliding
  phase aliases (`default` together with `*`) are rejected instead of
  silently loading defaults or overwriting a stop. Fixing the policy
  requires restarting the node.
- HMAC secrets come only from `GUARDIAN_EVENT_SECRET` and
  `GUARDIAN_FEEDBACK_SECRET`, never from a ROS parameter or tracked file.
  `require_feedback_signature` is enabled by default in the tracked YAML;
  command, status and ACK signatures are verified before state changes.
  Set `require_signature=true` only with an event secret and a signing event
  producer. Demo simulator events remain unsigned, while Guardian-to-adapter
  control traffic is authenticated.
  Non-ASCII signatures and identities containing the signing delimiter `|`
  are rejected without advancing the source's replay sequence.

The integration tests in `tests/test_guardian_runtime.py` use real ROS
publishers, subscriptions, the parameter service, and the simulator adapter
in an isolated localhost domain. Their clock is controlled explicitly to
test the activation boundary without timing sleeps.

The active event registry and audit logger are bounded. Capacity overflow is
latched as a safety configuration fault, and audit files rotate within a fixed
size budget.

Remaining demo limits: the Guardian-side feedback watchdog is implemented, but
the simulator's acknowledgement is software state rather than physical
actuator proof. DDS/SROS2 authorization and message-level authentication are
deployment responsibilities, not replaced by matching fields. Reset starts
from permissive local simulation defaults, and injected attacks use fixed
sequences and one-shot observations. Repeated injections and long-lived faults
therefore need further lifecycle work. Do not treat this simulator as a
production safety controller or connect its `/cmd_vel` to real hardware
without independent hardware watchdogs, authenticated enforcement
acknowledgement, real actuator feedback, and acceptance testing.

## Windows and WSL

Run `deploy/start_guardian_dashboard.ps1` from PowerShell. It resolves the
current repository through `wslpath`, so the checkout may be under any Windows
user or directory:

```powershell
.\deploy\start_guardian_dashboard.ps1 -Distro humble
.\deploy\start_guardian_dashboard.ps1 -Distro jazzy -WslDistro Ubuntu-24.04
.\deploy\start_guardian_dashboard.ps1 -Workspace C:\work\ros2-resilience-guardian
```

The launcher starts WSL with a hidden process window and invokes
`deploy/run_guardian.sh dashboard`. `-Distro` selects the ROS installation;
`-WslDistro` selects the WSL distribution used for path conversion and
execution.

## User Service

`deploy/guardian@.service` is a template for a per-user systemd service. It
does not install itself and does not require `sudo`. Copy it into the user's
unit directory, review the workspace and distro environment values, then
reload the user manager:

```bash
mkdir -p ~/.config/systemd/user
mkdir -p ~/.config/ros2-resilience-guardian
cp deploy/guardian@.service ~/.config/systemd/user/
cp deploy/guardian.env.example ~/.config/ros2-resilience-guardian/guardian.env
# Edit guardian.env and replace every placeholder before starting the service.
systemctl --user daemon-reload
systemctl --user enable guardian@simulator.service
systemctl --user start guardian@simulator.service
```

The instance name is passed as the helper command, so `simulator` maps to
`run_guardian.sh simulator`. The template defaults to
`%h/ros2-resilience-guardian` and `GUARDIAN_DISTRO=auto`; edit these explicit
environment values for another checkout or a fixed ROS distro. Use
`systemctl --user disable guardian@simulator.service` when it is no longer
needed. The template enables `ROS_SECURITY_ENABLE=true` with
`ROS_SECURITY_STRATEGY=Enforce` and loads the per-user DDS keystore path.
Prepare SROS2 governance, permissions and enclave certificates under that
keystore before connecting a real adapter.

Choose one launch mode. `guardian@all.service` already starts Guardian,
Dashboard and the simulator; do not enable `guardian-simulator.service` at the
same time, or two simulator processes can publish duplicate commands and ACKs.
The compatibility unit should only be used when the other nodes are managed
separately.

## CI

`.github/workflows/ros2.yml` runs a matrix on `ubuntu-22.04`/Humble and
`ubuntu-24.04`/Jazzy. Each job uses the ROS tooling setup action, initializes
rosdep, installs dependencies from `ros2_ws/src`, builds through the helper,
and runs only the project `tests` directory. The workflow does not call
dashboard, simulator, external APIs, or system-service commands.

## Verification Limits

The local Windows environment can verify helper behavior with fake ROS setup
files and fake commands. A real ROS build requires the matching Linux
distribution and ROS installation. Jazzy verification is therefore limited
unless an Ubuntu 24.04/Jazzy environment is available; the CI matrix is the
authoritative cross-distro build path.
