# ROS 2 General Security Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把 Guardian 的实时安全链路推广为可配置的 ROS 2 通用安全 profile，并消除命令反馈重放、ROS 时间 watchdog 和消息乱序带来的安全缺口。

**Architecture:** 用 `security_profile_json` 注入资源与可信源，不改变核心 RiskEngine/Planner 的设备无关接口。用 `command_epoch` 表示动作语义、`transmission_id` 表示每次发送、`feedback_sequence` 表示确认新鲜度；Guardian 用 monotonic watchdog，适配器用 epoch/传输状态门控。

**Tech Stack:** Python 3、ROS 2 Humble/Jazzy 消息生成、rclpy、pytest、ament_cmake、现有 AMR 仿真适配器。

**Spec:** `docs/superpowers/specs/2026-09-29-ros2-general-security-design.md`

## Global Constraints

- 核心 Guardian 不依赖 `/cmd_vel`、AMR 运动学或车辆组件名。
- 非法 profile、未知不可隔离资源、反馈缺失或顺序冲突必须保守进入 `SAFE_STOP`。
- ROS 时间不参与 watchdog 超时判断。
- 仿真 ACK 不等价于真实执行器物理确认。
- 保留现有未提交工作，不回滚用户已有修改。

### Task 1: Generic ROS 2 Security Profile

**Files:**
- Create: `ros2_ws/src/guardian_core/guardian_core/security_profile.py`
- Modify: `ros2_ws/src/guardian_core/guardian_core/config.py`
- Modify: `ros2_ws/src/guardian_core/guardian_core/models.py`
- Modify: `ros2_ws/src/guardian_core/guardian_core/guardian_node.py`
- Modify: `ros2_ws/src/guardian_core/guardian_core/__init__.py`
- Modify: `tests/test_ros2_security_profile.py`
- Modify: `tests/test_guardian_runtime.py`
- Modify: `configs/guardian.yaml`

**Interfaces:**
- Produces `SecurityProfile`, `ResourcePolicy` and `parse_security_profile(payload)`.
- `GuardianNode` consumes `security_profile_json` and passes profile resource maps into `GuardianConfig`.

- [x] **Step 1: Write failing profile tests** for valid generic resources, duplicate JSON keys and invalid resource values.
- [x] **Step 2: Run `pytest -q tests/test_ros2_security_profile.py`** and confirm the missing parser/API failure.
- [x] **Step 3: Implement bounded parser and profile dataclasses** with strict strings, integer thresholds, native booleans and conservative validation.
- [x] **Step 4: Run the focused profile tests** and confirm they pass.
- [x] **Step 5: Wire `GuardianNode` to the profile parameter** while retaining the AMR profile as the tracked default.
- [x] **Step 6: Add a runtime test** proving a non-AMR component can be detected and isolated from profile data.

### Task 2: Authenticated Fresh Command Feedback

**Files:**
- Modify: `ros2_ws/src/guardian_interfaces/msg/MitigationCommand.msg`
- Modify: `ros2_ws/src/guardian_interfaces/msg/MitigationAck.msg`
- Modify: `ros2_ws/src/guardian_interfaces/msg/SafetyStatus.msg`
- Modify: `ros2_ws/src/guardian_core/guardian_core/guardian_node.py`
- Modify: `tests/test_guardian_runtime.py`

**Interfaces:**
- `MitigationCommand`: `adapter_id`, `transmission_id`.
- `MitigationAck`: `adapter_id`, `transmission_id`, `feedback_sequence`.
- `SafetyStatus`: `adapter_id`, `command_epoch`, `transmission_id`.

- [x] **Step 1: Add replay and stale ACK tests** using wrong adapter, old transmission and duplicate feedback sequence.
- [x] **Step 2: Run the focused runtime tests** and confirm the new fields/behavior fail.
- [x] **Step 3: Implement per-transmission command IDs and strict ACK matching**.
- [x] **Step 4: Run runtime watchdog tests** and confirm stale feedback cannot prevent `SAFE_STOP`.

### Task 3: Steady Watchdog and Adapter Ordering

**Files:**
- Modify: `ros2_ws/src/guardian_core/guardian_core/guardian_node.py`
- Modify: `ros2_ws/src/guardian_core/guardian_core/amr_simulator.py`
- Modify: `tests/test_amr_simulator.py`
- Modify: `tests/test_guardian_runtime.py`

**Interfaces:**
- `GuardianNode.monotonic_seconds()` is the watchdog clock seam used by tests.
- `AmrSimulationModel.update_mitigation()` rejects stale/jumped/conflicting epochs.
- `AmrSimulationModel.update_safety()` ignores old status and gates motion on matching command/status identity.

- [x] **Step 1: Add tests** for simulated clock pause, old/duplicate commands, epoch jumps and old safe status.
- [x] **Step 2: Run the focused tests** and confirm expected failures.
- [x] **Step 3: Implement monotonic timing and adapter state ordering**.
- [x] **Step 4: Run AMR and runtime tests** and confirm the existing closed loop remains green.

### Task 4: Documentation and Full Verification

**Files:**
- Modify: `README.md`
- Modify: `docs/deployment.md`
- Modify: `HANDOFF.md`
- Modify: `ros2_ws/src/guardian_core/package.xml`

- [x] **Step 1: Document profile format, adapter contract, SROS2 boundary and ROS 2-only scope.**
- [x] **Step 2: Run Python compile and diff checks.**
- [x] **Step 3: Run the full pytest suite.**
- [x] **Step 4: Build `guardian_interfaces` and `guardian_core` in ROS 2 Humble.**
- [x] **Step 5: Re-run the full test command and report residual production gaps.**
