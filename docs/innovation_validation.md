# 创新功能验证报告

验证日期：2026-09-18

## 运行方式

```bash
cd /mnt/c/Users/user/Documents/Codex/2026-09-10/ban/ros2-resilience-guardian
python3 experiments/run_innovation_experiments.py
```

脚本是确定性的 headless 实验。每个实验都包含断言，任一断言失败都会以非零状态退出；详细 JSON 结果写入被忽略的 `experiments/results/innovation_validation.json`。

## 实验结果

### 1. 零信任事件门

验证来源、时间戳、未来时间、序列号重放和 HMAC 签名。

| 输入 | 结果 |
| --- | --- |
| 可信事件 | `ACCEPTED` |
| 未知来源 | `UNKNOWN_SOURCE` |
| 过期事件 | `STALE` |
| 未来时间事件 | `FUTURE` |
| 重复序列号 | `REPLAY` |
| 正确 HMAC | `ACCEPTED` |
| 错误 HMAC | `INVALID` |

共阻止 5 类不可信事件，说明攻击事件不会绕过验证器直接进入风险引擎。

### 2. 计划生效前的多波重新规划

第一波左右机械臂攻击生成 `ISOLATE_COMPONENT(left_arm)` 计划，激活时间为 `t=1.0`。在计划生效前 `t=0.5` 插入关键组件 `left_wheels` 攻击，系统生成新的计划 `ISOLATE_COMPONENT(left_arm,left_wheels)`，激活时间更新为 `t=1.5`。

验证结果：

- 生效前完成 2 次规划；
- 新旧计划 ID 不同；
- 新计划包含新出现的关键组件；
- 执行隔离后残余风险下降；
- 恢复评估得到 `NONE + RESUMABLE`。

这验证了新攻击到达时不会继续执行已经过时的隔离计划。

### 3. 安全状态机和任务门控

| 条件 | 状态 | 任务允许 | 速度上限 |
| --- | --- | --- | --- |
| 无攻击 | `NORMAL` | 是 | `0.35 m/s` |
| 单个非关键攻击 | `RESUMABLE` | 是 | `0.35 m/s` |
| 可隔离攻击正在处理 | `CONTAINING` | 否 | `0.15 m/s` |
| 不可隔离关键组件 | `SAFE_STOP` | 否 | `0.00 m/s` |

结果证明风险评估、缓解动作和任务放行之间存在独立的安全策略边界。

### 4. 驾驶舱状态与审计链

使用 ROS 2 消息形状的测试消息写入风险、缓解和安全状态，验证 `/api/state` 对应的缓存结构：

- 时间线顺序为 `safety → mitigation → risk`；
- 状态快照包含 `risk`、`mitigation`、`safety`、`timeline`、`updated_at`；
- 两条审计事件能够写入 JSONL 并重新读取。

之前的真实进程 smoke test 还验证了 `guardian_dashboard` 的 `/api/health`、`/api/state` 和 HTML 页面可访问。

## 当前结论

已经验证的创新层包括：事件可信验证、攻击生命周期接入、计划生效前的多波重新规划、独立安全状态机、只读驾驶舱状态聚合和审计输出。

尚未验证或尚未实现的研究方向包括 ROS 2 图感知风险传播、风险自适应速度控制、完整 SROS 2/DDS 身份策略和 Webots 实际底盘控制。后续实验必须在这些模块实现后单独增加基线对比，不能把当前结果当成已完成的功能。
