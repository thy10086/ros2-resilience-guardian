# 工业 ROS 2 代码安全检查

“工业代码安全检查”页面用于在代码进入 ROS 2 运行时之前做一轮只读检查。当前配置面向
输送线与机械臂上下料单元，关注 `/cmd_vel`、`/joint_trajectory` 和
`/gripper/command` 三类执行器主题。

## 检查边界

上传内容只作为 UTF-8 源代码文本处理。服务不会：

- `import`、`exec`、`eval` 或启动上传的代码；
- 把上传内容发布到 ROS 2；
- 把源代码发送给 Jev 或其他外部服务；
- 自动修改源文件或替用户解除安全状态。

检查器使用 Python AST 和有界文本规则，输出规则编号、严重级别、行号、脱敏证据、
整改建议和 Guardian 防护映射。

## 当前规则

| 规则 | 检查内容 | 默认级别 | Guardian 映射 |
| --- | --- | --- | --- |
| `PARSE-001` | Python 语法无法解析 | critical | `SAFE_STOP` |
| `DYN-001` | `eval`、`exec`、`compile` 或动态导入 | critical | `SAFE_STOP` |
| `DYN-002` | `subprocess` 或外部进程调用 | high | `ISOLATE_COMPONENT` |
| `SEC-001` | 疑似硬编码 password/token/secret | high | `ISOLATE_COMPONENT` |
| `ACT-001` | 执行器主题缺少限速、限位或安全状态边界 | high | `ISOLATE_COMPONENT` |
| `ACT-002` | 执行器发布缺少急停或任务许可门控 | high | `ISOLATE_COMPONENT` |
| `CALL-001` | 控制路径包含阻塞等待 | medium | `REVIEW_REQUIRED` |

检查结论分为 `PASS`、`REVIEW` 和 `BLOCKED`。代码检查的 Guardian 映射是上线前的
安全门建议，运行时仍由 Guardian 的 ROS 2 状态机和安全控制器执行限速、隔离或停车。

## 前端操作

1. 打开 `http://127.0.0.1:8088`，使用 `admin/admin` 登录。
2. 进入“工业代码安全检查”。
3. 选择“安全输送线与机械臂控制节点”或“待整改的输送线控制节点”，点击“导入内置样例”。
4. 点击“执行安全检查”，查看风险数量、执行器主题、代码行和 Guardian 动作。
5. 也可以导入项目中的 `experiments/industrial_conveyor_arm_safe.py` 或
   `experiments/industrial_conveyor_arm_unsafe.py`。
6. 对 `BLOCKED` 结果，先按行号整改，再把代码重新导入检查；检查通过后，再使用“防护实验室”
   的 `guardian-replay/v1` 事件样例验证运行时事件校验和安全状态。

## 与现有闭环的关系

代码检查是上线前入口，防护实验室是事件级离线回放，工程仿真是 ROS 2 闭环验证：

```text
工业控制代码
    ↓ 只读 AST/文本检查
代码风险与 Guardian 映射
    ↓ 整改后
guardian-replay/v1 事件回放
    ↓
Guardian 风险、缓解和安全状态
    ↓
AMR/产线仿真节点的安全反馈
```

这样可以把“代码中是否存在危险控制路径”和“运行时是否能够限速、隔离或停车”分开验证，
避免把静态检查结果误认为真实机器人已经完成安全认证。
