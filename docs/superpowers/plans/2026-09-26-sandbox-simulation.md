# 机器人代码沙箱仿真实施计划

1. 增加 `sandbox_simulation.py`，实现输入校验、SDF/URDF 解析、隔离运行、固定步长仿真、风险证据和 Jev 摘要。
2. 在 Dashboard 增加认证的 `/api/sandbox/samples` 与 `/api/sandbox/run`，限制请求大小和字段，禁止宿主机直接执行源码。
3. 增加“代码沙箱仿真”页面，支持可见本地文件选择、内置样例、轨迹图、事件表、指标和中文安全总结。
4. 增加安全测试：危险导入、XXE/plugin/include、沙箱不可用、实际控制器轨迹、XML 模型验证和 HTTP 鉴权。
5. 运行 Python 测试、ROS 2 构建、JavaScript 语法检查和 Playwright 上传/运行流程，记录真实结果与边界。
