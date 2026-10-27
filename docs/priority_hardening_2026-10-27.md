# 2026-10-27 分梯度改动与运行记录

本轮按10月25日审计的前两梯度实施。历史审计保持当时结论，当前状态以本文为准。当前修复随main同步；固定源码发布标签仍为snapshot-2026-10-22，不重写既有标签。

## 实施状态

| 项目 | 当前结果 |
| --- | --- |
| A01观测年龄包络 | 采集年龄进入位移折损和制动速度上界；原0.49秒/.35m/s/.34m反例现在停车 |
| A03重复攻击 | 普通事件生命周期序号递增、reset不回退；专用replay第二条保留重复 |
| A04/A05静态控制路径 | 相对名、字面namespace、create_node解析；动态话题/namespace、CLI remap和多节点归属冲突保留NAME-001/REVIEW；八种门控赋值失效同源 |
| A06分批复核 | 16项一批，短索引回填完整报告，原16次角色/12次执行预算不放宽；保留已完成批次和待复核ID |
| A07证据选择 | 按风险与类型选择至多8项，第9/128文件的高危规则可见；记录实际可见ID。额外补读工具尚未实现 |
| A08安装定位 | 受信标记向上定位或管理员GUARDIAN_RESEARCH_ROOT；固定解释器，实际Humble安装副本runtime available |
| A09研究CI | 独立venv安装两份requirements并验证导入、JUnit零跳过；未据本地结果宣称远程Actions通过 |
| A10Jev总截止 | 与agent复用固定stdlib worker；父进程绝对截止、终止回收、有界输出、无代理或重定向 |
| A11本地语料边界 | 解析/读取前拒绝符号链接并核对根内目标；未声称抵抗所有并发目录替换 |
| G01属性范围 | 新增逐属性满足/违反/证据不足；物理包络和来源完整性明确不可判定，独立重算尚待实施 |

## 年龄包络假设

MotionSample.observation_age_sec默认0，原调用兼容。年龄来自 `now - telemetry.received_at`；该时间已由接收端映射为采集时刻，不按到达时间续期。

`v_bound=max(observed_speed,default_speed_limit)`；保守当前净距为 `max(0,measured_distance-v_bound×age)`。年龄大于零时以同一上界计算制动；延迟为控制延迟加 `max(0,sensor_latency-age)`，避免重复计算已知年龄。

它假设后续运动确实受速度上界约束，障碍静止或其运动已由外部误差界覆盖，不证明任意加速/动态障碍/硬件制动安全。低净距可能保守拒绝恢复：持续年龄0.01秒、零速、0.24m净距可保持停车；0.40m正常恢复对照通过。独立审查14,280组年龄网格未发现年龄增加导致权限或速度上限提高。

## 多智能体契约

提示词v3，goals/planner仅引用明确可见证据，记录选择ID及输入/输出字节。reviewer每批至多16项，返回 `i/a/c/m`（索引/固定assessment/反证说明/缺失证据），解释合计至多16字符，规范UTF-8回复不超过2048字节。程序验证完整唯一索引和固定判定，回填原finding/intent/artifact身份；旧完整报告字段保留。成功批次立即checkpoint，所有批次仍计入16次角色预算，超额明确INCOMPLETE。

128个CPP输入的真实离线执行已完成：6次注册模型执行、8批复核、16次角色调用，128 findings/128 reviews，待复核0。未支持CPP的静态审查项继续保留，最终STATIC_REVIEW_REQUIRED、CLI退出1；完成研判不等于这些程序通过动态测试。本轮没有调用外部模型。

当前仍是goals→planner→worker→reviewer单轮流程。worker确认固定意图，程序执行注册模型；没有加入任意源码运行或自行扩权。

## 检测页

保留原verdict，新增 `evidence_sufficiency=PARTIAL` 与四项 `property_assessments`：恢复授权、有界恢复、运动包络、来源完整性。短前缀、采样空窗、没有合法恢复转换时不宣称观察到有界恢复。独立审查发现“单帧未授权NORMAL也算有界恢复”的问题，已通过RED/GREEN修正。

页面新增属性表，无授权违规时显示“授权检查未见违规·证据不完整”，运动包络与来源仍不可判定；原过期/重放违规继续保留。

## 运行

```bash
bash deploy/run_guardian.sh build --distro humble
bash deploy/run_guardian.sh demo --distro humble
```

demo使用同一rclpy SingleThreadedExecutor组合已有Guardian、AMR、Dashboard，固定localhost及默认域42，每次启动在进程内生成新的控制/事件签名Key。默认页面 `http://127.0.0.1:8080/#research`；未配置管理员密码时，显式demo模式可用admin/admin。它是本地软件组合演示，不是多进程DDS稳定性或硬件隔离验证。原生产/all入口保留。

启动代码正式收录于deploy/run_local_demo.py，避免依赖忽略目录临时脚本。研究功能仍需源码与固定研究venv，或管理员配置GUARDIAN_RESEARCH_ROOT；HTTP不能选择解释器。

实际浏览器完成登录、正常/过期轨迹、属性范围、相对cmd_vel检查、输入带入、安装环境URL校验、390px布局、两轮软件攻击停车与中间恢复，正常速度0.2；无外部浏览器请求或运行期JS异常。场景已reset并停车，服务保留后台运行。

另以本机临时HTTP协议夹具实际走通页面选模型、创建任务、5次角色调用、两次注册场景执行和下载原始JSON。下载及128项离线报告的8份执行产物已独立复算trace/artifact摘要、上下文/计划绑定和当前来源哈希。该服务是脚本协议夹具，外部真实模型调用0；临时夹具与验收浏览器已关闭。当前Linux演示PID258、Windows launcher PID41420仅对应本次实例。

## 验证

各逻辑修复均先失败回归再修复。核心定向92通过、相邻ROS/反馈23通过；静态返修后99通过；agent批量边界12通过、原相关79通过、作业接口28通过；HTTP/属性/前端范围79通过。独立审查另复放静态原四案例并完成81项agent验证；这些重叠套件不相加为独立总数。

完整回归 **950 passed /319.06s，0失败、0错误、0跳过**；Humble两包构建成功（27.3秒），三个JS语法通过。完整证据以 `output/priority-20261027/full-pytest.xml`、`verification-receipt.json` 为准。目录还保存RED/GREEN日志、安装检查、bulk报告、浏览器日志和独立review；截图与脚本在 `output/playwright/priority-*-1027.png`、`verify-priority-1027.js`。PID仅适用于本次运行，停止前应核对session.json与实际进程。

## 第三梯度

1. A02认证重启接入：启动会话加入签名和授权，旧会话撤销—停车握手—重建水位—重新观察，不能简单接受小序号。
2. 独立运动包络Oracle：原始证据schema、可信参数引用、连续制动边界与独立实现。
3. 证据补读与有界再规划：reviewer异议转为可验证复放请求，全部调用纳入统一预算。
4. 固定协议后接外部ROS任务/轨迹与真实模型，开展规则/单agent/多agent等预算实验。

第三梯度需要独立规格与验证，不由本轮软件闭环通过推断已经完成。
