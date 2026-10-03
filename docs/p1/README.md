# P1 数据与平台可行性探针

截至 2026-10-04，P1 后续数据补证已完成，**数据可行性出口通过，阶段整体 blocked**。候选任务收敛为单个 HTTP 服务入站慢请求/连接滥用；完整 CIC 原件、111 条关联和 20 条起点审查已完成。最新WFP探针六项非重启场景通过，一次明确授权的重启后无残留，但缺少期限内清零观察，自动启动观察任务退出1，严格跨重启TTL仍未验证。详见[机器可读裁决](stage-exit.json)。未进入P2、模型训练、数据库迁移或生产自动运行。

| 对象 | 当前结果 |
|---|---|
| 数据 | 两个 CIC 工作日共 22,260,098,668 字节，完整 PCAPNG/MD5/SHA-256 校验通过；111/111 条关联匹配。5 个 IoT-23 捕获的 150 条历史抽查及失败保留 |
| 起点 | 原 20 条 Slowloris 样本修正来源匹配后有 5 条结构候选；其中 3 条可在发布者观察窗口内定位到后续 1s/5s/50s 快照时刻。全量 prefix 标签未批准 |
| 困难正常任务 | Windows 固定内存 HTTP 下载、并发和 Range 恢复；8 项中 7 项内容校验通过，1 项正常并发超时保留；抓包 2,958 帧，范围验证通过 |
| Windows | 原 canary 实际启动，Npcap 1.89 与真实抓包通过；隔离、既有/新连接阻断、30 秒到期、进程退出、断连完成试验 |
| 重启恢复 | 首次延迟约 593 秒失败；修订后启动 25.9 秒清理，但超原定到期约 19.7 秒，严格跨重启 TTL 未通过 |
| Mac | 仅只读预检，尚未验证 PF 动作和恢复，不授予 auto |
| 结束状态 | 全部 6 个试验命名空间的规则/任务为 0；专用试验进程为 0；管理服务、防火墙和 Npcap 运行，训练工作区保留 |

## 动态会话恢复补证

2026-10-04 新增 [WFP 动态恢复探针](wfp-dynamic-probe.md)与[机器报告](wfp-dynamic-probe.json)。临时阻断使用动态会话，独立恢复进程与健康监视器负责30秒期限和故障回收；六项非重启场景通过。跨重启与当前清理状态以该补证报告为准，历史持久规则超时证据不覆盖。Mac 按用户要求暂不验证；周五官方校验入口返回登记要求，继续保留仅镜像校验等级。

## 本轮产物

- [定向补证报告](continuation-report.md)：结论、失败、真实变更和阶段边界。
- [数据审计汇总](continuation-data.json)：完整原件、111 条关联、20 条起点、表格质量及全部证据哈希。
- [当前可观测性矩阵](continuation-coverage.md)：核心特征、时间方案、独立活动、全量预算和平台缺口。
- [阶段出口裁决](stage-exit.json)：数据可行性通过与平台出口未通过分别判定。
- [平台证据汇总](continuation-platform.json)：连接结果、实际清理时间、环境及可复算哈希。
- [补充标签策略](continuation-label-policy.md)：任务、Attempted、起点候选、困难负样本和暴露活动。
- [预算决策](continuation-budget.md)：两个完整 CIC 工作日的获取范围与原件/临时预算。

原始PCAP、端点映射、远端缓存、未去敏日志和下载账本放在忽略目录。未提交或推送。历史两次重启证据保留；最新补证另获授权执行了一次重启，现已结束，没有追加重启。所有本任务试验规则、计划任务、探针进程和动态对象均已清零。

## 工具与验证

Go 工具位于 `sensor/cmd/p1audit`、`p1canary`、`p1httpcanary`，分别提供离线抽查、固定 TCP 回显和固定内存 HTTP 任务。它们不操作防火墙，不接入 v4；Windows 临时规则由 [windows-rule-probe.ps1](../../scripts/p1/windows-rule-probe.ps1) 按不可变 manifest 和独立命名空间处理。恢复任务直接调用系统签名的 netsh，无执行策略绕过。

[下载器](../../scripts/p1/download_cic_mirror.py)核对每段 Content-Range、完成账本与完整 MD5，未完成文件保持 `.partial`；[CIC 抽查器](../../scripts/p1/cic_probe.py)核对完整容器、标签、计数和可观察的连接起点。[头部参考工具](../../scripts/p1/pcap_reference.py)现支持经典 PCAP 及单 section/单接口 PCAPNG，拒绝混捕获域和损坏块，只读取截止点之前的包，尚非 P2 提取器。

```sh
python3 -m unittest discover -s scripts/p1 -p 'test_*.py'
python3 -m py_compile scripts/p1/*.py
python3 scripts/p1/summarize_platform.py --check
python3 scripts/p1/summarize_data.py --check
python3 scripts/p1/adjudicate_stage.py --check
node scripts/p1/summarize.mjs --check
cd sensor
CGO_ENABLED=0 go test ./...
```

`--check` 必须有本任务的忽略证据目录；公开摘要不包含原始端点。历史和本轮报告分别验证。裁决脚本成功表示报告可复算，输出仍为 `blocked`，不能由退出码 0 推定阶段通过。

## 历史 v1

[首次探针说明](initial-probe.md)、[source-manifest.json](source-manifest.json)、[sample-join-audit.json](sample-join-audit.json)、[coverage-matrix.json](coverage-matrix.json)、[coverage-matrix.md](coverage-matrix.md)、[platform-capability-probe.json](platform-capability-probe.json)与[初始标签策略](label-policy.md)完整保留。它们对应当时的 3 个捕获/90 条样本和 Windows 4551/无 Npcap 状态，不代表后续当前环境。
