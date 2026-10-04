> 历史快照：2026-10-03 首次探针。最新状态见 [P1 入口](README.md)；本文件不代表后续补证结果。

# P1 数据与平台可行性探针

日期：2026-10-03；契约 `host-guard 5.0.0-rc.1`。P1 已实施有界探针，**阶段状态 blocked，出口尚未通过**。没有进入 P2、训练、数据库迁移、部署或真实自动运行。

## 结果

| 对象 | 当前证据 | 出口判断 |
|---|---|---|
| P1-D 工具与采样 | 3 个完整 IoT-23 捕获，逐文件 SHA-256，90 条抽查；8-1 和 3-1 各 30 条关联通过 | 研究采样通过，不代表全量或自动资格 |
| 34-1 标签 | 18 条关联通过，12 条 DDoS 标签关联歧义；发布者包计数为零与原始包矛盾 | 关联修订待完成，保留失败 |
| 目标家族 | 水平扫描跨 peer，DDoS 关联未通过，C&C 有多活动完整连接候选 | 自动任务数据出口 failed；prefix 起点及困难负样本不足 |
| Windows | win-dev / Windows 11 build 26200，管理员；真实程序启动错误 4551，Code Integrity 3033/3077；无 Npcap | P1-P blocked，没有开始动作测试 |
| Mac | macOS 27.2 / 26B5091g，Apple libpcap 1.10.1、pfctl；BPF0 为 root 0600 | 只读预检；尚无该平台隔离动作授权 |

远端训练分支 `training/windows-cuda`，HEAD `9378f02`；原有未提交的 phase2 文件保留，未改写训练工作区。Windows 程序和证据放在训练仓库的忽略缓存目录；未安装依赖、调整应用控制、改变防火墙策略或重启。结束时本任务规则数量为 0，MpsSvc/sshd 仍运行。

六个原始 PCAP/标签文件共 215,077,369 字节（205.114MiB），低于 2GiB；完整原件校验后只清理本次 SCP 中断产生的约 2MiB 片段，其内容可由已核验的完整原件恢复。既有远端数据和诊断证据均保留。

## 产物

- [source-manifest.json](source-manifest.json)：两候选来源、实际原件大小/哈希、许可版本、镜像修订、CIC 获取失败及预算。
- [label-policy.md](label-policy.md)：标签层级、抽样、连接定义、歧义、final-only 与下一实验。
- [sample-join-audit.json](sample-join-audit.json)：90 条去敏逐样本证据、两方向计数和有界头部参考值。
- [coverage-matrix.json](coverage-matrix.json)和[可观测性说明](coverage-matrix.md)：采集点、方向、协议、可计算特征及能力缺口。
- [platform-capability-probe.json](platform-capability-probe.json)：Windows 实际启动失败和 Mac 预检，明确未执行的动作/恢复测试。

每份 JSON 绑定工具源码/二进制、配置、契约和标签策略 SHA-256。原件、初次诊断、未去敏路径和远端执行缓存不进 Git；去敏汇总可审查。研究标签和统计不输入现有 v4 运行时。

## 已实现工具

[p1audit](../../sensor/cmd/p1audit/main.go)只读完整 PCAP/PCAPNG 和 Zeek 标签；拒绝坏字段、重复 UID、截断容器，支持两个明确的发布者标签布局。输出路径必须不存在。它复用包读取/解析，不复用 v4 流窗口公式，也不是 v5 提取器。

从应用仓库根目录执行；`P1_SCENARIO_ANCHOR` 取该场景发布者 README 的本机地址，`P1_OUTPUT` 使用新报告路径。三个原件 stem 为 hakai/muhstik/mirai，场景分别为 8-1/3-1/34-1。

```sh
cd sensor
CGO_ENABLED=0 go test ./...
CGO_ENABLED=0 go build -o bin/p1audit ./cmd/p1audit
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o bin/p1canary.exe ./cmd/p1canary
cd ..
sensor/bin/p1audit -pcap data/raw/p1/iot23/hakai.pcap \
  -labels data/raw/p1/iot23/hakai-conn.log.labeled \
  -scenario CTU-IoT-Malware-Capture-8-1 -local-addr "$P1_SCENARIO_ANCHOR" \
  -contract-profile docs/contracts/feature-profile.json -samples 30 -report "$P1_OUTPUT"
node scripts/p1/summarize.mjs --check
git diff --check
```

[p1canary](../../sensor/cmd/p1canary/main.go)的 `--self-check` 不监听或改防火墙。TCP 回显仅能绑定一个本机私网/覆盖网 IPv4 高端口，接受一个指定 peer，期限不超过 180s、最多 8 个并发连接，不主动发起连接。它不具备系统隔离、规则管理或恢复功能；应用 peer 校验不能替代网络层隔离。

[windows-preflight.ps1](../../scripts/p1/windows-preflight.ps1)以当前身份实际启动 canary，核验签名、SHA-256、Npcap 和有效防火墙 profile，写入新报告。退出码 2 为程序未启动，3 为缺少抓包依赖。需要的 Windows 路径由授权 runner 提供，不在代码中固化机器目录。

```powershell
powershell -NoProfile -NonInteractive -File $P1_PREFLIGHT_SCRIPT `
  -CanaryPath $P1_CANARY_BINARY -ReportPath $P1_NEW_REPORT
```

本轮实际退出码为 2；程序散列与本机交叉构建一致。交叉构建成功不等于 Windows 可运行。系统策略不接受该 unsigned 构建时，保持当前系统防护，不导入自签信任或设置 ExecutionPolicy Bypass。

## 平台出口待办

Windows 先取得当前应用控制认可的可信签名构建，再核验许可合规的 Npcap 和实际采集；随后建立专用 canary 的网络层隔离证据，保护 SSH/Tailscale。只有这些入口通过后，才实现/执行独立规则命名空间、对端/服务/方向粒度、既有和新连接效果、30s TTL、进程退出、控制面断开和重启恢复。当前没有这些成功证据，也没有自动能力。

Mac 需明确隔离测试资产和接口，再验证 PF 规则范围及恢复；不能从 pfctl 存在推定 auto 支持。P1 整体不得标 passed；独立的公开数据研究可以继续，下一阶段开发仍按[开发路线](../开发路线.md)的入口推进。
