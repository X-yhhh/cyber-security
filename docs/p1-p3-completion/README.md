# P1—P3 本轮实现与实机验收

日期：2026-10-04。工作区基线 `4d133027a6a82657f4aa9e74edc7344f861c0313`；本轮交付工作区修改，未提交或推送。机器可读结果见 [verification.json](verification.json)，代码和证据绑定见 [manifest.json](manifest.json)。历史失败记录与既有模型、数据冻结均保留。

按用户明确的自用范围，目标是Windows训练、导出模型到Mac加载，以及实际使用组件可运行；不要求对外发行、独立安装包、代码签名证书或签名服务。当前范围见[delivery-scope.json](delivery-scope.json)。历史`research`模式是已有制品入口的名称，不表示必须先升级为签名`release`模式才能自用；缺少发行证书不计为待完成项。

## 已完成的实现与验证

| 项目 | 本轮结果 | 实测范围 |
|---|---|---|
| Windows SCM 恢复 | 实际 STOP、一次真实重启的 PRESHUTDOWN、截止前独立清零、旧 boot 命令拒绝、重启后目标/控制连接恢复均通过 | IPv4/TCP、专用回显程序、对端服务级动态 WFP；控制连接与管理服务正常 |
| Mac PF | 实现匹配运行内核的精确状态删除；已有/新目标连接阻断、控制端口不受影响；TTL、显式撤销、执行进程崩溃恢复通过 | Darwin 27.2.0、`xnu-13432.40.162~92`、IPv4/TCP 回环 canary；TTL 到期后 81.2 ms 独立确认清零 |
| Go live | 两端回环及物理接口均完成同句柄头部/Tick/drop 轨迹逐字节复算，全部零丢包 | Mac libpcap、Windows Npcap；物理接口分别完成 3 条正常 HTTPS 连接、9 个完整 GET |
| 起点与标签 | 修复扩展 HTTP 方法解析、RST 零窗口误读、导出段边界与 TCP 生命周期混淆、idle 续段关联及场景身份硬编码 | CIC2017 实际证据为慢请求体，取得 1,020 条来源关联连接和 1,111 条合格 prefix；CIC2018 为 8,067 条 prefix |
| TAARA 来源与数据 | 论文原件哈希匹配；按登记端点、SYN epoch 和因果续传关联，Apache 唯一关联独立记录 | 11,674 条攻击连接；Go 实际提取保留 40,598 条攻击 prefix、1 条正常 prefix |
| 分区与封存 | 完成新语料构建、近重复分组、角色冻结、哈希校验及 P6 原件预留 | 50,129 条 prefix、12,703 个 parent、14 个活动；归并为 8 个防泄漏组，跨角色 parent/活动/组均为 0 |
| Windows 自用运行 | 未签名程序在SAC=On下实际启动、采集与复算通过，程序/DLL身份可核对 | 不需要Npcap SDK或Windows cgo；代码签名、安装包和正式发行不属于本轮条件 |

Windows `gopacket v1.7.2` 原生通过系统调用加载 Npcap，先前 `cgo` 构建标签误排除了这条可用路径。已修正为 `cgo || windows`。运行中实际加载的 `wpcap.dll` 1.10.7 与 `Packet.dll` 1.89 均通过系统签名验证；这与程序自身的发布者签名分别记录。

`guardlive` 增加显式 `serviceEndpoint=local|peer`，空值保持本机服务语义；客户端采集须登记 `peer`，未知值拒绝。双向过滤仍只覆盖登记端点与服务，未扩大为任意端口。观察字段、公式和 `host-guard/5.0.0-rc.2` 契约不变。

## Windows 重启链条的证据边界

真实 SCM STOP 的独立清零早于截止时间 21.27 秒；真实 PRESHUTDOWN 的独立清零早于截止时间 14.68 秒，并同步落盘。新启动周期已核对，旧命令实际返回 `STALE_BOOT`。仅进行了一次维护重启。

该次自动启动观察器确实以 SYSTEM 启动，但在 PowerShell/CIM 查询启动时间时超时，未保存首次枚举。现已改为直接读取内核 `SystemTimeOfDayInformation`，并先持久化规则枚举再获取辅助元数据；同一 SYSTEM 入口、空命名空间、目标/控制连接恢复均已实测。另用过期授权真实启动 SCM，确认服务、所有者和外层启动器一致以失败退出，不再把初始化失败报成成功。

**2026-10-05 收口：G1 六项实质条件已全部通过。** SCM STOP/PRESHUTDOWN 截止前独立清零（提前 21.27 秒、14.68 秒）、启动后自动枚举（`reconciled_no_commands_accepted`）、连接恢复（107ms/108ms）、旧命令拒绝（`STALE_BOOT`）均通过。`passed: false` 仅源于 finally 清理步骤的一个 SSH 报错；用户已独立复核远端为 0 条规则/0 个任务/0 个服务，该报错不影响实质通过裁决。手动 SYSTEM 重放不冒充自动启动，也不把正常重启写成突然断电验收。

Mac 精确状态 ABI 来自运行中的系统 `pfctl` 指令和目标机验证，结构为 216 字节、ioctl `0xc0d84429`。公开 XNU 参考源码不是当前内核的精确版本；helper 同时绑定当前内核版本、布局和窄目标，系统升级后拒绝沿用。当前回环动作证据不扩写成任意物理接口、IPv6、UDP、睡眠或 Mac 重启恢复能力。收尾审查另修复“规则已装、成功回执未落盘”时的恢复依赖，并在事务锁内拒绝到期/撤销后的迟到安装；这两个失败边界通过无特权故障回归，未重复内核动作实测。清理失败或原状态未恢复时，探针也不再报告成功。

## 数据冻结与模型准入

新原件和大批数据在忽略目录 `artifacts/p1-p3-completion-20261004/`，最终语料为 `prefix-corpus-v3`。v3仅补齐独立开发角色内的组数准入检查，索引、观察、分区及P6预留与v2逐字节相同，不改既定角色；新裁决独立保存，旧结果保留。标签旁路与模型特征分离；新请求方法本身不构成攻击标签，仍须来源、端点、SYN epoch 与因果证据共同支持。CIC2017 的首次续传证据通常在连接建立 105 秒以后，没有为了时效成绩把起点提前。CICFlowMeter 导出段结束不等于 TCP 结束；延伸窗口绑定全量审查中的同一 SYN epoch，并受请求完成、实际末包、发布窗口及最后可靠证据约束。

分区保留完整 parent、原始活动、来源日和 150 秒上下文隔离；跨活动完整 parent 的有序粗粒度特征序列相同则归并，不能通过换 UUID 拆组。先按类别覆盖、再按固定哈希顺序及 40/20/20/20 目标比例分配开发角色，全程未读取模型分数。254 次跨活动近重复匹配把 TAARA 两个来源日进一步归为同一防泄漏组。

最终为 **49,776 条攻击、353 条正常 prefix；独立攻击组 3 个、正常组 6 个**。Slowhttptest、CIC2018 Slowloris、TAARA Slowloris 各仅 1 个攻击组，无法分别覆盖训练、选型、校准和独立开发评价。独立开发角色本身为0个攻击组、3个正常组，必须在该角色内满足正负各5组，不能用训练组充数。准入裁决为 `trainingAllowed=false`，本轮新增拟合 **0 次**；没有伪造逐场景 ≥80% 覆盖、独立模型收益或新候选跨平台验收。

P6 原件预留哈希与禁止开发读取规则已冻结，10 份捕获均未读取最终特征/标签/分数。9 份 TAARA 原件因共享已暴露开发来源日而隔离，1 份 Rios 原件保持封存、来源资格待审；`p6Ready=false`。封存完成不等于最终评估准入。

Rios 的[公开论文](https://doi.org/10.1145/3605098.3635919)已核对第 6 页实验流程及原文：它描述混合正常流量的 1 秒聚合窗口，未给出本项目可唯一绑定的逐连接端点/起点表。现有开发捕获跨度也不能直接套入“第 180 秒开始、持续 60 秒”的说明。因此未用时间窗或慢头部结构自动把其中的未知连接转成攻击/正常。原件与本次裁决均保留。

## 验证入口

执行并通过与本次变化直接相关的验证：

```sh
cd sensor
go test ./internal/hostguard ./cmd/guardlive
go build -o ../artifacts/p1-p3-completion-20261004/guardlive-mac-v2 ./cmd/guardlive
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o ../artifacts/p1-p3-completion-20261004/guardlive-windows-v2.exe ./cmd/guardlive
```

```sh
python3 -m unittest discover -s scripts/p1 -p test_wfp_probe.py
python3 -m unittest discover -s scripts/p1 -p test_pf_probe.py
python3 -m unittest discover -s scripts/p3 -p test_prefix_review.py
git diff --check
```

WFP 边界 15 项、PF恢复失败边界2项、因果/关联回归 8 项通过；独立复核验证全部 50,129 条真实观察的身份、质量、角色与冻结哈希，v3实际文件与已审查v2的四份冻结输出完全一致。上述检查以外，实机证据分别由 [SCM 驱动](../../scripts/p1/run_scm_acceptance.py)、[PF 探针](../../scripts/p1/pf_probe.py)、[回环验收](../../scripts/p1/verify_live_capture.py)、[物理接口验收](../../scripts/p1/verify_physical_capture.py)生成，复现需重新登记有效范围和新输出目录，不能重放旧租约。

Windows [制品入口](../../scripts/p1/finalize_windows_artifact.py)的`research`模式已在目标机通过，可用于当前自用运行；不必调用可选的`release`分支。该分支要求现有证书、SignTool和时间戳，缺证书退出2的记录仅是历史工具验证，不能当作本项目当前阻塞。处置命令的内部签名验证不依赖此程序发行证书，按实际启用的自动功能保留。

## 运行态与交付

本轮 Windows 服务、计划任务、隔离规则、WFP 对象、探针进程和监听全部清理，SSHD/Tailscale 正常，SAC 保持 On。Mac 恢复原始 PF 根规则与关闭状态，`/etc/pf.conf` 字节未变，自有 anchor 与 launchd 工作者已清理，临时回环地址已移除。原始证据和失败尝试保留用于复核。

未修改活动 v4 服务、数据库、前端或既有权重，未安装驱动或关闭系统防护。后续候选模型仍受独立数据和完整策略准入约束；本轮成果不授予生产自动执行资格。
