# Go 软件传感器：当前实现与迁移

现有 `cmd/sensor` 运行路径仍实现 `unsw-nb15-flow-v4`；P2 已新增独立 host-guard v5 研究引擎和 CLI，入口见本文末节。目标输入、prefix与时间窗、目标引用及质量规则见 [检测与处置契约](../docs/检测与处置契约.md)，实施顺序见 [开发路线](../docs/开发路线.md)。

**P1/P2 已完成并收口**，范围见 [P1 交接](../docs/系统实施记录.md#1-p1-数据与平台探针交接)及 [P2 交接](../docs/系统实施记录.md#2-p2-因果提取与观测契约交接)。独立探针提供 `cmd/p1audit` 的公开标签/PCAP 关联审查、`cmd/p1canary` 的有界 TCP 回显和 `cmd/p1httpcanary` 的固定内存 HTTP 下载；Go canary 不操作防火墙，不走 v4 上报。P3 多分类路线用 `guardextract` 从公开 PCAP 提取 prefix 与 final 快照，见 [P3](../docs/模型训练与评估记录.md)；生产执行与恢复属于 P5。

## v4 当前能力与限制

- 被动读取授权接口或离线PCAP/PCAPNG，组流、计算v4特征；原在线上报目标 `/api/v1/machine/sensors/{id}` 已于 2026-10-21 从后端删除（BE-11 后端部分），`cmd/sensor` 只剩离线用途，Go 侧退役另行处理。
- 旧算法使用100条已完成流窗口及61秒重排序等待，规范记录不携带可执行目标引用；不能满足新方案早期检测和目标级阻断契约。
- 旧模型适用范围不能按新文档扩大；现有传感器没有防火墙执行权限。
- 此旧v4实时路径依赖cgo/libpcap及系统权限。编译通过不等于现场可用，新构建仍按实际运行路径验证；独立v5的Windows路径见下文。
- [旧v4规格](../docs/特征规格-unsw-nb15-flow-v4.md)及后端目录下的 `feature-contract` 资源与夹具仍被本目录 `internal/spec`、`cmd/g2fixtures` 测试读取，随 Go 侧 v4 退役一起处理；后端已不再加载。v5实现时新建版本，不能原位改旧语义。

## 构建与离线提取

以下为已有 v4 CLI；工作目录为仓库下的sensor，输出为本地构建产物，不提交Git。P2 已回归 Go 测试，本阶段的真实数据提取使用末节的 v5 命令。

```sh
cd sensor
go test ./...
CGO_ENABLED=0 go build -o bin/sensor-offline ./cmd/sensor
bin/sensor-offline extract -pcap in.pcap -out records.jsonl -diagnostics diag.json \
  -local-addr 192.0.2.2 -subnet 192.0.2.0/24
```

本节旧 v4 CLI 的纯Go构建只能离线读取，实时run明确不支持。macOS实时版本需要系统libpcap与SDK；使用自建clang时先正确配置SDKROOT，再执行 `go build -o bin/sensor ./cmd/sensor`。独立 v5 `guardlive` 的 Windows 构建见末节。本文不授权安装依赖、改系统权限或开始抓包。

extract按文件魔数识别PCAP/PCAPNG，当前仅支持Ethernet。容器截断或不支持链路时失败，已写出的前缀不能当作成功的完整数据。成功诊断、原件/派生文件哈希及提取配置一起保存到受控目录。

可选 `-label-audit` 为公开数据标签关联生成本地旁路，包含端点及连接统计，不上传、不进入模型。原始包、地址账本、日志和大批特征文件不进Git。`cmd/pcapaudit`是离线审查/头部派生工具，不向网卡回放流量；全局排序派生物不能替代v5实时因果评估。

## 已有在线配置

现有 `run` 使用sensor.json：baseUrl、sensorId、dataSourceId、sourceMappingVersion、stateDir、allowedInterfaces、keystoreService、keystoreAccount。stateDir为仓库外受控绝对路径，配置不含凭据。凭据仅通过现有credential导入入口写入系统安全存储，不能放argv或日志。

非回环后端须HTTPS；下发配置不能扩大本机接口白名单。开始实时运行前必须有对应主机、接口和时段授权；权限不足明确失败，不改变系统权限掩盖问题。v5执行器将是独立进程与机器身份，不能把旧sensor的采集凭据用于处置。

迁移差距及兼容文件退役条件见 [开发路线第 4 节](../docs/开发路线.md#4-当前实现与迁移边界)。
## v5 P2 独立研究提取器

`cmd/guardextract`、`internal/hostguard` 为 `host-guard/5.0.0-rc.2` 独立路径；原有 v4 命令、资源和上传流程保留。研究提取CLI离线读取，不上传或执行防火墙动作；详细语义与范围见[P2交接](../docs/系统实施记录.md#2-p2-因果提取与观测契约交接)。

```sh
CGO_ENABLED=0 go test ./...
go test -race ./internal/hostguard
CGO_ENABLED=0 go run ./cmd/guardgolden -check
CGO_ENABLED=0 go build -o bin/guardextract ./cmd/guardextract
```

`guardextract -config <受控配置> -pcap <完整捕获> -out <新JSONL> -ledger <本机旁路> -report <新摘要>` 只支持 research；用 `-start`/`-end` 指定隔离分区，每个独立分区必须使用新 bootId 和新引擎。配置包含 UUID 身份、`localAddresses`、`secretFile`、`keyEpoch`；密钥为至少32字节随机值，原始地址/密钥/配置/旁路和特征输出均放忽略的受控目录。重试保留身份与密钥，不能覆盖已有输出；只有完整输入通过后才生成完成摘要。

`guardjoin` 消费离线规范标签，核对全部连接计数及受控起点旁路；不把载荷、标签或地址送入模型。`guardgolden` 默认生成小型合成夹具，日常使用 `-check` 防止改写冻结期望。共享因果引擎已按P2交接，实际采集使用下列独立入口。

## v5 有期限的实时采集

已登记的本机还支持[后端生命周期内持续监测](../docs/传感器持续监测.md)：就绪后自动启动、退出时停止；原短窗口模式保留。持续模式与真实接口授权、机器 mTLS 及已批准构建共同校验，不能单独使用 `-duration 0` 绕过准入。

`cmd/guardlive` 复用同一因果引擎，记录同一捕获句柄的头部、Tick、drop/gap及关闭事件，使用 `-replay` 逐字节复算。macOS依赖cgo/libpcap；Windows的gopacket通过系统调用加载已安装Npcap，**不要求cgo或Npcap SDK**。构建标签为 `cgo || windows`，不是把Windows实时请求静默转为离线处理。

```sh
go build -o bin/guardlive ./cmd/guardlive
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o bin/guardlive.exe ./cmd/guardlive
```

配置除v5身份、密钥和本机地址外，还需 `interface`、`allowedInterfaces`、`peerAddresses`、`servicePort`、`authorizedUntil`；`serviceEndpoint` 可为 `local` 或 `peer`。默认/空值为本机服务，客户端访问已登记对端服务时指定 `peer`；未知值拒绝。BPF同时绑定接口、本机/对端和服务端口，登记期限不能由命令行采集时长延长。原始端点和私有轨迹留在受控忽略目录。

Mac/Windows回环和物理接口的实时输入与同轨迹逐字节复算已作为P1/P2基线收口。Windows未签名程序在目标机既有系统策略下的自用运行已交接，不增加发行签名或安装包任务。该基线仅覆盖实测范围；新构建绑定自己的文件/依赖哈希，不授予模型或自动处置资格。

### S1—S4（2026-10-08，代码与离线测试）

以下为传感器线 S1—S4 的实现范围；未在真实后端、真实接口长时运行或 lab 中验收，不构成自动处置资格。

Z1 集成复验（2026-10-10）已重编译 `guardtargets`：cgo 与纯 Go 的 `go test ./...`、`hostguard/guardup/capturehealth/jcs/guardlive` 的 `-race`、20 场景/55 观察的 `guardgolden -check`、51 项执行器测试及 5 Schema/8 负例/55 观察的契约检查通过。真实 P4/数据库接收、服务端 mTLS 终端配置、长时间全入站采集与健康链、`guardtargets` 租约接入及 Windows 全入站仍未验证。

- **S1 全部入站 TCP**：配置 `captureScope` 取 `service`（默认，沿用上文对端+服务端口）或 `all_inbound_tcp`。后者不接受 `peerAddresses`/`servicePort`/`serviceEndpoint`，BPF 只放行一端为登记本机地址（≤16 个、同一地址族）、另一端为非本机地址的 TCP，两个方向都保留，以免 SYN-ACK/RST/出站字节缺失而与离线提取不同口径；接口仍受 `allowedInterfaces` 限定。写出与上传只保留 TCP 且方向不是 `outbound`（本机主动外连）的观察，方向未知的段保留给后端按 not_applicable 处理。上下文窗口仍由同一引擎按捕获到的全部报文计算。
- **S2 1 倍速文件回放**：`guardlive -pcap <冻结文件> [-start/-end 原事件时间]` 只读文件、不打开网卡、不注入报文，默认仅限 research；显式 lab 配置可使用已核验会话与 canary 映射接入，见[传感器 lab 接入](../docs/contracts/sensor-lab.md)。research 模式由首包确定整秒 `timeOffsetMicros`，此后所有报文一次性平移并按原包间隔等待；等待期间每 100ms 推进引擎使快照按时发出，但 Tick 不越过下一个待送报文，文件读完不再 Tick，因此观察与 `guardextract` 对同一文件、同一身份/密钥的结果逐字段一致（`emittedAt` 为真实墙钟，事件时间减去平移量即原时间）。`-report` 记录平移量、原首末包时间、墙钟起止、最大落后和 PCAP 哈希；`guardreplaydiff -offline -replay -report` 按同一范围过滤后逐字段比对。中断或截断文件不报告完成。
- **S3 v2 观察上传**：配置可选 `upload` 对象（`baseUrl` https 根地址、`caFile`、`certificateFile`、`keyFile`、`credentialFile`、绝对 `spoolDir`、可选 `healthWindowMs`）。传输为 TLS 1.3 并强制出示传感器客户端证书，同时带 v2 `Bearer mch_…` 凭据；不继承代理、不跟随重定向，私钥与凭据文件须为属主专用的绝对普通文件。启动时读取已批准配置，契约版本、profile 摘要、健康版本、捕获域、地址族和本程序 SHA-256 任一不符即拒绝。观察先按 `maxBatchSize` 或 500ms 封口并 fsync 到 `spoolDir/<bootId>/`，再按 sequence 顺序单批在途发送；先发心跳登记 bootId。网络错误、408/429/5xx 以同一 batchId、Idempotency-Key 与原字节退避重试，其余 4xx（身份、范围、幂等冲突等）立即停止采集。环境取配置 `environment`（research/lab/authorized），未配置 lab 接入时，本节不接入 `guardtargets` 租约；显式 lab 接入通过独立可信登记器取得目标引用。
- **续传与 boot**：同一 bootId 重新采集会生成相同观察 ID 而 `emittedAt` 不同，因此已有 spool 时拒绝启动，须换新 bootId；结束时未确认的批次保留在 spool，用 `guardlive -config <同一配置> -drain` 续传。已封口批次不丢不重；进程崩溃时内存中未满 500ms 的未封口观察会丢失，表现为新 boot 的缺口。
- **S4 健康窗口**：配置 `upload` 时同时运行 `host-guard-capture-health/1.0.0` 观察器（默认 1 秒、上限 5 秒窗口），只读捕获句柄的累计读包数、内核丢包（不可测为 null）与引擎容量丢弃，独立于特征引擎；`previousSha256` 为前一窗口完整 payload 的 RFC 8785 JCS SHA-256，服务端返回摘要不一致即停止。轮询停顿超过 5 秒时按上限切分并标记 `captureGap` 与未知计数。`clockSkewMs` 取 60 秒内往返 ≤1 秒的心跳估计，否则为 null。文件回放的历史丢包未知，窗口不能证明连续健康。
- **BE-7 现场生命周期（2026-10-14，工作区代码完成）**：`capture` 经 `runLiveSource` 接入健康链；首包前建立基线，空闲超时持续采样，退出前重读丢包计数并包含引擎关闭时的容量变化，封口尾窗。健康签发或上传器致命错误即时停止，读取异常标记缺口并尝试送达；不能把未知计数当零或把回放窗口用于现场。合成捕获源与严格 mTLS 替身后端覆盖 16 个新增场景，真实采集及现场预算恢复仍待 P8 授权验证；详见[实施记录 6.12](../docs/系统实施记录.md#612-be-7现场健康观察器代码2026-10-14)。
- **正式 lab 回放健康 1.1.0**：仅 `-lab-plan` 会话清单选择该版本时输出 `captureSource=file_replay`，kernelDrops=null 表示不适用；回放计数已知且连续、无容量丢弃或 gap 时由后端判为 `replay_healthy`。仅绑定同版本 subject 的 running 正式 lab 会话可用于 T2 判定/领取，不能作为现场健康或预算恢复证明。research/现场默认 1.0.0 字节保持不变，远端配置须与实际观察器版本一致。

```sh
go build -o bin/guardlive ./cmd/guardlive
go build -o bin/guardreplaydiff ./cmd/guardreplaydiff
bin/guardlive -config <配置> -pcap <冻结片段> -out <新JSONL> -report <新摘要>
bin/guardreplaydiff -offline <guardextract 输出> -replay <上一步输出> -report <上一步摘要>
```

## P5 本机目标服务

新增 `cmd/guardtargets`，将 P2 易失注册表以独立回环 mTLS 服务运行；不持有防火墙权限。保留旧lease/resolve，新增resolve-lease返回原始lastPacketAt/expiresAt，供P5在安装前核验新鲜度。配置包含明确期限和collector/executor分离证书指纹；退出销毁引用，执行器boot变化须重新配对。构建为 `go build -o bin/guardtargets ./cmd/guardtargets`，运行与执行器对接见[执行器说明](../executor/README.md)。现有guardlive仍是research入口，不因新增目标服务自动取得真实执行资格。

## J1 V3 v8 research 收口边界（2026-10-11）

两轮 1 倍速文件回放已经完成，观察/模型/规则/决策经真实 mTLS 进入隔离 MySQL 副本，正式证据见 `.cache/j1-20261011-v8/REPORT.md` 与 `.cache/j1v3-20261011/closeout.json`。J1 未通过，J2/P8 保持关闭；research 未接 target 或执行器，动作/命令增量为 0，研究组合已批准但未激活。此结果不能证明真实接口长期采集、全入站健康链或自动处置资格。

A7 本轮只完成本机配置与恢复检查：`en0` 活跃、TSO4/TSO6 开启、`net.inet.tcp.tso=1`；没有免密 sudo，`pfctl` 因 `/dev/pf` 权限拒绝。未改变网卡、sysctl、PF、服务或系统配置；静态 PF ABI 与恢复单测通过不等于全局 PF 快照验证。历史 CIC PCAP 的 offload/质量事实不能通过当前本机 TSO 检查修复，本轮不进行实时对端流量对照。

## lab 会话、canary 与可信目标接入（2026-10-11，已合入）

已于 2026-10-11 合入 main：`mvn test` 445 项 0 失败（含 `GuardSensorHealthIntegrationTest`），相关 Go 包 `-race` 通过，`guardtargets` 已重编译、执行器 mTLS/engine 51 项通过；未部署、未在真实 lab 运行。独立 `guardlab` 适配模块只读核验后端 `runnable`、配置给定的会话 ID（`runId`）、会话 JCS 摘要（`sessionSha256`）与映射原字节摘要（`mappingSha256`）、runner 签名映射及 PCAP/构建摘要，按登记的固定偏移回放，并经独立 mTLS `guardtargets` 登记器取得 targetRef；租约过期、映射不符或 normal/attack 共用 targetRef 均 fail-closed。单场景用 `-pcap`，非重叠多场景用 `-lab-plan`，共用同一 boot/队列；不更改 K2 的上传/spool 实现。

`guardreplaydiff` 对 `lab_pcap_replay` 摘要自动进入 lab 对拍：除已登记差异字段（`emittedAt,environment,peerKey,targetRef,targetExpiresAt,quality.clockSkewMs`，多场景另加 ID 三项）外，与 research 离线提取逐字段比较。健康链补充了回环替身后端端到端测试（窗口连续、缺口、未知计数、断连重连、重复证明拒绝）。这些都是离线合成验证，不是现场长期采集或 G3 证据。

配置、身份分离、初始注册、事件交接、原字节续传、限制及与 lab 线的字段对齐见[完整接入契约](../docs/contracts/sensor-lab.md)。lab 后端新接口仍在其分支待合入，缺少 `runnable=true` 时本入口明确拒绝。research 路径保持原行为；本线不含前端、常驻部署或真实防火墙操作。

## 演示专用 utun 采集

`guardlive` 的 `captureScope=lab_peer_tcp` 仅允许 environment=lab、一个本机/一个不同对端的 Tailscale IPv4、utun 接口、最多128个非重复高位 `servicePorts` 与固定私有 `captureLockDir`。按接口加锁，同接口第二个进程失败；不同接口可共存，仍须实际 BPF 权限。`liveTargets` 仅用于此范围并要求实时上传；向本地 mTLS 解析器取得短期目标，inboundPorts 映射全入站，其他登记服务映射单服务。生成配置和准备流程见 [演示工具](../scripts/demo/README.md)。

现场读取使用 libpcap immediate mode/25ms 超时。排队包不被读取墙钟强行越过，只有真实空闲超时推进墙钟水位；100ms 重排边界与真正 latePacket 语义不变。合成包与过滤器测试通过不等于 utun 现场方向、权限、丢包率或模型效果已经验证。本次未启动采集或修改 en0 部署。

## 动态本机地址

后端托管的 `all_inbound_tcp` 可在配置中设置 `localAddressSource: "interface"`：启动入口按采集接口当前地址生成本次配置，`guardlive -parent-pid` 每 5 秒核对，地址变化即收尾并以退出码 3 结束，由托管方用新地址重启。说明见 [传感器持续监测](../docs/传感器持续监测.md)。
