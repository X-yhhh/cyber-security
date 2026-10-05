# Go 软件传感器：当前实现与迁移

现有 `cmd/sensor` 运行路径仍实现 `unsw-nb15-flow-v4`；P2 已新增独立 host-guard v5 研究引擎和 CLI，入口见本文末节。目标输入、prefix与时间窗、目标引用及质量规则见 [检测与处置契约](../docs/检测与处置契约.md)，实施顺序见 [开发路线](../docs/开发路线.md)。

独立 [P1 探针](../docs/p1/README.md)提供 `cmd/p1audit` 的公开标签/PCAP 关联审查、`cmd/p1canary` 的有界 TCP 回显和 `cmd/p1httpcanary` 的固定内存 HTTP 下载。Go canary 不操作防火墙；动作由独立授权探针管理。[最新实机结果](../docs/p1-p3-completion/README.md)已验证 Windows STOP/PRESHUTDOWN 截止前清零及 Mac 回环 PF 恢复；自动启动首次枚举修复后未再重启验证。任务规则/服务均已清理，P1 工具不走 v4 上报。

## v4 当前能力与限制

- 被动读取授权接口或离线PCAP/PCAPNG，组流、计算v4特征；在线上报 `/api/v1/machine/sensors/{id}`。
- 旧算法使用100条已完成流窗口及61秒重排序等待，规范记录不携带可执行目标引用；不能满足新方案早期检测和目标级阻断契约。
- 旧模型适用范围不能按新文档扩大；现有传感器没有防火墙执行权限。
- 实时采集依赖cgo/libpcap及系统权限。Windows纯Go交叉编译不等于现场可用，凭据、采集和权限链路必须按P1实机核验。
- [旧v4规格](../docs/特征规格-unsw-nb15-flow-v4.md)因现有测试哈希引用暂时保留；v5实现时新建版本，不能原位改旧语义。

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

迁移差距及兼容文件退役条件见 [现状与迁移](../docs/现状与迁移.md)。
## v5 P2 独立研究提取器

`cmd/guardextract`、`internal/hostguard` 为 `host-guard/5.0.0-rc.2` 独立路径；原有 v4 命令、资源和上传流程保留。P2 不启动网卡、不上传、不执行防火墙动作。详细语义、验收及范围见[阶段报告](../docs/p2/README.md)。

```sh
CGO_ENABLED=0 go test ./...
go test -race ./internal/hostguard
CGO_ENABLED=0 go run ./cmd/guardgolden -check
CGO_ENABLED=0 go build -o bin/guardextract ./cmd/guardextract
```

`guardextract -config <受控配置> -pcap <完整捕获> -out <新JSONL> -ledger <本机旁路> -report <新摘要>` 只支持 research；用 `-start`/`-end` 指定隔离分区，每个独立分区必须使用新 bootId 和新引擎。配置包含 UUID 身份、`localAddresses`、`secretFile`、`keyEpoch`；密钥为至少32字节随机值，原始地址/密钥/配置/旁路和特征输出均放忽略的受控目录。重试保留身份与密钥，不能覆盖已有输出；只有完整输入通过后才生成完成摘要。

`guardjoin` 消费离线规范标签，核对全部连接计数及受控起点旁路；不把载荷、标签或地址送入模型。`guardgolden` 默认生成小型合成夹具，日常使用 `-check` 防止改写冻结期望。P2原验收只验证输入夹具；后续真实输入由下列独立入口完成。

## v5 有期限的实时采集

`cmd/guardlive` 复用同一因果引擎，记录同一捕获句柄的头部、Tick、drop/gap及关闭事件，使用 `-replay` 逐字节复算。macOS依赖cgo/libpcap；Windows的gopacket通过系统调用加载已安装Npcap，**不要求cgo或Npcap SDK**。构建标签为 `cgo || windows`，不是把Windows实时请求静默转为离线处理。

```sh
go build -o bin/guardlive ./cmd/guardlive
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o bin/guardlive.exe ./cmd/guardlive
```

配置除v5身份、密钥和本机地址外，还需 `interface`、`allowedInterfaces`、`peerAddresses`、`servicePort`、`authorizedUntil`；`serviceEndpoint` 可为 `local` 或 `peer`。默认/空值为本机服务，客户端访问已登记对端服务时指定 `peer`；未知值拒绝。BPF同时绑定接口、本机/对端和服务端口，登记期限不能由命令行采集时长延长。原始端点和私有轨迹留在受控忽略目录。

2026-10-04已在Mac/Windows回环和物理接口实际运行：四次均零丢包、三个parent，实时与同轨迹复算逐字节一致；物理接口为每端三条正常HTTPS连接/九个GET。[验收报告](../docs/p1-p3-completion/README.md)绑定程序及运行时加载的Npcap DLL哈希。Windows未签名程序在SAC=On下通过，满足该构建在目标机的自用运行核验；不要求另做签名或安装包。[制品入口](../scripts/p1/finalize_windows_artifact.py)中的正式签名模式保留为可选工具，不属于本次交付条件。该证据仅覆盖实测IPv4/TCP范围，不授予模型或自动处置资格。
