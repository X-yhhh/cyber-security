# Go 软件传感器：当前实现与迁移

现有 `cmd/sensor` 运行路径仍实现 `unsw-nb15-flow-v4`；P2 已新增独立 host-guard v5 研究引擎和 CLI，入口见本文末节。目标输入、prefix与时间窗、目标引用及质量规则见 [检测与处置契约](../docs/检测与处置契约.md)，实施顺序见 [开发路线](../docs/开发路线.md)。

**P1/P2 已完成并收口**，范围见 [P1 交接](../docs/p1/README.md)及 [P2 交接](../docs/p2/README.md)。独立探针提供 `cmd/p1audit` 的公开标签/PCAP 关联审查、`cmd/p1canary` 的有界 TCP 回显和 `cmd/p1httpcanary` 的固定内存 HTTP 下载；Go canary 不操作防火墙，不走 v4 上报。后续从 [P3](../docs/p3/README.md) 的 prefix 计划接续，生产执行与恢复属于 P5。

## v4 当前能力与限制

- 被动读取授权接口或离线PCAP/PCAPNG，组流、计算v4特征；在线上报 `/api/v1/machine/sensors/{id}`。
- 旧算法使用100条已完成流窗口及61秒重排序等待，规范记录不携带可执行目标引用；不能满足新方案早期检测和目标级阻断契约。
- 旧模型适用范围不能按新文档扩大；现有传感器没有防火墙执行权限。
- 此旧v4实时路径依赖cgo/libpcap及系统权限。编译通过不等于现场可用，新构建仍按实际运行路径验证；独立v5的Windows路径见下文。
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

`cmd/guardextract`、`internal/hostguard` 为 `host-guard/5.0.0-rc.2` 独立路径；原有 v4 命令、资源和上传流程保留。研究提取CLI离线读取，不上传或执行防火墙动作；详细语义与范围见[P2交接](../docs/p2/README.md)。

```sh
CGO_ENABLED=0 go test ./...
go test -race ./internal/hostguard
CGO_ENABLED=0 go run ./cmd/guardgolden -check
CGO_ENABLED=0 go build -o bin/guardextract ./cmd/guardextract
```

`guardextract -config <受控配置> -pcap <完整捕获> -out <新JSONL> -ledger <本机旁路> -report <新摘要>` 只支持 research；用 `-start`/`-end` 指定隔离分区，每个独立分区必须使用新 bootId 和新引擎。配置包含 UUID 身份、`localAddresses`、`secretFile`、`keyEpoch`；密钥为至少32字节随机值，原始地址/密钥/配置/旁路和特征输出均放忽略的受控目录。重试保留身份与密钥，不能覆盖已有输出；只有完整输入通过后才生成完成摘要。

`guardjoin` 消费离线规范标签，核对全部连接计数及受控起点旁路；不把载荷、标签或地址送入模型。`guardgolden` 默认生成小型合成夹具，日常使用 `-check` 防止改写冻结期望。共享因果引擎已按P2交接，实际采集使用下列独立入口。

## v5 有期限的实时采集

`cmd/guardlive` 复用同一因果引擎，记录同一捕获句柄的头部、Tick、drop/gap及关闭事件，使用 `-replay` 逐字节复算。macOS依赖cgo/libpcap；Windows的gopacket通过系统调用加载已安装Npcap，**不要求cgo或Npcap SDK**。构建标签为 `cgo || windows`，不是把Windows实时请求静默转为离线处理。

```sh
go build -o bin/guardlive ./cmd/guardlive
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o bin/guardlive.exe ./cmd/guardlive
```

配置除v5身份、密钥和本机地址外，还需 `interface`、`allowedInterfaces`、`peerAddresses`、`servicePort`、`authorizedUntil`；`serviceEndpoint` 可为 `local` 或 `peer`。默认/空值为本机服务，客户端访问已登记对端服务时指定 `peer`；未知值拒绝。BPF同时绑定接口、本机/对端和服务端口，登记期限不能由命令行采集时长延长。原始端点和私有轨迹留在受控忽略目录。

Mac/Windows回环和物理接口的实时输入与同轨迹逐字节复算已作为P1/P2基线收口。Windows未签名程序在目标机既有系统策略下的自用运行已交接，不增加发行签名或安装包任务。该基线仅覆盖实测范围；新构建绑定自己的文件/依赖哈希，不授予模型或自动处置资格。

P3新增的连续健康旁证、plannedRole传递、共同早期轨迹检查和稳定预算恢复仍需按新计划实施。现有guardlive的单次轨迹复算不能替代跨活动连续健康证明；逻辑特征引擎可重置，健康观察器和真实目标预算必须连续。闭阶段报告工具如需旧输入，恢复相应Git基线或备份，不在当前docs重建旧报告。

## P5 本机目标服务

新增 `cmd/guardtargets`，将 P2 易失注册表以独立回环 mTLS 服务运行；不持有防火墙权限。保留旧lease/resolve，新增resolve-lease返回原始lastPacketAt/expiresAt，供P5在安装前核验新鲜度。配置包含明确期限和collector/executor分离证书指纹；退出销毁引用，执行器boot变化须重新配对。构建为 `go build -o bin/guardtargets ./cmd/guardtargets`，运行与执行器对接见[执行器说明](../executor/README.md)。现有guardlive仍是research入口，不因新增目标服务自动取得真实执行资格。
