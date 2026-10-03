# Go 软件传感器：当前实现与迁移

现有 `cmd/sensor` 运行路径仍实现 `unsw-nb15-flow-v4`；P2 已新增独立 host-guard v5 研究引擎和 CLI，入口见本文末节。目标输入、prefix与时间窗、目标引用及质量规则见 [检测与处置契约](../docs/检测与处置契约.md)，实施顺序见 [开发路线](../docs/开发路线.md)。

独立 [P1 探针](../docs/p1/README.md)提供 `cmd/p1audit` 的公开标签/PCAP 关联审查、`cmd/p1canary` 的有界 TCP 回显和 `cmd/p1httpcanary` 的固定内存 HTTP 下载。Go canary 不操作防火墙；授权 Windows 试验由独立 PowerShell 工具管理临时窄规则和原生计划清理。实际启动、Npcap 抓包与连接阻断已验证，全部规则/任务已清理；严格跨重启 TTL 尚未通过。P1 工具不走 v4 上报、不输出训练集；后续因果提取与研究分区由 P2 独立工具完成。

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

纯Go构建只能离线读取，实时run明确不支持。macOS实时版本需要系统libpcap与SDK；使用自建clang时先正确配置SDKROOT，再执行 `go build -o bin/sensor ./cmd/sensor`。本文不授权安装依赖、改系统权限或开始抓包。

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

`guardjoin` 消费离线规范标签，核对全部连接计数及受控起点旁路；不把载荷、标签或地址送入模型。`guardgolden` 默认生成小型合成夹具，日常使用 `-check` 防止改写冻结期望。实时接口为 `RunLive`，由调用方提供已授权捕获句柄；本阶段只验证输入夹具对拍，不代表真实网卡实时验收。
