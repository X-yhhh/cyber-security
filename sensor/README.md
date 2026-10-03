# Go 软件传感器：当前实现与迁移

当前源码仍实现 `unsw-nb15-flow-v4`，不是 host-guard v5。新的目标输入、prefix与时间窗、目标引用及质量规则见 [检测与处置契约](../docs/检测与处置契约.md)，实施顺序见 [开发路线](../docs/开发路线.md)。本文仅保留现有工具入口，不列不存在的v5命令。

## 当前能力与限制

- 被动读取授权接口或离线PCAP/PCAPNG，组流、计算v4特征；在线上报 `/api/v1/machine/sensors/{id}`。
- 旧算法使用100条已完成流窗口及61秒重排序等待，规范记录不携带可执行目标引用；不能满足新方案早期检测和目标级阻断契约。
- 旧模型适用范围不能按新文档扩大；现有传感器没有防火墙执行权限。
- 实时采集依赖cgo/libpcap及系统权限。Windows纯Go交叉编译不等于现场可用，凭据、采集和权限链路必须按P1实机核验。
- [旧v4规格](../docs/特征规格-unsw-nb15-flow-v4.md)因现有测试哈希引用暂时保留；v5实现时新建版本，不能原位改旧语义。

## 构建与离线提取

以下为已有CLI；工作目录为仓库下的sensor，输出为本地构建产物，不提交Git。本次文档修改未执行这些命令。

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
