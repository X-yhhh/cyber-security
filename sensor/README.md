# sensor：unsw-nb15-flow-v4 软件传感器

在本机授权接口上被动抓包（snaplen 128，只读头部），组流并构造 v4 特征，上报到后端 `/api/v1/machine/sensors/{id}`。不上传载荷、地址或 pcap，不执行任何处置动作。规格见 `docs/特征规格-unsw-nb15-flow-v4.md`，阶段记录见 `docs/路线B-可移植特征契约v4实施路线.md` §12。

## 构建

```sh
cd sensor
export SDKROOT="$(xcrun --show-sdk-path)"   # 自建 LLVM clang 需要，否则找不到 libpcap / libresolv
go test ./...
go build -o bin/sensor ./cmd/sensor
```

实时抓包依赖系统 libpcap（cgo）；pcap 文件读取、特征构造和上报都是纯 Go。`GOOS=windows` 只验证了交叉编译，Windows 的凭据库和降权尚未实现，当前会 fail-closed。

## 本机配置

`sensor.json` 只放标识和白名单，不能包含凭据；出现未知字段会拒绝启动。

```json
{
  "baseUrl": "http://127.0.0.1:18080",
  "sensorId": 2,
  "dataSourceId": 2,
  "sourceMappingVersion": "1.0",
  "stateDir": "<仓库外的绝对路径>/sensor-state",
  "allowedInterfaces": ["en0"],
  "keystoreService": "cyber-security-sensor",
  "keystoreAccount": "sensor-2"
}
```

- 非回环的后端地址必须使用 HTTPS，客户端不跟随重定向。
- 后端下发的配置只能收窄本机授权：接口必须在 `allowedInterfaces` 内；`filterPolicy` 只接受 `{}` 或 `{"bpf":"ip or ip6"}`；`samplingPolicy` 必须为 `{}`；契约必须是 `unsw-nb15-flow-v4`。不满足时直接拒绝运行。
- `stateDir` 只保存批次序号（0600）。状态文件损坏时拒绝启动，不会猜测序号。

## 凭据

凭据在登记传感器时一次性签发，只存 macOS 钥匙串。导入时从 stdin 读取，不经过 argv、日志或配置文件：

```sh
bin/sensor credential import -config sensor.json   # 粘贴 mch_<id>.<secret> 后回车
bin/sensor credential delete -config sensor.json   # 撤销时删除
```

## 运行（推荐：sudo 启动后降权）

```sh
sudo bin/sensor run -config sensor.json -interface en0 -duration 20m
```

进程以 root 身份只打开 BPF 句柄，然后立即降到调用 sudo 的用户（`SUDO_UID`/`SUDO_GID`），并确认无法再恢复 root；之后读钥匙串、联网和写状态都以普通用户身份进行。这种方式不需要修改系统权限。以 root 直接运行、但不是经 sudo 从普通用户启动的（例如 launchd），无法确定降权目标，会拒绝运行。`-duration` 到期或收到 Ctrl-C / SIGTERM 时停止抓包，剩余批次最多再等 30 秒送达。

## 可选：access_bpf 组（持久授权，本机未执行）

用这种方式可以让普通用户直接运行传感器、不经过 sudo，但它会持久改变系统权限。§7.0.2 和 §12.7 的授权都没有覆盖这种做法，本机也没有执行过。确需使用时，参照 Wireshark ChmodBPF 的做法：

```sh
# 安装
sudo dseditgroup -o create -r "BPF access" access_bpf
sudo dseditgroup -o edit -a "$USER" -t user access_bpf
sudo chgrp access_bpf /dev/bpf*
sudo chmod g+rw /dev/bpf*
# 重新登录后，组成员身份才会生效
```

macOS 按需创建 `/dev/bpf*`，重启后权限会恢复成 root:wheel 0600。要持久生效，需要一个开机时执行上面两条 `chgrp`/`chmod` 的 LaunchDaemon（Wireshark 的 ChmodBPF 就是这样做的）。本仓库不提供这个 LaunchDaemon。

撤销：

```sh
sudo chmod g-rw /dev/bpf*
sudo chgrp wheel /dev/bpf*
sudo dseditgroup -o edit -d "$USER" -t user access_bpf
sudo dseditgroup -o delete access_bpf
# 如果装过 LaunchDaemon，先 launchctl bootout 并删除它的 plist
```

## 离线工具（不联网、不打开网卡）

```sh
# pcap/pcapng → 特征记录 JSONL（含非 ready 记录），用于对拍
bin/sensor extract -pcap in.pcap -out records.jsonl -diagnostics diag.json \
  -local-addr 192.0.2.2 -subnet 192.0.2.0/24

# 本机抓取的 pcap 假名化：文档保留地址、只保留到传输层头部、时间平移；映射表不落盘
go run ./cmd/pcapanon -in raw.pcap -out anon.pcap -subnet 10.0.0.0/24 -local-v4 10.0.0.5 \
  [-local-v6 ...] [-keep 3m]

# G2 fixtures：合成场景，或基于已假名化的 pcap
go run ./cmd/g2fixtures -dir ../backend/src/test/resources/feature-contract/fixtures/unsw-nb15-flow-v4-packet
go run ./cmd/g2fixtures -dir <目录> -pcap anon.pcap -local-addr 192.0.2.40 -subnet 192.0.2.0/24
```

后端 `PacketLevelParityTest` 会用独立的 Java 参考实现逐字段比对 fixtures。仓库外的原始 pcap 目录可以通过 `-Dg2.externalDir=<目录>` 加入比对。

## 能力边界

- 只能看到部署了传感器的主机自己收发的流量，看不到其他设备之间的流量。
- 首个模型只评估 `responder` 视角的 IPv4 流；其他记录照常上报，由后端标记为 `not_in_model_scope`。
- `::ffff:a.b.c.d` 形式的 IPv4 映射地址：Java 参考实现会当作 IPv4，Go 保留为 IPv6。


阶段 2 离线数据审核：`extract` 按文件魔数识别经典 pcap 或 pcapng，不依赖后缀。两种容器使用相同特征流水线；逐包要求 Ethernet，包含 pcapng 后续 section/接口，遇到不支持链路或容器截断显式失败（已写出的前缀不得作为完整提取结果使用）。`go test ./...` 覆盖两容器完整记录/时间戳/诊断一致性及上述失败场景。该能力不修改冻结 v4、MTU 或在线上传字段。

### 公开数据集标签旁路与排序审核

`extract -label-audit audit.label-audit.jsonl` 显式启用离线旁路（默认关闭，0600、新文件独占创建）。记录公开端点、流区间、原始方向包数以及 `IPTotal - IPHdr - TCPHdr` 的载荷长度；**不读取或保存载荷内容**。分片、缺失 TCP 头长或长度回退等条件标记长度不可靠，不用于 Attempted 判定。旁路只供离线标签关联，不能进入特征、上传或模型。正常的 `records.jsonl` 格式和 v4 特征计算不变；`sbytes/dbytes` 仍含 IP 头，不能当成 CICFlowMeter 载荷长度。

```sh
go build -o bin/pcapaudit ./cmd/pcapaudit
bin/pcapaudit -pcap public-source.pcap -report audit.json -sorted-headers headers-sorted.pcap
bin/sensor extract -pcap headers-sorted.pcap -local-addr 192.0.2.2 \
  -out records.jsonl -diagnostics diagnostics.json -label-audit audit.label-audit.jsonl
```

`pcapaudit` 只读遍历全部 Ethernet 接口，统计物理包顺序/SYN 顺序回退、UTC 边界及已公开攻击端点每分钟计数。顺序回退不等于 SYN/SYNACK 因果倒置。可选派生 PCAP 按时间戳稳定排序，只保存协议头、原始时间戳和 wire length，不保存传输层载荷；派生文件与原件分别登记哈希。它不是网络重放工具。非 IP 或解析失败帧只保留链路头，malformed 可能变为 truncated，须以原件审查报告解释，不能据诊断名变化宣称原件无异常。

排序暂存在内存，百万级帧需要数 GB 内存；当前完整日抓包只在已核对资源的离线审核主机运行，不把此内存开销当作 Windows 8 GB 训练预算内能力。失败时已写出的前缀不是完整产物，须有成功的审查报告/诊断、源与输出哈希才能复用。原件、派生 PCAP、旁路及索引均留在 Git 外。
