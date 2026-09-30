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
# pcap → 特征记录 JSONL（含非 ready 记录），用于对拍
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
