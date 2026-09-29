# 特征规格：unsw-nb15-flow-v4

> 状态：**已冻结**（2026-09-29，决策门 G1，见路线 B §7.2、§21）。本文是训练端、后端 `FeatureBuilder` 与 Go 传感器共同遵守的唯一计算定义。冻结后的任何修改都按路线 B §4.5 的缺陷修复流程处理，并重新登记 SHA-256。
>
> 依据：《路线 B：可移植特征契约 v4 实施路线》（`docs/路线B-可移植特征契约v4实施路线.md`，下称“路线 B”）§4.2～§4.3 的决策 D1～D13，§7.0.6 本机 Mac 探测，§7.1.1～§7.1.2 训练端审计、消融与异常核查。

## 1. 范围与总则

- 契约版本 `unsw-nb15-flow-v4`。输入为 17 个数值字段 + 2 个类别字段（§2）。数值字段顺序即 ONNX `flow_numeric` 的列顺序，必须与 manifest `feature_contract.inputs` 逐项一致。
- 相对 v3.1 删除 9 项：`sttl`、`ct_state_ttl`、`sloss`、`sjit`、`djit`、`dinpkt`、`ct_flw_http_mthd`、`ct_dst_sport_ltm`、`ct_dst_src_ltm`。
- 只使用 IP 头与传输层头部，不读取载荷（D8）。snaplen 128 字节已在本机验证足够：TCP 选项被截断的流为 0/9,479。
- 契约只定义单条已完成流及其所在窗口的原始输入。模型内的派生特征（如 `rate`、各类比率）由 ONNX 图从这些输入计算，属于模型，不属于契约。
- 「训练端」指从 UNSW-NB15 原始 CSV（`d1_raw.parquet`）重算；「传感器」指从抓到的包计算。§2 的两栏必须指向同一定义，出现分歧时以本文公式为准。

### 1.1 流与方向（D7）

- 流键：`(proto, 低端点地址, 低端点端口, 高端点地址, 高端点端口)`。端点按（地址, 端口）比较，较小者为低端点。ICMP 等无端口协议的端口记为 0。
- initiator（发起方）：TCP 流能看到握手时，取纯 SYN（SYN=1、ACK=0）的发送方；否则取流的首包发送方。一旦确定，整条流不再翻转。字段前缀 `s` 表示 initiator → responder 方向，`d` 表示反方向。
- 元数据 `handshake_seen`：TCP 流的首包是否为纯 SYN。看不到握手的流仍按首包定方向，但记 `handshake_seen=false`，由 manifest 的评估范围决定是否排除。本机探测中被判为入站的 76 条 TCP 流全部属于这种情况（路线 B §7.0.6）。
- 结束条件：
  - TCP 双向都出现 FIN，或任一方出现 RST，立即导出；
  - 否则按空闲超时导出：TCP 60 s，UDP、ICMP 及其他协议 30 s；
  - 自首包起满 60 s 强制切段导出。后续段是一条新的流记录，但继承首段的 initiator。
- FIN/RST 导出后 5 s 内，同一流键上的非纯 SYN 报文（尾随 ACK、重传）被吸收，只计入 diagnostics，不新建流；这 5 s 内出现纯 SYN 则按端口复用新建流。
- 训练端：UNSW CSV 已经是 Argus 导出的流记录，`dur` 上限正好 60 s（路线 B §7.1.1），与上述规则一致，训练端不重做封流。

### 1.2 地址族、视角与排除（D10、D12）

- 窗口按地址族分开维护：每个传感器一个 IPv4 窗口、一个 IPv6 窗口，互不混入。首个 v4 模型声明 `supported_address_families: ["ipv4"]`，IPv6 流照常进 IPv6 窗口，状态记 `not_in_model_scope`。
- `viewpoint`：本机是 responder 记 `responder`，是 initiator 记 `initiator`。首个模型声明 `supported_viewpoints: ["responder"]`。出站流照常进窗口，但不送推理，状态记 `not_in_model_scope`。
- 排除规则：目的地址为多播、受限广播 `255.255.255.255`、接口子网定向广播或回环地址的流，不进窗口、不推理，只计入 diagnostics。两端都不是本机地址的单播流同样排除并计数。
- 训练端没有接口掩码。UNSW 各子网为 /24，因此按「末字节为 255」判定定向广播；源地址不是合法 IPv4 的记录也排除。实测排除 0.01%。

### 1.3 包与字节口径（D6、D11）

- 包按 IP 数据报计数：重传计入，分片按分片数计。非首片按（源地址、目的地址、协议、IP ID）归入首片所在的流；30 s 内找不到首片的后续分片丢弃，并计入 diagnostics。
- 字节 = IP 数据报总长，含 IP 头，不含链路层头。IPv4 取 Total Length；IPv6 取 40 + Payload Length。长度字段为 0（巨型帧或卸载）时，取「线路长度 − 链路层头长」。

- 卸载分段折算（D11）：IP 总长超过接口 MTU 的 TCP 包按 `n = ceil(TCP 载荷长度 / MSS)` 折算为 n 个线路分段。MSS 取对端在握手中通告的值；未观测到握手时取 `MTU − IP 头长 − TCP 头长`。折算后该方向包数加 n，字节加 `载荷 + n × (IP 头长 + TCP 头长)`。折算次数计入 diagnostics。训练数据本身是线路分段，训练端不做折算。
- 本机 en0 探测期间未出现超大包，D11 只有单测覆盖，真实验证推迟到 Windows 补测（路线 B §7.0.5）。

## 2. 字段定义（顺序即模型输入顺序）

### 2.1 数值字段

| # | 字段 | 单位 | 定义（传感器） | 边界取值 | 训练端（CSV 列） |
|---:|---|---|---|---|---|
| 0 | `dur` | 秒 | 末包时间 − 首包时间，保留微秒 | 单包流为 0 | `dur` |
| 1 | `sbytes` | 字节 | initiator → responder 方向字节和（§1.3） | ≥ 0 | `sbytes` |
| 2 | `dbytes` | 字节 | responder → initiator 方向字节和 | 无反向包时为 0 | `dbytes` |
| 3 | `sload` | bit/s | `sbytes × 8 × (spkts − 1) / spkts / dur`（不计首包，与 Argus 一致） | `spkts ≤ 1` 或 `dur = 0` 时为 0 | `Sload` |
| 4 | `dload` | bit/s | `dbytes × 8 × (dpkts − 1) / dpkts / dur` | `dpkts ≤ 1` 或 `dur = 0` 时为 0 | `Dload` |
| 5 | `tcprtt` | 秒 | `synack + ackdat` | 非 TCP 或握手不完整时为 0 | `tcprtt` |
| 6 | `ackdat` | 秒 | responder 的首个 SYN-ACK → initiator 此后首个纯 ACK（ACK=1、SYN=0） | 同上 | `ackdat` |
| 7 | `synack` | 秒 | initiator 的首个纯 SYN → responder 的首个 SYN-ACK | 同上 | `synack` |
| 8 | `smean` | 字节 | `round(sbytes / spkts)`，四舍五入到整数 | `spkts = 0` 时为 0 | `smeansz` |
| 9 | `dmean` | 字节 | `round(dbytes / dpkts)` | `dpkts = 0` 时为 0 | `dmeansz` |
| 10 | `spkts` | 包 | initiator → responder 方向包数（§1.3，含 D11 折算） | ≥ 1 | `Spkts` |
| 11 | `dpkts` | 包 | responder → initiator 方向包数 | 无反向包时为 0 | `Dpkts` |
| 12 | `ct_srv_src` | 条 | 窗口内 `service` 与源地址都和当前流相同的流数 | 1～100；窗口未满不推理 | 重算 `ct_srv_src_v4` |
| 13 | `ct_srv_dst` | 条 | 窗口内 `service` 与目的地址都相同的流数 | 同上 | 重算 `ct_srv_dst_v4` |
| 14 | `ct_dst_ltm` | 条 | 窗口内目的地址相同的流数 | 同上 | 重算 `ct_dst_ltm_v4` |
| 15 | `ct_src_ltm` | 条 | 窗口内源地址相同的流数 | 同上 | 重算 `ct_src_ltm_v4` |
| 16 | `ct_src_dport_ltm` | 条 | 窗口内源地址与目的端口都相同的流数 | 同上 | 重算 `ct_src_dport_ltm_v4` |

说明：

- 握手字段只在同一条流内按顺序观测到纯 SYN、SYN-ACK、随后的纯 ACK 三者时取值，缺任何一个三项全为 0。训练端 TCP 行中三项非零占 99.40%，`tcprtt = synack + ackdat` 逐行成立。
- `ct_*` 中「源」「目的」沿用 UNSW 原定义：源 = initiator 地址，目的 = responder 地址，端口 = responder 端口。计数包含当前流自身。
- 训练端 `ct_*` 一律用单主机重算值（§3），CSV 原列不作为 v4 输入。重算实现：训练分支 `src/cyber_training/v2/feature_audit.py::recompute_ct`，已用逐条参考实现单测对拍。

### 2.2 类别字段

| 字段 | 规则（传感器） | 训练端 |
|---|---|---|
| `proto` | IANA 协议号 → IANA Protocol Numbers 注册表中的关键字，转小写（6→`tcp`，17→`udp`，1→`icmp`，58→`ipv6-icmp`）。映射表随 golden fixtures 一起入库；表中没有的协议号记 `proto-<号>` | CSV `proto` 原值（小写） |
| `service` | 只看 responder 端口与协议，查 §2.3 固定映射表，未命中或非 TCP/UDP 取 `-`。不读载荷 | 用同一张表从 `proto`、`dsport` 重算，不用 CSV 的 Bro 识别值 |

- 词表属于模型，不属于契约：后端从激活模型的 `preprocessing.json` 读取。词表外取值按 `CATEGORY_OUT_OF_VOCABULARY` 记遥测，由 ONNX 图编码为 −1，不拒绝记录（D5）。

### 2.3 `service` 端口映射表（D4，冻结）

| 协议/responder 端口 | 取值 | 协议/responder 端口 | 取值 |
|---|---|---|---|
| udp/67、udp/68 | `dhcp` | tcp/110 | `pop3` |
| tcp/53、udp/53 | `dns` | udp/1812、udp/1813 | `radius` |
| tcp/21 | `ftp` | tcp/25 | `smtp` |
| tcp/20 | `ftp-data` | udp/161、udp/162 | `snmp` |
| tcp/80、tcp/8080 | `http` | tcp/22 | `ssh` |
| tcp/6667 | `irc` | tcp/443 | `ssl` |
| 其他 | `-` | | |

- 训练端与 Bro 原值一致率 91.73%。最大差异是 `ftp-data`：UNSW 中该类流全部使用 ≥ 1024 的被动 FTP 端口，端口映射一次也命中不了，因此 v4 训练数据中不出现 `ftp-data`。
- udp/443（QUIC）按表取 `-`，不归入 `ssl`。

## 3. 窗口（D2）

- 范围：每个传感器、每个地址族一个窗口。成员为本机作为 initiator 或 responder 的全部已完成流（已按 §1.2 排除的流不进窗口），与 `viewpoint` 无关。
- 长度：最近 100 条已完成流，**包含当前流自身**。窗口不足 100 条时不推理，状态记 `window_not_ready`，不造值。
- 排序键：`(flowEndAt, flowStartAt, 导出序号)`。训练端对应 `(Ltime, Stime, 原始行号)`，UNSW 时间戳为秒级，行号作确定性 tie-break。
- 迟到：后端 `FeatureWindow` 的 `allowedLatenessSeconds = 0`。空闲超时导出的流，其 `flowEndAt` 比导出时刻早一个超时周期，因此**传感器必须先重排序再上报**：已完成流进入缓冲，只有 `flowEndAt ≤ 当前时间 − (TCP 空闲超时 + 1 s)` 的记录才按排序键依次释放。本机探测按此实现，迟到记录为 0。
- 训练端视角：每条流以 responder（`dstip`）主机为传感器所在主机；窗口在切分前的完整时间轴（去重前 2,540,047 行）上计算，只用流元数据，不用标签。

## 4. 边界取值汇总

| 情况 | 规则 |
|---|---|
| 单包流 | `dur = 0`，`sload = dload = 0`；`dpkts = dbytes = dmean = 0` |
| `dur = 0` | `sload = dload = 0`（不取 NaN） |
| 某方向包数 ≤ 1 | 该方向 load 为 0 |
| 某方向包数为 0 | 该方向字节、均值、load 均为 0 |
| 非 TCP | `synack = ackdat = tcprtt = 0` |
| TCP 握手不完整或看不到握手 | 三项握手字段为 0；`handshake_seen=false`（元数据） |
| IP 分片 | 按 §1.3 归流；孤立后续分片丢弃并计数 |
| 超大 TCP 包 | 按 §1.3 D11 折算 |
| 窗口未满 | 不推理，`window_not_ready` |
| IPv6 / 出站流 | 进窗口，不推理，`not_in_model_scope` |
| 多播、广播、回环、非本机单播 | 不进窗口，只计 diagnostics |

所有数值字段都不允许为空；任何字段算不出时整条记录拒绝推理，不补默认值。

## 5. 实测可得率与分布摘要

本机 Mac：2026-09-29 `en0` 三个场景各 20 分钟，IPv4 流 6,935 条（路线 B §7.0.6）。训练端：train + validation 1,715,903 行（路线 B §7.1.1）。探测脚本当时用的是修正前的口径（最长存活 300 s、`sload` 未扣首包、`smean` 未取整），所以本机的 `dur`、`sload`、`dload`、`smean`、`dmean` 分布只作量级参考；可得率不受影响。

| 字段 | 本机可得率 | 本机 p50 / p99 | 训练端摘要 |
|---|---|---|---|
| `dur` | 100% | 0.173 / 297 s | TCP p99 10.9 s、UDP p99 0.36 s，最大 60 s |
| `sbytes` / `dbytes` | 100% | 168 / 35,544；112 / 255,540 | — |
| `sload` / `dload` | 100% | 13,921 / 2.34e7；9,014 / 7.5e5 bit/s | 新公式在 CSV 上 99.94% 误差 ≤ 1% |
| `spkts` / `dpkts` | 100% | 3 / 148；2 / 265 | — |
| `smean` / `dmean` | 100% | 68 / 844；56 / 1,127 | 四舍五入口径逐行相等 97.6%～98.6% |
| `synack` / `ackdat` / `tcprtt` | TCP 流 90.5% | 0.0248 / 0.303；0.00014 / 0.00089；0.0249 / 0.303 s | TCP 行三项非零 99.40% |
| `ct_*`（5 项） | 窗口已满 95.7% | 见下 | 窗口已满 99.88% |
| `proto` | 100% | tcp 72.6%、udp 27.2%、icmp 0.2% | — |
| `service` | 100%（非 `-` 69.7%） | ssl 54.7%、dns 11.9%、http 3.1% | 与 Bro 原值一致 91.73% |

`ct_*` 均值 / 标准差（本机为全部视角，训练端为 responder 视角）：

| 字段 | 本机 | 训练端重算 |
|---|---|---|
| `ct_srv_src` | 48.1 / 29.5 | 7.6 / 11.8 |
| `ct_srv_dst` | 8.2 / 11.1 | 44.1 / 24.8 |
| `ct_dst_ltm` | 8.3 / 11.1 | 98.9 / 7.4（众数 100 占 89.5%） |
| `ct_src_ltm` | 92.4 / 18.9 | 13.5 / 11.7 |
| `ct_src_dport_ltm` | 44.9 / 31.3 | 3.8 / 10.8 |

两边差异来自视角：笔记本以出站为主，本机多为 initiator，以「源」为键的计数接近窗口长度；UNSW 受害主机多为 responder，以「目的」为键的计数接近窗口长度。定义相同，没有退化字段（标准差 ≥ 1 且众数占比 < 95%）。

## 6. diagnostics 附加块（D9，不进契约、不参与哈希）

帧数与解析状态、pcap 内核/接口丢包、按原因的排除流计数、孤立分片数、封流后吸收的尾随报文数、D11 超大包折算次数、重排序后仍迟到的记录数、各地址族窗口是否已满、`handshake_seen=false` 的流数、`service` 命中率、最大活动流数。内容可随传感器版本调整，不需要改契约。

## 7. 能力边界

- 首个模型只评估 IPv4 的 responder（入站）流。以出站为主的终端上覆盖的流量比例很低（本机探测中 IPv4 入站仅 4.2%，且没有真实入站 TCP 连接），此时规则研判是主要手段。
- `service` 只认标准端口：非标准端口上的服务、被动 FTP 数据连接、QUIC 都记为 `-`。
- `ct_*` 的贡献依赖攻击流量的突发程度。UNSW 攻击由工具集中生成，真实环境中低频、分散的攻击会让以源地址为键的计数贡献明显下降。UNSW 上无法检验对从未见过的主机的效果（验证集中每台主机都在训练分区出现过），留给阶段 7 影子验证。
- 看不到握手的 TCP 流（抓包前已建立、空闲超时后恢复）可能方向判反，已用 `handshake_seen` 标记。
- D11 折算规则尚未在真实超大包上验证（Windows 补测）。

## 8. 证据

| 证据 | 位置 |
|---|---|
| 本机探测报告 | 仓库外 `~/Workspace/deliveries/sensor-probe/probe-report-2026-09-29.md` |
| 公式对拍、`ct_*` 与 `service` 重算 | 训练端 `runs/feature-audit-20260929-1327` |
| F0～F5 消融与泛化对照 | 训练端 `runs/feature-ablation-20260929-1359` |
| F2→F3 异常核查 | 训练端 `runs/feature-diagnose-20260929-1420` |

训练端小体积证据副本归档在训练分支 `docs/route-b/evidence/`。
