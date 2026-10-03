# 整改阶段 2：传感器特征兼容性与完整流标签关联试点

日期：2026-10-03（Asia/Shanghai）。**阶段 2 的本次有界试点已收口；IoT-23 子集未通过阶段 3 数据准入，返回阶段 1 寻找合适来源。Windows 原生提取对拍未验证。readiness/S3 保持 `BLOCKED`，`trainingAuthorized=false`。** 本记录对应当前整改计划，区别于历史 CIC 阶段二交付。

## 1. 范围与执行契约

只读取阶段 1 已冻结 SHA-256 的 IoT-23 官方四成员子集，原始总量 84,415,438 字节。逐流关联发布方 Zeek 时间、双向端点、协议、方向、包数和 IP 字节数；窗口、60 秒切段、握手和单位复用冻结 v4 的 Go 流水线。未知、冲突、截断、无法唯一关联或字段不完整的记录保持排除，不能补零或产生训练标签。

传感器纯 Go 构建使用 `CGO_ENABLED=0`，只开放既有 `extract` 离线命令。实时抓包入口在该构建中明确失败；没有内核丢包来源时返回错误。cgo 构建继续由 libpcap/Npcap 提供实时抓包。此变更不调整 v4 字段、计算语义、在线协议或模型范围。

Windows 训练仓库增加独立离线审计模块，绑定来源、许可、提取器代码/二进制、PCAP、旁路及特征输出哈希。逐流决定账本与原始端点留在 Git 忽略目录；Git 只保存可复算工具、测试和去敏摘要。固定 golden PCAP 已在 Mac 通过同源 Go 提取器和独立 Java 参考实现对拍；Windows 原生运行被系统策略阻止，Windows 完成的是标签与字段审计。

该阶段不冻结训练分区；完整关联候选仍须第二人标签复核、独立活动证据和后续 readiness。S3 维持 `trainingAuthorized=false`。

## 2. 结果与停止决定

| 提取范围 | 入窗流 | v4 ready | 完整关联且 v4 合格的 Normal / Attack | 当前模型范围内候选 |
|---|---:|---:|---:|---:|
| Somfy LAN 地址 | 77 | 0 | 0 / 0 | 0 |
| Somfy setup 地址 | 7 | 0 | 0 / 0 | 0 |
| Muhstik 受感染主机 | 85,905 | 85,803 | 0 / 2,964 | 0 |

两个 Somfy 地址的窗口分别维护，不能拼成一个虚构传感器窗口；100 条完成流的冻结要求保持不变。Muhstik 共有 1,218 条完整关联攻击标签连接，其中 2,964 条切段同时通过 v4 字段审查；**这些合格切段全部为 initiator 视角**，1,747 条还没有首包 SYN。它们满足 v4 特征审查并不意味着符合 `2026.10.2` 的 IPv4/responder/TCP/handshake 范围。

发布方标签区间与传感器 60 秒切段不是一对一关系。仅允许整个切段落入唯一标签区间；同一完整连接的所有切段共享分组键，起止时间（最多 1 微秒的发布方舍入差）、方向、双向原始包数、IP 字节数均须匹配。缺失 duration 的发布方单包记录只能由精确起点和完整单包计数证明；多包记录缺 duration 直接排除。端口复用、跨区间合流、尾随报文吸收、区间不全、包/字节差异或背景标签都不会传播成训练标签。

Somfy 原始 capture 有 70 条完整关联标签连接，其中包括不进入本机单播窗口的流；这一数不能当作 70 条 ready Normal。Muhstik 原始 capture 有 4,377 条完整关联标签连接，只有 1,218 条具有明确攻击候选标签。三个 profile 共享的 capture/标签不作为相互独立的样本；没有创建 train/validation/holdout 分区。

保留候选另有精确特征和近重复候选签名；Muhstik 的 2,964 条合格切段对应 1,218 条连接，5 条连接包含多段，精确重复特征超出首条 681 行，近重复签名超出首条 925 行。近重复索引按时长 1 ms、握手 1 us、字节 64 B、均值 4 B、load 5% 对数桶分组，协议/service、包数和窗口计数精确保留；它只供复核，可能漏掉桶边界上的相近对，不据此删行或宣称无近重复。`groupingAudit` 记录连接多段、重复特征、UTC 日期和分区状态；所有切段保持连接分组，`partitionedRows=0`、`crossPartitionLeakageStatus=NOT_EVALUABLE_NO_PARTITIONS`。独立活动未核实，不能把现有连接/日期分组当作已通过的分区独立性。

19 个冻结输入逐项检查顺序、有限值、范围、微秒/秒单位、IP 字节、load/mean/RTT 公式、端口 service 和窗口范围。85,803 条 ready 记录中字段审查失败为 0。两个 capture 物理顺序回退均为 0，没有孤立分片或容量丢弃；Somfy 有 1 次 D11 超大包折算，Muhstik 吸收 7,278 个封流后报文。经典 PCAP 不提供已验证的内核丢包数，故保持未知；未把未知写成 0。离线 /24 参数和发布方实际接口掩码的等价性尚未独立验证。

**数据准入结论：** 合格 Normal 为 0，当前模型范围内 Normal/Attack 候选均为 0。独立主机事件/活动证据、第二人标签复核和独立分区仍未接受，`trainingEligibleRows=0`。保留该子集供流实现和攻击覆盖研究；不用于当前模型重训，不缩短窗口、不混主机、不翻转视角、不改 v4。下一步返回阶段 1，寻找能提供独立良性单主机流量及目标范围攻击证据的来源。

## 3. 实现与验证边界

| 项目 | 已核实结果 |
|---|---|
| Go 同源提取 | Mac 实际提取全部冻结 PCAP；cgo 和纯 Go 测试均通过，纯 Go Windows/amd64 构建成功 |
| 离线旁路 | 增加未折算 IP 字节及其可靠性、生产地址策略排除原因；旁路开/关的正常特征与诊断输出保持逐字节相同 |
| Java 独立对拍 | JDK 25.0.2；固定前 10,000 帧的仅头部 public PCAP，共 1,868 条流（ready 1,769），Go/Java 元数据、19 字段及诊断完全一致；原有两套边界 fixture 同时通过 |
| Windows 门禁测试 | 原来源审计和新完整关联审计共 51 项通过；没有导入训练框架 |
| Windows 原生提取 | 尝试运行已校验 SHA-256 的新 EXE 时被系统应用控制以 `WinError 4551` 阻止；原生离线提取/平台 parity **未验证**，不能以交叉编译代替 |
| Windows 标签/字段审计 | 校验本机原始成员和许可，消费绑定相同来源哈希的 Mac 同源提取包，在 Windows Python 3.12.10 完成逐流关联、排除、字段与分组键检查；其结论不宣称 Windows 执行过 Go |

固定 public golden PCAP、旁路、逐流账本和运行目录保存在 Git 外；仓库保存其哈希、参数及去敏报告。原生 Windows 失败目录保留，没有完整报告，不能作为有效提取产物。报告中的 `extractionContext` 区分 Mac 提取、Windows 审计及 Windows 运行阻断。

## 4. 证据与复算

- `evidence/feature-pilot-v1.json`：Windows 上生成的完整审计摘要、逐 profile 字段可得率、关联/排除与输入/账本哈希。
- `evidence/extraction-provenance-v1.json`：Mac Go 版本、应用基线、实际源码哈希、原始四成员和每份提取结果哈希。
- `evidence/parity-verification-v1.json`：公开 golden 的 Go/Java 对拍、构建/测试结果和 Windows `4551` 边界。
- `evidence/remote-integrity-v1.json`：远端原有 15 个未跟踪文件与历史冻结证据的哈希核对、Git 忽略及训练授权检查。
- `evidence/closeout-v1.json`：两仓库交付范围、历史冻结证据、旧未跟踪文件保留情况及阶段退出决定。

训练仓库工具为 `src/cyber_training/feature_pilot.py`，测试为 `tests/test_feature_pilot.py`。其当前记录目录是 `docs/remediation-phase2/`；不要与旧 `src/cyber_training/phase2/`（CIC 历史审查）混淆。

在 Windows 训练仓库中可复算标签/字段审计，输出必须使用新的目录：

```sh
PYTHONPATH=src .venv/Scripts/python.exe -m pytest tests/test_source_screening.py tests/test_feature_pilot.py -q -o addopts=""

PYTHONPATH=src .venv/Scripts/python.exe -m cyber_training.feature_pilot \
  --data data/raw/source-screening-20261003-pilot-v1 \
  --evidence docs/phase1/evidence \
  --metadata data/raw/source-screening-20261003-metadata-import-v1 \
  --contract docs/remediation-phase2/evidence/v4-contract.json \
  --spec docs/remediation-phase2/evidence/v4-specification.md \
  --extractor data/processed/remediation-phase2-iot23-20261003-v1/sensor-offline-windows-v3.exe \
  --extractor-sha256 5e4dc1d130f57f7727b4ee30ec63b68a02aee1466791cb265384c575e61af530 \
  --imported-extraction data/processed/remediation-phase2-iot23-20261003-v1/mac-extraction-import-v1 \
  --bundle-sha256 15482d31e96cea85e29d8bc9ca74d6153758dfee88f2e4046c507abb5eab7013 \
  --application-head 557d8c2bb91be875279a9c1b80b7bb0ea66b02ee \
  --out data/processed/remediation-phase2-iot23-reproduction-NEW
```

本次没有拟合、预测、读取既有 holdout、导出/激活模型、修改生产阈值、抓取真实网卡或执行响应。业务 API、数据库和前端没有变更，服务没有重启，既有数据/历史证据没有删除。验收时交付为两仓库工作区修改，尚未提交或推送；本记录及 closeout 中的 HEAD、工作区和 committed/pushed 是验收时快照，后续提交推送以 Git 历史和远端分支为准。
