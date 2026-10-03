# 阶段 1：小体量候选数据源初筛

日期：2026-10-03（Asia/Shanghai）。状态：**阶段 1 已完成；IoT-23 官方有界子集进入阶段 2 兼容性与标签关联试点。数据 readiness/S3 继续 `BLOCKED`，`trainingAuthorized=false`。**

本记录对应《模型整改与分阶段开发计划》的阶段 1。训练侧工具在 Windows 独立训练仓库运行；本目录原有 `runtime-status.json`、`rule-replay-report.json` 和 `experiment-summary.json` 继续作为历史开发证据保留。

## 1. 出口核对

| 要求 | 结果 | 证据与边界 |
|---|---|---|
| 核对当前进度 | 完成 | 应用基线 `6b4345f`、训练基线 `91158e9`；阶段 0 的原始矩阵、readiness、Monday 复核和既有 Unknown 决定保持不变 |
| 来源、版本、许可与体量清单 | 完成 | [候选登记](evidence/source-screening-registry-v1.json)覆盖 10 项；4 个 Kaggle owner/slug/version 的文件清单完整，原始成员字节总和与平台 metadata 一致 |
| 解决 IoT-23 使用条款 | 完成 | [许可审查](evidence/license-review-v1.json)绑定发布方 FAQ、官方 DOI 版本/CC BY 4.0 及旧 README 原文的 SHA-256；仅限按要求引用的公开离线子集 |
| 有界 Normal/Attack pilot | 完成 | 4 个官方成员合计 `84,415,438` 字节（80.5 MiB）；Windows 下载长度与预登记值一致，逐文件 SHA-256 已冻结；未下载完整归档 |
| 标签可追溯及独立良性依据 | 初筛通过 | 独立未感染 Somfy 设备场景有 29 条明确良性候选；Muhstik 场景有 151,567 条攻击候选。均有时间、协议、双向端点对应的精确起始包；4,637 条保持 Unknown |
| 工具与失败边界 | 完成 | Windows Python 3.12.10；24 项测试通过，覆盖字节/时间/成员上限、许可哈希、重定向、截断、重复/冲突、大小写、Unknown 和禁止覆盖 |
| 阶段 2 交接 | 完成 | [当前 pilot 报告](evidence/source-screening-pilot-v2.json)为 `stage2Candidate=true`；完整连接关联、独立活动日志、v4 兼容性及训练标签复核继续在后续 gate 验证 |

阶段 1 接受的是一个可进入下一步核验的**候选来源**。本次没有创建可训练标签、冻结训练分区、训练/预测、读取既有 holdout、导出模型或执行防火墙动作。

## 2. 候选结论

| 来源 | 当前核实的体量/结构 | 初筛结论 |
|---|---|---|
| IoT-23 官方子集 | 2 个 PCAP + 2 个带标签 Zeek conn.log，80.5 MiB | 接受为阶段 2 候选；成员身份按本次官方 URL、长度、更新时间和 SHA-256 固定 |
| ToN-IoT 官方 | 2 个官方共享下载入口均为 HTTP 403；样本读取 0 字节 | 访问阻断；学术许可说明仍须配合真实可访问文件与逐流/活动关联 |
| CICIoT2023 官方 | 发布说明有 PCAP/加工特征，未记录本项目要求的独立事件日志证据 | 本轮不优先；没有下载全量数据 |
| CTU-13 官方 | 正常/背景流的完整 PCAP 因隐私不公开，公开 PCAP 仅含 botnet 流量 | 无法完成本轮正常流 PCAP 对拍，淘汰该路线 |
| `dhoogla/ctu13` v3 | 13 个 Parquet 文件，122,260,500 原始文件字节 | 加工表不能代替同源正常 PCAP/活动证据 |
| `dhoogla/nftoniotv2` v2 | Parquet + 特征说明，209,172,454 原始文件字节 | 没有本轮需要的同源 PCAP/活动审查包 |
| `sonalimishra3/iot-2023-dataset-full` v1 | 84 个成员，113,571,284,237 原始文件字节 | 超过 2 GiB；未下载镜像，采用有界官方成员 |
| `emmanuelwestra/uwf-zeekdata` v5 | 117 个 CSV/Parquet/YAML 文件，1,674,573,873 字节，平台许可 `Unknown` | 许可与抓包来源未证实，拒绝准入 |
| AIT-LDS / CSE2018 既有 pilot | 保留原审查摘要；可信 Normal/Attack 仍为 0/0 | 未重算原始数据，未把背景或未匹配流改为 Normal |

Kaggle API 的 `totalBytes` 与完整文件清单的原始成员总量一起记录；列表页显示的压缩下载大小不用于判断 2 GiB 原始数据预算。[完整清单](evidence/kaggle-inventory-v2.json)保留每个文件名与字节数。平台能下载、票数或标题都不产生标签准入效果。

## 3. IoT-23 许可与 pilot

### 3.1 许可依据

- 发布方 [FAQ](https://www.stratosphereips.org/datasets-faq)明确允许按要求引用后使用其数据集。
- 发布方链接的 [Zenodo DOI 4743746](https://zenodo.org/records/4743746)登记版本 `1.0.0`、开放访问和 `CC BY 4.0`。
- 旧场景 README 的“需 Stratosphere Lab 授权”原文仍保留并登记哈希；本次将发布方 FAQ 的明确许可作为该离线引用用途的授权依据，没有删改旧文件。
- 引用：Sebastian Garcia、Agustin Parmisano、Maria Jose Erquiaga（2020），*IoT-23: A labeled dataset with malicious and benign IoT network traffic*，Version 1.0.0，DOI `10.5281/zenodo.4743746`。

完整 Zenodo 归档未下载，归档 MD5 **未验证**；当前单独成员与整个 DOI 归档的字节等价性**未声称成立**。阶段 2 使用本次官方单成员快照及其内容哈希，不能扩展到未登记文件。

### 3.2 场景与标签

| 场景 | 标签行数 | 精确起始包对应 | 候选/Unknown |
|---|---:|---:|---|
| `CTU-Honeypot-Capture-7-1/Somfy-01` | 130 | 29（22.31%） | Normal 候选 29（TCP 10、UDP 19）；Unknown 101 |
| `CTU-IoT-Malware-Capture-3-1` | 156,103 | 154,896（99.23%） | Attack 候选 151,567；Unknown 4,536 |

良性依据来自发布方明确说明的独立未感染真实设备场景及网关首次启动活动。Muhstik 的依据是发布方逐流人工分析标签、场景说明和抓包起点；没有仅按攻击日程给整段流量打标签。恶意场景中即使标作 `Benign` 的背景流也保持 Unknown。

初次审计发现 Somfy 的明确标签为小写 `benign`。工具现在仅对发布方的明确 coarse label 做大小写规范化；原文件没有改写。`source-screening-pilot-v1.json` 保留该初次大小写问题，**v2 是当前结论**。重复/冲突、无精确起始包及当前起点审计不支持的协议/地址族都保留 Unknown。

本次只证明标签流的双向端点、协议和微秒起点存在于同场景 PCAP；**完整连接、长连接分段、方向、握手、应用/安全日志关联尚未验证**。Somfy 样本仅有 10 条 TCP 候选，不满足 L2 Normal≥1,000 的数量门槛，也不证明当前 responder/IPv4/TCP 模型范围可用。人工复核样本以哈希键留在报告，第二人标签复核尚未执行，`trainingEligibleRows=0`。

## 4. 训练侧工具与复算

新增工具为训练仓库 `src/cyber_training/source_screening.py`，测试为 `tests/test_source_screening.py`。它只依赖 Python 标准库，不导入训练框架，不拟合或评分。

下载前验证 32 个成员、元数据单成员 2 MiB/合计 16 MiB、pilot 原始成员合计 1 GiB、900 秒和已知长度的上限。仅允许登记的公开 HTTPS 域名/无凭据 URL；重定向继续校验。pilot 必须复核许可证据哈希并限定为官方 IoT-23 子集，拒绝归档、脚本/可执行内容和已有输出。失败或部分下载不能用于审计。

在 **Windows 训练仓库目录内**执行：

```sh
PYTHONPATH=src .venv/Scripts/python.exe -m pytest tests/test_source_screening.py -q -o addopts=""

PYTHONPATH=src .venv/Scripts/python.exe -m cyber_training.source_screening fetch \
  --plan docs/phase1/evidence/pilot-fetch-plan-v1.json --mode pilot \
  --license-review docs/phase1/evidence/license-review-v1.json \
  --metadata-root data/raw/source-screening-20261003-metadata-import-v1 \
  --ca-file .cache/source-screening/public-ca-20261003.pem \
  --out data/raw/source-screening-reproduction-NEW

PYTHONPATH=src .venv/Scripts/python.exe -m cyber_training.source_screening audit \
  --data data/raw/source-screening-20261003-pilot-v1 \
  --spec docs/phase1/evidence/scenario-spec-v1.json \
  --out source-screening-reproduction-NEW.json
```

复算输出必须使用新的目录/文件名。现有原始数据位于训练仓库被 Git 忽略的 `data/raw/source-screening-20261003-pilot-v1/`；元数据和公开 CA 包也留在忽略目录。本次 Windows 默认信任链对部分发布站点校验失败，采用按命令指定的公开 Mozilla CA 包继续校验 HTTPS；没有关闭 TLS 校验或修改系统信任、代理和 Tailscale。详见[传输记录](evidence/transport-v1.json)。

## 5. 验证、交付与下一阶段

机器证据索引与最终校验见 [阶段 1 收口记录](evidence/source-screening-closeout-v1.json)。两仓库保存相同字节的当前 pilot、许可、清单与收口摘要；本地只更新文档/摘要，业务代码、数据库、API、在线传感器及前端没有变更。

下一步为阶段 2：先对当前有界子集做完整流/分段与独立活动证据关联，再复用 Go 传感器同源提取，审查 19 个冻结 v4 字段、方向、单位、窗口及握手可见性。不能证明同义字段时停止这条路线；需要新契约时先版本化设计。Unknown 继续隔离，不能进入训练。新的训练标签、足量独立良性样本、分组分区/readiness 和训练授权都还需要各自通过 gate。

本阶段交付为两仓库工作区变更，尚未提交或推送；原有远端未跟踪阶段 2 文件保留。没有服务重启或数据删除。
