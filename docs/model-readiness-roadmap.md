# 模型数据整改与训练路线

日期：2026-10-03。状态：**阶段 0、1 已完成，阶段 2 的 IoT-23 有界试点已收口，但该子集未通过阶段 3 数据准入，返回阶段 1 寻找合适来源。Windows 原生提取未验证。数据 readiness/S3 仍为 `BLOCKED`，训练和真实处置未授权；本文件是训练仓库唯一实施入口。**

适用仓库：`win-dev:E:\Workspace\ai\experiments\cyber-security-training`，分支 `training/windows-cuda`。此仓库只负责公开/获准数据的离线审查、预处理、训练、独立评估和制品导出。在线推理、资产授权、前端、模型激活和防火墙处置属于 macOS 应用仓库。

## 1. 当前结论

| 项目 | 事实 | 结论 |
|---|---|---|
| UNSW v4 历史 holdout | Macro-F1 `0.9456`、FNR `4.94%`、FPR `0.77%`、PR-AUC `0.9741`、ROC-AUC `0.9988` | 仅在旧 UNSW 切分通过；FNR 距 `5%` 门槛仅 `0.06` 个百分点，不能外推至其他来源或重建权重 |
| UNSW → D2 | Macro-F1 约 `0.510`、ROC-AUC `0.681` | 现有模型的跨域能力不足 |
| CIC-IDS2017 Windows validation | 41,820 条，FPR `1.2723%`、Recall `38.0367%`、Macro-F1 `0.33076`、PR-AUC `0.99656`、ROC-AUC `0.93147` | Recall/Macro-F1 未达门槛；攻击占比约 96%，PR-AUC 不能证明良性误报或召回合格 |
| 阶段三数据 | L1-P 独立切分未冻结；L2 trusted Normal/Attack 为 `0/0`；独立规则场景 `0/10`；L3 授权计划未完成 | readiness 与 preflight 为 `BLOCKED`，不训练、不预测、不读 holdout |
| 当前 S3 预算登记 | XGBoost/LightGBM、P1、seed `20261003`、每来源 ≤`100,000` 行、合计 ≤`200,000` 行、≤`30` 分钟、最多两轮、禁用 Optuna | 预算登记不是运行授权，矩阵仍须保持 `trainingAuthorized=false` |

当前应先整改数据和标签证据，再确认特征契约是否可迁移；不能通过反复调阈值或扩大模型搜索弥补不可信的 Normal 标签。

## 2. 来源初筛状态

- ToN-IoT：发布说明的 PCAP、Zeek、带标签流及事件时间信息与目标较匹配；官方链接要求登录，尚未读取样本或验证逐流关联，不准入。
- IoT-23：许可和 80.5 MiB 官方子集身份保持冻结；阶段 2 已完成完整流/字段审查。Somfy 的单主机 100 流窗口不能暖机，ready Normal=0；2,964 条 v4 合格攻击切段全部为 initiator，当前模型范围内候选为 0。该子集不进入阶段 3。完整归档 MD5 未验证，独立活动和第二人复核未接受，没有可训练标签。
- CICIoT2023：发布说明未提供项目所需的独立可审计主机/安全事件日志来源，本轮不优先。
- AIT-LDS：有少量关联试点候选，但没有接受为可信 Normal/Attack 的标签，也没有冻结独立活动分区。
- CSE-CIC-IDS2018 Thursday-15：EVTX 筛查未找到同时具备地址和端口字段的成员，无法形成可信逐流真值；旧的背景 Normal 标签不采信。
- Kaggle 上发现相似名称、CSV 或高票数都不构成准入。每个 Kaggle owner/slug/version 都要单独核对官方来源、许可、真实文件清单、完整字节数、字段/标签语义和可复算的 PCAP—逐流—活动关联。

初筛体量建议：候选完整归档不超过 `2 GiB`；如许可允许只取官方场景子集，pilot 原始成员合计不超过 `1 GiB`。超限候选不先行全量下载。不能在此体量内证明良性与攻击流的独立性时，淘汰候选或缩小研究范围，不以削弱标签标准换取可训练行数。

## 3. 特征、标签与切分不变量

1. 本机 `unsw-nb15-flow-v4` 的 19 个输入字段、单位、方向、窗口和 fail-closed 规则是冻结契约。新数据只有能产生同语义字段时才复用 v4；不允许把外部 NetFlow/CSV 列名重命名后冒充 v4。
2. 对 PCAP 做标签关联时，登记规则来源、UTC 时间范围、协议、双向五元组/稳定连接键、重复和冲突处理、旁路哈希、关联成功率及审计样本。攻击日程只能界定候选时间窗，不能自动证明其中每条流是攻击；背景流也不能自动标作 Normal。
3. 无唯一关联、语义冲突、截断或来源不明的记录标记为 `Unknown`，不进入 Normal/Attack。每条训练标签均可追溯到来源和规则版本。
4. 训练/验证/holdout 按 capture、日期、主机、场景或独立活动分组；相同连接、精确/近重复流和同一活动不能跨分区。编码器、缩放器、插补器、特征选择和阈值不能使用 holdout 拟合/选择。
5. 若候选需要新字段、不同窗口或不同单位，先形成新版本（例如 v5）的规格、golden fixtures 和应用侧变更清单；v4 保持原样，训练不得先行。
6. 数据/模型/报告以 Git 外的只读或内容寻址目录保存。Git 只保存工具、契约、代码、测试及去敏后的必要摘要；不提交原始 PCAP、全量 CSV、模型权重、检查点、缓存或运行日志。

## 4. 分阶段执行与停止条件

### 阶段 0：冻结状态并保持训练阻断

- **训练仓库：** S3 预检维持 `BLOCKED`，不跑训练、调参、holdout 预测或导出；不要为绕过阻断改 readiness 计数或授权布尔值。
- **数据：** Monday 1,674 条保持 `Unknown`；ToN-IoT、IoT-23、CICIoT2023、AIT 和 CSE 按 §2 当前状态记录。
- **应用、传感器与前端：** 活动部署 `2026.10.2` 和发布台账 `approved` 只表示本机开发状态；当前模型作为历史/开发候选，不作生产批准。执行端点保持 `503 ACTION_EXECUTION_UNAVAILABLE`，不开放适配器；v4 严格校验和接口白名单保留，不新增训练启动或自动封禁控件。
- **证据：** [阶段 0 验收记录](phase0/README.md)与 `docs/phase0/evidence/freeze-20261003.json` 记录两仓库状态和路径；同目录保存原字节的 `s3-experiment-matrix-v1.json`、`phase3-dataset-readiness-v4.json`、`s3-preflight-20261003-v3.json`、`cic-monday-human-review-acceptance-v1.json`。这些是既有摘要的哈希校验与同步，没有重算原始 pilot 或创建标签。
- **矩阵：** 原矩阵 SHA-256 `14c71d367d3ae584ba235c74802c9500f584f93a6235e1e6b4ab368c1c3048e7` 保持不变；FNR≤`4%`、FPR≤`1.5%` 是更严格的开发停止条件，L1-P 最终验收仍为 FNR≤`5%` 等既有门槛。预算登记不授权运行；preflight 尚未接入所有历史训练入口，不能宣称任意旧命令均有不可绕过的 guard。
- **出口：** 两仓库当前事实、门槛、证据路径与“不得开始 S3”一致，已达到。数据 readiness 仍为 `BLOCKED`，Monday 不转 Normal。许可/PCAP—标签—活动 pilot 属于阶段 1～2，阶段 0 完成不批准后续训练。

### 阶段 1：候选来源清单与有界 pilot

- **训练仓库要实现：** 候选 metadata/manifest 审计工具，记录来源 ID/version、许可/引用、下载字节数、文件 SHA-256、PCAP/flow/log 清单、label schema、时间范围、类别计数、访问状态与审核结论；小样本读取必须有字节、成员数和时间上限，不遍历/展开无界归档。
- **数据要实现：** 先选 1～2 个最有希望的来源验证一段 Normal 与一段 Attack；保存逐流标签关联报告、人工核验样本、Unknown/冲突原因及分来源计数。
- **本地接口依赖：** 无后端改动；发布方与许可要求必须在训练仓库登记。
- **停止条件：** 许可不明/只允许登录但无法授权、文件过大、没有可唯一关联的逐流标签、没有独立可信良性流或只能提供攻击流，均拒绝该来源。

**执行记录（2026-10-03）：** 阶段 1 已完成，详见[候选初筛与有界 pilot](phase1/README.md)。10 项来源/镜像的版本、许可、体量与结论已登记；`source-screening-pilot-v2.json` 为当前报告，`stage2Candidate=true`、Normal 候选 29、Attack 候选 151,567、Unknown 4,637。标准库工具 `src/cyber_training/source_screening.py` 与 24 项测试已验证字节/时间/许可、源哈希、重复/冲突、Unknown 和禁止覆盖门禁。仅准备阶段 2 的公开离线 PCAP；完整流与独立活动日志关联、v4 兼容性、第二人标签复核和活动分区尚未验证，`trainingEligibleRows=0`、`trainingAuthorized=false`，原 readiness/preflight 不改写。

### 阶段 2：v4 兼容性与传感器同源提取

- **训练仓库要实现：** 以边界明确的 PCAP 小样本运行与 Go 传感器一致的流构造/特征逻辑；逐字段报告流方向、窗口、单位、缺失/默认值、提取成功率和 label join。训练端不得另用 CICFlowMeter 输出替代在线传感器语义。
- **数据要实现：** 每条入选记录有唯一 flow-to-label 关系；Unknown 明确隔离，展示攻击/正常标签抽样核对和关联冲突。
- **本地后端与传感器交接：** v4 可完整复现则锁定相同 contract hash 并提供双端 golden rows。v4 不可复现则远端停止，先由应用仓库更新特征规格、Java validator、Go/Windows 流处理和 manifest schema 的版本化设计。
- **出口：** 所有保留样本的必需字段、单位、类别编码和阈值输入语义都准确；每条未能确认的流均排除，不能造值。契约不兼容就更换数据或先完成新版本契约，不进入正式 split。

**执行记录（2026-10-03）：** 本次有界试点已收口，见[完整关联与特征审计](remediation-phase2/README.md)。`feature_pilot.py` 复核许可、原始成员、v4 与提取包哈希，关联完整区间/方向/双向原始包和 IP 字节；全部标签与完成流都有候选/排除账本，Unknown 不进入训练。精确/近重复特征签名、连接切段及日期分组已审查，未创建分区，不声称跨分区零泄漏。Mac 同源提取产生 85,803 条 v4 ready 攻击场景流，字段检查失败 0；其中 2,964 条具有完整连接攻击证据，但全部是 initiator。Somfy 两个窗口仅 77/7 条、ready Normal=0，因此当前子集不进入阶段 3，返回阶段 1。Windows 原生新 EXE 被应用控制以 `WinError 4551` 拒绝；没有修改该策略，Windows 只完成了来源哈希绑定 Mac 结果的审计，原生提取 parity 未验证。51 项 Windows 门禁测试和 JDK 25 的 Go/Java 公开 golden 对拍通过。可训练标签仍为 0，独立活动/第二人复核/分区未接受；S3、旧 readiness/preflight 和 holdout 保持原状态。

### 阶段 3：数据冻结和 readiness 通过

- **训练仓库要实现：** 可复算的数据 manifest、标签证据账本、完全/近重复审计、分组切分、跨分区泄漏检查和不可绕过的 holdout guard；输出代码/数据/特征/分区指纹。
- **数据要实现：** 至少达到冻结 L2 的可信 Normal `1,000`、Attack `100` 数量。锁定独立 test 必须包含足以报告各来源指标的样本；不以 pooled metrics 隐藏失败来源。记录未覆盖类别，不能事后扩大能力声明。
- **本地接口依赖：** 训练仓库向本机传递版本化 `model_manifest`、来源/切分 ID 和特征契约；若现有 schema 不支持，在训练前提变更请求并由应用仓库审查。
- **出口：** 所有源、许可、标签、字段、样本数、活动独立性和 holdout 访问策略通过 readiness；preflight 返回 `PASS`。否则任何训练命令都必须被拒绝。

### 阶段 4：受限开发训练

- **训练仓库要实现：** 测试行数限制、holdout 访问拒绝、每来源指标、阈值扫描、资源上限、运行身份与内容哈希。readiness 通过且本轮训练被明确授权后，按新冻结矩阵只训练 XGBoost/LightGBM 等小范围基线；每来源最多 100,000 行、总计 200,000 行、最多两轮、30 分钟、禁止 Optuna。数据/特征变化必须更新矩阵。
- **数据要实现：** 仅开发 train/validation 可读；报告 Normal 的 FPR、Attack recall/FNR、Macro-F1、PR/ROC、混淆矩阵、置信区间、按来源/场景/类别分层的误差。
- **本地后端与传感器：** 不改活动模型、不接实网、不改阈值、不执行响应；仅复用本轮冻结的模型/特征契约。
- **出口：** 所有来源在 validation 达到拟定 L1-P（Macro-F1≥`0.92`、FNR≤`5%`、FPR≤`1.5%`、PR-AUC≥`0.93`、ROC-AUC≥`0.99`），holdout 未读。若失败则用 development/validation 定位，不进入最终评估。

### 阶段 5：独立验收与候选制品

- **训练仓库要实现：** 只在 validation 出口通过后冻结报告模板和 `model_manifest.json`，对新 holdout 评估一次；产出逐来源/类别 metrics、置信区间、阈值来源、行数、样本指纹、原始源/切分/代码/模型 SHA-256、ONNX parity 和性能结果。所有失败均保留，不覆盖之前的 candidate。
- **数据要实现：** holdout 访问写审计；读后设为已暴露。失败后不能在同一个 holdout 上调参或重新选阈值。
- **本地后端与传感器交接：** 交付 ONNX、manifest、预处理说明、阈值策略、label map、19 字段顺序/单位、contract hash、golden fixtures 和软件运行时要求。候选保持 `candidate_only=true`、`production_approved=false`。
- **出口：** L1-P 每来源通过，ONNX/native 最大概率误差 ≤`1e-4`，artifact 与 manifest 哈希相符，运行时性能可接受。下一步是应用仓库的 backend/传感器 parity，不等于上线或自动阻断许可。

### 阶段 6：双仓库对拍和影子交接

- **训练仓库要实现：** 提供固定的 PCAP/规范流/golden feature/probability fixtures 和最小重放工具；报告文件只覆盖完成对拍所需内容。
- **数据要实现：** golden fixtures 与 holdout 完全分离；不能用锁定样本调试到通过。
- **本地后端/传感器依赖：** 应用侧独立验证后端 manifest/contract gate、Java ONNX、macOS/Windows 传感器流构造；失败/未知字段明确拒绝。不执行模型自动处置。
- **出口：** 逐字段、阈值和模型概率跨训练/Java/Mac/Windows 对拍通过；之后才开始独立 L2/L3 被动影子收集。窗口与已授权资产的观察指标由应用仓库负责。

## 5. 后续应用侧门槛（训练仓库不得自行放行）

- L2：独立可信 Normal ≥`1,000`、Attack ≥`100`；FPR≤`3%`、Recall≥`80%`。
- L3：两个独立时间段、`8` 个授权资产小时、可信 Normal ≥`1,000`，FPR≤`2%`，并继续满足 L2 Recall。
- 自动处置：需另有冻结的规则/动作安全场景且当前 readiness 要求 `10/10`；应用后端执行器、目标操作系统回滚和单独的发布/响应审批全部通过。训练报告或模型自身不能授予防火墙权限。

## 6. 交付与维护

每个候选版本都绑定 dataset/split fingerprint、source/license、标签规则、contract hash、feature 顺序/单位、preprocessing、algorithm/library/runtime、threshold policy、逐来源指标、锁定测试暴露情况、ONNX SHA-256、golden fixtures 和 `candidate_only` 状态。重建权重不得继承旧模型 holdout 指标。没有来源/权重/报告哈希，或缺少许可和标签证明时，应用后端应拒绝登记或验证。

### 相关文档

- 本文件：训练仓库当前路线与 gate。
- [`phase1/README.md`](phase1/README.md)：阶段 1 的候选、许可、字节预算、Windows 工具与 pilot 交接；当前数据仍不能训练。
- [`remediation-phase2/README.md`](remediation-phase2/README.md)：当前阶段 2 的审计与退回来源初筛决定，不是历史 CIC 阶段二；原始/派生/旁路/账本留在忽略目录。
- [`phase2/README.md`](phase2/README.md)：CIC-IDS2017 历史审查、冻结范围和 Windows validation 结果；不表示新模型训练完成。
- [`v2/training-plan-v2.md`](v2/training-plan-v2.md) 和 [`v2/evidence/`](v2/evidence/)：UNSW v2 旧实验协议与其原始结果，仅供历史复现。
- [`route-b/evidence/`](route-b/evidence/)：冻结 v4 路线中的原始审计摘要和报告。
- 原始数据、权重、运行目录和详细日志留在受控训练盘或运行目录，不提交到 Git。
