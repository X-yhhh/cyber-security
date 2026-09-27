# 网络流量威胁检测模型训练计划（基线 v2）

适用仓库：Windows 训练主机上的本训练仓库（目录约定见 `README.md`），分支 `training/windows-cuda`（基线提交 `061486a`）。
范围：本计划覆盖第 3～10 步（数据登记 → 可交付模型）。第 1、2 步（归档旧实验、补齐依赖）已完成并推送。
边界：只使用 Kaggle 公开数据做离线训练，不扫描、不产生攻击流量、不做在线自训练。

## 0. 已确定的前提

| 项 | 内容 |
|---|---|
| 硬件 | i9-12900H（14 核 / 20 线程）、内存 15.7 GB（空闲约 8.8 GB）、RTX 3070 Ti Laptop 8 GB、E 盘空闲约 150 GB；Python 3.12.10；已开启 Windows 智能应用控制 |
| 依赖 | numpy 2.2.6、pandas 2.3.3、scikit-learn 1.7.2、torch 2.7.1+cu126、xgboost 3.4.1、lightgbm 4.7.0、imbalanced-learn 0.14.2、onnx 1.19.1、onnxruntime 1.23.2、skl2onnx 1.19.1、onnxmltools 1.16.0、pyarrow 21.0.0、optuna 5.0.0 |
| 主数据集 D1 | Kaggle `mrwellsdavid/unsw-nb15`：4 个原始 CSV，共 2,540,047 行 × 49 列；另有 45 列预定义子集（注意文件名是反的：`testing-set.csv` 175,341 行是训练部分，`training-set.csv` 82,332 行是测试部分） |
| 泛化数据集 D2 | Kaggle `dhoogla/nftoniotv2`：`NF-ToN-IoT-V2.parquet`，13,135,881 行 × 43 列（NetFlow v2 特征，不含 IP；`Label` 为二分类，`Attack` 有 10 类） |
| 已排除 | HIKARI（来源 Zenodo，不是 Kaggle），放在 `data/excluded/`，禁止读取 |
| 旧结果 | 全部在 `archive/runs-legacy-20260926/`，旧 holdout 视为已暴露，不再作为验收依据 |

## 1. 任务定义与交付目标

- 主任务 T1：D1 原始数据上的流量二分类（Normal=0 / Attack=1）。这是最终上线模型。
- 辅任务 T2：D1 45 列子集上的 10 类 `attack_cat` 多分类。只作为研判参考输出，不驱动任何自动处置。
- 泛化任务 T3：在 D1 与 D2 的公共特征上做跨数据集评估，只用于报告，不参与选型。
- 最终交付：1 个 T1 二分类 ONNX 模型 + 预处理契约 + 阈值 + `model_manifest.json`（带 SHA-256），交给本机后端。

### 验收门槛（只在锁定 holdout 上判定，而且只判定一次）

| 指标 | 门槛 |
|---|---|
| Macro-F1 | ≥ 0.92 |
| FNR（漏报率） | ≤ 5% |
| FPR（误报率） | ≤ 1.5% |
| PR-AUC | ≥ 0.93 |
| ROC-AUC | ≥ 0.99 |
| 多种子 FNR 标准差（验证集） | ≤ 2% |
| 单条推理延迟 P95（ONNX Runtime CPU） | ≤ 5 ms |
| 批量 1024 条吞吐 | ≥ 20k 条/秒 |
| ONNX 与训练框架的概率差 | 最大绝对误差 ≤ 1e-4 |

达不到门槛的模型不能交付，只能回到第 7～8 步调整。调整后需要生成新的 holdout（见 §4.3），不能在同一个 holdout 上反复试。

门槛依据（2026-09-26 验证集实测，未使用 holdout）：去重后攻击率只有 3.9%，LightGBM 默认参数在 FNR=5% 时 FPR 为 0.91%、Macro-F1 为 0.933、PR-AUC 为 0.958。原门槛 Macro-F1 ≥ 0.93 与 FNR ≤ 5% 同时满足时几乎没有余量，考虑到 holdout 攻击率（4.03%）与分组差异，Macro-F1 门槛调为 0.92，并新增 PR-AUC（在强不平衡下比 ROC-AUC 更敏感）。

## 1.1 资源预算与运行约束（2026-09-26 审视后新增）

所有步骤按下列预算设计，超出预算就先缩小规模，不能靠延长时间硬跑。

| 资源 | 约束 |
|---|---|
| 内存 | 单进程常驻 ≤ 8 GB。D1 V0 视图全量约 0.75 GB（float32）；任何步骤不同时保留两个森林模型，不把 D2 全量 1300 万行载入内存 |
| CPU | 并行度 `n_jobs=16`，给系统、SSH 和驱动留 4 个线程；同一时间只跑一个训练进程 |
| GPU | 显存 ≤ 6 GB（留 2 GB 给桌面）；MLP 和 XGBoost 使用 GPU，其余模型使用 CPU |
| 时长 | 单个步骤 ≤ 3 小时，整个训练阶段（第 6～8 步）合计 ≤ 8 小时 |
| 后台运行 | 远端 SSH 断开会结束子进程，长任务一律通过 `scripts/launch.sh <步骤>` 以计划任务方式运行；训练期间阻止系统睡眠；结果逐条追加写入，支持 `--resume` 续跑 |
| 智能应用控制 | 不支持按文件夹加白名单，也就无法把 `.venv` 设为信任；关闭它不可逆，需要重装系统才能重新开启。当前策略：保持开启；单组实验失败时记录错误并继续，完成后用 `--resume` 只重跑失败的组 |

实测基准（40 万行训练抽样、完整验证集）：LR 约 11 s，RF（100 棵）约 16 s，MLP（15 轮）约 9 s，SMOTE+RF 约 38 s；LightGBM 在完整训练集（140 万行）上 600 轮约 41 s。

## 2. 全局约定

- 每次运行输出到 `runs/<step>-<YYYYMMDD-HHMM>/`，其中必须包含 `run-config.json`（参数、种子、git commit、依赖版本、GPU 信息）、`metrics.csv`、`checksums.json`；日志写 `training.log`。
- 全局种子：主种子 `20260927`；多种子复现用 `20260927, 20260928, 20260929, 20260930, 20260931`。
- 拟合规则：插补器、编码器、缩放器、PCA、SMOTE、阈值只能在训练集上拟合（阈值在验证集上选）。holdout 在第 9 步之前不能被读取。代码里用 `HoldoutGuard` 实现：读取 holdout 要显式传 `--unlock-holdout`，并写审计记录。
- 入模特征禁止使用：`srcip`、`dstip`、`stime`、`ltime`、`id`、`label`、`attack_cat`（D2 的 `Label`、`Attack` 同理）。
- 新代码放在 `src/cyber_training/v2/`，入口是 `python -m cyber_training.v2 <step>`。旧 stage 模块保持不动，不删除。
- 每一步完成后运行 `pytest -q`，然后单独提交一次，提交信息用中文。

## 3. 第 3 步：数据登记

命令：`python -m cyber_training.v2 register`

1. 计算两个数据集所有文件的 SHA-256、字节数、行数、列数，与已有的 `manifest.json` / `download-manifest.json` 核对，不一致就终止运行。
2. D1 原始 CSV：用 `NUSW-NB15_features.csv`（cp1252 编码）解析 49 列字段名；`attack_cat` 去掉首尾空格，`Backdoors` 统一成 `Backdoor`，正常行的空值填 `Normal`；`ct_flw_http_mthd`、`is_ftp_login` 的空值保持 NaN，交给预处理处理；`sport`、`dsport` 中的十六进制值和 `-` 转成整数，无法转换的记为 NaN，并记录条数。
3. D1 子集：验证 175,341 行对应训练部分、82,332 行对应测试部分，并记录文件名反转这一事实。
4. D2：读取 parquet，检查 `Label` 与 `Attack=="Benign"` 是否完全一致，把不一致的条数写进报告。
5. 输出 `runs/register-*/dataset-manifest.json`，内容包括来源 URL、许可（D1 按原作者学术使用条款，D2 为 CC-BY-NC-SA-4.0）、哈希、行列数、缺失值数、完全重复行数、标签分布，以及统一的缓存文件 `data/processed/d1_raw.parquet` 和 `d2.parquet` 的哈希。

完成标准：manifest 中两个数据集的标签计数与本文 §0 一致（D1 原始数据 label 0 为 2,218,764、label 1 为 321,283）。

## 4. 第 4～5 步：EDA 与切分

### 4.1 EDA（命令 `v2 eda`，只读取训练集和验证集之外的汇总信息，不做任何拟合）

输出到 `runs/eda-*/`，图保存为 PNG（300 dpi），数值另存 CSV：

1. 数据概览表：行数、列数、各列类型、缺失率、唯一值数。
2. 标签分布：二分类和攻击类别的柱状图（对数纵轴），附不平衡比。
3. 数值特征：分位数表（p1、p50、p99、max）、偏度；前 12 个偏度最大的特征画 log1p 前后的直方图。
4. 类别特征：`proto`、`service`、`state` 各取 Top-20 频次，以及各取值下的攻击率。
5. 相关性：Spearman 热力图；|ρ| > 0.95 的特征对单独列表，供第 7 步去冗余时参考。
6. 重复分析：完全重复行、"特征相同但标签不同"的冲突行，分别统计数量和占比。
7. 与标签的关系：互信息 Top-20（在 20 万条分层抽样上计算）。
8. D1 与 D2 公共特征的分布对比（KS 统计量），为第 9 步的泛化实验提供解释依据。

### 4.2 切分（命令 `v2 split`）

- D1 原始数据：去重键为 39 列模型候选特征（排除 IP、端口、时间、目标，以及近似随机的 TCP 初始序列号 `stcpb/dtcpb`）。先整组删除"特征相同、标签冲突"的 1,879 行，再删除 521,771 行重复，保留 2,016,397 行。
- 分组切分：以无序端点对 `{srcip, dstip}` 为组（共 171 组，其中 40 组含攻击），同一组只进入一个分区。含攻击的组按 9 类攻击的计数做多维分层分配（每个种子做 4000 次随机贪心，取偏差最小者），纯正常组按行数分配。比例为训练 70% / 验证 15% / holdout 15%。依次试 5 个种子（20260927～20260931），只按切分统计挑选，不看任何模型结果。
- 切分审计（`split-audit.json`）：端点组重叠 = 0，特征向量重叠 = 0；各分区攻击比例与总体偏差 ≤ 2 个百分点，行数占比与目标偏差 ≤ 3 个百分点，每个分区都有攻击样本。任何一项不满足就终止。
- D1 子集：保持官方切分。官方训练部分再按 `attack_cat` 分层 85/15 分出验证集；官方测试部分（82,332 行）作为 T2 的锁定测试集。官方子集自带 5,115 个训练/验证之间的重复特征向量，只报告、不剔除，以保持与官方切分可比。
- D2：按 `Attack` 分层抽样 150 万行，再按标签分层 70/15/15。该副本没有 IP 字段，所以不能分组切分，只用于 T3。
- 切分结果只保存行位置索引（`split-d1-raw.npz`、`split-d1-subset.npz`、`split-d2.npz`）及其指纹，后续各步都复用这几份索引。

### 4.2.1 实际切分结果（run `split-20260926-2119`，选中种子 20260930）

| 分区 | 行数 | 攻击行 | 攻击率 | 端点组 |
|---|---:|---:|---:|---:|
| train | 1,405,222 | 54,179 | 3.86% | 113 |
| validation | 310,681 | 11,709 | 3.77% | 22 |
| holdout | 300,494 | 12,108 | 4.03% | 36 |

去重后攻击率从 12.65% 降到 3.87%，不平衡比约 25:1。重复主要集中在 Generic 类（215,481 行去重后剩 17,332 行）。后续预处理对比中的不平衡处理组（P9～P11）因此更关键。

### 4.2.2 EDA 主要发现（run `eda-20260926-2231`）

- 高度偏态的特征：`sbytes`、`sloss`、`Djit`、`Sjit`、`ackdat`、`synack`、`Spkts`、`Sload` 等，偏度 26～129。多数做 log1p 后偏度降到 1 以下，但 `ackdat`、`synack`、`tcprtt` 在 log1p 后仍然偏度 > 12，原因是取值范围在 0～6 秒、log1p 基本不起作用，需要 QuantileTransformer（P7）作对照。
- 高相关特征对（|ρ| > 0.95）共 8 对，例如 `is_ftp_login`/`ct_ftp_cmd`、`trans_depth`/`ct_flw_http_mthd`、`swin`/`dwin`、`Spkts`/`Dpkts`、`tcprtt`/`synack`，这些作为 V3 去冗余的候选。
- 互信息前几名：`sttl`、`dttl`、`ct_state_ttl`、`sbytes`、`dbytes`。TTL 类特征信息量最高，这一点在报告中需要说明：UNSW 实验环境中攻击主机的 TTL 取值较固定，模型可能依赖这一环境特征。
- D1 与 D2 公共特征的 KS 统计量在 0.56～0.77 之间，分布差异很大，跨数据集泛化性能明显下降属于预期结果。

### 4.3 holdout 使用规则

holdout 只在第 9 步读取一次。如果第 9 步未通过、需要回到第 7～8 步调整，必须换一个种子重新切分（`20261001`、`20261002`…），并在报告中注明是第几次尝试。

## 5. 第 6 步：预处理对比试验（重点）

命令：`python -m cyber_training.v2 preprocess-compare`

### 5.1 实验设计

- 数据：D1 原始数据。从训练集中分层抽样 40 万行用于拟合，在完整验证集上评估（验证集不抽样）。
- 特征：统一使用 V0 基础特征视图（见 §6），这样对比时只有预处理一个变量。
- 评估模型（3 个，分别代表三类对预处理敏感度不同的模型）：
  - LR：`C=1.0`，`solver=lbfgs`，`max_iter=1000`（saga 在 40 万行上收敛慢且结果相同，改用 lbfgs）
  - RF：`n_estimators=100`，`max_depth=24`，`n_jobs=16`
  - MLP：2×256 隐层，ReLU，dropout 0.2，AdamW 学习率 1e-3，batch 8192，15 轮，CUDA
- 阈值统一取 0.5，避免阈值策略干扰预处理之间的比较。
- 每组配置跑 3 个种子（20260927～20260929，种子同时决定训练抽样），报告均值（CSV 中附标准差）。
- 规模与耗时：12 组 × 3 模型 × 3 种子 = 108 次，实测单次 5～40 秒，预计 40～60 分钟。
- 表中 Precision/Recall/F1 以攻击类为正类，另在 CSV 中记录 Macro-F1、FPR、FNR；选择规则使用 Macro-F1。

### 5.2 对比组（从基线出发，每组只改一个因素）

| 编号 | 缺失值 | 类别编码 | 数值变换 | 缩放 | 降维 | 不平衡处理 |
|---|---|---|---|---|---|---|
| P0 基线（不做预处理） | 填 0 | Ordinal | 无 | 无 | 无 | 无 |
| P1 | 中位数 + 缺失指示列 | Ordinal | 无 | 无 | 无 | 无 |
| P2 | 同 P1 | One-hot（出现频率 < 0.1% 的取值合并为 `other`） | 无 | 无 | 无 | 无 |
| P3 | 同 P2 | 同 P2 | 无 | StandardScaler | 无 | 无 |
| P4 | 同 P2 | 同 P2 | 无 | MinMaxScaler | 无 | 无 |
| P5 | 同 P2 | 同 P2 | 无 | RobustScaler | 无 | 无 |
| P6 | 同 P2 | 同 P2 | 有符号 log1p | StandardScaler | 无 | 无 |
| P7 | 同 P2 | 同 P2 | QuantileTransformer（输出正态分布） | 无 | 无 | 无 |
| P8 | 同 P6 | 同 P6 | 同 P6 | 同 P6 | PCA 保留 95% 方差 | 无 |
| P9 | 同 P6 | 同 P6 | 同 P6 | 同 P6 | 无 | class_weight=balanced |
| P10 | 同 P6 | 同 P6 | 同 P6 | 同 P6 | 无 | 随机欠采样到 1:3（仅训练集） |
| P11 | 同 P6 | 同 P6 | 同 P6 | 同 P6 | 无 | SMOTE 到 1:2（仅训练集，在编码和缩放之后进行） |

### 5.3 对比表格式（按参考图片版式，输出 `preprocessing-comparison.md` 和 `.csv`）

版式与参考论文的"表4"一致：表题在上方（中文表题 + 英文表题），行是指标，列是对比对象，数值保留 3 位小数，每行最优值加粗。

预处理对比：每个评估模型一张表，列为 P0～P11。示例（数值为占位符）：

表 1  LR 模型在不同预处理方案下的性能对比
Table 1  Performance comparison of LR under different preprocessing schemes

| 指标 | P0 | P1 | P2 | P3 | … | P11 |
|---|---:|---:|---:|---:|---:|---:|
| Precision | 0.xxx | | | | | |
| Recall | | | | | | |
| F1-score | | | | | | |
| Accuracy | | | | | | |
| AUC | | | | | | |

RF、MLP 各一张同版式表（表 2、表 3）。CSV 另外保留 FPR、FNR、训练耗时和 3 个种子的标准差，Markdown 表只放上面 5 项指标。表格下方用 3～5 句话写结论，例如"缩放对 LR/MLP 影响显著、对 RF 几乎无影响"。另外输出一张热力图（方案 × 模型，数值为 F1）。

第 7、8 步的特征对比表和模型对比表沿用同一版式，把列换成特征视图或模型（例如"表 5  9 个模型性能参数对比"，列为 LR、SVM、GNB、DT、RF、ET、XGBoost、LightGBM、MLP）。

### 5.4 选择规则

以 3 个模型验证集 Macro-F1 的平均值排序，取第一名作为统一预处理方案 `P*`。如果与第二名的差距小于 0.002，就选更简单的那个（组件更少者优先）。树模型可以另外使用 P1（不缩放）版本，在 manifest 中分别记录。

### 5.5 实际结果（run `preprocess-20260926-2250`，108 次全部成功，用时约 25 分钟）

3 个模型验证集 Macro-F1 均值（阈值 0.5）：

| 方案 | P0 | P1 | P2 | P3 | P4 | P5 | P6 | P7 | P8 | P9 | P10 | P11 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| LR | 0.624 | 0.668 | 0.674 | 0.924 | 0.919 | 0.853 | 0.925 | 0.923 | 0.893 | 0.919 | 0.919 | 0.919 |
| RF | 0.932 | 0.930 | 0.931 | 0.931 | 0.931 | 0.931 | 0.931 | 0.931 | 0.924 | 0.923 | 0.920 | 0.928 |
| MLP | 0.492 | 0.492 | 0.492 | 0.919 | 0.917 | 0.904 | 0.925 | 0.925 | 0.921 | 0.920 | 0.919 | 0.920 |
| 均值 | 0.683 | 0.697 | 0.699 | 0.925 | 0.922 | 0.896 | **0.927** | 0.926 | 0.913 | 0.921 | 0.919 | 0.922 |

结论：
- 缩放是 LR 和 MLP 的决定因素：不缩放时（P0～P2），MLP 几乎把所有样本判为正常（FNR 约 99.8%），LR 的 FNR 为 74%～82%；做 Standard 缩放后，Macro-F1 分别提高 0.43 和 0.25。RobustScaler（P5）明显较差，原因是多个特征的中位数和四分位距为 0，缩放后出现极端值。
- RF 对预处理基本不敏感，12 组的 Macro-F1 都在 0.920～0.932 之间，不做预处理的 P0 最好。
- log1p（P6）与 QuantileTransformer（P7）效果相当，均值差 0.0006。
- PCA（P8，保留 95% 方差后剩 17 维）在三个模型上都下降（LR −0.031）。与参考论文一致：降维会丢失部分重要特征的信息。
- 不平衡处理（P9～P11）在阈值 0.5 下显著降低 FNR：LR、MLP 从 12%～14% 降到 0.4% 以下，FPR 从约 0.7% 升到约 1.4%；RF 的类权重（P9）和 SMOTE（P11）只降到约 3.4%，FPR 约 1.1%～1.2%，欠采样（P10）降到 0.26%、FPR 1.40%。三个模型的 Macro-F1 均小幅下降，AUC 基本不变。说明它主要改变的是工作点，而非排序能力；第 8 步统一在验证集上选阈值，已经能覆盖这一作用。

选定方案（§5.4 规则）：P6 与 P7 的差距小于 0.002，按组件更少选 **P7**（中位数插补 + 缺失指示 + One-hot + QuantileTransformer，输出正态分布）。另一个优势是 skl2onnx 支持 QuantileTransformer，而 P6 的 `FunctionTransformer(log1p)` 不能直接导出 ONNX（已实测）。

对后续步骤的影响：
- `P*` = P7，用于 LR、SVM、GNB、MLP；树模型（DT、RF、ET、XGBoost、LightGBM）使用 P1（中位数插补 + Ordinal 编码）。P0 用 0 填充缺失，会把"字段缺失"与"值为 0"混在一起，违反"不静默造值"的约束，所以树模型取与 P0 相差 0.0015 的 P1。
- 默认不做类权重和重采样，由阈值选择控制工作点；MLP 不使用 pos_weight。

## 6. 第 7 步：特征工程对比

命令：`v2 feature-compare`。预处理：RF 和 LightGBM 均为树模型，按 §5.5 使用 P1；评估模型用 RF 和 LightGBM，抽样规模与第 6 步相同，3 个种子。规模为 4 个视图 × 2 个模型 × 3 个种子 = 24 次，预计约 20 分钟。

| 视图 | 内容 |
|---|---|
| V0 基础 | 与 45 列子集同名的 42 个特征（去掉 id、label、attack_cat），用原始数据的列按名称映射得到 |
| V1 端点 | V0 + `dsport` 分桶（知名端口 0–1023 / 注册端口 1024–49151 / 动态端口）。不对 `sport` 分桶：源端口基本是随机的临时端口，EDA 中未显示区分作用 |
| V2 工程 | V1 + 比率特征：`sbytes/(spkts+1)`、`dbytes/(dpkts+1)`、`sbytes/(dbytes+1)`、`spkts/(dpkts+1)`；差值特征：`sttl-dttl`、`synack-ackdat`；速率特征：`(sbytes+dbytes)/(dur+1e-6)`；以及对长尾特征做 log1p |
| V3 精简 | V2 去掉 EDA 列出的 8 对 |ρ| > 0.95 冗余特征（每对保留互信息更高者），再去掉 `stcpb`、`dtcpb`（近似随机的 TCP 初始序列号），最后按训练集上 LightGBM gain 重要性保留累计 99% 的特征 |
| V4 去 TTL（诊断） | 最优视图去掉 `sttl`、`dttl`、`ct_state_ttl`，只用于量化模型对 UNSW 环境 TTL 特征的依赖程度，不参与选型 |

实现细节（2026-09-27 确认）：
- LightGBM 使用 M8 参数（lr=0.05，num_leaves=127，min_child_samples=50，feature_fraction=0.8，bagging_fraction=0.8，bagging_freq=1），但固定 600 轮、不在验证集上早停，避免验证集参与拟合；`n_jobs=16`。RF 参数与第 6 步相同（100 棵，max_depth=24）。
- 阈值固定 0.5（与第 6 步一致），CSV 另记 PR-AUC、FPR、FNR 与训练耗时。
- V2 不对长尾特征做 log1p：单调变换不改变树模型的分裂结果，且 `FunctionTransformer(log1p)` 无法直接导出 ONNX（§5.5 已实测）。
- V1 的 `dsport` 分桶为 `well_known`（0–1023）/ `registered`（1024–49151）/ `dynamic`（49152–65535）/ `missing`（缺失或超出 0–65535，例如原始数据中 2 条值为 538989345 的记录），作为类别特征 Ordinal 编码。
- V3 冗余对按 |ρ| 降序贪心处理：若一对中两个特征都还在，删除 EDA 互信息较低者。EDA 使用原始字段名，按 `features.SUBSET_TO_RAW` 映射到 V0 名称。重要性筛选在第一个种子的训练抽样上拟合 LightGBM（600 轮、同参数）并按 gain 累计 99% 保留，结果写入 `feature-views.json`，其余种子复用同一特征列表。
- V4 在 V0～V3 选出的最优视图上去掉 `sttl`、`dttl`、`ct_state_ttl`，只用 LightGBM、3 个种子，不参与选型。

输出 `feature-comparison.md` 表格（版式同 §5.3，列为 V0～V3），以及 V2 的特征重要性 Top-30 图。选择规则：以 Macro-F1 为准；如果 V3 与最优视图的差距不超过 0.002，优先选 V3（特征少、推理快）。选出的视图记为 `V*`。

## 7. 第 8 步：多模型训练与调优

命令：`v2 train --stage screen` → `v2 train --stage tune` → `v2 train --stage seeds`

数据：完整训练集（约 140 万行，不抽样），配合 `P*` 和 `V*`。树模型和线性模型统一使用 `P*`；如果 §5.4 给出了树模型专用的不缩放方案，树模型改用该方案并在 manifest 中记录。

### 7.1 模型与初筛参数（9 个模型）

| # | 模型 | 初始参数 | 设备 |
|---|---|---|---|
| M1 | Logistic Regression | C=1.0，lbfgs，max_iter=1000 | CPU |
| M2 | Linear SVM（`LinearSVC` + `CalibratedClassifierCV` sigmoid 校准，cv=3） | C=0.5，dual=False | CPU |
| M3 | Gaussian NB | 默认参数 | CPU |
| M4 | Decision Tree | max_depth=24，min_samples_leaf=5 | CPU |
| M5 | Random Forest | 200 棵树，max_depth=32，min_samples_leaf=2，max_features=sqrt，n_jobs=16（完整深度的 300 棵树在 140 万行上约需 6～8 GB 内存，超出预算） | CPU |
| M6 | Extra Trees | 200 棵树，其余参数同 M5 | CPU |
| M7 | XGBoost | tree_method=hist，device=cuda，n_estimators=2000，lr=0.05，max_depth=8，subsample=0.8，colsample_bytree=0.8，early_stopping_rounds=100（用验证集） | GPU |
| M8 | LightGBM | n_estimators=3000，lr=0.05，num_leaves=127，min_child_samples=50，feature_fraction=0.8，bagging_fraction=0.8，early_stopping=100 | CPU |
| M9 | PyTorch MLP | 输入层 → 512 → 256 → 128 → 1，BatchNorm + ReLU + Dropout 0.3，AdamW(lr 1e-3，wd 1e-4)，OneCycle 学习率调度，batch 8192，最多 30 轮，验证损失早停（patience 5）；不使用 pos_weight（§5.5 结论） | GPU |

初筛只看验证集，输出 `model-screening.md`，版式同 §5.3（行为指标、列为 9 个模型），另在 CSV 中记录推理延迟和模型大小。

### 7.2 调优（初筛 Macro-F1 前 3 名，外加 MLP 必选；合计不超过 4 个模型）

使用 Optuna 的 TPE 采样器，固定种子，只在训练集上训练、在验证集上评分。每个模型使用固定的试验次数和时间上限（先到者为准），调优阶段合计 ≤ 3 小时：

| 模型 | 试验次数 | 时间上限 | 说明 |
|---|---:|---:|---|
| XGBoost（GPU） | 30 | 40 分钟 | 每次约 1 分钟，带早停 |
| LightGBM | 30 | 40 分钟 | 每次约 1 分钟，带早停 |
| RF / ET | 12 | 50 分钟 | 每次 3～4 分钟；搜索时用 50% 训练行，最终参数再用全量重训 |
| MLP（GPU） | 20 | 40 分钟 | 每次约 2 分钟，带早停 |

启用 Optuna 的 MedianPruner，对明显较差的试验提前终止。

- XGBoost：max_depth 6–12，lr 0.02–0.2，min_child_weight 1–20，gamma 0–5，subsample 0.6–1，colsample 0.5–1
- LightGBM：num_leaves 31–255，lr 0.02–0.2，min_child_samples 20–200，lambda_l2 0–10
- RF/ET：n_estimators 100–250，max_depth {24, 32, 40}，min_samples_leaf 1–10，max_features {sqrt, 0.3}
- MLP：宽度 {256, 512, 1024}，层数 2–4，dropout 0.1–0.5，lr 3e-4–3e-3

Optuna 已以 `optuna==5.0.0` 加入依赖（提交 `bfc358f`）。

### 7.3 阈值策略

每个模型在验证集上选择阈值：在满足 FNR ≤ 4% 的阈值中，取 FPR 最小的那个；如果没有阈值能满足，就取验证集 F1 最优的阈值，并标记"约束未满足"。阈值写入 manifest。

### 7.4 多种子复现与最终选型

调优后的前 3 名分别用 5 个种子重训（种子同时影响切分之外的所有随机性），合计 15 次训练，预计 ≤ 1 小时。报告验证集指标的均值 ± 标准差，输出 `model-comparison.md`（主对比表）和 Precision/Recall/F1/AUC 分组柱状图。

选型规则（按顺序判断）：
1. 验证集 FNR 标准差 ≤ 2%；
2. 平均 FNR ≤ 5%，且平均 FPR ≤ 1.5%；
3. 在满足以上两条的模型中，Macro-F1 最高；
4. 差距不超过 0.003 时，优先选延迟更低、体积更小的模型。

预计候选：XGBoost 或 LightGBM。

### 7.5 T2 多分类（在第 8 步之后进行，不影响 T1）

使用 D1 子集，以 LightGBM（objective=multiclass）和 XGBoost 作为主模型，RF 和 MLP 作为对照。类别不平衡用 class_weight 处理；对 Worms、Shellcode 等小类，比较"不重采样"与"SMOTE 到 5000 条"两种做法。不做超参搜索，直接复用 T1 调优得到的参数量级，预计 ≤ 30 分钟。报告 Macro/Weighted F1、Balanced Accuracy、每类召回率和混淆矩阵。只在官方测试部分上锁定评估一次。

## 8. 第 9 步：锁定评估与泛化评估

命令：`v2 final-eval --unlock-holdout --candidate <model>`

1. 冻结候选模型：把模型文件、预处理器、阈值、特征顺序的哈希写入 `pre-final-freeze.json`，并提交到 Git（只提交这个 JSON，不提交权重）。
2. holdout 只运行一次，输出以下内容：
   - 完整指标：Accuracy、Precision、Recall、Macro-F1、Weighted-F1、ROC-AUC、PR-AUC、Specificity、FPR、FNR、MCC；
   - 混淆矩阵；
   - ROC 曲线和 PR 曲线；
   - 按 `attack_cat` 分组的召回率（查看各类攻击的漏报情况）；
   - 阈值敏感性曲线（阈值取 0.1～0.9 时 FNR/FPR 的变化）。
3. 按 §1 的门槛判定是否通过，结果写入 `final-verdict.json`。
4. T3 泛化评估（结果只写入报告，不影响是否通过）：
   - 取 D1 与 D2 的公共语义特征，包括时长、双向字节数、双向包数、TTL 最小/最大值、协议、目的端口分桶，以及由这些特征派生的比率，并编写显式映射表（单位统一换算为秒和字节）；
   - 做 4 组实验：D1→D1、D1→D2、D2→D2、D2→D1。模型用 LightGBM，参数使用 §7 调优得到的参数；D2 使用第 5 步抽样的 150 万行，不加载全量；
   - 公共特征只用 `datasets.COMMON_FEATURES` 中定义的 9 个（时长、双向字节/包、TTL 最小/最大、每包字节数）。协议和端口在两个数据集中的编码不同（D1 是字符串，D2 是协议号），不做强行映射；
   - 输出一张 2×2 矩阵表（Macro-F1 / ROC-AUC）。预期跨数据集的性能会明显下降，这一点正好支撑"模型只对其训练分布负责"的说明。

## 9. 第 10 步：导出与交付

命令：`v2 export --candidate <model>`

1. 导出格式：
   - XGBoost / LightGBM 用 `onnxmltools` 导出；
   - sklearn 模型用 `skl2onnx` 导出；
   - MLP 用 `torch.onnx.export`，opset 17，动态 batch 维度。
   预处理有两种做法：优先把预处理和模型打包成同一个 ONNX 图；如果做不到，就把预处理导出为 `preprocessing.json`（列顺序、插补值、编码表、log1p 列、缩放参数），由后端按契约实现。
2. 一致性校验：从验证集中取 1 万条，比较 ONNX Runtime 与原框架输出的概率，最大误差 ≤ 1e-4，且在阈值下的判定结果 100% 一致。
3. 性能测试：ONNX Runtime CPU 下单条推理 P50/P95 延迟、batch=1024 的吞吐、模型大小。
4. `model_manifest.json` 至少包含：
   - `model_version`（例如 `unsw-binary-2026.10.0`）、`task=binary_flow_classification`；
   - 数据集和切分的哈希、特征列表（顺序、类型、单位）、预处理契约；
   - 标签映射 `{0: Normal, 1: Attack}`、阈值及阈值策略；
   - holdout 指标、运行时要求（onnxruntime 1.23.2，opset 17）；
   - 训练 commit、所有文件的 SHA-256；
   - 使用限制说明：只适用于 UNSW-NB15 分布的流特征；不做攻击类别判定；输入字段缺失时拒绝推理。
5. 交付目录 `delivery/unsw-binary-<version>/`（已被 Git 忽略），包含 `model.onnx`、`preprocessing.json`、`model_manifest.json`、`checksums.json`、`evaluation-report.md`、所有对比表和图。通过 scp 传到本机，由本机后端按 manifest 校验哈希后激活。权重不提交到 Git。
6. 本机验证：后端加载模型，用同一批 1 万条样本回放，结果必须与远端完全一致，本机回放的记录写入交付报告。

## 10. 执行顺序与时间预估

| 步骤 | 命令 | 预计耗时 | 产物 | 提交 |
|---|---|---|---|---|
| 3 登记 | `v2 register` | 10 分钟 | dataset-manifest | 代码 + 测试 |
| 4 EDA | `v2 eda` | 20 分钟 | eda/ 图表 | 代码 |
| 5 切分 | `v2 split` | 10 分钟 | split-indices、audit | 代码 + 审计 JSON |
| 6 预处理对比 | `v2 preprocess-compare` | 40～60 分钟（108 次） | 对比表 + 热力图 | 代码 + 表格 |
| 7 特征对比 | `v2 feature-compare` | 约 20 分钟（24 次 + 1 个 TTL 诊断） | 特征对比表 | 代码 + 表格 |
| 8 训练调优 | `v2 train --stage screen/tune/seeds` | 初筛约 1 小时 + 调优 ≤ 3 小时 + 复现 ≤ 1 小时 | 模型对比表 | 代码 + 表格 |
| 8b 多分类 | `v2 train-multiclass` | ≤ 30 分钟 | 多分类报告 | 代码 |
| 9 锁定评估 | `v2 final-eval` | 20 分钟 | final-verdict | freeze + verdict |
| 10 导出交付 | `v2 export` | 30 分钟 | delivery/ | manifest 摘要 |

每一步都需要新增单元测试，至少覆盖：
- 泄漏防护：holdout 被锁定、拟合只接触训练集索引；
- 切分重叠为 0；
- 特征映射的列名和单位；
- 阈值选择逻辑；
- ONNX 一致性。

长时间任务通过 `scripts/launch.sh <步骤>` 以计划任务方式在远端后台运行（nohup 在 SSH 断开时会被一起结束，已实测）；日志写入 `runs/task-<步骤>.log` 和对应运行目录的 `training.log`。

## 11. 风险与应对

- UNSW 原始数据中存在大量完全重复行（约 48 万条），去重后正类比例会变化。这一点在 EDA 中如实报告，不做掩盖。
- 端点分组切分可能导致各分区攻击比例不均衡。应对：最多换 5 个种子，选比例偏差最小的一次，并在报告中注明。
- 8GB 显存：XGBoost 在完整数据上开启 hist 算法可以放下；MLP 的 batch 最大 8192。如果显存不足，XGBoost 改用 `max_bin=128`。
- 15.7 GB 内存：森林模型在全量训练集上限制树数和深度（§7.1）；每个模型训练完立即释放，不同时持有多个森林。
- 智能应用控制偶发拦截 DLL：单组失败只记录不中断，完成后用 `--resume` 补跑。
- 跨数据集泛化性能差属于预期结果，报告中写明这是限制，不作为调参目标。
- 模型不等于实网防护能力：交付物只声明"对 UNSW-NB15 分布的流量特征做二分类"，其余能力不做宣称。
