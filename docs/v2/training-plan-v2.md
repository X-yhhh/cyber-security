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

### 6.1 实际结果（run `feature-20260927-1249`，提交 `0a5f1c5`，27 次全部成功，用时约 7 分钟）

验证集、阈值 0.5、3 个种子均值（种子标准差均 ≤ 0.0013）：

| 视图 | 特征数 | RF Macro-F1 | LightGBM Macro-F1 | 均值 | RF PR-AUC | LightGBM PR-AUC |
|---|---:|---:|---:|---:|---:|---:|
| V0 | 42 | 0.9304 | 0.9308 | 0.9306 | 0.958 | 0.958 |
| V1 | 43 | 0.9328 | 0.9328 | 0.9328 | 0.960 | 0.961 |
| V2 | 50 | 0.9338 | 0.9332 | **0.9335** | 0.962 | 0.962 |
| V3 | 32 | 0.9335 | 0.9314 | 0.9324 | 0.962 | 0.961 |

V3 的构造（`feature-views.json`，在第一个种子的训练抽样上确定，其余种子复用）：
- 冗余对去除 7 个：`is_ftp_login`、`trans_depth`、`dwin`、`dloss`、`spkts`、`synack`、`sinpkt`；再去除 `stcpb`、`dtcpb`；
- 累计 gain 99% 之外去除 9 个：`state`、`dpkts`、`dttl`、`swin`、`response_body_len`、`ct_ftp_cmd`、`is_sm_ips_ports`、`dsport_bucket`、`ttl_diff`；
- 保留 32 个：`dur`、`proto`、`service`、`sbytes`、`dbytes`、`rate`、`sttl`、`sload`、`dload`、`sloss`、`dinpkt`、`sjit`、`djit`、`tcprtt`、`ackdat`、`smean`、`dmean`、`ct_srv_src`、`ct_state_ttl`、`ct_dst_ltm`、`ct_src_dport_ltm`、`ct_dst_sport_ltm`、`ct_dst_src_ltm`、`ct_flw_http_mthd`、`ct_src_ltm`、`ct_srv_dst`、`sbytes_per_spkt`、`dbytes_per_dpkt`、`sbytes_dbytes_ratio`、`spkts_dpkts_ratio`、`synack_ackdat_diff`、`bytes_rate`。

结论：
- 特征工程带来的提升很小：V0 → V2 的 Macro-F1 均值只提高 0.003；`dsport` 分桶（V1）贡献约 0.002，比率/速率特征（V2）再加约 0.001。
- V2 最高，V3 与其差距 0.0010（≤ 0.002），按规则选定 **`V*` = V3**（32 个特征，比 V2 少 36%）。需注意 LightGBM 单独看 V3 比 V2 低 0.0018，已接近容差。
- 阈值 0.5 下各视图 FPR 约 0.6%、FNR 约 10%～11%，工作点问题留给第 8 步的验证集阈值选择。
- TTL 依赖：V2 的 LightGBM gain 中 `sttl` 与 `ct_state_ttl` 合计约 80%，说明模型确实大量使用 UNSW 环境中的 TTL 特征；但 V4（V3 去掉 `sttl`、`ct_state_ttl`，`dttl` 在 V3 中已被去除）的 Macro-F1 为 0.934（V3 为 0.931），PR-AUC 0.962（V3 为 0.961），FNR 从 11.0% 升到 11.5%、FPR 从 0.63% 降到 0.56%。即去掉 TTL 后其他特征几乎完全替代其区分作用，TTL 是“高重要性但可替代”的特征。V4 不参与选型，第 8 步仍使用 V3，报告中需说明这一点。

## 7. 第 8 步：多模型训练与调优

命令：`v2 train --stage screen` → `v2 train --stage tune` → `v2 train --stage seeds`

数据：完整训练集（约 140 万行，不抽样），配合 `V*` = V3。按 §5.5，树模型（DT、RF、ET、XGBoost、LightGBM）使用 P1，LR、SVM、GNB、MLP 使用 `P*` = P7，并在 manifest 中分别记录。

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

实现（2026-09-27）：代码 `src/cyber_training/v2/multiclass.py`，运行目录 `train-multiclass-*`，`--resume` 续跑时跳过已成功的组合。
- 数据：官方训练文件按第 5 步 `split-d1-subset.npz` 分为训练 149,039 行、验证 26,302 行（读取前校验该文件 SHA-256 与切分审计一致）；特征为 V0 的 42 列（与子集同名）；类别按固定顺序编码，出现契约外类别即终止。官方测试文件不被读取。
- 预处理：LightGBM/XGBoost/RF 用 P1，MLP 用 P7，只在真实训练行上拟合。
- 类权重：样本权重 n / (k·n_c)，各类权重和相等；早停看验证分区的未加权 mlogloss。
- SMOTE：训练分区中少于 5,000 条的 4 个类（Analysis、Backdoor、Shellcode、Worms）用 SMOTE-NC（k=5）合成到 5,000 条，合成在 signed log1p 数值空间进行、类别列取名义近邻，逆变换回原单位，整数列取整；合成行只追加到训练矩阵，同样使用类权重。
- 参数：XGBoost（多分类 softprob）、RF、MLP 复用 T1 调优参数，LightGBM 在 T1 未调优，复用 T1 初筛参数。判定取 argmax。
- 选型：验证集 Macro-F1 最高；差距 ≤ 0.003 时优先不用 SMOTE，再按 Balanced Accuracy。选中组合以主种子重训保存到 `candidate/`（模型、预处理器、类别映射、文件哈希），供第 9 步锁定评估。

实际结果（运行 `train-multiclass-20260927-1632`，8 个组合全部成功，合计约 2.5 分钟）：

| 组合 | Macro-F1 | Weighted-F1 | Balanced Acc. | 最小类召回率 |
|---|---:|---:|---:|---:|
| LightGBM（类权重） | **0.600** | 0.804 | 0.642 | 0.191 |
| LightGBM（+SMOTE） | 0.597 | **0.815** | 0.662 | 0.206 |
| XGBoost（类权重） | 0.580 | 0.787 | 0.665 | 0.221 |
| RF（类权重） | 0.579 | 0.797 | 0.651 | 0.191 |
| XGBoost（+SMOTE） | 0.572 | 0.794 | **0.685** | 0.229 |
| RF（+SMOTE） | 0.567 | 0.802 | 0.675 | 0.221 |
| MLP（+SMOTE） | 0.526 | 0.772 | 0.673 | **0.344** |
| MLP（类权重） | 0.507 | 0.762 | 0.675 | 0.240 |

- 选定 **LightGBM（类权重）**：与 LightGBM + SMOTE 差 0.003，按规则优先不用 SMOTE。
- 主要困难在 Analysis / Backdoor / DoS / Exploits 四类：选中模型验证集召回率分别为 0.22、0.19、0.29、0.53，混淆矩阵显示它们之间大量互相误判（例如 DoS 被判为 Backdoor 664 条、Analysis 448 条）。这四类在子集的流特征上难以区分；Generic（0.98）、Shellcode（0.89）、Fuzzers（0.86）、Normal（0.87）较好。
- SMOTE 使 3 个树模型的 Macro-F1 下降 0.003～0.012、Balanced Accuracy 上升约 0.02，Analysis/Backdoor 召回率小幅上升；LightGBM 与 XGBoost 的 Worms 召回率下降（验证集只有 19 条，波动大）。MLP 的 Macro-F1 +0.020，但 Backdoor 召回率 −0.36，且仍是最低的一组。
- Normal 召回率 0.87：平衡类权重把部分 Normal 推向 Fuzzers（989 条）。T2 不承担攻击/正常判定（由 T1 负责），这个误判不影响处置，但作为研判参考输出时应先经 T1 判为攻击再看 T2 类别。
- 验证集只用于选型，且早停使用了验证集，最终以第 9 步在官方测试文件上的一次锁定评估为准。

### 7.6 实现细节（2026-09-27 确认）

- 代码 `src/cyber_training/v2/train.py`，三个阶段各写一个运行目录：`train-screen-*`、`train-tune-*`、`train-seeds-*`；后一阶段缺省读取前一阶段的最新目录（可用 `--source` 指定），`--resume` 续跑时跳过已成功的行。
- 数据：D1 原始数据完整训练分区 1,405,222 行，不抽样；完整验证分区 310,681 行评估；特征视图 `V*` = V3（32 列）。预处理按 §5.5：树模型（DT、RF、ET、XGBoost、LightGBM）用 P1，LR、SVM、GNB、MLP 用 P7；预处理器只在训练分区拟合，每个种子重新拟合。
- 阈值：每次训练都按 §7.3 在验证分区上选阈值，表中指标均在所选阈值下计算。XGBoost、LightGBM 与 MLP 用验证分区早停（§7.1），所以验证集指标偏乐观，最终以第 9 步锁定 holdout 为准。
- 调优：Optuna TPE（种子 20260927）+ MedianPruner（前 5 次不剪枝；XGBoost/LightGBM 每 50 轮报告一次验证 logloss，MLP 每轮报告），试验逐条写入 journal 文件。Windows 普通用户不能创建符号链接，journal 使用 `JournalFileOpenLock`。候选只从有搜索空间的模型（XGBoost、LightGBM、RF、ET、MLP）中取；RF/ET 在 50% 分层抽样的训练行上搜索，所有模型的最优参数都在完整训练分区上用主种子重训后排序，取前 3 名进入多种子复现。
- 推理速度：原框架 CPU（XGBoost 切到 CPU，sklearn `n_jobs=1`）、已变换矩阵、不含预处理；单条 200 次取 P50/P95，batch=1024 重复 10 次算吞吐。只用于模型间比较和 §7.4 第 4 条，§1 的延迟门槛在第 10 步用 ONNX Runtime 判定。
- 候选制品：选中模型以主种子重训后写入 `runs/train-seeds-*/candidate/`（模型文件、预处理器、`candidate.json` 记录阈值、特征列、切分指纹与文件 SHA-256），只在训练主机上供第 9～10 步使用，不提交到 Git。

### 7.7 实际结果（运行 `train-screen-20260927-1354`、`train-tune-20260927-1425`、`train-seeds-20260927-1458`，用时约 1.3 小时）

初筛（表 6，主种子，验证集，阈值按 §7.3）：

| 模型 | XGBoost | RF | ET | LightGBM | MLP | LR | SVM | GNB | DT |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Macro-F1 | **0.934** | 0.934 | 0.933 | 0.932 | 0.928 | 0.925 | 0.923 | 0.914 | 0.036 |
| PR-AUC | 0.961 | **0.965** | 0.954 | 0.959 | 0.952 | 0.942 | 0.934 | 0.739 | 0.849 |
| FPR | **0.93%** | 0.94% | 0.96% | 0.97% | 1.04% | 1.10% | 1.15% | 1.34% | 100% |
| 单条延迟 P95（ms） | 0.72 | 4.52 | 5.02 | 0.85 | 0.45 | 0.04 | 1.15 | 0.25 | 0.05 |
| 模型体积（MB） | 4.00 | 164.5 | 182.6 | 1.67 | 0.77 | <0.01 | <0.01 | <0.01 | 0.51 |

- 前 4 名（XGBoost、RF、ET、LightGBM）Macro-F1 相差不到 0.003；MLP 与线性模型低 0.006～0.011，GNB 的 PR-AUC 明显较差。
- DT 是退化结果：深度 24 的单棵树叶子几乎都是纯的，验证集中 4.16% 的攻击落在概率为 0 的叶子里（已复核），任何正阈值都达不到 FNR ≤ 4%，只有阈值 0 满足约束，于是全部判为攻击（FPR 100%）。这是 §7.3 规则作用于离散概率模型的结果，不是运行错误；DT 不进入后续阶段。
- 首次运行 DT、RF、ET 在统计模型体积时失败（pickle 协议 5 以 `PickleBuffer` 写出数组，旧代码对其调用 `len()`），修复后用 `--resume` 补跑；最终 9 个模型全部成功。
- 调优候选：XGBoost、RF、ET（前 3 名）+ MLP（必选）。

调优（`model-tuning.md`，最优参数在完整训练分区重训后）：

| 模型 | 试验 / 完成 / 剪枝 | 初筛 Macro-F1 | 调优后 Macro-F1 | 提升 |
|---|---|---:|---:|---:|
| XGBoost | 30 / 12 / 18 | 0.9340 | 0.9335 | −0.0005 |
| RF | 12 / 12 / 0 | 0.9336 | 0.9348 | +0.0012 |
| ET | 12 / 12 / 0 | 0.9327 | 0.9329 | +0.0001 |
| MLP | 20 / 15 / 5 | 0.9282 | 0.9289 | +0.0007 |

调优提升都在 0.0012 以内，XGBoost 调优后反而略低（TPE 按验证 Macro-F1 选参，初筛参数恰好更好）。在 V3 特征和 FNR = 4% 的工作点上，超参数已经不是瓶颈，性能上限主要由特征决定。四个模型搜索合计约 26 分钟、重训约 6 分钟，都没有触及时间上限。进入多种子复现：RF、XGBoost、ET。

多种子复现（表 7，5 个种子均值 ± 标准差）：

| 指标 | RF | XGBoost | ET |
|---|---:|---:|---:|
| Macro-F1 | **0.9348 ± 0.0001** | 0.9332 ± 0.0002 | 0.9330 ± 0.0004 |
| PR-AUC | **0.9657 ± 0.0005** | 0.9613 ± 0.0003 | 0.9561 ± 0.0007 |
| ROC-AUC | **0.9986** | 0.9984 | 0.9983 |
| FPR | **0.92%** | 0.95% | 0.95% |
| FNR | 4.00% ± 0 | 4.00% ± 0 | 4.00% ± 0 |
| 单条延迟 P95（ms） | 4.95 | **0.71** | 3.70 |
| batch=1024 吞吐（条/秒） | 99,068 | **618,856** | 106,852 |
| 模型体积（MB） | 74.4 | **1.60** | 115.8 |
| 训练用时（s） | 119 | **4** | 94 |

选型（§7.4）：三个模型都满足前两条；Macro-F1 最高的是 RF（0.9348），XGBoost 与其差距 0.0016、ET 差距 0.0018，均在 0.003 以内。按第 4 条选延迟更低、体积更小者，选定 **XGBoost**（单条延迟约为 RF 的 1/7，体积约为 1/46）。

候选模型（`train-seeds-20260927-1458-candidate.json`）：XGBoost，max_depth=11，learning_rate=0.0449，min_child_weight=18.43，gamma=3.63，subsample=0.652，colsample_bytree=0.972，早停于第 269 轮；阈值 0.3082；验证集 Macro-F1 0.9335、FNR 4.00%、FPR 0.94%、PR-AUC 0.961、ROC-AUC 0.9984。

需要注意：
- 每个种子都在验证集上重新选阈值，使 FNR 落在 4% 附近，所以 FNR 标准差为 0，§7.4 第 1 条在该阈值策略下自然满足；种子稳定性应看 FPR 与 Macro-F1 的标准差（均 ≤ 0.0004）。第 9 步 holdout 上使用固定阈值 0.3082，FNR 会有波动。
- 验证集结果满足 §1 中可在验证集上观察的门槛（Macro-F1 ≥ 0.92、FNR ≤ 5%、FPR ≤ 1.5%、PR-AUC ≥ 0.93、ROC-AUC ≥ 0.99），但验收只看第 9 步 holdout，且早停使用了验证集。
- 延迟和吞吐是原框架、不含预处理的 CPU 测量，ONNX 延迟门槛在第 10 步判定。

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

### 8.1 实现（2026-09-27）

- 代码 `src/cyber_training/v2/final_eval.py`，分两个阶段，中间必须提交冻结文件：
  - `v2 final-eval --final-stage freeze`：不读取任何 holdout。校验 T1/T2 候选制品的 SHA-256，在验证分区上用 CPU 推理复现候选记录的验证指标（容差 1e-3），写入 `docs/v2/pre-final-freeze.json`（模型/预处理器哈希、阈值、特征顺序、切分指纹、门槛）。已有冻结文件时拒绝覆盖。
  - `v2 final-eval --unlock-holdout --candidate XGBoost`：要求冻结文件已提交且与 HEAD 一致、manifest/切分审计/制品哈希未变、同一切分的 holdout 在 `runs/holdout-audit.jsonl` 中从未解锁；写追加式解锁记录后，T1 在 D1 原始 holdout 上、T2 在子集官方测试文件上各评估一次，T3 做 2×2 泛化。T3 失败不影响判定，可用 `--final-stage generalization --resume <运行目录>` 补跑。
- `preprocessor.pkl` 只在 SHA-256 与冻结记录一致后才反序列化（本仓库第 8/8b 步生成）。
- T3 模型：计划写"LightGBM，参数使用 §7 调优得到的参数"，但第 8 步没有调优 LightGBM（初筛前 3 名是 XGBoost/RF/ET），因此沿用 T1 初筛参数；判定阈值 0.5。

### 8.2 实际结果（运行 `final-eval-20260927-1800`，第 1 次尝试，冻结提交 `bb25a99`）

冻结：T1 XGBoost（阈值 0.308187）与 T2 LightGBM（类权重）的验证指标在 CPU 上完全复现（最大误差 1.6e-9），CPU 上重选阈值与冻结阈值相同。

T1 验收判定（holdout 300,494 行，攻击 12,108 行，4.03%）：

| 指标 | 门槛 | holdout | 结果 |
|---|---|---:|---|
| Macro-F1 | ≥ 0.92 | 0.9362 | 通过 |
| FNR | ≤ 5% | 4.88% | 通过 |
| FPR | ≤ 1.5% | 0.91% | 通过 |
| PR-AUC | ≥ 0.93 | 0.9747 | 通过 |
| ROC-AUC | ≥ 0.99 | 0.9988 | 通过 |
| 多种子 FNR 标准差（验证集） | ≤ 2% | 0.00% | 通过 |
| 延迟 P95 / 吞吐 / ONNX 误差 | 见 §1 | — | 第 10 步判定 |

**第 9 步判定：通过**（`final-verdict.json` 中 `deliverable = pending_export`，第 10 步门槛通过后才可交付）。

- 其余指标：Accuracy 0.9893、Precision 0.815、Recall 0.951、Weighted-F1 0.990、Specificity 0.991、MCC 0.875；混淆矩阵 TN 285,774 / FP 2,612 / FN 591 / TP 11,517。
- FNR 余量小：holdout FNR 4.88%，离 5% 门槛只有 0.12 个百分点（验证集为 4.00%）。阈值敏感性显示阈值 0.30→0.35 时 FNR 从 4.70% 升到 5.79%，工作点对阈值较敏感；后端必须严格使用冻结阈值，不得自行调整。
- 按类别：Exploits、Generic、Reconnaissance、DoS、Shellcode、Backdoor、Worms 检出率 ≥ 98.5%；漏报集中在 Fuzzers（535 条，检出率 81.1%）和 Analysis（27 条，76.7%），两者合计占全部 591 条漏报的 95%。
- T2（官方测试文件 82,332 行，只作研判参考）：Macro-F1 0.524（验证集 0.600）、Weighted-F1 0.751、Balanced Accuracy 0.637。Normal 召回率只有 0.64（大量 Normal 被判为 Fuzzers 等攻击类），Analysis/Backdoor 的 Precision 不足 0.06。这说明 T2 只能在 T1 判为攻击之后作类别参考，不能单独使用。
- T3（Macro-F1 / ROC-AUC，阈值 0.5）：D1→D1 0.940 / 0.998、D2→D2 0.973 / 0.994；D1→D2 0.510 / 0.681、D2→D1 0.483 / 0.244。跨数据集接近或低于随机（D2→D1 的 AUC 0.244 表示排序方向相反），与 EDA 中 KS 0.56～0.77 的分布差异一致，支撑"模型只对其训练分布负责"。
- holdout 已消耗（解锁记录 4 条：D1 原始 holdout、子集官方测试文件、D2 holdout、T3 读取 D1 公共特征）。之后若回到第 7～8 步，必须按 §4.3 换种子重新切分。

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

### 9.1 实现（2026-09-27）

- 代码 `src/cyber_training/v2/export.py`，命令 `v2 export --candidate XGBoost [--model-version 2026.09.0]`。前置条件 fail-closed：冻结文件已提交且与 HEAD 一致；最新 `final-verdict.json` 通过（`deliverable = pending_export`）且冻结哈希、候选、阈值一致；候选制品 SHA-256 一致；同版本交付目录已存在时拒绝覆盖。
- 预处理与模型打包成同一个 ONNX 图（opset 17 + ai.onnx.ml 3，只用标准算子）：输入 `flow_numeric`（float64，26 个原始数值字段）与 `flow_categorical`（string，`proto`、`service`），图内依次计算派生特征（`rate` 与 6 个比率/差值/速率，公式与精度同 `features.py`）、中位数插补与 2 个缺失指示列、有序编码（词表外 → -1），再接 XGBoost 树集成（`best_iteration + 1 = 270` 棵树）；输出 `attack_probability`（float32）与 `is_attack`（`prob >= 冻结阈值`）。
- 实现偏差：onnxmltools 1.16 的 XGBoost 转换器最高只支持 opset 15，因此树集成先按 15 转换，再嵌入 opset 17 的整图（`TreeEnsembleClassifier` 属于 ai.onnx.ml 域，不受主域版本影响）。
- `preprocessor.pkl` 只在导出时于训练主机上、哈希校验通过后反序列化，用于推出契约并做对照；交付物不含 pickle。`preprocessing.json` 只是图内预处理的可审查说明，后端不得重复实现预处理。
- 一致性样本从验证分区用主种子抽取 1 万条，不读取 holdout（`holdout-audit.jsonl` 仍为 4 条）。

### 9.2 实际结果（运行 `export-20260927-1912`，提交 `c067169`，用时约 5 秒）

| 门槛 | 要求 | 实测 | 结果 |
|---|---|---:|---|
| ONNX 与训练框架概率最大绝对误差 | ≤ 1e-4 | 6.6e-7（平均 3.1e-8） | 通过 |
| 阈值判定一致率 | 100% | 100%（0 条不一致） | 通过 |
| 单条推理延迟 P95（CPU，单线程） | ≤ 5 ms | 0.304 ms（P50 0.239、P99 0.425） | 通过 |
| batch 1024 吞吐（单线程） | ≥ 20k 条/秒 | 100,522 条/秒 | 通过 |

**第 10 步判定：通过**，`deliverable = ready_for_review`。连同第 9 步，§1 的全部 9 项门槛均已通过。

- 图内特征矩阵与 sklearn 预处理输出完全一致（缺失位置相同，最大误差 0）；模型 0.64 MiB。
- 交付目录 `delivery/unsw-binary-2026.09.0/`（Git 忽略）：`model.onnx`、`preprocessing.json`、`model_manifest.json`、`checksums.json`、`evaluation-report.md`、`replay-sample.csv`（1 万条原始输入 + 远端输出，不含地址、端口、时间戳）、三个校验 JSON，以及 `evidence/` 下第 9 步的报告、指标与图。
- 本机初步回放（2026-09-27，macOS arm64，onnxruntime 1.27.0，Python 脚本）：16 个文件哈希全部一致；1 万条概率最大误差 4.8e-7，9,804 条逐位相同，判定 0 条不一致；单线程 P95 0.038 ms、吞吐约 52 万条/秒。注意本机版本不是 manifest 要求的 1.23.2，且这不是后端（Java）加载验证。
- 未完成：§9 第 6 项"后端加载模型回放"。当前后端只有模型登记与审批接口，没有 ONNX 推理运行时；需要在 `main` 分支按 manifest 实现哈希校验、输入契约校验和 ONNX Runtime（Java，版本 1.23.2）推理后，再用 `replay-sample.csv` 回放并把结果写回交付报告。在此之前模型保持 `candidate` 状态，不能激活。

## 10. 执行顺序与时间预估

| 步骤 | 命令 | 预计耗时 | 产物 | 提交 |
|---|---|---|---|---|
| 3 登记 | `v2 register` | 10 分钟 | dataset-manifest | 代码 + 测试 |
| 4 EDA | `v2 eda` | 20 分钟 | eda/ 图表 | 代码 |
| 5 切分 | `v2 split` | 10 分钟 | split-indices、audit | 代码 + 审计 JSON |
| 6 预处理对比 | `v2 preprocess-compare` | 40～60 分钟（108 次） | 对比表 + 热力图 | 代码 + 表格 |
| 7 特征对比 | `v2 feature-compare` | 约 20 分钟（24 次 + 1 个 TTL 诊断） | 特征对比表 | 代码 + 表格 |
| 8 训练调优 | `v2 train --stage screen/tune/seeds` | 初筛约 1 小时 + 调优 ≤ 3 小时 + 复现 ≤ 1 小时（实测合计约 1.3 小时） | 模型对比表 | 代码 + 表格 |
| 8b 多分类 | `v2 train-multiclass` | ≤ 30 分钟（实测约 2.5 分钟） | 多分类报告 | 代码 |
| 9 锁定评估 | `v2 final-eval` | 20 分钟（实测约 1 分钟） | final-verdict | freeze + verdict |
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
