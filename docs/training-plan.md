# UNSW-NB15 Training Plan

## 1. Objective and Boundary

Build an offline network intrusion detection demonstration that can be integrated into the local frontend/backend system. The Windows host is for CUDA training and model maintenance only. The local host is for application logic and model inference integration. No experiment performs scanning, exploitation, attack traffic generation, or external traffic injection.

## 2. Dataset

### Primary dataset

Use the verified Kaggle dataset `mrwellsdavid/unsw-nb15` as the primary source. It is the same UNSW-NB15 direction as the initial dataset, exceeds 100 MB, and provides four raw CSV files with approximately 2.54 million records and 49 raw fields. The source also provides official training and testing CSV files.

The raw CSV files are headerless flow records. The feature dictionary `NUSW-NB15_features.csv` defines the 49-field layout. The raw files are used for the large-scale binary experiment. Attack-category values exist for attack rows but contain whitespace and inconsistent `Backdoor`/`Backdoors` names, so they require normalization and label-consistency checks before any optional raw-data multiclass experiment.

### Baseline subset

Use the two 45-column subset files as an independent predefined-split baseline. In this Kaggle copy the filenames are reversed relative to their contents and the commonly used UNSW-NB15 split: `UNSW_NB15_testing-set.csv` has 175,341 rows (training partition), while `UNSW_NB15_training-set.csv` has 82,332 rows (held-out test partition). Their first records and label counts were cross-checked against the smaller Parquet copy. Preserve the source filenames and record this mapping in the data manifest; never assign split roles from filenames alone. Both files contain binary `label` and ten `attack_cat` values including `Normal`. Do not combine these rows with the primary raw-data split.

### Data registration

Before training, create a manifest containing source URL, retrieval date, license statement, file size, SHA-256, row count, column count, missing-value count, duplicate count, and label distribution. The raw dataset is not committed to Git.

## 3. EDA, Data Preparation, and Feature Engineering

The code path is explicitly staged as EDA -> preprocessing comparison -> feature engineering -> model comparison. EDA writes row/column counts, class balance, missingness, categorical cardinality, numeric summaries, and a bounded overview plot before fitting. EDA is descriptive only and never fits an imputer, encoder, scaler, threshold, or model.

1. Parse the four raw CSV files using the feature dictionary and preserve the original field order.
2. Read the feature dictionary as Windows-1252, normalize field names and category whitespace, and handle empty or `-` markers according to column type. Record every conversion and verify `label=0` maps to normal while `label=1` maps to attack.
3. Keep the full source schema in the data layer, but exclude identifiers and targets from model input.
4. For binary detection, derive `Normal` versus `Attack` from the original label semantics.
5. For multiclass detection, use only the official subset's `attack_cat` target.
6. Remove exact duplicates from the primary training pool and report the count; never deduplicate silently.
7. Check overlap between train, validation, and test feature-target rows. Record any overlap and block a run that uses test rows for fitting.
8. Use a fixed-seed, deduplicated, stratified 70/15/15 row split for the primary raw experiment. This is not entity-isolated and must not be represented as such. Separately report an unordered endpoint-pair isolation stress split, including group/row shares, class coverage, group overlap, and whether each partition is evaluable. Keep the predefined subset as an independent future experiment; never merge it into raw training.
9. Before full training, confirm audited hashes, the 49-column raw schema, 42-field V0 input contract, CUDA availability, and the host resource budget in the Windows README.

The implemented engineered view extends V0 with non-identity traffic features: log1p byte/packet values, bytes per packet, packet/byte balance, load ratio, TTL delta, latency sum, and jitter sum. It excludes labels, IDs, raw IPs, ports, and timestamps.

## 4. Feature Views

All encoders, imputers, scalers, and PCA objects are fitted on training data only.

- **V0 official flow baseline**: the 42 predictive fields in the 45-column labeled subset, excluding `id`, `label`, and `attack_cat`. Map equivalent raw column names and units explicitly before reusing this view on the full dataset.
- **V1 endpoint view (raw data only)**: V0 plus source/destination ports and endpoint-derived categorical features. Protocol, service, and state are already in V0; high-cardinality raw IPs and timestamps are not used as direct identity keys.
- **V2 engineered traffic view**: V1 plus packet/byte ratios, rate transforms, latency differences, TTL differences, count ratios, and numerically stable `log1p` transforms for heavy-tailed values.
- **PCA comparison**: compare no reduction, PCA retaining 95% training variance, and 20 components (or all available components when fewer than 20). Fit PCA on the encoded and scaled training features only; it is a comparison path, not a prerequisite for tree models.

## 5. Preprocessing Comparison

Compare three train-fitted strategies using a bounded train/validation probe: median imputation + StandardScaler, median imputation + RobustScaler, and median imputation without numeric scaling (all with one-hot categorical encoding). Select the strategy by validation F1, record the full table, and never use the locked test for this choice. The selected transformer is then refit on the complete training partition only.

## 6. Models and Baselines

The bounded first run compares ten concrete model instances from nine sklearn model families plus a CUDA MLP: Linear SVM, Gaussian NB, Logistic Regression (C=0.1), Passive-Aggressive, AdaBoost, Decision Tree, Random Forest, Extra Trees, SGD log-loss, and a PyTorch MLP that must train on CUDA. This satisfies the requirement of more than five models without counting repeated configurations of one algorithm. CPU baselines run sequentially under a 14-physical-core cap; tree ensembles use 50 estimators and depth 24. Use one fixed seed for the primary comparison. Rank candidates only on validation, then run the best three using three seeds and report mean and standard deviation on validation. Choose thresholds only on validation. Evaluate each of the ten candidates on the locked test set exactly once; extra-seed runs never use test data. The workflow writes a model-by-metric comparison table and heatmap with Precision, Recall, F1, Accuracy, and AUC, matching the supplied reference structure, and exports candidate artifacts with a train-fitted preprocessing manifest. PCA/feature-selection variants, XGBoost, LightGBM, CatBoost, and the official-subset multiclass baseline are follow-up experiments, not first-run gates.

The endpoint stress diagnostic preserves whole unordered endpoint-pair groups and is capped at 100,000 rows per partition for the measured 16 GiB host. It is not used for primary model selection.

Raw binary target is Label (0=normal, 1=attack); the 42 model inputs exclude IPs, ports, timestamps, row IDs, and attack category. Rate is derived from packet counts and duration, with zero duration represented as missing. The audited raw view encodes to 214 columns after train-fitted imputation, scaling, and one-hot encoding.

## 6. Evaluation Metrics

### Binary detection

Report Accuracy, Precision, Recall, Macro-F1, Weighted-F1, ROC-AUC, PR-AUC, Specificity, FPR, FNR, MCC, training duration, model size, and single-row/batch inference latency.

### Multiclass detection

Report Macro/Micro/Weighted Precision, Recall, and F1, Balanced Accuracy, per-class Recall, confusion matrix, and one-vs-rest AUC. Minority-class results must be visible; accuracy alone is not an acceptance criterion.

## 7. Experiment Records and Paper Figures

Every run records dataset fingerprint, split fingerprint, feature view, model name, hyperparameters, seed, software/runtime versions, GPU information, training duration, model size, threshold policy, and all metrics. Use machine-readable JSON/CSV as the source of truth.

Generate:

- model comparison tables;
- Precision, Recall, F1, Accuracy, and AUC comparison charts;
- ROC and PR curves;
- binary and multiclass confusion matrices;
- PCA cumulative explained-variance chart;
- training-size versus performance chart;
- per-class metric table and error analysis.

Save paper-ready PNG/SVG figures and Markdown/CSV tables under generated report directories. Large generated files, checkpoints, and logs remain ignored by Git.

## 8. Delivery Contract

Each candidate model delivered to the local application includes:

- a versioned model artifact;
- `model_manifest.json`;
- exact feature order and preprocessing configuration;
- label mapping and threshold policy;
- final metrics and evaluation split fingerprint;
- runtime requirements;
- SHA-256 checksum.

The local backend must reject an artifact when its checksum, feature contract, label mapping, or manifest version is invalid. The local application consumes the artifact for offline inference only.

## 9. Acceptance Tests

- The two working directories are independent Git repositories connected to the same GitHub repository, with `main` and `training/windows-cuda` pointing to the intended commits.
- The Windows data manifest proves the raw source exceeds 100 MB, has the expected 49-field schema, and records rows, labels, missing values, duplicates, and hashes.
- No target, identifier, test-derived encoder, scaler, PCA object, or threshold leaks into model fitting.
- Windows verifies the project-local Python environment, CUDA visibility, PyTorch GPU availability, and required gradient-boosting backends without modifying the global Python 3.14 installation.
- At least ten first-pass model instances complete binary evaluation with the common metrics schema, and the official subset completes multiclass evaluation in a separate baseline.
- The local integration accepts valid single and batch inputs and returns the documented detection result shape.
- All demonstrations use offline data or synthetic inputs and perform no external network activity.


## 第三、四阶段独立验收（2026-09-24）

阶段编号按准备、预处理、十模型基线、三种子稳定性、制品交付、发布审查区分；旧 `phase1-*` 目录名代表首轮实验，不代表只完成准备阶段。

当前 `train` 仍是全流程入口。已完成的运行不应为补报告而重训。新增独立命令仅读取既有运行记录，不拟合、不重新推理锁定测试集：

```text
.venv\Scripts\python.exe -m cyber_training.stage_review --run runs/phase3-20260924-223305 --previous-run runs/phase1-20260924-163000 --output runs/phase3-20260924-223305-review
```

该命令要求 10 条验证、10 条测试及 3 模型 × 3 种子的完整记录，独立按混淆矩阵核对指标，用验证集二分类 F1 核对前三名，检查制品哈希后输出稳定性均值、样本标准差（ddof=1）及阶段审查 JSON/CSV。不完整或冲突记录失败关闭；不会用测试排名替代验证排名，不会覆盖源文件。ROC-AUC/PR-AUC 仅校验范围和 manifest 一致性，没有原始分数时不声称重算通过。

三种子只改变模型随机性，数据切分保持固定，不代表跨实体/跨切分稳定性。重复使用相同测试指纹的历史必须保留，不得因新建目录而标为全新未见测试。

MLP 既有 CUDA 推理计时缺失；新运行修复批次计时。可用独立 `cyber_training.validation_latency --run <运行目录> --output <新JSON>` 从保存的预处理参数复现验证样本，测量 CPUExecutionProvider 的 ONNX 单行/批次延迟；不重拟合预处理、不读测试分数、不把 CPU 测量替代历史 GPU 耗时。模型循环取出后从注册表删除引用，防止已完成的森林被整个迭代字典保留。

候选导出状态单独验收；`candidate_export=true` 只表示旧工作流调用了导出，不表示所有制品成功。第五阶段 ONNX 修复和第六阶段发布仍单独处理，所有结果保持 candidate-only。

## 第五阶段独立候选交付（2026-09-25）

使用 `python -m cyber_training.stage5 --source-run runs/phase3-20260924-223305 --output runs/stage5-20260925 --previous-run runs/phase1-20260924-163000`，不要启动全流程 `train`。

入口先复核第三、四阶段记录和原制品 SHA-256，再校验 raw 数据、去重和固定切分指纹。复用已有五个 ONNX；仅为缺失权重的 LinearSVC、AdaBoost、DecisionTree、RandomForest、ExtraTrees 按原种子与配置在训练分区重建候选。预处理参数从已有 JSON 分块恢复，保留原 float64 训练输入；不拟合预处理、不调阈值、不重新选择模型、不推理或评价测试分区。原始数据仍需读取以验证数据和切分指纹。

重建制品必须通过验证样本上的 native/ONNX 连续分数与冻结阈值决策 parity。原有制品保留历史 native parity 并新增运行时 smoke；由于历史 native 权重未保存，不声称重新执行其 native parity。重建模型的 `locked_test_metrics` 为 null，原测试结果保存在 `historical_locked_test_metrics` 且标注未验证与新权重的绑定。验证集复现差异单独报告，不通过历史指标冒充新权重已获锁定测试验收。

输出含历史模型对比 CSV/热力图（图中 F1 是 Macro-F1）、EDA/预处理证据、十个候选 ONNX、预处理 JSON、模型 manifest、parity、SHA-256 清单、阶段状态及交付报告。新目录不覆盖原实验；所有候选保持 `candidate_only=true` 和 `production_approved=false`。转换器的树属性兼容修复仅作用于本次容器，未修改全局环境依赖。异常失败关闭，未完成目录不能当作完整交付。

端点压力测试、重复测试暴露与泄漏审查、重建权重的评估绑定、macOS ONNX 一致性、影子验证和人工审批仍是第六阶段门槛；第五阶段完成不授权激活或发布模型。
