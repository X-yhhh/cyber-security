# 网络流量威胁检测模型训练仓库（Windows CUDA）

本仓库是"网络威胁研判与受控响应平台"的离线模型训练工作区，只做防御性的流量特征分类训练：不扫描网络、不利用漏洞、不生成或注入攻击流量，也不做在线自训练。

当前状态（2026-09-28）：v2 基线第 3～10 步全部完成，T1 二分类模型 `unsw-binary-2026.09.0` 在锁定 holdout 上通过全部 9 项验收门槛，交付包状态为 `ready_for_review`。2026-09-27 本机 Java 后端（ONNX Runtime 1.23.2）已完成 1 万条样本回放，最大概率误差 9.5e-7、判定 0 条不一致。回放通过不等于发布审批，模型仍为 `candidate`，须经独立审批并在本机显式激活后才能使用。

## 仓库分工

| 工作区 | 分支 | 职责 |
| --- | --- | --- |
| macOS 本机项目 | `main` | 前端、后端、数据库、推理接口、业务流程、模型输入输出契约、本地集成 |
| Windows CUDA 训练项目（本仓库） | `training/windows-cuda` | 数据准备、离线训练、实验记录、评估、模型导出与交付清单 |

- 训练实现与实验产物只放在 `training/windows-cuda`；只有经审查的接口契约和结果摘要可以合入 `main`。
- 不强推、不改写共享历史，不与 `E:\Workspace\ai\experiments` 下的其他训练项目混用。

## 数据集

| 代号 | 来源 | 规模 | 用途 |
| --- | --- | --- | --- |
| D1 | Kaggle `mrwellsdavid/unsw-nb15` | 原始 CSV 2,540,047 行 × 49 列；另有 45 列预定义子集 | T1 二分类（主任务）、T2 多分类 |
| D2 | Kaggle `dhoogla/nftoniotv2` | 13,135,881 行 × 43 列（NetFlow v2） | T3 跨数据集泛化评估，只写报告 |

- 数据只存放在训练主机 `data/` 下，不提交到 Git。D1 按原作者学术使用条款引用，D2 许可为 CC-BY-NC-SA-4.0。
- D1 预定义子集的文件名是反的：`testing-set.csv`（175,341 行）是训练部分，`training-set.csv`（82,332 行）是测试部分，已按内容核实并在登记清单中记录。
- HIKARI（Zenodo）已排除，只保留在被忽略的 `data/excluded/`，禁止读取。根目录 `dataset-metadata.json` 描述的是早期弃用的 `dhoogla/unswnb15` 候选，仅作来源追溯。
- 2026-09-26 之前的实验全部归档到被忽略的 `archive/runs-legacy-20260926/`，旧 holdout 视为已暴露，不作为验收依据。
- 入模特征不使用 `srcip`、`dstip`、`stime`、`ltime`、`id`、`label`、`attack_cat`（D2 的 `Label`、`Attack` 同理）。

## v2 流程与主要结论

完整设计、每步实际结果与风险见 [`docs/v2/training-plan-v2.md`](docs/v2/training-plan-v2.md)；小体积证据摘录（不含权重、原始数据、IP 和主机路径）及其 SHA-256 见 [`docs/v2/evidence/`](docs/v2/evidence/README.md)。

| 步骤 | 运行目录 | 结论 |
| --- | --- | --- |
| 3 数据登记 | `register-20260926-2019` | 两个数据集哈希、行列数与标签计数核对一致 |
| 4 EDA | `eda-20260926-2231` | 长尾特征明显；8 对 \|ρ\|>0.95 冗余；TTL 类特征互信息最高；D1/D2 公共特征 KS 0.56～0.77 |
| 5 切分 | `split-20260926-2119` | 去重 + 端点分组 + 固定种子（20260930）：train 1,405,222 / validation 310,681 / holdout 300,494 行，攻击率约 3.9% |
| 6 预处理对比 | `preprocess-20260926-2250` | 108 次运行；线性/MLP 选 P7（中位数插补 + 缺失指示 + One-hot + QuantileTransformer），树模型用 P1（中位数插补 + Ordinal 编码）；PCA 使性能下降 |
| 7 特征对比 | `feature-20260927-1249` | 选 V3（32 个特征）；TTL 重要性高但可被其他特征替代 |
| 8 训练调优 | `train-screen/tune/seeds-20260927-*` | 9 个模型初筛 → Optuna 调优 → 5 种子复现；RF、XGBoost、ET 差距 ≤0.002，按延迟和体积选定 **XGBoost** |
| 8b 多分类 | `train-multiclass-20260927-1632` | T2 选 LightGBM（类权重），只作研判参考 |
| 9 锁定评估 | `final-eval-20260927-1800` | holdout 只解锁一次，T1 判定通过；冻结文件 `docs/v2/pre-final-freeze.json` 于提交 `bb25a99` |
| 10 导出交付 | `export-20260927-1912` | 预处理与模型打包为单个 ONNX 图，一致性与性能门槛通过 |

### T1 验收结果（锁定 holdout，300,494 行，攻击 12,108 行）

| 指标 | 门槛 | 实测 | 结果 |
| --- | --- | ---: | --- |
| Macro-F1 | ≥ 0.92 | 0.9362 | 通过 |
| FNR（漏报率） | ≤ 5% | 4.88% | 通过 |
| FPR（误报率） | ≤ 1.5% | 0.91% | 通过 |
| PR-AUC | ≥ 0.93 | 0.9747 | 通过 |
| ROC-AUC | ≥ 0.99 | 0.9988 | 通过 |
| 多种子 FNR 标准差（验证集） | ≤ 2% | 0.00% | 通过 |
| ONNX 与训练框架概率最大误差 | ≤ 1e-4 | 6.6e-7，判定 100% 一致 | 通过 |
| 单条延迟 P95（CPU 单线程） | ≤ 5 ms | 0.304 ms | 通过 |
| batch 1024 吞吐（单线程） | ≥ 20k 条/秒 | 100,522 条/秒 | 通过 |

- 混淆矩阵：TN 285,774 / FP 2,612 / FN 591 / TP 11,517；Precision 0.815，Recall 0.951，MCC 0.875。
- FNR 余量只有 0.12 个百分点，阈值 0.30→0.35 时 FNR 从 4.70% 升到 5.79%。后端必须严格使用冻结阈值 0.308187，不得自行调整。
- 漏报集中在 Fuzzers（检出率 81.1%）和 Analysis（76.7%），合计占全部漏报的 95%；其余攻击类别检出率 ≥ 98.5%。
- T2 多分类（官方测试文件）：Macro-F1 0.524，Normal 召回率仅 0.64，只能在 T1 判为攻击后作类别参考，不驱动任何处置。
- T3 泛化（Macro-F1 / ROC-AUC）：D1→D1 0.940 / 0.998，D2→D2 0.973 / 0.994，D1→D2 0.510 / 0.681，D2→D1 0.483 / 0.244。跨数据集接近或低于随机，模型只对其训练分布负责。
- holdout 已消耗（`runs/holdout-audit.jsonl` 共 4 条解锁记录）。若重新回到第 7～8 步，必须换种子重新切分。

## 模型交付包

交付目录 `delivery/unsw-binary-2026.09.0/`（Git 忽略，通过 scp 传到本机）：

- `model.onnx`：opset 17 + ai.onnx.ml 3，输入 `flow_numeric`（float64，26 个原始数值字段）与 `flow_categorical`（string：`proto`、`service`），图内完成派生特征、插补、缺失指示和编码；输出 `attack_probability` 与 `is_attack`。模型约 0.64 MiB。
- `model_manifest.json`：模型版本、数据集与切分指纹、特征顺序和单位、标签映射 `{0: Normal, 1: Attack}`、阈值策略、holdout 指标、运行时要求（onnxruntime 1.23.2）及全部文件 SHA-256。
- `preprocessing.json`：图内预处理的可审查说明，后端不得重复实现预处理。
- `checksums.json`、`evaluation-report.md`、`export-*.json` 校验结果、`replay-sample.csv`（1 万条验证分区样本及远端输出，用于本机回放）和 `evidence/`。
- 交付物不含 pickle；权重、检查点和原始数据不提交到 Git。

使用限本机回放：Java 后端（ONNX Runtime Java 1.23.2，CPU 单线程）回放 `replay-sample.csv` 共 10,000 条，最大概率绝对误差 9.5367e-7、平均 4.83e-9，标签不一致 0，逐位相同 9,757 条；逐行结果 `backend-replay-results.csv` 已写入交付目录并追加到 `evaluation-report.md`。证据见 [`docs/v2/evidence/backend-java-replay-20260927.md`](docs/v2/evidence/backend-java-replay-20260927.md)。剩余步骤是独立发布审批和本机显式激活，均不在训练仓库内完成。v` 回放并把结果写回交付报告。已做过 Python 版本机回放（onnxruntime 1.27.0，判定 0 条不一致），但它不能替代后端验证。

## 环境

- 硬件：i9-12900H（14 核 / 20 线程）、约 16 GB 内存、RTX 3070 Ti Laptop 8 GB、E 盘空闲约 150 GB。
- 软件：Python 3.12.10，依赖锁定在 `requirements.lock`（torch 2.7.1+cu126、xgboost 3.4.1、lightgbm 4.7.0、scikit-learn 1.7.2、onnxruntime 1.23.2、onnxmltools 1.16.0、optuna 5.0.0 等）。
- 种子：主种子 `20260927`，多种子复现用 `20260927～20260931`。

## 常用命令

远端默认 shell 为 Git Bash：

```bash
cd /e/Workspace/ai/experiments/cyber-security-training
source .venv/Scripts/activate
python -m pytest -q
python -m cyber_training.v2 <步骤>   # register / eda / split / preprocess-compare / feature-compare / train / train-multiclass / final-eval / export
scripts/launch.sh <步骤> [参数...]    # 长任务以计划任务方式后台运行，日志在 runs/task-<步骤>.log
```

- `final-eval` 分 `--final-stage freeze` 与 `--unlock-holdout` 两阶段，冻结文件必须先提交；同一切分的 holdout 只能解锁一次。
- `export` 要求冻结文件与 HEAD 一致、`final-verdict.json` 通过且哈希不变，同版本交付目录已存在时拒绝覆盖。
- 每次运行输出到 `runs/<步骤>-<YYYYMMDD-HHMM>/`，包含 `run-config.json`、指标与 `checksums.json`。
- 旧版 `python -m cyber_training.cli` 与 `docs/training-plan.md`、`docs/phase1-training-result.md` 等为 v1 历史记录，保留但不再作为验收依据。

## 安全边界

所有实验只使用公开数据集或离线文件，只输出检测与防护导向的结果。模型再训练只在本机离线进行，必须经过数据/标签审查、锁定测试、误报评估、影子验证和人工审批后才能发布；禁止伪标签驱动的在线自训练或自动换权重。
