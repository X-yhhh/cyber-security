# 第三阶段收敛与第四阶段完成报告

核实与验收：2026-09-24，北京时间。训练运行 `runs/phase3-20260924-223305` 于 23:17:27 完成。23:22 核实无训练进程。源代码 HEAD 为 `84be3a6859d51b8af69fe70fb8dec984667aa212`，此次修改尚未提交或推送。

## 完成范围

现有任务已完整完成第三、四阶段，因此复用本轮真实产物，没有追加全量训练，没有重评锁定测试集。测试中的微型 CUDA smoke 与 pytest 固定小样本拟合不属于基准重训。

第三阶段：10 个模型的 validation 与 locked_test 各 10 条；逐条按混淆矩阵重算 Accuracy、Precision、Recall、Macro-F1、Weighted-F1、Specificity、FPR、FNR、MCC，与原 CSV/候选 manifest 一致。ROC-AUC/PR-AUC 仅核对范围和 manifest 一致性，因未保存原始分数，没有声称独立重算。

第四阶段：按原验证集二分类 F1 复核排名，前三名为 Random Forest、Decision Tree、Extra Trees；每个模型种子为 20260923、20260924、20260925，总计 9 条验证结果。完整种子网格、标签总量和指标一致性已通过，不需要再跑第四阶段。生成均值和样本标准差（ddof=1）。所有种子固定同一训练/验证切分，仅改变模型随机性，不代表跨切分、跨实体稳健性。

| 模型 | 二分类 F1 均值 ± 标准差 | Macro-F1 均值 ± 标准差 | FPR 均值 | FNR 均值 |
|---|---:|---:|---:|---:|
| random_forest | 0.899865 ± 0.001563 | 0.947893 ± 0.000797 | 0.4359% | 9.3907% |
| decision_tree | 0.895623 ± 0.000406 | 0.945682 ± 0.000210 | 0.4586% | 9.7108% |
| extra_trees | 0.885457 ± 0.003498 | 0.940360 ± 0.001816 | 0.5595% | 9.5663% |

随机森林是后续制品修复与影子验证的首选候选，决策树可作为更稳定的对照。没有以测试分数重新挑选模型、种子或阈值，没有设立事后稳定性通过阈值。以上仅说明实验完成，不代表误报/漏报已满足实网要求。

## 第三阶段计时补充

历史 MLP 的 GPU 推理延迟仍无法从旧记录恢复，未填写伪造值。已用现有 ONNX 和预处理 JSON 的 SHA-256，复现固定验证分区前 8192 行，使用保存参数而非重新拟合，测量 CPUExecutionProvider 的延迟：

- 单条中位数 0.0290 ms，P95 0.0309 ms，100 次测量。
- 8192 行批次中位数 11.4429 ms，P95 15.5375 ms，20 次测量。

每组 10 次预热；CPU intra-op 线程 14，inter-op 1；不含预处理、模型加载、网络及应用开销。这是补充的 ONNX CPU 计时，不替代历史 CUDA 计时或端到端服务压测。旧 CPU `per_row_ms` 也是批次均摊值，不能解释为独立单条时延。

## 实现与验证

- `src/cyber_training/stage_review.py`：独立验收命令，只读取现有 JSON/CSV/制品。完整性、种子、排名、指标、候选边界和哈希不匹配时失败关闭。输出到新目录，原实验文件不覆盖。
- `src/cyber_training/validation_latency.py`：验证样本 ONNX 延迟补测；数据文件校验、数据/验证切分指纹匹配；恢复保存的预处理参数，不执行 fit、不评价测试样本。类别缺失值超出历史预处理支持范围时明确拒绝。
- `src/cyber_training/workflow.py`：逐个从模型注册表移除对象，消除持有已完成森林的引用；为将来的 MLP 运行补充批次计时。
- `tests/test_stage_review.py`：完整/缺失/重复种子、指标篡改、排名错误、测试集选模拒绝、预处理恢复一致性和路径越界测试。
- `docs/training-plan.md`：补充阶段语义、验收命令与评价边界；本报告保存在 `docs/stage34-completion-20260924.md`。

修改前的被修改文件备份位于 `runs/stage34-review-prechange-20260924/`。本次未修改 raw 数据、环境依赖、Git 历史和原指标；保留 macOS main 的原有未跟踪文件。

最终验证：pytest **31 passed in 6.98s**（含 CUDA smoke）；compileall、git diff --check 均通过。实际验收命令和验证样本计时命令执行成功；所有记录在验收清单中的原始指标、manifest 和已有制品 SHA-256 均未变化。23:35 最终进程检查无训练任务。验证证据另存 final-verification.json。

## 遗留边界

1. 第五阶段仍阻断 5 个导出：LinearSVC 的 zipmap 选项不兼容，AdaBoost/DecisionTree/RandomForest/ExtraTrees 的 TreeEnsembleClassifier 转换失败。其余 5 个 ONNX 与预处理制品的实际哈希匹配，manifest 记录 128 行 parity 通过；仅 MLP 在本轮另做验证样本推理。
2. `candidate_export=true` 只代表调用导出，不代表全部成功。第三阶段分类实验完成不等于候选可交付。
3. 两次运行使用相同测试指纹，保留重复测试暴露记录；本轮无新增测试评估。主实验仍为随机分层切分，有 95/81/26 个跨分区特征向量交集，不能描述为实体隔离。
4. 端点隔离仅有切分审计，实际压力测试仍未完成；没有进行 macOS 推理联调、影子验证或实网验收。
5. 完整训练仍为单一 train 入口；独立 review 入口解决结果收敛，不声称已实现训练断点续跑。
6. 日志仍有预处理比较 Logistic Regression 的 max_iter=300 及 SGD 收敛警告；当前结果如实保留，不为消除警告而触发测试集调参。
7. 全部制品保持 `candidate_only=true`，未获生产批准、未激活。第五阶段导出修复未纳入此次第三、四阶段收敛，未借此重训。

## 结果文件

源运行 `runs/phase3-20260924-223305/` 保持原样；验收目录为 `runs/phase3-20260924-223305-review/`：

- `stage34-review.json`：审查状态、源文件 SHA-256、历史测试暴露、交付缺项。
- `stage3-locked-results.csv`：已有十模型结果的规范化副本。
- `stage4-seed-metrics.csv`：9 条验证结果。
- `stage4-stability-summary.csv`：均值和样本标准差。
- `mlp-validation-onnx-latency.json`：验证分区上的 CPU ONNX 补充计时。

这些文件是本轮真实核实和测量结果，不是计划值。
