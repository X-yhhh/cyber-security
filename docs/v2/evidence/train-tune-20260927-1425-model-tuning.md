# 第 8 步调优：Optuna TPE 搜索结果

每个模型固定试验次数与时间上限（先到者为准），TPE 种子 20260927，MedianPruner（前 5 次不剪枝）。森林在 50% 训练行上搜索；所有模型的最优参数都在完整训练分区上用主种子重训后评估。

| 模型 | 试验 / 完成 / 剪枝 / 失败 | 初筛 Macro-F1 | 调优后 Macro-F1 | 提升 | 调优后 FNR | 调优后 FPR | 最优参数 |
|---|---|---:|---:|---:|---:|---:|---|
| XGBoost | 30 / 12 / 18 / 0 | 0.9340 | 0.9335 | -0.0005 | 4.00% | 0.94% | `{"n_estimators": 2000, "learning_rate": 0.0449, "max_depth": 11, "subsample": 0.6524, "colsample_bytree": 0.9723, "min_child_weight": 18.4348, "gamma": 3.6302}` |
| RF | 12 / 12 / 0 / 0 | 0.9336 | 0.9348 | +0.0012 | 4.00% | 0.92% | `{"n_estimators": 200, "max_depth": 32, "min_samples_leaf": 7, "max_features": "sqrt"}` |
| ET | 12 / 12 / 0 / 0 | 0.9327 | 0.9329 | +0.0001 | 4.00% | 0.95% | `{"n_estimators": 150, "max_depth": 40, "min_samples_leaf": 5, "max_features": 0.3}` |
| MLP | 20 / 15 / 5 / 0 | 0.9282 | 0.9289 | +0.0007 | 4.00% | 1.03% | `{"width": 512, "layers": 2, "dropout": 0.1759, "lr": 0.003, "weight_decay": 0.0001, "batch_size": 8192, "max_epochs": 30, "patience": 5}` |

进入多种子复现：RF, XGBoost, ET。
