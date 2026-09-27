# 特征工程对比（验证集，阈值 0.5，3 个种子均值）

数据：D1 UNSW-NB15 原始数据；预处理 P1（中位数插补 + 缺失指示 + Ordinal 编码）；每个种子从训练分区分层抽样拟合，完整验证分区评估；holdout 未读取。Precision/Recall/F1 以攻击为正类；标准差、PR-AUC、FPR、FNR、Macro-F1 与耗时见 feature-summary.csv，视图构造见 feature-views.json。

表 4  RF 模型在不同特征视图下的性能对比
Table 4  Performance comparison of RF under different feature views

| 指标 | V0 | V1 | V2 | V3 |
|---|---:|---:|---:|---:|
| Precision | 0.847 | 0.848 | 0.850 | **0.850** |
| Recall | 0.886 | 0.895 | **0.897** | 0.895 |
| F1-score | 0.866 | 0.871 | **0.873** | 0.872 |
| Accuracy | 0.990 | 0.990 | **0.990** | 0.990 |
| AUC | 0.998 | 0.998 | **0.998** | **0.998** |
| 特征数 | 42 | 43 | 50 | 32 |

表 5  LightGBM 模型在不同特征视图下的性能对比
Table 5  Performance comparison of LightGBM under different feature views

| 指标 | V0 | V1 | V2 | V3 |
|---|---:|---:|---:|---:|
| Precision | 0.846 | 0.850 | **0.852** | 0.847 |
| Recall | 0.889 | **0.892** | 0.892 | 0.890 |
| F1-score | 0.867 | 0.871 | **0.871** | 0.868 |
| Accuracy | 0.990 | 0.990 | **0.990** | 0.990 |
| AUC | 0.998 | 0.998 | **0.998** | 0.998 |
| 特征数 | 42 | 43 | 50 | 32 |

## 选择

- Macro-F1 均值（RF 与 LightGBM）：V2 0.9335，V1 0.9328，V3 0.9324，V0 0.9306。
- 第一名 V2，V3 与第一名差距 0.0010（阈值 0.002），选定 V* = **V3**。

## TTL 依赖诊断（V4 = V3 去掉 sttl、dttl、ct_state_ttl，不参与选型）

- LightGBM：去掉 TTL 特征后 Macro-F1 0.931 → 0.934（+0.002），PR-AUC 0.961 → 0.962，FNR 10.99% → 11.54%，FPR 0.63% → 0.56%。
