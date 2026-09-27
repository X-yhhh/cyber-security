# 预处理对比试验（验证集，阈值 0.5，3 个种子均值）

数据：D1 UNSW-NB15 原始数据 V0 视图（42 个特征）；每个种子从训练分区分层抽样拟合，完整验证分区评估；holdout 未读取。 Precision/Recall/F1 以攻击为正类；标准差、FPR、FNR、Macro-F1 与耗时见 preprocessing-summary.csv。

表 1  LR 模型在不同预处理方案下的性能对比
Table 1  Performance comparison of LR under different preprocessing schemes

| 指标 | P0 | P1 | P2 | P3 | P4 | P5 | P6 | P7 | P8 | P9 | P10 | P11 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Precision | 0.594 | 0.595 | 0.596 | 0.815 | 0.776 | 0.723 | 0.830 | **0.847** | 0.791 | 0.732 | 0.733 | 0.733 |
| Recall | 0.184 | 0.251 | 0.264 | 0.897 | 0.925 | 0.710 | 0.881 | 0.857 | 0.797 | **0.999** | 0.997 | 0.998 |
| F1-score | 0.266 | 0.353 | 0.366 | 0.854 | 0.844 | 0.716 | **0.855** | 0.852 | 0.794 | 0.845 | 0.845 | 0.845 |
| Accuracy | 0.965 | 0.965 | 0.966 | 0.988 | 0.987 | 0.979 | 0.989 | **0.989** | 0.984 | 0.986 | 0.986 | 0.986 |
| AUC | 0.922 | 0.924 | 0.921 | 0.998 | 0.997 | 0.971 | 0.997 | **0.998** | 0.996 | 0.997 | 0.997 | 0.998 |

表 2  RF 模型在不同预处理方案下的性能对比
Table 2  Performance comparison of RF under different preprocessing schemes

| 指标 | P0 | P1 | P2 | P3 | P4 | P5 | P6 | P7 | P8 | P9 | P10 | P11 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Precision | **0.849** | 0.847 | 0.848 | 0.848 | 0.848 | 0.847 | 0.848 | 0.848 | 0.824 | 0.764 | 0.737 | 0.779 |
| Recall | 0.890 | 0.886 | 0.886 | 0.886 | 0.886 | 0.887 | 0.886 | 0.886 | 0.887 | 0.967 | **0.997** | 0.966 |
| F1-score | **0.869** | 0.866 | 0.867 | 0.866 | 0.867 | 0.866 | 0.866 | 0.866 | 0.854 | 0.853 | 0.847 | 0.862 |
| Accuracy | **0.990** | 0.990 | 0.990 | 0.990 | 0.990 | 0.990 | 0.990 | 0.990 | 0.989 | 0.987 | 0.986 | 0.988 |
| AUC | **0.998** | 0.998 | 0.998 | 0.998 | 0.998 | 0.998 | 0.998 | 0.998 | 0.998 | 0.998 | 0.998 | 0.998 |

表 3  MLP 模型在不同预处理方案下的性能对比
Table 3  Performance comparison of MLP under different preprocessing schemes

| 指标 | P0 | P1 | P2 | P3 | P4 | P5 | P6 | P7 | P8 | P9 | P10 | P11 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Precision | 0.603 | 0.600 | 0.550 | 0.824 | 0.825 | 0.757 | 0.831 | **0.846** | 0.825 | 0.734 | 0.733 | 0.734 |
| Recall | 0.001 | 0.002 | 0.001 | 0.868 | 0.855 | 0.889 | 0.884 | 0.867 | 0.873 | **1.000** | 0.999 | 0.999 |
| F1-score | 0.003 | 0.004 | 0.003 | 0.845 | 0.840 | 0.816 | **0.857** | 0.856 | 0.848 | 0.846 | 0.846 | 0.846 |
| Accuracy | 0.962 | 0.962 | 0.962 | 0.988 | 0.988 | 0.985 | 0.989 | **0.989** | 0.988 | 0.986 | 0.986 | 0.986 |
| AUC | 0.577 | 0.616 | 0.605 | 0.997 | 0.997 | 0.995 | 0.998 | **0.998** | 0.998 | 0.998 | 0.997 | 0.998 |

## 方案说明

- P0：不做预处理（插补=zero，编码=ordinal，变换=none，缩放=none，降维=none，不平衡=none）
- P1：中位数插补（插补=median，编码=ordinal，变换=none，缩放=none，降维=none，不平衡=none）
- P2：One-hot（插补=median，编码=onehot，变换=none，缩放=none，降维=none，不平衡=none）
- P3：Standard（插补=median，编码=onehot，变换=none，缩放=standard，降维=none，不平衡=none）
- P4：MinMax（插补=median，编码=onehot，变换=none，缩放=minmax，降维=none，不平衡=none）
- P5：Robust（插补=median，编码=onehot，变换=none，缩放=robust，降维=none，不平衡=none）
- P6：log1p+Standard（插补=median，编码=onehot，变换=log1p，缩放=standard，降维=none，不平衡=none）
- P7：Quantile（插补=median，编码=onehot，变换=quantile，缩放=none，降维=none，不平衡=none）
- P8：P6+PCA（插补=median，编码=onehot，变换=log1p，缩放=standard，降维=pca，不平衡=none）
- P9：P6+类权重（插补=median，编码=onehot，变换=log1p，缩放=standard，降维=none，不平衡=class_weight）
- P10：P6+欠采样（插补=median，编码=onehot，变换=log1p，缩放=standard，降维=none，不平衡=undersample）
- P11：P6+SMOTE（插补=median，编码=onehot，变换=log1p，缩放=standard，降维=none，不平衡=smote）

## 结论

- LR：StandardScaler（P3）相对未缩放（P2）的 Macro-F1 变化 +0.249。
- LR：log1p+Standard（P6）与 Quantile（P7）的 Macro-F1 分别为 0.925 / 0.923。
- LR：PCA 降维（P8）相对 P6 的 Macro-F1 变化 -0.031。
- RF：StandardScaler（P3）相对未缩放（P2）的 Macro-F1 变化 -0.000。
- RF：log1p+Standard（P6）与 Quantile（P7）的 Macro-F1 分别为 0.931 / 0.930。
- RF：PCA 降维（P8）相对 P6 的 Macro-F1 变化 -0.007。
- MLP：StandardScaler（P3）相对未缩放（P2）的 Macro-F1 变化 +0.428。
- MLP：log1p+Standard（P6）与 Quantile（P7）的 Macro-F1 分别为 0.925 / 0.925。
- MLP：PCA 降维（P8）相对 P6 的 Macro-F1 变化 -0.005。
- 按 3 个模型 Macro-F1 均值，选定方案为 P7（均值最高的是 P6，差距阈值 0.002）。
