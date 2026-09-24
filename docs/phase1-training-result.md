# 第一阶段首轮训练结果

## 运行信息

- 运行目录：`runs/phase1-20260924-163000`
- 数据集：`mrwellsdavid/unsw-nb15`
- 数据指纹：`35526937350f82d7d1c36aca825c2cb761492bd6c950ee218e9b78a7da21a372`
- 原始数据：2,540,047 行，49 列
- V0 去重后：2,059,415 行
- 训练设备：CUDA `cuda:0`，NVIDIA GeForce RTX 3070 Ti Laptop GPU
- CPU 线程上限：14

## 验收结果

- 数据验证通过，文件哈希、字段数量、标签分布和重复行记录已写入运行 manifest。
- 22 项项目测试通过，包含 CUDA MLP smoke test。
- EDA、预处理比较、特征工程和固定种子数据切分均完成。
- 首轮完成 10 个模型实例；每个模型锁定测试集评估一次。
- 验证集 F1 选出 `random_forest`、`decision_tree`、`extra_trees`，并完成三种子验证。
- 候选制品均包含 ONNX（适用时）、预处理 manifest、模型 manifest 和 SHA-256；全部保持 `candidate_only=true`，未激活到本地应用。

## 锁定测试摘要

| 模型 | Macro-F1 | Accuracy | ROC-AUC | PR-AUC | 设备 |
| --- | ---: | ---: | ---: | ---: | --- |
| Random Forest | 0.9485 | 0.9922 | 0.9988 | 0.9722 | CPU |
| Decision Tree | 0.9450 | 0.9917 | 0.9805 | 0.9243 | CPU |
| Extra Trees | 0.9440 | 0.9915 | 0.9985 | 0.9638 | CPU |
| CUDA MLP | 0.9420 | 0.9913 | 0.9987 | 0.9681 | CUDA |

## 边界与风险

- 这是离线 UNSW-NB15 流特征分类结果，不代表原始包检测、终端行为识别或通用 DDoS 防护能力。
- Logistic Regression 和 SGD 出现收敛警告，但运行完成并写出结果；后续阶段需结合训练稳定性和误报成本复核。
- `runs/`、模型权重和大型生成物按仓库规则保留在远端训练主机，不提交到 Git。
