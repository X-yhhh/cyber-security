# 网络威胁检测模型训练仓库

Windows CUDA 仓库为本地网络威胁研判平台提供离线数据审查、训练、评估和候选制品。只处理公开或另行获准的数据及预制回放；不扫描网络、不利用漏洞、不生成/注入攻击流量，不在线自训练。

## 当前状态（2026-10-03）

- UNSW v4 历史 holdout 为 Macro-F1 `0.9456`、FNR `4.94%`、FPR `0.77%`、PR-AUC `0.9741`、ROC-AUC `0.9988`。它只证明原 UNSW 切分内表现，FNR 门槛余量很小；D1→D2 Macro-F1 约 `0.510`、ROC-AUC `0.681`，不能据此声称跨域可用。
- 现有 `2026.10.2` 在 CIC-IDS2017 Windows validation 上 Recall `38.0367%`、Macro-F1 `0.33076`，L2 不通过。PR-AUC `0.99656` 受极高攻击比例影响。
- 新来源 readiness 与 S3 preflight 为 `BLOCKED`；L2 trusted Normal/Attack=`0/0`，独立规则场景=`0/10`。S3 预算矩阵已登记但 `trainingAuthorized=false`；当前不训练、不预测、不解锁 holdout。
- ToN-IoT 需要登录且样本关联未做；IoT-23 授权条款冲突未解决；CICIoT2023 缺独立事件日志证据；AIT/CSE 尚未产生合格的 Normal/Attack 标签。没有新数据集获准训练。

## 当前计划

下一步只做小体量来源与标签/PCAP pilot，再验证是否能产生与传感器一致的 v4 特征。完整阶段、资源上限、数据切分、门禁与停止条件见[模型数据整改与训练路线](docs/model-readiness-roadmap.md)。不要只因 Kaggle 上存在可下载数据，就把它当作可训练数据。

在独立来源、可信 Normal/Attack、分组 holdout 和 readiness 全部通过之前，不开始 S3。即使训练通过，产物仍为 `candidate_only=true`、`production_approved=false`；模型训练不会批准本地应用激活或防火墙动作。

## 文档与证据

- [当前模型数据整改与训练路线](docs/model-readiness-roadmap.md)：唯一当前实施入口。
- [CIC-IDS2017 阶段二审查](docs/phase2/README.md)：历史数据、标签范围和 Windows validation 结果，旧模型明确未达 Recall 门槛。
- [UNSW v2 训练计划](docs/v2/training-plan-v2.md) 与 [`v2/evidence/`](docs/v2/evidence/)：仅作已完成历史实验与审计证据，不是新数据源批准或新权重验收。
- [`route-b/evidence/`](docs/route-b/evidence/) 与 `route-b/pre-final-freeze-v4.json`：v4 契约/制品冻结证据。

原始数据、模型权重、检查点、运行目录、缓存和日志留在受控训练盘或 Git 忽略目录，不提交到 Git。提交只包含审查过的代码、测试、契约及必要的去敏摘要。

## 环境与基本检查

训练仓库：`E:\Workspace\ai\experiments\cyber-security-training`；分支：`training/windows-cuda`。已核实训练环境为 Python 3.12.10、PyTorch 2.7.1+cu126、RTX 3070 Ti Laptop GPU。操作前仍须确认当前主机、分支、上游、HEAD 和工作区状态。

```bash
cd /e/Workspace/ai/experiments/cyber-security-training
source .venv/Scripts/activate
python -m pytest -q
```

在单独阶段获得训练授权之前，不运行会拟合、评分 holdout、导出模型或下载完整数据集的命令。训练输出目录必须唯一；失败产物保留，不覆盖既有 runs 或候选。
