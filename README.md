# 网络威胁检测模型训练仓库

Windows CUDA 仓库为本地网络威胁研判平台提供离线数据审查、训练、评估和候选制品。只处理公开或另行获准的数据及预制回放；不扫描网络、不利用漏洞、不生成/注入攻击流量，不在线自训练。

## 当前状态（2026-10-03）

阶段 0 状态冻结及阶段 1 小体量来源初筛已完成，记录见[阶段 0 状态冻结与验收](docs/phase0/README.md)和[阶段 1 候选初筛](docs/phase1/README.md)。IoT-23 官方有界子集进入阶段 2 试点；数据 readiness 与 S3 仍为 `BLOCKED`，可训练标签仍为 0，训练、应用激活和防火墙动作未获准。

- UNSW v4 历史 holdout 为 Macro-F1 `0.9456`、FNR `4.94%`、FPR `0.77%`、PR-AUC `0.9741`、ROC-AUC `0.9988`。它只证明原 UNSW 切分内表现，FNR 门槛余量很小；D1→D2 Macro-F1 约 `0.510`、ROC-AUC `0.681`，不能据此声称跨域可用。
- 现有 `2026.10.2` 在 CIC-IDS2017 Windows validation 上 Recall `38.0367%`、Macro-F1 `0.33076`，L2 不通过。PR-AUC `0.99656` 受极高攻击比例影响。
- 新来源 readiness 与 S3 preflight 为 `BLOCKED`；L2 trusted Normal/Attack=`0/0`，独立规则场景=`0/10`。S3 预算矩阵已登记但 `trainingAuthorized=false`；当前不训练、不预测、不解锁 holdout。
- IoT-23 的发布方 FAQ 与官方 DOI/CC BY 4.0 已补齐许可依据；4 个官方成员共 80.5 MiB，取得 29 条良性、151,567 条攻击候选的精确起始包证据，4,637 条保持 Unknown。完整连接/活动日志、v4 特征和第二人复核尚未完成；ToN-IoT 两个入口仍为 403，其他来源未获训练准入。

## 当前计划

下一步按阶段 2 核验已登记 IoT-23 子集的完整连接/标签/活动证据及传感器同源 v4 特征；不扩大到全量归档，也不启动训练。完整阶段、资源上限、数据切分、门禁与停止条件见[模型数据整改与训练路线](docs/model-readiness-roadmap.md)。不要只因 Kaggle 上存在可下载数据，就把它当作可训练数据。

在独立来源、可信 Normal/Attack、分组 holdout 和 readiness 全部通过之前，不开始 S3。即使训练通过，产物仍为 `candidate_only=true`、`production_approved=false`；模型训练不会批准本地应用激活或防火墙动作。

## 文档与证据

- [阶段 0 状态冻结与验收记录](docs/phase0/README.md)：阶段验收与当前阻断边界；`docs/phase0/evidence/` 保存冻结摘要、原始 S3 矩阵、最新 readiness/preflight 及 Monday 审查摘要。

- [阶段 1 候选初筛与有界 pilot](docs/phase1/README.md)：来源/许可清单、Windows 审计工具、24 项测试和当前 pilot v2；原始成员留在 Git 忽略目录。
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
