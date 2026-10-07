# 当前 P3 多分类路线（2026-10-07）

P3-A 已在应用仓库完成冻结。当前训练分支新增 `multiclass_train`、`multiclass_audit`、`verify_multiclass`；以下 prefix/UNSW 段落仅为历史，不作为当前入口。

本轮 `p3-multiclass-20261006-v1` 的 13-fit 主矩阵位于 `.cache/p3b-20261007/run-main-v3`，已结束。研究候选为 `main-lightgbm-seed42`；validation 四类等权检出率 98.5961%、macro-F1 0.993117、内部/网页 FPR 均为 0。修正后的真实来源/最新证据预览、规则对比、分布与消融在 `.cache/p3b-20261007/audit-mac-v2`；所有类别仍为 `alert_only`，`candidateOnly=true`，未接入应用或真实动作。

**P3-B 已于 2026-10-07 收口，P3-C 未开始。** 负责人书面把本轮累计拟合上限调整为 33（smoke、中断、重跑全部计入），`multiclass_reproduce fit`（`scripts/run_step.cmd B5R`）复现 `main-lightgbm-seed42` 1 次，train/validation ONNX 输出与 v3 原候选逐位一致；原生 LightGBM 文本模型、train/validation 全量框架概率及 int64 输入 ONNX 在 `.cache/p3b-20261007/run-reproduce-v1`，框架/ONNX 对拍 Windows 与 Mac 均通过（最大分差 3.47e-6，翻转 0）。台账 `.cache/p3b-20261007/fit-ledger.jsonl` 已计 33/33，再预留会被拒绝。test/L3 未读取，新增代码未提交或推送。

代码回归：`scripts/run_step.cmd B1`（14 项）。B0/B2/B3/B4/B5 只输出审计说明并拒绝；零拟合验证入口为 `python -m cyber_training.host_guard.multiclass_audit` 和 `python -m cyber_training.host_guard.verify_multiclass`，输出目录必须新建。

# 已终止的 P3 prefix 路线（历史 2026-10-05）

P1/P2 已收口。P3-A 已接入严格 plannedRole、公共组固定角色、共同早期轨迹、原始活动起点评价、连续目标预算与认证健康链验证。实际入口仍为 `cyber_training.host_guard.prefix_runner check/run`，运行计划已原位更新为 `docs/host-guard-p3/experiment-plan.json`。

零拟合诊断在保留全部机会的条件下证明当前公共来源受 120 秒目标预算限制而不可达 80% 覆盖；P3-A 结构出口 blocked，P3-B—E 暂不启动，candidateOnly/alert_only，不读取 P6。健康验证器的单元通过不能替代真实跨活动连续采集旁证；新轨迹与持续采集属于尚未准入的 P3-B。

当前证据在 `.cache/p3-implementation-20261005-v3/`，原语料和历史契约包字节保持不变。`check` 现在校验真实代码、数据、完整计划及阶段诊断；不满足准入返回退出码 2。以下内容为历史记录，不覆盖当前 prefix 计划。

# 网络威胁检测模型训练仓库

2026-10-05 P3来源组修复完成：[离线修复与重新冻结](docs/host-guard-p3/source-repair-20261005.md)及[双平台验证记录](docs/host-guard-p3/source-repair-verification.json)。6次受控活动已分开来源标识，但整parent近重复仍合并为2个防泄漏组；完整语料50,606条，独立开发攻击/良性组3/9，校准攻击样本0。Windows26项相关检查通过，原生受控重建与Mac语义一致，实际训练模块对同一冻结集的结果一致；完整性通过，训练准入仍为false，新增拟合0次。下文保留历史阶段记录。

2026-10-04 解决方案更新：[当前修复与交付记录](docs/host-guard-p3/resolution/README.md)登记42项回归、累计预算修复及最新数据证据。下文保留原阶段快照。

2026-10-04 后续实施更新：[P3-A诊断/回归与P3-B/C有界审查记录](docs/host-guard-p3/continuation/README.md)已交付。完整策略选型仅4/28，prefix及独立数据准入未通过，P3仍blocked；未重训、未获得处置授权。下文首轮记录保留。

Windows CUDA 仓库为本地网络威胁研判平台提供离线数据审查、训练、评估和候选制品。只处理公开或另行获准的数据及预制回放；不扫描网络、不利用漏洞、不生成/注入攻击流量，不在线自训练。

## 当前状态（2026-10-04，host-guard v5）

已获授权完成[P3模型与策略研究](docs/host-guard-p3/README.md)：10次完整拟合、LightGBM基础特征候选、独立角色校准及Windows/Mac的23020条ONNX对拍。研究实现完成，出口仍blocked；选型覆盖19/28，校准开发对照模型＋策略81/84、规则2/84，正常机会误伤均0/18。缺少合格早期证据、足量独立活动/正常机会及final_test，不能进入P6或自动执行。候选保持candidateOnly/alert_only，未接入应用。

新实现入口为`src/cyber_training/host_guard/`及上述P3报告。P2数据与契约分别保存在`contracts/host-guard-p2-final-development-20261004`、`contracts/host-guard-v5-rc2`，原件与制品在忽略目录。下列UNSW/v4整改记录仅作历史证据，不能约束或替代已独立冻结的v5研究。

## 历史整改状态（2026-10-03）

阶段 0、1 已完成，当前[阶段 2 的 IoT-23 有界试点](docs/remediation-phase2/README.md)已收口，但该子集未通过阶段 3 数据准入，返回来源初筛。数据 readiness/S3 仍为 `BLOCKED`，可训练标签为 0，训练、应用激活和防火墙动作未获准。

- UNSW v4 历史 holdout 为 Macro-F1 `0.9456`、FNR `4.94%`、FPR `0.77%`、PR-AUC `0.9741`、ROC-AUC `0.9988`。它只证明原 UNSW 切分内表现，FNR 门槛余量很小；D1→D2 Macro-F1 约 `0.510`、ROC-AUC `0.681`，不能据此声称跨域可用。
- 现有 `2026.10.2` 在 CIC-IDS2017 Windows validation 上 Recall `38.0367%`、Macro-F1 `0.33076`，L2 不通过。PR-AUC `0.99656` 受极高攻击比例影响。
- 新来源 readiness 与 S3 preflight 为 `BLOCKED`；L2 trusted Normal/Attack=`0/0`，独立规则场景=`0/10`。S3 预算矩阵已登记但 `trainingAuthorized=false`；当前不训练、不预测、不解锁 holdout。
- IoT-23 4 个已许可官方成员共 80.5 MiB。Somfy 两个单主机窗口仅 77/7 条，ready Normal=0；Muhstik 有 2,964 条完整关联且 v4 合格的攻击切段，全为 initiator，当前模型范围内候选为 0。Windows 完成了来源哈希绑定的 Mac Go 提取结果审计；原生 EXE 被应用控制以 `4551` 拒绝，平台 parity 未验证。独立活动、第二人复核和分区仍未接受；ToN-IoT 两个入口仍为 403。

## 历史整改计划（v4）

阶段 2 的当前子集审查结束，下一步返回阶段 1，寻找单主机良性流足够、逐流/独立活动可追溯且符合目标模型范围的来源。100 流窗口、v4 和 responder 范围不放宽；本次没有扩大下载、冻结分区或训练。完整阶段、资源上限、门禁与停止条件见[模型数据整改与训练路线](docs/model-readiness-roadmap.md)。

在独立来源、可信 Normal/Attack、分组 holdout 和 readiness 全部通过之前，不开始 S3。即使训练通过，产物仍为 `candidate_only=true`、`production_approved=false`；模型训练不会批准本地应用激活或防火墙动作。

## 文档与证据

- [阶段 0 状态冻结与验收记录](docs/phase0/README.md)：阶段验收与当前阻断边界；`docs/phase0/evidence/` 保存冻结摘要、原始 S3 矩阵、最新 readiness/preflight 及 Monday 审查摘要。

- [阶段 1 候选初筛与有界 pilot](docs/phase1/README.md)：来源/许可清单、Windows 审计工具、24 项测试和当前 pilot v2；原始成员留在 Git 忽略目录。
- [整改阶段 2 完整流与特征试点](docs/remediation-phase2/README.md)：同源提取、逐流决定/近重复分组、51 项门禁测试、Go/Java 对拍和 Windows 原生阻断边界。
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
