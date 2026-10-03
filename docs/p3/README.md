# P3 模型与策略可行性研究

日期：2026-10-04。**P3研究实现和有界实验已完成，阶段出口仍为 blocked，不能进入P6。** 使用 P2 冻结的 23,020 条 `flow-final-v1` 观察，在 Windows `training/windows-cuda` 分支独立实现训练、选型、校准和 ONNX 候选交付。训练代码位于远端仓库的 `src/cyber_training/host_guard/`，本地应用主干保存计划、审查和去敏结果，不混入训练实现或权重。当前完整结论见[结果摘要](results-summary.json)和[出口裁决](stage-exit.json)。

本轮获准执行 P3 研究。真实防火墙动作、P5 恢复补证和 P6 最终评估不属于本轮实验；模型与策略始终保持候选及 `alert_only`。现有 v4 应用不切换。

## 计划与角色

[实验计划](experiment-plan.json)在训练前登记；[Windows 依赖锁](requirements-windows.lock)绑定实际环境。原件、输入、软件与近重复分区沿用 [P2 数据冻结](../p2/data-readiness/freeze-manifest.json)。

| 角色 | 用途 | 禁止事项 |
|---|---|---|
| train | 拟合插补、对数缩放、类别词表和模型 | 不接收校准或最终测试数据 |
| validation_selection | E1/E2、两项 E3 和优胜者三种子比较 | 不回流拟合，不作为最终成绩 |
| validation_calibration | 选型锁落盘后的 Platt 校准、告警及候选策略选择 | 不改模型或预处理，不冒充无偏评价 |
| final_test | 未分配 | 加载器拒绝该角色，本轮不访问 |

每个 parent 的快照权重总和为1；校准不改变训练权重或缩放器。类别表只拟合训练数据，未知类别编码为0。ID、地址、服务端口、绝对时间、来源、任务名和标签不进入模型张量。

## 实验与评价边界

E1/E2 比较 XGBoost、LightGBM 和 CUDA MLP 的基础流特征与基础加上下文特征。每次拟合最多300秒，总预算4小时；树120轮、MLP80轮，无最终测试早停。E3仅做两项：去掉训练中的受控困难良性作为对照，以及移除覆盖时长/主机全局上下文以诊断来源混淆。删除困难良性的模型不能被选为交付优胜者。优胜者固定保留种子42；43/44只报告方差，不挑最好种子。

E4不实施：当前没有独立合格的 prefix 或序列输入契约。E5用相同数据和零正常机会误伤预算比较仅规则、仅模型、模型加策略；规则包含连接速率、慢速低流量及两者结合。所有评价保持原时间和目标语义，使用最新 parent 快照，按完整主机/传感器/boot/捕获域/peer/keyEpoch/服务隔离证据，并实施新鲜度、TTL去重和动作预算。

**final 观察机会不是攻击起点事件。** 本研究以同目标30秒桶内实际输出的 final 观察作为诊断机会；不把连接年龄当攻击起点，也不把未输出 final 的时间桶凭空补成可识别事件。正式及时阻断覆盖率、攻击开始至动作延迟、OS安装延迟均没有本轮证据。研究观察没有可执行 targetRef、有效时钟偏差或发布授权，候选计数绝不代表真实动作。

每个分区仅一个攻击活动，相关快照不能当独立实验。置信区间保持不可估计；按10%、1%、0.1%攻击机会配比提供的精确率只作分布敏感性诊断。校准与策略选择使用同一独立开发角色，因此校准后表现也不是无偏最终成绩。

## 可复现入口

在 Windows 训练仓库使用既有 `.venv/Scripts/python.exe`，无需改变全局环境：

```sh
.venv/Scripts/python.exe -m pytest tests/test_host_guard_p3.py -q
.venv/Scripts/python.exe -m cyber_training.host_guard.runner smoke \
  --dataset .cache/host-guard-p2-final-development-20261004 \
  --contracts contracts/host-guard-v5-rc2 \
  --public contracts/host-guard-p2-final-development-20261004 \
  --plan docs/host-guard-p3/experiment-plan.json \
  --output runs/host-guard-p3-smoke-<unique-id>
.venv/Scripts/python.exe -m cyber_training.host_guard.runner run \
  --dataset .cache/host-guard-p2-final-development-20261004 \
  --contracts contracts/host-guard-v5-rc2 \
  --public contracts/host-guard-p2-final-development-20261004 \
  --plan docs/host-guard-p3/experiment-plan.json \
  --output runs/host-guard-p3-<unique-id>
.venv/Scripts/python.exe -m cyber_training.host_guard.verify \
  --run runs/host-guard-p3-<unique-id>
```

输出目录独占创建，失败留存，不覆盖旧运行。候选 ONNX 包含图内插补、缩放和校准，接受冻结的43个数值、43个mask和3个类别编码，输出 `[N,1]` 的 `attack_score`。制品使用 JSON/ONNX/无pickle的NPZ保存，全部哈希绑定。manifest的提取器哈希明确绑定冻结Go源码集合，具体定义另附 `extractor-binding.json`；能力引用只指向未授予自动资格的研究提案。

## 实际结果

训练运行 `runs/host-guard-p3-20261004-01`，最终复核交付 `runs/host-guard-p3-20261004-final`。10次完整拟合包含6个基线、2个E3对照及优胜者额外2个种子；全流程首次完整运行约167.18秒，不含后续交付复核。所有完整模型均通过ONNX对拍。

| 模型 / 特征 | 选型ROC-AUC（parent加权） | 选型final机会覆盖 | 正常机会误伤 |
|---|---:|---:|---:|
| XGBoost / 基础 | 0.996315 | 19/28（67.86%） | 0/1342 |
| **LightGBM / 基础，优胜者** | **0.997792** | **19/28（67.86%）** | **0/1342** |
| MLP / 基础 | 0.979970 | 19/28（67.86%） | 0/1342 |
| XGBoost / 上下文 | 0.982760 | 12/28（42.86%） | 0/1342 |
| LightGBM / 上下文 | 0.992920 | 11/28（39.29%） | 0/1342 |
| MLP / 上下文 | 0.989420 | 17/28（60.71%） | 0/1342 |

E3移除受控困难良性后，LightGBM在相同零机会误伤预算下仍为19/28，但parent加权召回从77.10%降至23.71%，log loss从0.04827增至0.06230；对应阈值分别0.95和0.999，不能当作同阈值比较。移除主机全局上下文的试验为11/28，未带来净机会覆盖增益。优胜者42/43/44三个种子均为19/28；ROC-AUC分别0.997792/0.997556/0.997540。同一选型活动上的低方差不证明跨活动泛化。

仅用良性样本区分“受控Windows/公开捕获”的来源诊断ROC-AUC为1.0。这说明采集域高度可分，必须保留来源混淆风险；不等于已经证明攻击分类器一定依赖来源身份。

选型锁落盘后，用独立校准角色拟合正斜率Platt。告警阈值0.975；候选策略阈值0.999，至少3个独立parent，5秒窗口至少3次peer新连接，证据跨度下限0毫秒，TTL30秒。模式为 `alert_only`，能力引用只指向未授予资格的研究提案。

| E5校准开发对照 | final攻击机会覆盖 | 正常机会误伤 | 候选动作 |
|---|---:|---:|---:|
| 仅规则 | 2/84（2.38%） | 0/18 | 1 |
| 仅模型 | 81/84（96.43%） | 0/18 | 79 |
| 模型＋策略 | 81/84（96.43%） | 0/18 | 78 |

模型＋策略相对仅规则的**开发诊断覆盖增益为94.05个百分点**。这是参与校准及策略搜索的数据；其中正常机会仅18个，攻击活动仅1次。点精确率100%以及三种攻击配比下的零经验误伤都不能证明真实99%阻断精确率。选型活动19/28和校准活动81/84须分别保留，不能混合平均掩盖前者未达80%。

## 验证、修复与交付

- Windows的29项P3回归测试、Python编译检查及依赖检查全部通过。覆盖角色门禁、预处理隔离、parent去重、目标/epoch隔离、证据过期、TTL与预算、附带误伤、非法日期、制品篡改及路径逃逸；原P2软件和数据冻结清单仍通过。
- [Windows独立校验](windows-verification.json)与[Mac独立校验](mac-verification.json)均通过69份制品哈希和23,020条全量对拍；最大分数差 `3.5390e-7`，0.975/0.999两阈值均0翻转。运行时分别为ONNX Runtime 1.23.2/AMD64和1.27.0/arm64。
- CUDA显卡为RTX3070Ti Laptop、8GiB；XGBoost/MLP在CUDA拟合，LightGBM在CPU拟合。PyTorch峰值已分配内存约20.24MiB，不等于完整进程/驱动显存峰值。Windows CPU单条ONNX暖运行200次，P95约0.0602毫秒；不是防火墙生效延迟。
- 冒烟首轮暴露转换器缺少默认ONNX opset，修复后[三个冒烟](smoke-report.json)通过。相对登记的3次冒烟，多做了1次相同参数的小批修复重跑；完整实验仍为10次，未增加超参搜索或完整重训，登记计划保持原件。
- 交付最后一步发现虚拟环境缺少 `jsonschema`；安装锁定的4.26.0及其依赖，`pip check`通过。格式检查显式拒绝非法月份/日期，避免可选依赖缺失时静默跳过。
- 补充了TTL内误伤同目标正常连接的计数回归。复算未改变本数据上的工作点、统计或选型；原权重SHA-256未变。原失败目录保留，修正后的清单和报告在新目录生成；没有复训或重新拟合校准器。[训练代码哈希](training-code-manifest.json)与[复核代码哈希](evaluation-code-manifest.json)分别记录。
- [候选manifest](candidate-manifest.json)、[候选策略](candidate-policy.json)与[能力研究提案](candidate-capability.json)均通过Schema。模型SHA-256为 `fcc1f3910575441be86f96d15f55b8317fe7b5c1ceef60d583af4cf5d0c3767f`；最终测试报告引用保持null。

本地应用主干的P1/P2基线已提交推送为 `efcbd1260a42cc4f3d8e06504a5b86734dc40680`。P3报告在`main`、训练实现和冻结公共依赖在`training/windows-cuda`分别交付；远端已有phase2工作不在本次提交范围。`delivery-verification.json`中的提交/推送字段是验证生成时的历史快照，实际交付以对应分支Git记录为准。原始输入、权重、NPZ和完整实验报告均在忽略目录，公开材料只包含去敏指标与哈希。

## 出口与下一步

P3实现、实验、候选导出和复核已完成；**P3出口未通过**。原因是选型覆盖不足、缺少合格的早期起点/prefix证据、每角色只有一个攻击活动、正常机会数不足，final_test也未分配。84个final攻击机会和18个正常机会未满足至少100/3000的样本要求，且不是正式起点事件。无法计算可靠的活动聚类置信区间或及时阻断覆盖率。

下一步返回P2补独立活动的可观察早期证据、独立prefix选型/校准及困难正常机会，冻结新版本后再做有界验证；P6前另行准备未暴露最终测试。P4/P5可按原依赖独立实施，P1严格恢复缺口仍保留。本轮没有实网攻击流量、真实防火墙动作、服务重启、模型激活或数据库迁移。
