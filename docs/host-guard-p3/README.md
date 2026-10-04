# host-guard v5 P3 离线模型与策略研究

2026-10-04 解决方案更新：[当前修复与交付记录](resolution/README.md)登记42项回归、累计预算修复及最新数据证据。下文保留原阶段快照。

2026-10-04 后续实施更新：[P3-A诊断/回归与P3-B/C有界审查记录](continuation/README.md)已交付。完整策略选型仅4/28，prefix及独立数据准入未通过，P3仍blocked；未重训、未获得处置授权。下文首轮记录保留。

2026-10-04：P3实现及有界实验完成，阶段出口blocked，不能进入P6或自动执行。依据已同步的P2 rc.2冻结契约和23020条final研究观察；不复用UNSW/v4成绩，不使用历史整改路线的阻塞记录代替本次数据准入。

结果见[汇总](results-summary.json)、[出口裁决](stage-exit.json)、[实验计划](experiment-plan.json)及[环境依赖锁](requirements-windows.lock)。应用仓库main的P1/P2基线为efcbd12。P3训练实现与冻结公共依赖在training/windows-cuda分支交付，应用报告在main交付；原phase2未提交工作保留，不在本次提交范围。delivery-verification.json中的提交/推送字段是验证生成时的历史快照，实际交付以分支Git记录为准。

## 实现与边界

- [数据与角色门禁](../../src/cyber_training/host_guard/data.py)：验证P2公开/输入哈希、整parent权重和按组隔离；预处理仅拟合train，选型锁之后才允许校准，不接受final_test角色。
- [训练入口](../../src/cyber_training/host_guard/runner.py)、[模型](../../src/cyber_training/host_guard/models.py)：XGBoost/CUDA、LightGBM/CPU、MLP/CUDA；E1/E2、最多两个E3对照及优胜者3种子。
- [候选策略回放](../../src/cyber_training/host_guard/evaluation.py)：完整目标绑定、最新parent证据、时效、TTL及预算，统计TTL内正常连接的附带误伤。没有真实动作或网络注入。
- [ONNX导出](../../src/cyber_training/host_guard/export.py)和[独立校验](../../src/cyber_training/host_guard/verify.py)：43数值/43mask/3类别代码，图内插补、缩放及Platt校准；attack_score为[N,1]，不加载pickle。
- [收尾复核](../../src/cyber_training/host_guard/finalize.py)：从已冻结权重恢复交付，复算指标到新目录；禁止静默换选型、策略或重训。

## 结果与限制

10次完整拟合，LightGBM基础特征优胜。选型final机会覆盖19/28（67.86%）、正常机会误伤0/1342；三个种子均为19/28。增加上下文或移除主机全局上下文未改善。良性来源分类ROC-AUC=1.0，存在采集域混淆风险。

独立校准开发角色：模型＋策略81/84（96.43%）、仅模型81/84、规则2/84，正常机会误伤均0/18。校准/策略选择使用该角色，结果不是无偏最终成绩。每角色只有一个攻击活动；缺少合格起点/prefix、足量正常机会与未暴露final_test，不能证明及时阻断、真实99%精确率或跨活动泛化。

[候选manifest](candidate-manifest.json)保持candidateOnly；[策略](candidate-policy.json)保持alert_only，alert=0.975、auto候选阈值=0.999、distinctFlows=3、peerStarts5s=3、span=0、TTL=30s，能力仅为研究提案。Windows与Mac在23020条上最大ONNX误差3.539e-7，两阈值0翻转，69份制品哈希通过。Windows暖CPU推理P95约0.0602ms，仅代表ONNX，非OS阻断延迟。

## 复现

在仓库根目录使用既有Windows虚拟环境；输出必须为未存在的新目录：

```sh
.venv/Scripts/python.exe -m pytest tests/test_host_guard_p3.py -q
.venv/Scripts/python.exe -m cyber_training.host_guard.runner smoke --dataset .cache/host-guard-p2-final-development-20261004 --contracts contracts/host-guard-v5-rc2 --public contracts/host-guard-p2-final-development-20261004 --plan docs/host-guard-p3/experiment-plan.json --output runs/host-guard-p3-smoke-<unique-id>
.venv/Scripts/python.exe -m cyber_training.host_guard.runner run --dataset .cache/host-guard-p2-final-development-20261004 --contracts contracts/host-guard-v5-rc2 --public contracts/host-guard-p2-final-development-20261004 --plan docs/host-guard-p3/experiment-plan.json --output runs/host-guard-p3-<unique-id>
.venv/Scripts/python.exe -m cyber_training.host_guard.verify --run runs/host-guard-p3-20261004-final
```

环境缺失时只在项目虚拟环境安装requirements-windows.lock，不覆盖全局Python。首个导出冒烟失败因转换器缺少默认opset，修复多做一次相同小批拟合；完整实验没有增加。交付收尾补装jsonschema 4.26.0及依赖，显式校验日期格式；pip check通过。原失败运行和训练源码传输包保留。首次完整运行约167.18秒；后续复核不重训。

成功制品：runs/host-guard-p3-20261004-final；原始实验：runs/host-guard-p3-20261004-01；通过的冒烟：runs/host-guard-p3-smoke-20261004-02。以上均被Git忽略；完整JSON报告、模型和NPZ不提交。本轮未重启、未变更系统防护/业务服务、未激活模型。下一步返回P2补独立早期证据和正常机会，P4/P5可独立继续。
