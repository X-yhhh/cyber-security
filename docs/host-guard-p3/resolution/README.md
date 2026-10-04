# P1—P3 后续修复的训练分支交付

日期：2026-10-04。训练基线 `d6a3afd8`，本轮训练代码提交 `de335fabed61a0dfc581e32dd6ca3e685bc1fd71`。

本轮交付完整策略诊断、冻结收尾、稳定目标累计预算及独立标签时间线评估；Windows `pytest tests/test_host_guard_p3.py -q` 的42项回归通过。研究预算不能作为生产执行器。原phase2未提交文件保持不变。

[去敏结果摘要](results-summary.json)和[软件清单](software-manifest.json)是跨分支实施证据生成时的快照；其中 `gitCommitted=false / gitPushed=false` 记录的是Git交付之前的状态，实际提交及推送以分支Git记录和远端引用为准。软件清单的 applicationFiles/binaryFiles 属于应用分支，不要求在训练仓库存在；trainingFiles 绑定本次实际训练代码。先前[后续审查](../continuation/README.md)与评估哈希保留为历史版本，未用新代码改写旧分数。

应用分支的[完整实施报告](https://github.com/X-yhhh/cyber-security/blob/main/docs/p1-p3-resolution/README.md)记录数据、原生输入、平台恢复及良性实测。本轮新增拟合0次，未激活模型，候选保持 `candidateOnly=true / alert_only`。

尚未通过：2017慢读取因果起点、独立攻击与同源正常活动、正式近重复分区及P6封存、新prefix模型和完整策略的逐场景/独立评估。Windows恢复期限、两端Go live及正式签名也未通过；P1/P3继续blocked。八批长期良性任务及采集已经通过，完整旧候选包的两端差异已经关闭。
