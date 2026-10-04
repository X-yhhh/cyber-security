# P3后续优化实施

2026-10-04 解决方案更新：[当前修复与交付记录](../resolution/README.md)登记42项回归、累计预算修复及最新数据证据。下文保留原阶段快照。

2026-10-04：P3-A诊断、冻结回归和统一裁决已通过；P3-B/C审查完成但数据准入blocked。P3-D重训及P3-E/P6移交未启动，候选保持candidateOnly/alert_only。代码优化完成不等于模型交付或处置授权通过。

`src/cyber_training/host_guard/evaluation.py`新增逐观察/机会拒绝诊断，完整资产预算跨sensor/boot共享；`regression.py`先全域回放再按角色、来源、活动、场景汇总。`runner.py`和`finalize.py`共用阶段裁决；收尾只使用已冻结参数，不重做阈值、校准或策略选择。原权重及历史JSON保留。

| 工作点 | train | validation_selection | validation_calibration |
|---|---:|---:|---:|
| 原始分数 | 40/40 | 19/28 | 81/84 |
| 校准后单parent | 40/40 | 17/28 | 81/84 |
| 冻结完整策略 | 39/40 | 4/28 | 81/84 |

三个角色的正常误伤分别0/195、0/1342、0/18，错误候选动作均0。这些都是已暴露开发成绩；选型4/28不能被校准高分抵消。详细[回归摘要](regression-summary.json)、[裁决](stage-exit.json)、[代码哈希](evaluation-code-manifest.json)和[验证](verification.json)随文归档。

本机应用仓库的P3-B各审查28条，2017/2018分别23/24条观察到完整关闭。Slowhttptest模式未资格化，2018文档数字X-a与原件字面值b不符，prefix仍Unknown。P3-C现有3个攻击活动、6批正常任务全部暴露；正常连接最长2.39秒，没有长期困难负样本。两个新来源元数据审查未取得预算内可用完整原件，停止新增来源与重训。详见[起点摘要](onset-review-summary.json)、[活动核验](activity-availability.json)、[来源可得性](sources-availability.json)。

```sh
.venv/Scripts/python.exe -m pytest tests/test_host_guard_p3.py -q
.venv/Scripts/python.exe -m cyber_training.host_guard.regression \
  --source runs/host-guard-p3-20261004-final --out runs/p3-a-audit-<unique-id> \
  --dataset .cache/host-guard-p2-final-development-20261004 \
  --contracts contracts/host-guard-v5-rc2 \
  --public contracts/host-guard-p2-final-development-20261004
.venv/Scripts/python.exe -m cyber_training.host_guard.verify \
  --run runs/host-guard-p3-continuation-20261004-finalize-v2
```

最终收尾目录为`runs/host-guard-p3-continuation-20261004-finalize-v2`。Windows38项测试、编译、86份制品哈希和23020条ONNX对拍通过，最大误差3.539e-7、阈值0翻转。Mac独立验证相同权重/原夹具通过；未复制整份新元数据包。首次收尾验证因旧重复搜索逻辑中止，失败目录保留；新收尾0拟合/0搜索成功。

0次新训练、0字节新增原始下载，没有新采集、部署、真实动作或服务重启。原phase2未提交文件保留；源文件备份在`.cache/p3-continuation-20261004-before/`。未提交或推送。P3数据/覆盖缺口阻止P6；Windows严格TTL及Mac动作能力缺口另阻止对应P7自动资格，不能降低门槛或只修改授权配置解决。
