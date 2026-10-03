# P2 数据补齐与重新冻结

日期：2026-10-04。**final 特征的有界 P3 可行性研究数据已就绪**，见[数据裁决](readiness.json)。本次没有训练模型；prefix 模型、早期自动阻断、最终验收和实网误伤率均未获得资格。原 rc.2 提取器、契约及软件验收保持原冻结内容，新数据单独使用[数据冻结清单](freeze-manifest.json)。

## 实际补齐结果

以下均为去重、整 parent 排除和质量审查后的 `IPv4/TCP/inbound/servicePort=80/flow-final-v1` 快照。

| 角色 | 攻击快照 / parent | 正常快照 / parent | 独立攻击活动 |
|---|---:|---:|---|
| train | 2964 / 1701 | 880 / 879 | CICIDS2017 Slowloris |
| validation_selection | 1236 / 741 | 2887 / 2671 | CICIDS2017 Slowhttptest |
| validation_calibration | 14766 / 4927 | 287 / 279 | CSE-CIC-IDS2018 Slowloris |

合计 **23,020 条快照、11,198 个 parent**。校准角色只供 P3 选型完成后的分数校准及预登记策略选择，不可回流到预处理拟合、模型训练或超参选型，也不能同时充当无偏最终成绩。每个角色仅一个攻击活动，不把数千连接或多次快照当作数千独立攻击实验。

新增正常证据由两部分组成：同一公开来源中真实 TCP/80 业务，以及用户明确授权的 win-dev 回环正常任务。训练/选型验证的公开正常快照分别为 **608 / 2616**；2018 校准目标公开正常快照为 **24**。受控任务保留 **272 / 271 / 263** 条正常快照，三个角色都覆盖正常下载、四路并发、慢速下载、合法重试及中断后的 Range 恢复。

## 受控任务与活动隔离

[授权记录](controlled-authorization.json)限定 win-dev、Npcap 回环、服务端 `127.0.0.1:80`、客户端 `127.0.0.2`、30分钟内。六批共1008条连接，业务校验和捕获检查全部通过，实际877.542秒；三种角色各两批，各批之间至少155秒，重新启动提取器并使用独立boot。任务结束后已实际独占绑定80端口验证监听释放。没有修改防火墙、系统防护或进行主机重启。

原始 Npcap `DLT_NULL` 捕获完整保留；研究副本只去除经过核验的4字节AF_INET头，原IP字节、时间、地址和端口不变。六批均在 Windows 用原冻结 `guardextract.exe` 提取；第一批12365帧、190条prefix/final观察在Mac复算后[逐字节一致](cross-platform-parity.json)。这是回环测试证据，不能代表物理网卡、真实网络延迟或生产服务。

公开正常数据按预登记数量选取8个TCP/80服务端，每台使用独立捕获域和引擎，未合并主机上下文。保留原包的双向流量；第三方服务视角只覆盖基准捕获实际看到的流量，不宣称完整服务器观测。训练截至 `2017-07-05T13:10:30Z`，选型验证始于 `13:15:30Z`。同一客户端、同一15分钟背景时段即便访问多个服务器也共享活动组，跨边界标签及其parent整体排除。背景时段组不是可独立证明的业务任务。详情见[背景分组](public-grouping.json)。

对三个角色统一重算原冻结的近重复签名，**54个跨角色签名组涉及347个parent、467条快照，全部排除**；每个保留parent的样本权重总和为1。原train/validation攻击数量略减正是新增全局去重的结果，没有将同一次攻击重新拆成“独立校准”。

## 独立校准原件与缺损处理

[来源及许可清单](sources.json)绑定官方公开ZIP的ETag、成员CRC32、完整大小和SHA-256。只下载2018-02-15目标主机的完整成员和完整修正CSV，没有声称下载/校验整个41.28GB原始归档。CSV共5,410,102行，登记目标的38,980条TCP标签全部与原始包计数及载荷计数匹配；修正CSV数值特征没有进入模型输入。

官方成员本身末条记录少5字节。原件保留；派生件只去掉该记录的16字节头和49字节残余，共65字节，保留424625条完整帧。缺损在21:26:44 UTC，Slowloris活动约15:42结束。下游仍排除末尾150秒边界、EOF和不完整parent；不把派生件描述成完整原始捕获。原始失败提取也保留在忽略目录。

来源引用：Sharafaldin、Lashkari、Ghorbani，*Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization*，ICISSP 2018；[CSE-CIC-IDS2018官方](https://www.unb.ca/cic/datasets/ids-2018.html)、[AWS开放数据登记](https://registry.opendata.aws/cse-cic-ids2018/)。修正标注参考 Liu、Engelen、Lynar、Essam、Joosen，*Error Prevalence in NIDS datasets: A Case Study on CIC-IDS-2017 and CSE-CIC-IDS-2018*，IEEE CNS 2022，254–262页及其[公开说明](https://intrusion-detection.distrinet-research.be/CNS2022/index.html)。

## 475条prefix候选的裁决

[逐条裁决摘要](prefix-adjudication.json)结合发布者修正规则、明确排除的启动/收尾及人工导航连接、完整关联、SYN epoch、序号连续性、请求未结束和实际快照时刻。475条均有**来源限定的起点依据**；其中124个parent在原合格训练分区有669条起点之后、发布者窗口以内的干净prefix。此前快照保留unknown，窗口之后不延伸标签。

证据层级仍为 `publisher_documented`，未伪称两人 `analyst_reviewed`。上述669条仅保存为诊断候选，未混入23,020条final研究集。独立Slowhttptest选型活动和2018校准活动仍需各自的prefix起点复核，因此 `prefixResearchReady=false`。P3本轮只能使用final特征，不能用此结果宣布早期阻断可行。

## 验证与复算

新增数据工具的12项回归验证覆盖整parent近重复排除、跨角色活动/parent拒绝、权重、错误服务、EOF、发布者伪影/Attempted否决、来源尾损、Range对象变更、接收端篡改和归档路径逃逸。Schema及时间不变量验证通过23020条数据观察与55条既有golden，共23075条；旧45文件软件冻结校验继续通过。[本地数据验证](local-dataset-verification.json)重算所有索引身份、签名、分区及parent权重。

仓库根目录下可执行以下只读复核；Python依赖沿用P2，Go引擎无需重做验收：

```sh
python3 -m unittest discover -s scripts/p2/data_readiness -p 'test_*.py' -v
python3 scripts/p2/freeze.py --check
python3 scripts/p2/data_readiness/verify_dataset.py \
  --dataset artifacts/p2/data-readiness-20261004/dataset-v2
python3 scripts/p2/data_readiness/freeze_dataset.py \
  --run artifacts/p2/data-readiness-20261004 \
  --dataset artifacts/p2/data-readiness-20261004/dataset-v2 --check
```

重新生成索引须传入不存在的输出目录，工具不会覆盖历史证据：

```sh
python3 scripts/p2/data_readiness/build_dataset.py \
  --run artifacts/p2/data-readiness-20261004 \
  --controlled artifacts/p2/data-readiness-20261004/p2-benign-development-20261004 \
  --output artifacts/p2/data-readiness-20261004/dataset-rebuilt
```

Windows数据入口为训练仓库 `.cache/host-guard-p2-final-development-20261004`；公开冻结材料位于 `contracts/host-guard-p2-final-development-20261004`。接收端[交付核验](windows-delivery-verification.json)绑定实际传输哈希，并执行：

```powershell
python contracts/host-guard-p2-final-development-20261004/scripts/p2/data_readiness/verify_dataset.py --dataset .cache/host-guard-p2-final-development-20261004
```

## 保留边界与下一步

P3可在明确训练授权后使用此版本开展final可行性研究。必须分别报告公开数据、回环任务和来源/主机差异诊断，检查是否靠来源或平台特征分类；汇总高分不能替代这些检查。攻击目标本身公开正常样本仍少，回环困难良性不足以证明生产误伤率，315个索引活动组也不等于315次独立攻击或独立受控实验。

未暴露final_test仍未分配、未读取，须在P6前补齐并冻结。P1严格跨重启TTL、Mac动作能力继续沿平台路线解决，不阻塞此final离线研究资格。无模型训练/激活、数据库迁移、应用服务切换、Git提交或推送；无需重启，没有删除用户文件。旧软件冻结、原数据清单、失败输出和诊断提取均保留，撤回只需停用本次新数据版本。
