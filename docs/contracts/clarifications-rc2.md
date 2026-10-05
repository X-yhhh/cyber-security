# host-guard v5 rc.2 契约澄清

状态：**已裁决的澄清，尚未并入冻结正文**。对象为 `host-guard/5.0.0-rc.2`。

[检测与处置契约](../检测与处置契约.md)及本目录 6 个 Schema、profile、5 个示例共 45 个文件已由 [P2 冻结清单](../p2/freeze-manifest.json)按 SHA-256 绑定；本文不改写其中任何字节，也不改变任何字段、公式或状态机。本文只补 rc.2 正文未写明的**判定基准、检查次序和口径归属**，供实现（P4/P5）与后续版本使用。

下一次契约因语义变更递增版本时，本文各项应并入正文，并由新一轮冻结清单重新绑定；在此之前，实现与验收按"正文 + 本文"同时满足执行。本文不是发布资格、能力等级或真实动作授权。

## C1 `clockSkewMs` 的基准与计算方

正文第 5 节规定 `abs(clockSkewMs)>1000` 或 null 时禁止新自动执行，但未定义基准。补定如下：

- **基准是控制面的 `serverTime`。** 传感器在心跳、配置获取等已认证交互的成功响应中取得 `serverTime`，`clockSkewMs = 本机时钟 − serverTime`，单位毫秒，可为负。
- **计算方是传感器本人**，控制面不代算、不推断；控制面只在自己那侧记录传感器上报值并做趋势观察。
- **取值语义只有一个：字段保存"最近一次成功交互得到的偏差"。** 在心跳窗口内没有成功交互、或该次交互未能取得 `serverTime` 时，字段为 `null`，表示**偏差不可测**，不是"偏差为零"。
- null 与超限一样禁止新自动动作；**只有一次成功交互才能写入新值**，不得用缓存的旧偏差冒充新鲜有效。这与正文"无新包的定时器不能续证目标"同一原则：不可测就不能靠旧值续命。
- 该字段只影响自动执行资格。捕获、告警与观察路径不受影响；偏差恢复且落入阈值后，凭新的合格观测重新取得资格，不需要重放历史证据。

**理由**：rc.2 把"不可测"和"测得正常"折进了同一个禁止表达式，实现时会出现两种相反的解读——有人把 null 读成"没有偏差所以放行"，有人读成"无法验证所以拦住"。契约对质量字段的取向一直是 fail-closed，这里按同一取向写死。

## C2 自动候选检验的次序与拒绝原因码

正文第 8 节列出自动候选必须**同时**成立的条件，但未规定逐项次序，也未规定同时违反多项时返回哪个原因。补定如下：从 T1 起逐项评估，**取第一个不通过项的代码**作为本次结论的 reasonCode，不合并、不并列、不按严重度重排。

| 序 | 检验项 | 不通过时的稳定代码 |
|---|---|---|
| T1 | capability 已验收且声明覆盖本 `(platform,地址族,协议,方向,家族,profile)` | `CAPABILITY_NOT_SUPPORTED` |
| T2 | 数据质量无 `captureGap/latePacket/truncated/capacityDrop/offloadSuspected` | `QUALITY_UNSUPPORTED` |
| T3 | 时钟可测且偏差在阈值内（见 C1） | `CLOCK_UNTRUSTED` |
| T4 | `targetRef` 存在、绑定未变、未过期 | `TARGET_REF_STALE` |
| T5 | `score ≥ autoThreshold`（同 parentConnection 只取截至决策时最新合格快照） | `SCORE_BELOW_AUTO` |
| T6 | 满足 `minDistinctFlows`、`minEvidenceSpanMs` | `EVIDENCE_INSUFFICIENT` |
| T7 | 同目标上下文条件满足（含 `minPeerFlowStarts`） | `CONTEXT_CONDITION_UNMET` |
| T8 | 资产授权与自动发布包 active，revision 未变 | `AUTHORIZATION_INACTIVE` |
| T9 | 保护目标与动作预算检查通过 | `PROTECTION_OR_BUDGET_BLOCKED` |

- 次序固定为**"先证明能不能做，再证明该不该做"**：能力、质量、时钟、目标属于"这条证据本身是否可用"，排在分数与阈值之前；分不清可用性就先比分数，会把不可用的高分快照计入证据。
- reasonCode 进入 `guard_decision.reason_codes` 与观测拒绝事实；同一原因在人工界面、日志和接口错误里使用**同一字符串**，不各自翻译。
- 该表只定原因判定，不改变第 8 节任何阈值或既有硬约束；T5 必须仍满足 `autoThreshold ≥ alertThreshold`。

## C3 动作预算的口径

正文第 9 节与数据库设计第 7 节对预算有二义（"每资产"是否再乘 capability）。以 Schema 字段名作为唯一口径：

- `maxActiveRulesPerAsset` 与 `maxNewActionsPerMinute` 均为**每资产总量**，即该资产下所有已激活 capability、所有 bundle、所有 peer、所有方向共享同一额度，**不按 capability 或发布包分别计算**。
- 计数对象是**数据库已创建且尚未确认终结的动作**，不是消息条数、不是已发出的命令条数；重试与重发复用同一动作，不重复占用额度。
- "每分钟"以**数据库单调时间**上的滚动 60 秒窗口计，不使用代理本机墙钟；控制面时钟回退时窗口不重开、不额外放行。
- 额度是误伤约束，不是能力证明；提高额度等同于修改策略，须走新版本发布包，不能在运行时临场放宽。

## C4 策略与能力的绑定落点

**绑定唯一落在发布包，不在 `DecisionPolicy` 增加字段。** 自动策略的资格链固定为：

```
guard_capability(level=lab_auto|authorized_auto, 已验收且范围匹配)
  ← guard_bundle_capability ← guard_release_bundle(status=active)
  → guard_asset_binding(asset, bundle, authorization_revision)
```

- `DecisionPolicy.supportedCapabilityIds` 与 `guard_bundle_capability.capability_id` 必须一致；报告必须评估同一模型/策略/契约哈希，否则 bundle 不可批准。
- **禁止**出现"能力已登记为可自动、策略参数仍为 draft"的活动组合：`guard_asset_binding` 只接受 `status=active` 的 bundle，而 bundle 只能引用 `reviewed` 之后的策略。
- 未来若为方便查询在策略上冗余 capability 引用，须换版本发布新 Schema，不能原地加字段。

## C5 续段的快照与年龄口径

正文第 3 节的续段语义在 [P2 报告](../p2/README.md#实施前语义补充)已有实现裁决，本节将其**上升为契约层口径**，避免 P4 重新推断：

- 续段沿用 `parentConnectionId`，但按新 `flowId` 的 `firstSeenAt` **重新调度** prefix（1s、5s，其后每 5s）。
- **`snapshotIndex` 在新 `flowId` 下从 0 单调递增**；`elapsedMs = asOf − firstSeenAt` 用新 flowId 的起点，是"当前观察段年龄"，不是整条 TCP 连接的时长。
- 段内统计量（长度、IAT、标志计数）**按新段重置**；无新报文不建续段。
- 证据跨度 `minEvidenceSpanMs` 与 `maxEvidenceAgeMs` 按段内 `asOf` 计，跨段不累计，避免用一条长连接的旧高分延长另一段的证据寿命。
- 因此"同 parentConnection 只贡献一次独立流"与"每段重新计时"并不冲突：**去重按 parent，计时按段**。

## C6 版本递增与冻结的判定

- **只有语义变更才递增契约版本**：字段增减、公式、方向/服务判定、状态迁移、阈值语义、质量字段含义。纯文字排版、措辞、交叉引用修订**不构成**版本变更。
- **新增外部实测证据不自动升级版本。** `guardlive`、PF/SCM、Go live、ONNX 对拍等实测只增加证据，不改变 rc.2 字段与公式时，rc.2 继续有效，证据由各自清单绑定。禁止出现"同一契约版本对应互不兼容的语义"。
- 需要升版本时：递增 rc、复算样本、重跑两端对拍、生成新一轮冻结清单；旧清单与旧出口 JSON 保留不改写，新清单并行登记。
- 正式冻结发布使用新正式版本号与哈希，不把 rc 号直接改称正式版。

### C6.1 当前冻结漂移（待裁决，不得静默忽略）

截至本次文档修订，[P2 冻结清单](../p2/freeze-manifest.json)（45 个文件）中有 **3 个已知漂移且尚未登记**，另有 1 个已登记：

| 文件 | 状态 |
|---|---|
| `sensor/internal/hostguard/live.go` | 已登记于[本轮交付清单](../p1-p3-completion/manifest.json)，哈希一致 |
| `sensor/internal/hostguard/engine.go` | **漂移，未登记**：冻结 `55c3a05f…`，当前 `980f7176…` |
| `sensor/internal/hostguard/input.go` | **漂移，未登记**：冻结 `61a086fe…`，当前 `13d24d04…` |
| `sensor/internal/hostguard/input_test.go` | **漂移，未登记**：冻结 `041d493f…`，当前 `1047f362…` |

含义与约束：

- **契约文本与 6 个 Schema、profile、示例、golden、测试夹具均未漂移**，本次文档修订未触碰任何冻结文件。
- 漂移只发生在 Go 提取器实现文件。按 C6 第一条，这属于**实现变更**：若其行为不改变 rc.2 字段与公式，则 rc.2 契约仍有效，但**必须用新清单登记并重跑两端对拍**，才能声称"该实现仍是 rc.2 的合格实现"。
- 在完成登记与对拍前，**不得**把这 3 个文件描述为"与 rc.2 冻结一致"，也不得用 `p1-p3-completion` 的"逐字节复算通过"结论覆盖它们——该结论建立在漂移前的制品上。
- 处理选项（择一，需明确记录）：① 将三文件纳入新一轮提取器清单并重跑 Mac/Windows 对拍；② 若差异可归为无行为影响的内部重构，声明并附证据后登记；③ 回退到冻结版本。**不得**通过改写 rc.2 清单里的哈希来"消除漂移"。


## C7 rc.2 已知未写全项（留给后续版本）

以下不阻塞 P4/P5 设计，但实现前须由新一轮版本明确，本文不代替裁决：

1. 序列模型（TCN/GRU）的有序序列与 mask 契约、profile 与版本——正文第 7 节已声明必须新增，尚未给出结构。
2. `guard_decision` 与 `guard_episode_evidence` 的 `evidence_sha256` 覆盖范围（选定快照哪些字段参与摘要）。
3. 代理侧 `stateDigest` 的规范化算法（决定"实态一致"如何判等）。
4. `family_scores` 的族名注册表与 `familyScoreOrder` 的冻结清单。
