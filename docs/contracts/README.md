# host-guard v5 机器契约

P1/P2 已收口。此目录提供当前 **5 个 Schema、1 个特征 profile、5 个结构示例**：观测、profile 和回执沿用 `host-guard/5.0.0-rc.2`；manifest 与命令已随 P4 升级为 rc.3；策略于 2026-10-08 单独升为 rc.4。P3—P8 的业务规则统一见 [检测与处置契约](../检测与处置契约.md)，不再维护独立澄清附录。

| 文件 | 规范 |
|---|---|
| [observation.schema.json](observation.schema.json) | 因果快照、质量、上下文与目标引用 |
| [feature-profile.json](feature-profile.json) | 43 个数值输入和 3 个类别输入的顺序 |
| [model-manifest.schema.json](model-manifest.schema.json) | 候选模型、数据、校准与运行时绑定 |
| [decision-policy.schema.json](decision-policy.schema.json) | 版本化策略的结构与参数硬上限 |
| [action-command.schema.json](action-command.schema.json) | 不可变 payload 及签名封装 |
| [action-receipt.schema.json](action-receipt.schema.json) | 执行、拒绝、核对与恢复回执 |

结构版本与决策/评价版本分别绑定。当前 `host-guard-decision/2026-10-08.1`、`host-guard-evaluation/2026-10-07.1` 和 `host-guard-capture-health/1.0.0` 由计划、policyVersion 和发布组合绑定。P4 已实现对应多分类和规则决策；结构验证不代表 P6/G1—G2、P7/G3 或现场部署通过。

Schema 只能证明结构，不能证明时间先后、算术、归属、授权、签名、预算或实际 OS 效果。`contexts.5.*` 指 `windowSeconds=5` 的对象，不是数组第五项。正文和结构必须同时满足。

## 结构示例

[观察](examples/observation.json)、[模型 manifest](examples/model-manifest.json)、[策略](examples/decision-policy.json)、[命令](examples/action-command.json)、[回执](examples/action-receipt.json) 均为合成结构样例。零哈希、固定时间和故意无效的签名不构成真实制品或执行资格；阈值也不是新 P3 的选型结果。

## 验证与版本

使用 JSON Schema Draft 2020-12 和实际可用的 date-time/UUID format checker；未知字段必须拒绝。现有检查入口为 `python3 -B scripts/p2/validate_contracts.py`。命令签名采用 RFC8785 JCS，不用普通 JSON 打印顺序代替。

后端测试和 `validate_contracts.py` 直接读取当前文件，结构变更必须与代码同步。旧 P2 冻结包是独立历史制品，其原字节和集合哈希不变；当前 rc.3 文件不复用其集合哈希。P3 run 与后续 release bundle 绑定当前实际输入的逐文件哈希；字段、公式或状态语义发生不兼容变化时升级对应结构版本并重做相关一致性验证，不能只替换旧清单里的哈希。

## rc.3 结构变更

以下 `host-guard/5.0.0-rc.3` 结构已与 P4 后端、示例和测试同步。P5 对新命令范围的实际执行与恢复仍须单独验证：

| 文件 | 变更 |
|---|---|
| action-command.schema.json | `scope` 增加 `peer_inbound`（封禁单个来源到本机全部 TCP 端口）；该范围下 `servicePort` 为 null |
| decision-policy.schema.json | （rc.4 另见下节）必填四个唯一类别的 familyPolicies（类别、是否可自动、alertThreshold、autoThreshold、minDistinctFlows、封禁范围）；可选 rulePolicies，逐规则登记数值字段、比较符、阈值与自动资格；保留旧全局字段用于结构兼容，实际判定以类别表为准 |
| model-manifest.schema.json | 固定双输出及 `familyScoreOrder=[port_scan, brute_force, dos_flood, dos_slow]`；后端校验 float32、维度、范围及攻击概率和 |
| examples/ | 同步更新为 rc.3 合法示例 |

observation、feature-profile 与 action-receipt 不变；默认策略示例所有类别与规则保持只告警，不能据此取得自动资格。

## rc.4 策略变更（2026-10-08）

只升级 decision-policy，其余结构版本不变。原因是采纳“按来源判定自动资格”（[后续实施计划第 9.2 节](../后续实施计划.md#92-按来源判定自动资格须登记进新评价版本)）：类别可自动时，需要能单独关闭模型来源、只保留达标规则。

| 文件 | 变更 |
|---|---|
| decision-policy.schema.json | `contractVersion` 为 rc.4；familyPolicies 新增必填 `modelAutoEligible`。为 true 时 `autoEligible` 也须为 true（P4 校验）。规则来源仍由 `rulePolicies[].autoEligible` 控制 |
| examples/decision-policy.json | 同步为 rc.4，四类 `modelAutoEligible=false` |

新增必填字段是不兼容变更，因此升版本，不使用默认值：默认 true 会在缺字段时放开自动，默认 false 会静默改变旧策略含义。决策版本同步升为 `host-guard-decision/2026-10-08.1`；rc.3 策略和 `2026-10-06.1` 决策版本的策略保留为历史，P4 不再接受登记或激活。
