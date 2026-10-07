# host-guard v5 机器契约

P1/P2 已收口。此目录保留交接的 `host-guard/5.0.0-rc.2` 机器结构：**5 个 Schema、1 个特征 profile、5 个结构示例**。P3—P8 的业务规则统一见 [检测与处置契约](../检测与处置契约.md)，不再维护独立澄清附录。

| 文件 | 规范 |
|---|---|
| [observation.schema.json](observation.schema.json) | 因果快照、质量、上下文与目标引用 |
| [feature-profile.json](feature-profile.json) | 43 个数值输入和 3 个类别输入的顺序 |
| [model-manifest.schema.json](model-manifest.schema.json) | 候选模型、数据、校准与运行时绑定 |
| [decision-policy.schema.json](decision-policy.schema.json) | 版本化策略的结构与参数硬上限 |
| [action-command.schema.json](action-command.schema.json) | 不可变 payload 及签名封装 |
| [action-receipt.schema.json](action-receipt.schema.json) | 执行、拒绝、核对与恢复回执 |

结构版本与决策/评价版本分别绑定。当前 `host-guard-decision/2026-10-06.1`、`host-guard-evaluation/2026-10-07.1` 和 `host-guard-capture-health/1.0.0` 由计划、policyVersion 和发布组合绑定；不向现有 Schema 静默增加字段，也不声称现有程序已实现这些规则。

Schema 只能证明结构，不能证明时间先后、算术、归属、授权、签名、预算或实际 OS 效果。`contexts.5.*` 指 `windowSeconds=5` 的对象，不是数组第五项。正文和结构必须同时满足。

## 结构示例

[观察](examples/observation.json)、[模型 manifest](examples/model-manifest.json)、[策略](examples/decision-policy.json)、[命令](examples/action-command.json)、[回执](examples/action-receipt.json) 均为合成结构样例。零哈希、固定时间和故意无效的签名不构成真实制品或执行资格；阈值也不是新 P3 的选型结果。

## 验证与版本

使用 JSON Schema Draft 2020-12 和实际可用的 date-time/UUID format checker；未知字段必须拒绝。现有检查入口为 `python3 -B scripts/p2/validate_contracts.py`。命令签名采用 RFC8785 JCS，不用普通 JSON 打印顺序代替。

上述 11 个 JSON 文件保持原字节：后端测试和 `validate_contracts.py` 直接读取它们，结构变更必须与代码同步。旧 P2 冻结包是独立历史制品，新的 Markdown 不复用其集合哈希。P3 run 与后续 release bundle 绑定当前实际输入的逐文件哈希；字段、公式或状态语义发生不兼容变化时升级对应结构版本并重做相关一致性验证，不能只替换旧清单里的哈希。

## 下一版结构变更

多分类路线需要以下结构变更，登记为 `host-guard/5.0.0-rc.3`，随 P4/P5 代码一起修改 Schema、示例和测试，当前未实施：

| 文件 | 变更 |
|---|---|
| action-command.schema.json | `scope` 增加 `peer_inbound`（封禁单个来源到本机全部 TCP 端口）；该范围下 `servicePort` 为 null |
| decision-policy.schema.json | 增加按类别的参数表（类别、是否可自动、alertThreshold、autoThreshold、minDistinctFlows、封禁范围）；增加可自动规则清单 |
| model-manifest.schema.json | 结构不变：`familyScoreOrder` 已允许非空，多分类填 `[port_scan, brute_force, dos_flood, dos_slow]`；后端需取消“必须为空”的限制 |
| examples/ | 同步更新为 rc.3 合法示例 |

observation 与 feature-profile 不变。
