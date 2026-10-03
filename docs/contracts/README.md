# host-guard v5 声明式契约

状态：`5.0.0-rc.2`，P2 研究候选。独立 Go 提取器已实现观察/特征语义，旧后端运行时保持 v4；模型、策略与动作 Schema 仍为后续实现契约。集合哈希见[P2 冻结清单](../p2/freeze-manifest.json)，实际出口及未验证项见[P2 报告](../p2/README.md)。冻结候选不是正式发布或部署，不自动替换后端旧资源。

| 文件 | 规范 |
|---|---|
| [observation.schema.json](observation.schema.json) | 观察快照、质量、上下文、目标引用 |
| [feature-profile.json](feature-profile.json) | 43个数值输入（含布尔编码）和3个类别输入的顺序 |
| [model-manifest.schema.json](model-manifest.schema.json) | 候选模型及数据/校准/运行时绑定 |
| [decision-policy.schema.json](decision-policy.schema.json) | 检测证据与自动资格参数 |
| [action-command.schema.json](action-command.schema.json) | 签名包，内含不可变payload |
| [action-receipt.schema.json](action-receipt.schema.json) | 执行及恢复回执 |

[业务契约](../检测与处置契约.md)与Schema必须同时满足：Schema不能证明时间顺序、公式、身份、签名、目标授权、去重或OS规则效果。profile里的`contexts.5.*`表示windowSeconds=5的对象，而不是数组第五项。

## 结构示例

- [观察](examples/observation.json)
- [模型manifest](examples/model-manifest.json)
- [策略](examples/decision-policy.json)
- [命令](examples/action-command.json)
- [回执](examples/action-receipt.json)

所有示例使用人工构造UUID、零哈希及固定时间，仅验证结构。策略阈值不是选型结果；示例签名是故意无效的占位字节，没有真实密钥，真实执行器必须拒绝。模型示例没有真实权重、验收报告或可激活资格。Schema的`.invalid`标识是规范命名空间，不需要联网解析。

## 验证与冻结

使用JSON Schema Draft 2020-12及format checker校验Schema和示例；拒绝未知字段。验证环境必须实际注册date-time与uuid检查器，测试无效月份/日期确实被拒绝；仅传入FormatChecker但缺少可选日期依赖可能静默略过日期格式检查。实现还需覆盖以下业务反例：未来数据、mask错误、重复连接累加、签名篡改、boot/目标错配、过期租约、TTL延长及迟到回执逆转终态。

冻结时计算每个契约文件的SHA-256及集合清单，模型与配置分别绑定profile和提取器哈希；不把契约自己的集合哈希写入自身造成循环。任何字段/公式变化发布新版本并重跑样本生成与对拍。正式命令签名使用RFC8785 JCS，不使用普通JSON打印顺序代替规范化。
