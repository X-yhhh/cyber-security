# B2 rc.4 策略生成器

本目录只实现 B2。生成器读取冻结审计、候选层、P4 部署绑定与可选 P6 报告，写出新的 decision-policy JSON；不调用 P4 API、不审批、不激活、不读取 test、不修改旧候选。输出通过 Schema 不代表发布资格或 G3 通过。

## 输入契约

运行入口为 [compose_policy.py](compose_policy.py) 的 compose 子命令。所有路径均显式提供，见 [testdata](testdata) 中完整合成输入。候选层、部署绑定层和单条规则拒绝未知/缺失字段，不填写默认值。

| 参数 | 内容与校验 |
|---|---|
| --candidate-layer | 策略/模型 ID、版本、profile、全局兼容参数、四类 familyPolicies、rulePolicies、evaluationPlanSha256、sourceSha256 |
| --policy-preview | validation 的 policy-preview.json：全局告警阈值、证据年龄，以及四类 parameters.autoThreshold/minDistinctFlows；若含逐类 alertThreshold 也须一致 |
| --rules-comparison | validation 的 rules-comparison.json；rules 每项必须显式含 ruleId、family、field、operator、threshold、automatic=false；审计统计可放在顶层其他字段 |
| --deployment-binding | 从 P4 现行配置明确导出的六项：maxTtlSeconds、maxContinuousBlockSeconds、maxActiveRulesPerAsset、maxNewActionsPerMinute、supportedCapabilityIds、protectionSetSha256 |
| --evaluation-plan | 候选冻结的评价计划原文件；核对特征档案哈希及候选层引用 |
| --protection-set | P4 实际保护集 JSON；RFC8785 规范化 SHA-256 必须等于部署绑定，不使用普通 JSON 打印或原字节摘要代替 |
| --source-eligibility、--evaluated-policy | 同时提供或同时省略；分别是 P6 L1 完整报告与该报告绑定的只读策略 |
| --closeout | P6 收口记录（`closeout.py` 输出）。任一来源请求自动时必填：须 `completed=true`、`evidenceSha256.l1Report` 等于所给报告原字节摘要，且评价 ID/版本、模型、计划、门槛与分来源资格与报告一致；只能与报告同时提供 |
| --output | 新文件，父目录须已存在；既有文件或软链接不会被覆盖 |

候选层四类参数逐项显式提供，port_scan 用 peer_inbound，其余用 peer_service。逐类告警阈值必须先在 validation 上选择并冻结，不能从自动阈值推断。自动阈值不得小于告警阈值；规则字段必须属于当前冻结 feature-profile.numericFeatures。

sourceSha256 精确登记 policyPreview、rulesComparison、featureProfile、evaluationPlan 的原文件字节摘要；提供报告时还必须登记 sourceEligibility、evaluatedPolicy。文件只读取一次，再对同一份字节做哈希与解析。保护集使用 RFC8785；其他文件使用原字节 SHA-256，两者口径不能混用。摘要核对证明输入绑定，不能代替上游审计真实性、P4 能力存在性与授权核验。

报告直接对接任务 1 的 classEligibility.<family>.modelOnly.offlineEligible 与 ruleOnly.<ruleId>.offlineEligible，四类和每条规则必须完整。类别 offlineEligible 必须等于各来源资格的 OR；若同时带 sourceEligibility 别名，必须逐项一致。候选层 modelAutoRequested / 规则 autoRequested 只能收紧资格，不能把 false 变为 true；请求未达标来源时拒绝。最终类别 autoEligible 取启用来源的 OR。无报告且所有请求为 false 时生成 mode=alert_only、所有资格 false；无报告却请求自动则拒绝。

报告模式还检查 P6/L1、评价版本/登记 ID、计划摘要、模型摘要、被评价策略摘要及冻结参数一致性；自动模式要求 G1/G2 为 true。策略 ID、部署预算/能力/保护集、来源开关可以构成新发布组合，模型 ID、阈值、规则等冻结语义不能借旧报告更换。P6 的 offlineEligible 仅为离线来源资格，生成 auto 策略仍须后续 G3、独立审批、发布绑定及运行时授权，不授予真实动作权限。

## 运行与验证

依赖见 requirements.txt。本机已有 executor 虚拟环境包含同版本依赖，可通过 sh executor/python.sh 复用；不需要安装或改动环境。以下命令从仓库根执行，输出目录由调用者准备。

~~~sh
sh executor/python.sh -B scripts/p7/compose_policy.py compose \
  --candidate-layer scripts/p7/testdata/candidate-alert.json \
  --policy-preview scripts/p7/testdata/policy-preview.json \
  --rules-comparison scripts/p7/testdata/rules-comparison.json \
  --deployment-binding scripts/p7/testdata/deployment-binding.json \
  --evaluation-plan scripts/p7/testdata/evaluation-plan.json \
  --protection-set scripts/p7/testdata/protection-set.json \
  --output /tmp/b2-alert-policy.json
~~~

上例只生成合成测试策略。需要验证逐规则资格时，将 candidate-alert.json 换为 candidate-auto.json，增加 --source-eligibility scripts/p7/testdata/source-eligibility.json --closeout scripts/p7/testdata/p6-closeout.json 和 --evaluated-policy scripts/p7/testdata/evaluated-policy.json，并选择另一个新输出路径。所有 testdata 中的身份、报告和配置均为合成，不能拿去登记实际 P4。

~~~sh
sh executor/python.sh -B -m unittest discover -s scripts/p7 -p 'test_*.py'
"$JAVA_HOME/bin/java" -version  # JAVA_HOME 必须指向 JDK 25
mvn -q -f backend/pom.xml -Dtest=GuardComposedPolicyTest,GuardDomainTest test
sh executor/python.sh -B scripts/p7/compose_policy.py inspect \
  --policy .cache/p3c-20261007/candidate-v2/decision-policy.json
~~~

Python 44 项测试覆盖缺字段、哈希不符、类别不全、阈值越界、无报告请求自动、来源开关矛盾、自动缺收口或收口不符、保护集结构，以及旧规则、非法 JSON、输出不覆盖等路径。CLI 测试实际生成文件并与已存样例比较。GuardComposedPolicyTest 读取合成输出，调用真实 GuardContracts.policy()，并对拍保护集 RFC8785 摘要；与 GuardDomainTest 共 12 项通过（JDK 25.0.2）。

## 原候选与当前部署边界

candidate-v2 原研究策略对 rc.4 有 21 个 Schema 错误，计数与完整清单见 [B2 实施记录](../../docs/后续实施计划.md#b2-rc4-策略生成)。inspect 只读输出差异与输入/Schema 摘要；退出 0 表示完成检查，应以 count 判断是否合规。

旧 rules-comparison 的规则没有 ruleId/operator，且部分带 servicePorts、minElapsedMs。rc.4 无法表达这些额外条件，不能默认比较符或删条件后宣称原审计有效；必须先明确新规则语义并重新完成 validation 审计。历史类别汇总资格也不能顶替分来源资格。

本次未取得真实完整 P4 部署绑定，也未生成正式候选/发布组合。生成器不从示例、预算硬上限或候选内容猜测 P4 配置，缺真实输入即拒绝。实际导入和能力有效性验证属于后续 B3/P4，不在 B2 中执行。
