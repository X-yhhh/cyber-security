# P7 策略、交付包与 research 回放

本目录实现 B2 策略生成和 B3 分步导入。B2 生成器读取冻结审计、候选层、P4 部署绑定与可选 P6 报告，写出新的 decision-policy JSON；生成器不调用 P4 API。B3 导入器登记并封存已备好的制品，独立审批在脚本外进行。两个工具均不自动审批、不激活、不读取 test、不修改旧候选。输出通过 Schema 不代表发布资格或 G3 通过。

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

历史基线为 Python 44 项；当前 P7 回归已扩展为 82 项，覆盖缺字段、哈希不符、类别不全、阈值越界、无报告请求自动、来源开关矛盾、自动缺收口或收口不符、保护集结构，以及旧规则、非法 JSON、输出不覆盖等路径。CLI 测试实际生成文件并与已存样例比较。当前 `GuardComposedPolicyTest`、`GuardDomainTest`、`GuardReplayReadinessTest` 共 18 项通过（JDK 25.0.2）。

## 原候选与当前部署边界

candidate-v2 原研究策略对 rc.4 有 21 个 Schema 错误，计数与完整清单见 [B2 实施记录](../../docs/后续实施计划.md#b2-rc4-策略生成)。inspect 只读输出差异与输入/Schema 摘要；退出 0 表示完成检查，应以 count 判断是否合规。

旧 rules-comparison 的规则没有 ruleId/operator，且部分带 servicePorts、minElapsedMs。rc.4 无法表达这些额外条件，不能默认比较符或删条件后宣称原审计有效；必须先明确新规则语义并重新完成 validation 审计。历史类别汇总资格也不能顶替分来源资格。

本次未取得真实完整 P4 部署绑定，也未生成正式候选/发布组合。生成器不从示例、预算硬上限或候选内容猜测 P4 配置，缺真实输入即拒绝。实际导入和能力有效性验证由 B3/P4 执行，不在 B2 中执行。

## B3 交付包导入

[import_bundle.py](import_bundle.py) 使用现有 v2 API，写入顺序固定为 models → validations → evaluation-plans → capabilities → decision-policies。策略处于 draft 时原子保存状态并退出；另一身份在 `/decision-policies/{id}/reviews` 手动审查后，以 `--resume-state` 继续 release-bundles → imports → sealings。封存完成后再次退出，发布包 decisions 和 activations 始终由外部人工流程负责，脚本没有这些调用。

导入身份须具备 model.manage、model.validate、evaluation.run、bundle.request、policy.draft 和相关 resource.read/evaluation.read 权限。Cookie 和 CSRF token 必须属于同一已登录会话，通过私有文件传递；不要把凭据放入清单、命令行或 Git。恢复时会话失效须重新登录并更新凭据文件，不得跳过鉴权。

首次清单的完整结构见 [合成模板](testdata/import-bundle-plan.json)。该模板包含占位哈希和合成身份，不能直接用于真实导入；集成测试会在隔离目录中生成匹配的 ONNX、manifest 和签名报告。datasetRefs 须引用已登记数据集，实际制品预置于后端 `cyber.guard.artifact-root`，脚本只提交相对引用及 SHA-256，不上传、加载或执行任意序列化对象。

评价计划可以内联（RFC8785 摘要），也可以是 `{"planRef":"制品根内相对路径","planSha256":"原文件字节 SHA-256"}` 形式的 P6 冻结计划引用，此时 manifest 和策略绑定的是原字节摘要。复用已登记的模型和计划时，用 `existingModel: {id, manifestSha256}` 和 `existingEvaluationPlan: {id, planSha256}` 分别替代 `model`/`validation` 和 `evaluationPlan`，各项只能二选一；写入前回读核对，复用模型必须已是 validated。`sealing` 设为 `null` 时，导入报告后停在 `awaiting-joint-evaluations`，不尝试封存，用于等待同 subject 的 platform/canary 报告的 lab 组合。

清单必须二选一：`capability` 为新登记的单条能力；`existingCapabilities` 为非空既有能力列表，每项严格为 `{"id":"规范 UUID","payload":{完整登记请求},"payloadSha256":"payload 的 RFC8785 SHA-256"}`。列表拒绝重复 UUID、摘要不符和混合输入。复用时在任何写入前 GET 每条能力，核对 ID、level、scope、完整 payload 及摘要；缺失或漂移立即停止，不 POST 新能力，也不把 lab_auto 降为 research。保护集、豁免报告及签名平台证据引用必须保留在完整 payload 中。复用平台能力不授予类别自动资格。

清单支持完整字符串形式的 `${modelId}`、`${evaluationPlanId}`、`${evaluationPlanSha256}`、`${capabilityId}`、`${capabilityIds}`、`${policyId}` 引用。`${capabilityIds}` 整体替换为排序后的完整 UUID 数组；`${capabilityId}` 仅在单条能力时可用。策略 supportedCapabilityIds 与发布组合 capabilityIds 必须精确绑定本次核验的完整集合。评价计划及策略使用 RFC8785 摘要；manifest/ONNX/报告使用后端核验的原字节摘要。模型登记后回读 manifest 摘要，验证后核对 artifactSha256；能力回读 payload 与请求逐项一致；策略核对 definitionSha256，恢复时再次核对；发布组合独立计算 subjectSha256；导入报告回读 reportSha256；最终独立计算 sealedManifestSha256。任何非 2xx、状态或摘要不符均立即停止。

~~~sh
sh executor/python.sh -B scripts/p7/import_bundle.py \
  --base-url http://127.0.0.1:8080/api/v2 \
  --cookie-file "$P7_COOKIE_FILE" --csrf-file "$P7_CSRF_FILE" \
  --plan "$P7_IMPORT_PLAN" --state "$P7_IMPORT_STATE"

# 外部独立审查完成后，由导入身份继续。
sh executor/python.sh -B scripts/p7/import_bundle.py \
  --base-url http://127.0.0.1:8080/api/v2 \
  --cookie-file "$P7_COOKIE_FILE" --csrf-file "$P7_CSRF_FILE" \
  --resume-state "$P7_IMPORT_STATE" --reports "$P7_REPORT_REFS"
~~~

能力 UUID 在首次登记后产生，外部 runner 须以状态文件中的实际组合签发报告。`--reports` 文件仅包含 `{"imports":[{"reportRef":"...","sha256":"...","runnerIdentity":"..."}]}`，显式替代初始清单的报告引用；不提供时沿用原 imports。导入器不伪造报告、签名或评价结果。

状态文件不含会话秘密，记录本次清单、已收到的对象 ID、capabilityIds 和完整 capabilityBindings，首次运行拒绝覆盖既有文件。恢复时再次回读全部能力并检查状态绑定和策略/发布组合集合；能力漂移即停止。只有 awaiting-policy-review 阶段允许恢复；prepare/importing-reports 表示流程未完整核验，须先根据记录核对后端事实，不能直接重跑制造重复对象。网络超时不代表服务端回滚，脚本不自动重试、清理或补审批。

验证命令（需已配置隔离 MySQL/RabbitMQ 测试变量和 JDK 25）：

~~~sh
sh executor/python.sh -B -m unittest scripts/p7/test_import_bundle.py
P7_IMPORT_IT_ENABLED=true P7_PYTHON_WRAPPER="$PWD/executor/python.sh" \
  mvn -f backend/pom.xml verify
~~~

`GuardIntegrationTest` 的 B3 用例由 P7_IMPORT_IT_ENABLED 显式开启：Python CLI 经回环 HTTP 桥进入真实 Spring MVC、安全过滤器和 MySQL 事务，分别验证新登记能力与复用四条已登记签名 lab_auto 能力（含 peer_inbound 豁免），覆盖完整合成导入、越权、跳步、哈希不符、策略/发布包自审拒绝。该测试不会执行真实防火墙或激活发布组合。隔离 worktree 可通过 P7_PYTHON_WRAPPER 复用已安装依赖的包装器，无需复制虚拟环境。

Z2 集成复验（2026-10-10）是历史结果：P7 Python 60 项通过；JDK 25.0.2、启用隔离 MySQL/RabbitMQ 变量与 P7_IMPORT_IT_ENABLED 的 `mvn verify` 共 300 项，280 项通过、20 项按外部条件跳过，失败/错误均为 0。其中上述两种 CLI 导入均执行，V22→V23 单步迁移保留旧 Flyway 整行、全部账号及四条既有 lab_auto 能力。跳过项包括真实联合 lab、真实模型/原始回放夹具和跨语言执行协议，不能计为本次运行验收。当前 V24 业务库迁移与 J1 v8 验证见下文。

## B4 research 回放会话

`POST /api/v2/replay-runs` 已提供 research 会话登记，返回 202/queued；GET 列表与详情读取同一事实。只接受 scenarioId、scenarioSha256、modelId、policyId、speed，speed 固定为 1，服务端选择同模型/策略的 approved research 发布包。未批准、lab/authorized 组合和所有未知字段一律拒绝；列表也拒绝 assetId 过滤。幂等重试只返回原会话，不重复登记。

V24 向前追加 running/completed 状态和 latest-parent 索引，V1—V23 原字节不变。`starts` 校验冻结场景/PCAP/版本摘要、P6 验签报告绑定的 closeout 和仅观察的 research sensor/boot；T1 后独立 T2 消费真实 ONNX、规则和决策。`completions` 对照真实落库批数、最后序号及观察/推理数后结束会话。completed 与 J1 通过分开。research 不创建动作或命令，不登记执行器/target，不激活发布包。`/lab-validation-runs` 仍未实现，留到 J3 前再做，本次没有真实 lab 动作或 G3 验收。

## J1 V3 工具与证据

`j1_register.py` 只从 Mac 的已登记 CIC2017 原件及 P3-A validation 切分截取：核验 registry SHA-256/MD5 和官方 MD5，逐包检查冻结 validation 连接成员及时间范围，保留原时间和报文块字节。清单及每个片段的 SHA-256 在回放前冻结；不打开 frozen/test，不把 PCAP 复制到 Windows。`selection.json` 和提取 ledger 含原始端点，必须留在私有目录。

`j1_run.py` 用业务库备份的隔离恢复副本，追加 V24 后在 loopback 临时启动同一冻结 JAR，强制 TLS 1.3/client-auth=need，使用仅观察的 research 身份。每轮先用 `guardextract` 与 `GuardReplayReference` 生成真实 ONNX/规则/决策离线参照，再由 `guardlive -pcap` 每段 1 倍速读取文件并经真实 mTLS 上传；两轮复用同一清单、数值策略、PCAP 和二进制，轮次身份另行登记。多捕获域并发必须报告，并发正常时长之和不能描述为单主机连续正常时间。

假想准备度按 P6 已登记来源资格投影自动开关，数值策略与 M1 相同。复用正式判定器及最新快照替换：保留整组 profile/capability、推理可用、质量、时钟、时效、distinct parents 和上下文；仅排除现场健康、目标、执行授权及保护/预算，`actionable=false`。它不代表任何命令已签发。

```sh
sh executor/python.sh -B scripts/p7/j1_register.py --help
sh executor/python.sh -B scripts/p7/j1_run.py --help
sh executor/python.sh -B -m unittest discover -s scripts/p7 -p test_j1_audit.py -v
```

正式运行需显式提供 `--work`、`--registration`、0600 的 `--operator-file`、`--closeout` 及其验签绑定摘要。`--scenario-ref` 原样复用已经冻结的清单，拒绝二进制摘要不符；`--resume` 只恢复同一隔离 schema、原证书和未确认 spool，拒绝重新采集已有轮次，保留原采集/确认时间及中断日志。409 只在已落库 T1 请求摘要与原批次一致时允许重新消费；真正的内容冲突或无进展保持失败。凭据只从受控文件/Keychain 读取，禁止写在命令参数或报告中。

`j1_audit.py` 对照离线/回放/数据库事实，按独立 parentConnection 统计连接告警、正常误报及跨轮集合；低分连接不能继承同 episode 的其他连接告警。R3 分别报告纯 prefix、混组、final 和替换后的旧快照复用；R5 对同一 source/service/asOf 的全部更新替换后，计算 10 秒 latest distinct 质量连接，时钟与上下文资格另列，不能把纯质量比例当作完整自动覆盖率。时延保留 decidedAt，并以持久 mTLS 响应确认时间给出提交上界，中断续传不能抹掉原积压。OS 规则快照缺权限时标为未验证，不能用两个空摘要相等宣称安全验收通过。

两轮 completion 均为 completed 后，可用下式追加固定版本最终审计。输出 audit-final 与 summary-audit-final.json，并补全 REPORT.md；原已登记轮次报告不覆盖。复算门槛与已登记门槛不一致时停止收口并报告差异，不能静默改写验收结果。

```sh
sh executor/python.sh -B scripts/p7/j1_audit.py "$J1_RUN_DIR" --finalize
```

2026-10-10—11 的 v8 J1 两轮均 completed，完整报告在 `.cache/j1-20261011-v8/REPORT.md`，最终综合事实为 `summary-audit-final-v2.json`。J1 未通过：J1-1/2/3/4/6/7 通过，J1-5 失败，`dos_flood` 的 J1-9/J1-10 失败；计划 M2 为 `port_scan`、`brute_force`、`dos_slow`，但 J2/P8 保持关闭。零动作/命令已核验，研究组合已批准但未激活，OS 全局 PF 快照因权限边界未验证；临时服务已停。本机业务库已为 V24，迁移失败为 0。

`j1_register.py --preroll-seconds N [--preroll-families …]` 在每段评分窗口前追加同一来源紧邻 N 秒的上下文报文（只取 validation 与台账未分配连接，train/test 按台账排除），窗口内报文不变；片段登记 `captureStartUs`（预热起点）与 `scoringFirstUs`/`scoringLastUs`（评分窗口），`observedDurationSeconds` 按窗口计。审计以 `scoringFirstUs` 为攻击起点，预热期触发的判定不计入 J1-8—J1-10。v9 登记见后续实施计划 K3 段。

`derive_policy.py` 从已登记策略派生新版本：只允许改 `policyId`/`policyVersion` 并按 manifest.profiles 增设 `acceptedProfiles`，其余字段与来源不同即拒绝，输出附差异记录；不读 test、不登记、不审批。v8 的 r3 包策略由它派生（`policyVersion` `host-guard-decision/2026-10-08.1+profiles-20261011`）。

2026-10-11 v8 复跑沿用同一冻结片段并为新二进制登记新场景；`--server-threads` 设置后端线程数（默认 6）。运行器在后端迁移后先用 `policy_text.py` 把策略恢复为原件字节（结果写入 `policy-text-restore.json`），并为每轮记录 `privileges.json` 作为无免密 sudo 时 J1-6 的权限边界证据。收口记录为 `.cache/j1v3-20261011/closeout.json`；A7 仅完成本机配置/恢复检查：`en0` 的 TSO4/TSO6 与 `net.inet.tcp.tso=1` 保持现状，未执行 TSO/PF 切换，历史 PCAP 质量未被改写。

J1 收口验证摘要：`GuardIntegrationTest` 18/18、P7 Python 82/82、Java P7 回归 18/18、A7 PF 恢复单测 9/9，`compileall` 与 `git diff --check` 通过。上述结果不授予 J2、G3、P8 或真实资产自动执行资格。
