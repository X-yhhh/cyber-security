# B4 lab 会话与 G3 报告工具

后端入口为 `GuardLabController`，完整请求、状态和传感器交接见 [lab v1 契约](../../docs/contracts/lab-validation.md)。V25 保存运行投影/事件（任务单分配给 L2 lab 线）。工具只读取文件并生成报告，不启动回放、不连接数据库或防火墙。本线代码待主会话统一编译、测试和合并验证。

## 报告流程

1. 通过 events 接口引用已有后端事实，并提交同会话 runner 签名的场景结束文件。
2. 从 `GET /api/v2/lab-validation-runs/{id}/report-input` 取响应的 `data` 对象，保存到受控 run 目录。接口受 evaluation.read 和资产范围约束。
3. 分别执行 generate、sign、verify。以下文件必须来自当前受控 run；每个输出路径必须尚不存在。

```sh
sh executor/python.sh -B scripts/p7/lab_report.py generate \
  --input .cache/lab-run/input.json --output .cache/lab-run/report.json

sh executor/python.sh -B scripts/p7/lab_report.py sign \
  --input .cache/lab-run/report.json --key "$HOME/ai/keys/<runner-key-dir>/runner.der" \
  --key-id lab-runner --output .cache/lab-run/report.signed.json

sh executor/python.sh -B scripts/p7/lab_report.py verify \
  --input .cache/lab-run/report.signed.json --trust "$HOME/ai/keys/cyber-guard-trust/report-trust.json" \
  --expected-input .cache/lab-run/input.json \
  --sha256 "$(shasum -a 256 .cache/lab-run/report.signed.json | cut -d ' ' -f 1)"
```

签名直接复用 `scripts/p5/platform_report.py` 的 `private_key`/`sign`：私钥为 Ed25519 PKCS8 DER，必须在仓库外且权限恰为 0600，否则以 `REPORT_KEY_INSIDE_REPOSITORY`/`REPORT_KEY_PERMISSIONS` 拒绝。验签沿用后端 `cyber.guard.report-trust-file`（即 J1 使用的 report-trust.json）格式 `{keyId: base64(X509-DER-public-key)}`，不新建信任根。generate 不签名；verify 同时校验原文件字节摘要、JCS 签名、runner 和期望输入重算结果。向会话 `POST .../reports` 提交 `{reportRef,sha256,runnerIdentity}` 才进入报告事实库；通用 bundle imports 不接收新 G3 报告。

报告按 [验证与验收第 9 节](../../docs/验证与验收.md#9-报告要求) 输出：`classes` 为四个攻击类的逐类结果（场景、来源、最差状态、首个告警/生效时延）；`scenarios[]` 给出全链路时刻 `labStart`（攻击起点）→`firstAlertAt`→`firstIssuedAt`（命令签发）→`firstAppliedAt`（规则生效）→`lastClearedAt`（清理完成）及对应毫秒时延；`normal.perHour` 为误封禁折算到每小时；`quality`/`qualifiedCoverage`/`executionQualifiedCoverage` 为质量覆盖；`unverifiedItems` 汇总未验证项；`provenance`、`protocolVersions.evaluation`、`evaluationPlanSha256`、`subjectSha256` 绑定数据集、切分、标签、代码、模型、策略、提取器、执行器与评价版本。

## 合成开发与报告含义

[报告输入样例](../../docs/contracts/examples/lab-report-input.json)和[期望报告](../../docs/contracts/examples/lab-report-expected.json)供纯函数对拍。将该输入复制到受控 run 目录即可执行 generate；样例 `computedStatus=passed` 只表示合成数字满足计算条件，`status=unverified, passed=false` 始终保留。

- 资格是 pending/active/revoked；运行 completed 只表示结束。撤销记录 stopRequestedAt，cleanupStatus 继续为 not_asserted，真实清理只能由可信回执/核对证明。
- 正常场景累计时长与单资产区间并集分别报告。误封禁按核验 applied 的不同 command 计数；安装历史缺失或有未关联命令时不能假定为零。
- 按模型/规则分来源列场景、拒绝原因、只告警原因、质量分母、offload 和不可判定数。采集合格率与可执行合格率分别报告；空/过期引用、10 秒时效失败和窗外数据保留计数，不能当作自动处置证据。攻击到告警/生效时延只报告，不加入 J1 门槛。
- PCAP、私钥、真实映射、账号与生成报告留在受控 run 目录，不提交 Git。样例不能作为已通过 G3 的证据。

## 验证与并行集成

Java 使用已核验 JDK 25；Python 使用项目现有 `rfc8785`/`cryptography` 环境。定向验证：

```sh
sh executor/python.sh -B -m unittest discover -s scripts/p7 -p test_lab_report.py
cd backend
mvn -Dtest=GuardLabReportTest,GuardLabFactsTest,GuardLabExecutionGateTest,GuardLabIntegrationTest,GuardLabMigrationIntegrationTest,GuardMigrationIntegrationTest,MyBatisMigrationGuardTest test
```

集成测试要求从受控凭据注入 `DB_TEST_BASE_URL/DB_TEST_USERNAME/DB_TEST_PASSWORD`。测试创建随机 `cyber_it_lab_*` schema，完成后只删除自身所建 schema；迁移测试覆盖空库到 V25 与 V24→V25 单步，核验 V1—V24 Flyway 历史整行、账号/口令哈希和 V20 列不变。K2 P95/K4 两轮运行期间暂停构建、数据库验证和回放；以上命令尚未执行。

本线对 GuardCatalog 增加报告分流保护、GuardEligibility 追加会话门，保留历史迁移测试的 V24 口径，并修改接口 B4/数据库第 14 节。GuardQueries、GuardMapper/Store、research 生命周期和 K4 冻结文件保持原样；GuardEligibility 的会话门只在已登记的 lab sensor 上生效，K2 research 性能路径不受影响。其他并行线如需迁移应取 V26 及以上。正式 lab 仍需 K4/J1 最终交接、J2 登记、真实 canary/短租约接入、网络层隔离与另行试验授权。
