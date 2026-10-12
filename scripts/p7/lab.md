# B4 lab 会话与 G3 报告工具

后端入口为 `GuardLabController`，完整请求、状态和传感器交接见 [lab v1.1 契约](../../docs/contracts/lab-validation.md)。V25 保存运行投影/事件，原 B4/L2/L3 代码已随 PR #29—#31 合入并完成集成验证。`lab_report.py` 负责文件报告；阶段 0 的 `lab_run.py` 新增真实隔离后端、传感器和执行器替身编排，本次工作区交付及验收结果见 `.cache/route-20261012/handoff.md`。

2026-10-12 的第 15 次完整 18 段 rehearse 演练已通过 K7-R：三类候选达标、正常候选为 0、关联完整、替身空规则退出。原始门禁位于 `.cache/g3-rehearsal-20261012/attempt-15/gate.json`，目录索引为 `.cache/g3-rehearsal-20261012/gate.json`。这是 synthetic 诊断结果；正式 G3 和 K5/K7 的 E3/r4 前置闭环仍未完成。

## 隔离演练

```sh
sh executor/python.sh -B scripts/p7/lab_run.py --mode rehearse \
  --directory .cache/g3-rehearsal-20261012/attempt-N
sh executor/python.sh -B scripts/p7/g3_rehearsal.py \
  --run-dir .cache/g3-rehearsal-20261012/attempt-N
```

每轮使用新目录、随机 schema 和专用 synthetic 签名身份；正式 report-trust 不增加该身份。18 段原件逐文件核验，完整预热对端都保留。lab v1.1 每段固定一个偏移，评分起点对齐，1 倍速并发回放。替身持续心跳、领取与核对空规则；服务端执行门保持关闭，候选按 J1 同一判定器的 hypothetical 投影统计。报告及门禁均标 synthetic，不能作为正式 G3 或类别资格。 捕获完成后先停止替身并核验原记录以空规则 `stopped` 结束，再进行大量事实关联和报告查询；任一失败或缺失终态都使门禁失败，恢复不得换新进程抹去旧失败。

`--resume` 只恢复 captureComplete 后的收尾：复用原 schema、身份、签名输入、TLS 与场景偏移。采集中断没有完整引擎检查点时明确拒绝；保留失败目录并另开尝试，不能把未采集部分算成完成。`dry-run` 使用虚拟时钟和全替身，校验输入、模拟会话生命周期并完成报告生成/签名/验签，结果恒为未验证，不连接数据库、后端或防火墙；`pf` 当前在任何文件、数据库或进程副作用前返回 `LAB_PF_BLOCKED_BY_R4_E3_PRECONDITION`。方案 B 的 E3/r4 前置闭环按 K9 引导克隆解除（见 [lab 契约](../../docs/contracts/lab-validation.md#e3r4-前置闭环与-k9-引导克隆2026-10-12-登记规划未实施)）；K9 交付且业务库 r4 已用正式 platform/canary 报告激活前，pf 保持拒绝。正式 G3 只在业务库运行，克隆仅用于产出 E3 证据。K9-6 演练增加了四个参数：`--source-schema`（从隔离的 `cyber_guard_*` 源克隆）、`--existing-bundle`/`--existing-reports`（复用源中已批准的 r4 及其 final/platform/canary 证明，不新建组合）、`--extra-trust`（只加入本次隔离后端）和 `--scenarios`（只缩小场景集合，逐段仍核验原件）。复用既有组合只允许 rehearse 模式与非业务源。K6 的 root 暂存 subject 绑定工具已保留，不代表 K7 正式路径可用。

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

集成测试要求从受控凭据注入 `DB_TEST_BASE_URL/DB_TEST_USERNAME/DB_TEST_PASSWORD`。测试创建随机 `cyber_it_lab_*` schema，完成后只删除自身所建 schema；迁移测试覆盖空库到 V25 与 V24→V25 单步，核验 V1—V24 Flyway 历史整行、账号/口令哈希和 V20 列不变。既有验证已随 PR #29—#31 完成；阶段 0 新增代码的验证单独登记。真实回放计时窗口中暂停并行构建和数据库测试。

本线对 GuardCatalog 增加报告分流保护、GuardEligibility 追加会话门，保留历史迁移测试的 V24 口径，并修改接口 B4/数据库第 14 节。GuardQueries、GuardMapper/Store、research 生命周期和 K4 冻结文件保持原样；GuardEligibility 的会话门只在已登记的 lab sensor 上生效，K2 research 性能路径不受影响。其他并行线如需迁移应取 V26 及以上。正式 lab 仍需 K4/J1 最终交接、J2 登记、真实 canary/短租约接入、网络层隔离与另行试验授权。
