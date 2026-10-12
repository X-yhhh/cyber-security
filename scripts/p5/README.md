# E3 联合链路准备与 B6 lab 配置

本目录准备 Mac 回环联合环境，不切换现有服务，不部署常驻恢复器。真实 PF、sudo、lo0 别名操作须每轮 A4 单独授权。任务 2 的无权限演练中，模型、能力及签名评价报告均为合成夹具，不能用于 G3、发布资格或生产能力声明；2026-10-10 T3.8b 的真实运行方式见文末“root 暂存副本运行”。

## 入口与前置条件

从仓库根使用已有 `executor/python.sh` 包装器。要求 JDK 25、Maven 的 Java 同为 25、Go 1.26.4、执行器 requirements，以及本机 MySQL 8 测试身份。测试身份需具备临时 schema 的 CREATE/DROP 及迁移权限；脚本前置检查保守要求全局 CREATE/DROP，不会打印凭据或 grants。

预先在受控环境提供 `DB_TEST_BASE_URL=jdbc:mysql://127.0.0.1:3306`（仅服务地址，不带 schema、参数或凭据）、`DB_TEST_USERNAME`、`DB_TEST_PASSWORD`。不要把密码放在命令参数、Git 或报告中。`JAVA25_HOME` 指向已安装的 JDK 25；可用 `--maven/--go/--mysql` 指定正式工具绝对路径，否则按 PATH 查找。不要依赖默认 shell 的 Java 版本。

```sh
bash executor/python.sh scripts/p5/orchestrate.py \
  --mode dry-run --java-home "$JAVA25_HOME" \
  --directory "$HOME/Workspace/ai/outputs/<全新前置检查目录>"
```

`--directory` 必须为仓库外绝对路径且尚不存在；拒绝经软链接解析后位于仓库内的路径。目录 0700，生成文件 0600。dry-run 只查询工具、接口和 MySQL 版本/权限，输出完整 `preflight.json`；不会创建 schema、生成模型、启动后端、请求 sudo、安装规则或配置别名。`prepared=true` 表示准备条件满足，不能替代 PF ABI/根规则/清理验收；无 sudo 无法读取 PF 状态时如实记 `pfReadableWithoutSudo=false`。

## 无权限六场景演练

```sh
bash executor/python.sh scripts/p5/orchestrate.py \
  --mode rehearse --java-home "$JAVA25_HOME" \
  --directory "$HOME/Workspace/ai/outputs/<全新演练目录>"
```

顺序为 peer_service 的 revoke/disconnect/receipt_loss，再为 peer_inbound 的同三场景。每轮独立资产、授权、稳定预算密钥和账本，避免撤销墓碑或故障暂停状态污染下一轮。可用 `--scope` 与 `--scenario` 成对指定一轮。

`GuardJointLabTest#jointMatrix` 显式加载 lab profile，并创建 `cyber_guard_api_p4_<随机 UUID>` schema，应用现有迁移，结束仅删除自己的 schema。人工登记与批准复用 P4 API 夹具；机器领取、回执、撤销、核对走真实回环 HTTPS TLS1.3。执行器与本轮构建的 Go `guardtargets` 通过真实 mTLS 通信，collector/executor 证书分别认证。模拟观察没有抓包或攻击流量；真实端点只用 127.0.0.1/127.0.0.2、lo0。

演练模式的防火墙是 `MemoryFirewall`，独立恢复器由线程夹具模拟；不调用 PF，也不证明流量实际被阻断。链路覆盖签发→领取→规则替身安装→回执→人工撤销→实态核对→清理：

- revoke：应用成功后人工撤销，数据库 observed_state 与账本均为 revoked。
- disconnect：应用后注入 HTTPS 发送失败，清理自身规则并暂停，重连同步撤销。
- receipt_loss：服务端先接受首条 applied 回执，再丢弃响应；执行器保留原 receiptId/内容摘要并在重连重试，数据库该 public_id 仅一条，随后收敛为 revoked。

`summary.json` 汇总顺序、六轮结果、源码/guardtargets 二进制/执行器配置哈希。每轮 `result.json` 记录安装/清理时刻、规则摘要、账本、故障注入与原回执重试事实；`database-facts.json` 记录数据库末态、周期墓碑、预算 revision 与命令/回执数。`input.json`、credential、TLS 私钥及本机 SQLite 包含测试身份或端点，只留在受控外部目录，不提交、不公开。JUnit 失败时不自动打印 MockMvc 的完整认证请求。

## lab profile 与信任边界

`backend/src/main/resources/application-lab.yml` 必须显式选择。默认 `application.yml` 没有任何 `cyber.guard.*`，未启用 lab 时不会激活自动化；lab 的自动化默认也为 false。

| 环境变量 | 用途 |
|---|---|
| LAB_DB_URL | 专用隔离 lab schema 的 JDBC URL |
| DB_TEST_USERNAME / DB_TEST_PASSWORD | MySQL 测试身份，受控环境注入 |
| LAB_TLS_CERTIFICATE / LAB_TLS_KEY | 回环 HTTPS PEM 证书及私钥引用 |
| LAB_SIGNING_KEY_ID / LAB_SIGNING_KEY_FILE | Ed25519 控制面签名身份与 DER PKCS8 私钥引用 |
| LAB_REPORT_TRUST_FILE | 后端导入报告使用的 runner→公钥 DER base64 映射 |
| LAB_PROTECTION_FILE | P4 格式保护 JSON 引用 |
| LAB_ARTIFACT_ROOT | 仓库外受控制品根目录 |
| LAB_EXECUTOR_TRUST_FILE | lab.executor.trust-file，编排交给执行器 trustFile 的命令公钥清单 |
| LAB_AUTOMATION_ENABLED | 默认 false，独立授权的 lab 运行才显式启用 |

后端 `cyber.guard.report-trust-file` 验签评价报告；执行器 `trustFile` 验签 ActionCommand，两者格式与职责不同。命令清单按 keyId 含 `status/publicKeyDer/notBefore/notAfter`，不得把私钥发给执行器。独立部署可用 `bash executor/python.sh -m executor keygen --directory <仓库外全新目录> --key-id <身份>` 生成控制面私钥、公钥信任文件和稳定预算密钥；执行器的 `RuntimeConfig.trustFile` 指向公钥清单。

联合测试动态注入上述属性：同一次测试生成临时签名私钥、独立 runner/command 信任文件、TLS PKI，并按 lab.executor.trust-file 交给执行器。仅在专用随机 schema 注册合成模型和资格，不触及已有业务授权。它是协议夹具，不是服务切换或 B6 全阶段验收。

## T3.8 保护集来源

`scripts/p5/lab-protection.json` 为两种作用域共同的 P4 保护配置：

```json
{"protectedBudgetTargetIds":[],"protectedServicePorts":[22,53,3389]}
```

JCS SHA-256 为 `cfe3f15a5b8d6352dd3bef5965cc935973f2225d3ef774757d82da0842d22654`；有效保护端口摘要为 `0a8fc9174a067e5a12557351ed368486a68ea015d2416be8f510a77014929583`。T3.8 可读取该文件计算 protectionSetSha256；封装策略前仍须提供已登记能力 ID 和完整预算字段。22/53/3389 始终隐式保护，peer_inbound 区间由 P4/P5 各自扣除并复核。部署若增加保护目标/端口，必须重算摘要并重新绑定策略、能力和发布组合。

## A4 后的单轮 PF 入口

真实执行不属于本次验收。每次只允许一个 `--scope` 和 `--scenario`，同时须具备本轮授权引用并由管理员显式运行 root 进程；脚本不会自动调用 sudo。先 peer_service，独立验收后再 peer_inbound。禁止用一个模糊授权引用批量运行六轮。

```sh
# 仅供本轮 A4 已获授权且管理员已建立受控 root 环境后使用。
bash executor/python.sh scripts/p5/orchestrate.py \
  --mode pf --scope peer_service --scenario revoke \
  --authorization-reference '<本轮A4引用>' --java-home "$JAVA25_HOME" \
  --directory '<仓库外全新受控绝对目录>'
```

PF 会话只接受初始 Disabled PF、已知默认根或固定用户夹具组合、空专用 anchor，且没有已有 127.0.0.2 别名。核对 root-owned helper ABI，保存根/用户/apple 原始规则字节；仅挂专用 anchor，取得本轮 enable token，并启动单独恢复进程。正常退出或可处理的 SIGTERM/SIGINT 先清规则再停恢复器；最后仅在根字节仍匹配时恢复根，释放本轮 token，移除本轮别名。各清理动作独立尝试，外部改动保留并报失败，不全局 flush，不用 `pfctl -d`。`pf-session.json` 记录逐项清理结果。

SIGKILL、主机重启、系统工具故障或并行管理员变更可能使清理未完成；这些情况不能写成通过，须按保存的规则/本轮 token 与别名范围人工核对恢复。PF helper ABI、系统输出规范化、真实连接效果及异常清理尚待本轮 A4 实测，不能由演练和单元测试推断。

## 后端墓碑与 E4

控制面在资产→目标锁内追加 `guard_budget_event(event_kind=revoked)`，绑定当前 `cycleStartedAt`，包括未签发动作。同周期的新自动动作、人工申请、批准和签发均拒绝 TARGET_REVOKED；不改变计费或删除历史事件。健康恢复通过后开启新周期，零计费墓碑也须健康冷却，不能任意清零。没有新 migration。

执行器新增真实 Ed25519 key/keyId 与策略 hash 轮换测试，同一稳定 token 的四段 30 秒累计到 120 秒后拒绝；撤销后继续拒绝新动作。后端测试覆盖有/无签名撤销、短期引用/keyEpoch 轮换、预算保留和零计费墓碑的健康恢复。E4 的真实 PF 轮换证据仍待 A4。

```sh
# 在 backend/ 下，明确 JAVA_HOME/PATH 使用 JDK25。
mvn -B verify
# 在仓库根。
bash executor/python.sh -m unittest discover -s executor -t . -p 'test_*.py'
bash executor/python.sh -m unittest discover -s scripts/p5 -p 'test_*.py'
```

本次准备不等于 E1—E3 全部真实验收、P5 出口、G3 或生产发布；A5 业务库 V22、现有服务切换和 Windows/WFP 均保持未执行。

## root 暂存副本运行（T3.8b）

真实 PF 只由 root 运行 root 所有、逐文件核对过的副本，后端、Maven 与 JUnit 始终以普通用户运行（`orchestrate.py --mode pf` 以 root 运行会被拒绝）。

1. 用户态打包：`lab_stage.py` 把已提交代码、解释器、依赖和 `guardtargets` 冻结为带逐文件 SHA 的暂存包，得到清单 SHA；授权时同时给出该 SHA。
2. root 启动：把暂存包内的 `scripts/p5/lab_root_launch.py` 复制到 root 所有的 0700 目录，核对其 SHA 后用 `/usr/bin/python3 -I` 执行。任务只有 `p1-probe`、`e1e2-lab`、`e3-executor`；启动器在 `/private/var/root/hostguard-lab/<runId>` 复制并核对暂存包，以最小环境运行，结束后把证据副本（剔除密钥）交给 `--owner-uid`。子任务超时记为退出码 124 并照常交回证据。
3. E3 单轮：用户侧 `orchestrate.py --mode pf --scope … --scenario …` 运行后端与 JUnit，JUnit 经 `joint_relay.py` 建立两条命名管道；root 侧 `e3-executor` 等待管道后运行 `joint_executor.py`，只读取用户目录中数据文件的副本，管道和输入都按打开后的 fd 核对类型与属主。`--ready-marker` 在副本核验后创建，用户侧据此再启动后端。
4. 签名报告：`platform_report.py` 只接受真实证据——`--lab-run` 为 `e1e2-lab` 证据副本，`--e3-summary` 为 `orchestrate.py --mode pf` 汇总，`--e3-launch` 为对应各轮 `e3-executor` 证据副本。每条汇总场景都须有同一运行目录、退出码 0、root 侧 `result.json` 为 `realPF=true` 的启动记录，否则以 `REPORT_E3_ROOT_EVIDENCE_MISSING` 等错误拒绝。私钥须在仓库外且权限 0600。

T3.8b 的执行记录与证据位置见 [后续实施计划](../../docs/后续实施计划.md#t3-冻结准备mac零拟合)。

## K9 subject 报告上下文

`subject_report.py generate/verify` 需要 `--execution-context <受控 JSON>`。其中记录隔离克隆 schema、引导 platform/canary 文件的原字节 SHA-256 与专用 `e3-bootstrap-<runId>` keyId、源库运行前后逐表 `{rows,sha256}`、源库与克隆中 r4 的 `{bundleId,subjectSha256}` 及一致性结论。工具在生成和验签时拒绝字段缺失、源库前后不一致或克隆 subject 不匹配；正式 payload 仍固定 `evidenceKind=real_pf`，不接受非 root 或 `realPF=false` 的执行证据。摘要必须由编排器实读源库生成；报告中的一致性标记本身不构成数据库证明。

## K9 E3 引导克隆（无授权演练）

`e3_bootstrap.py --mode rehearse --source-schema <cyber_guard_*> --bundle-id <r4>` 的执行顺序：

1. 只读核对源库中的 r4：必须是 lab candidate，已有通过的 final，subject 等于冻结的 `f02022ba…`。
2. 克隆到 `cyber_guard_k9_<hex>`，签发 `e3-bootstrap-*` 引导报告。
3. 运行 `orchestrate.py --subject-step bootstrap`，在克隆内封存并由独立审批人批准。
4. 运行 `orchestrate.py --subject-step e3`，跑六轮替身矩阵。观察来自 guardlive 从登记的 `captureStart` 回放 brute_force-1/port_scan-1；`--inbound-segment` 可改用其他已登记的 port_scan 片段。
5. 删除克隆，核对源库逐表摘要，写出 `execution-context.json`。
6. 调用 `subject_report.py --rehearsal`，生成、签名并验签 synthetic platform。

运行目录位于制品根 `k9-e3/` 下（编排器要求在仓库外），尝试索引写入 `.cache/k9-20261012/attempts.json`。`--rounds scope-scenario` 只用于诊断：只跑指定轮次，不生成 K6 报告。

`k9_rehearsal.py` 串起 K9-6 全链路：S1 模拟 A18 → 上述 E3 引导克隆 → 在 S1 做开关关闭时的反例、封存与批准 → `lab_run.py --existing-bundle` 跑一段会话 → 删除 S1。

pf 模式需要 A6：编排器每轮调用 `orchestrate.py --mode pf`，root 侧仍由操作者按 T3.8b 流程启动 `lab_root_launch.py e3-executor`；canary 与正式 K6 报告按上一节单独生成。
