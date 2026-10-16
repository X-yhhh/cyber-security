# P8 部署准备脚本

本目录实现 BE-14、DB-9 及初版部署与回归工具。A21 允许本机独立 RabbitMQ vhost 和 r6 登记至 approved；常驻服务、真实资产、采集与激活须另按 A8/P8 授权。步骤和回退见 [部署与回退](../../docs/部署与回退.md)。T1 仅使用隔离库合成事实；B3 中的真实 PF 演示入口仍须独立授权。

## 运行环境

从仓库根使用现有 `sh executor/python.sh -B`。JDK 固定 Temurin 25.0.2、Maven 3.9.13、MySQL 8.0.42 和 RabbitMQ 4.2.5，参数可指定已审查的安装目录。密钥和凭据由受控文件、现有 `DB_TEST_*`/`RABBITMQ_IT_*` 环境或 Keychain 读取，不写入命令行或 Git。每次 `--work` 必须是不存在的新目录；结果、日志、TLS 材料与数据库备份按 0700/0600 保存。

## T1 端到端隔离回归

入口为 `frontend` 下的 `npm run test:e2e`。使用 JDK 25（显式设置 `JAVA_HOME`）、PATH 中的 Maven、Node/npm 和 MySQL 8 客户端；Python 使用 `executor/python.sh` 对应虚拟环境，依赖见 `requirements-e2e.txt`（可用 `sh executor/python.sh -m pip install -r scripts/p8/requirements-e2e.txt` 安装）。先在 frontend 运行 `npm ci` 与 `./node_modules/.bin/playwright install chromium`。

调用环境须通过受控注入提供以下变量，不把秘密写进命令或文档：

| 参数 | 契约 |
|---|---|
| `DB_TEST_BASE_URL` | 仅 `jdbc:mysql://127.0.0.1:<端口>` 或 localhost，无 schema、用户信息或查询串 |
| `DB_TEST_USERNAME` / `DB_TEST_PASSWORD` | 测试服务账号，须能创建、迁移和删除本次随机 schema |
| `RABBITMQ_IT_USERNAME` / `RABBITMQ_IT_PASSWORD` | 本机测试 broker 管理与消息账号，须能创建本次 vhost 及授权 |
| `RABBITMQ_IT_PORT` | 可选 AMQP 端口，默认 5672；仅本机 |
| `E2E_BROKER_MANAGEMENT_URL` | 可选回环 HTTP 管理入口，默认 `http://127.0.0.1:15672` |
| `E2E_MYSQL` | 可选 MySQL 客户端路径，默认 PATH 解析 |

每次新建 `cyber_it_e2e_<随机值>` schema 与 `cyber-security-e2e-<随机值>` vhost，构建并启动当前 worktree JAR/dist；JAR 先 `clean` 再打包，避免已删除接口的旧 class 残留。不读取或迁移业务库。真实 v2 登录、HTTP、MySQL、outbox 与 RabbitMQ 消费参与回归，六账号各绑定一个内置角色。U4 的常量 ONNX、自签报告和 U5 的 lab 动作、未核对回执均为一次性合成夹具，无实际模型成绩或平台资格。

U5 的自动化开关仅作用于本次隔离后端，保留真实授权/资格校验；命令签名配置为空，无执行器进程、不调用 claims、不抓包、不执行 PF。合成回执引用的命令明确标为 `t1-ui-synthetic` 且签名无效；`safety.json` 检查其余命令数量为零。

每轮必须核验 `.cache/t1-e2e/<运行号>/cleanup.json` 全部为 true：停止本次浏览器、预览和 JAR，删除本次 schema/vhost，脱敏日志与失败 trace 后删除凭据/私钥。目录 0700、文件 0600；脱敏失败会清除本次诊断副本并非零退出，不能把失败清理视作验收成功。正常保留 `runtime.json`、`results.json`、`safety.json`、`cleanup.json` 及失败 trace；可用已安装的 Playwright `show-trace` 查看。SIGTERM 会进入清理；强制终止进程/主机掉电不保证 finally 执行，须按 runtime 中准确 schema/vhost/PID 人工核验，不可按前缀批量清理。

最终验收连续执行两次 `npm run test:e2e`，均须 0 失败、0 跳过、0 重试。定位时可追加 `-- --skip-build -- journeys.spec.ts`；不提供业务环境或任意外部 URL 模式。R1 编排器可传入内部 `rehearsal` 上下文：从其独占克隆再建随机子克隆，使用同一不可变 JAR/dist，保留原 T1 合成模式；默认入口仍从空隔离库开始。

## R1 业务库克隆集成预演

入口为 `rehearsal.py`，对应[初版任务单 R1](../../docs/任务/初版落地任务单.md#r1-业务库克隆集成预演)。先安装上述 `requirements-e2e.txt`，在干净提交上用 `launchd.py build` 生成不可变发布目录；Maven 使用 `clean package`，避免接口退役后的旧 class 混入。JDK 必须为 25，业务库必须无人连接且保持 V25，上一版 JAR 的最高迁移必须为 V25，新包为 V27。以下变量只保存路径：

```sh
sh executor/python.sh -B scripts/p8/rehearsal.py \
  --release "$RELEASE" --previous-jar "$PREVIOUS_JAR" --java "$JDK25/bin/java" \
  --artifacts "$ARTIFACTS" --trust "$REPORT_TRUST" --mysql-service "$MYSQL_SERVICE" \
  --runtime-user xyh --runtime-user g3-operator --runtime-user guard-reviewer \
  --work "$WORK"
```

`RELEASE` 为 `program/releases/<完整提交>/`；`WORK` 为不存在的绝对路径，建议使用仓库 `.cache/v1-20261014/rehearsal/<运行号>/`。数据库凭据由现有 MySQL 服务配置读取，RabbitMQ 沿用上表受控环境；不接受任意 JDBC/schema/服务 URL。发布包在前后均检查完整文件集合与 SHA-256。

1. 只读快照业务库，备份到本轮私有 `backup/`，含 `database.sql`、`json-double-fidelity.sql` 与恢复证明。仅写入本次创建的 `cyber_r1_clone_<随机值>`，初次恢复与回退恢复均要求结构、行与 JSON/DOUBLE 精确一致。
2. 在独立 vhost、回环 TLS/mTLS 端口以严格 deploy profile 启动新包，自动化和引导报告保持关闭。核对 V27、权限设计第 5 节完整矩阵、9 个 builtin、退役角色停用；3 名已有运行账号不丢失保留的 v2 权限，退役 v1 键单列；已有用户 ID、状态和口令哈希不变。验证启动审计、健康、就绪及后端托管的前端字节。
3. 复用 B3 `enroll.enroll` 完成 r6 的 authorized 测试资产登记与配置，执行范围为空、观察执行器只告警；该步骤不启动抓包。r6 的 authorized 环境禁止文件回放，所以另建 research 资产，绑定克隆内既有 approved research 组合，以同一 Go 制品读取生成的回环 PCAP。真实上传、MQ 消费、模型/规则及实时统计参与；不发包、不打开采集接口、不启动执行器、不调用 claims/PF。
4. `status.inspect_rehearsal` 检查实际临时 PID、deploy、就绪、页面、回放与观察/告警；采集健康原样保留 `unknown`，launchd 为 `not_installed`、PF 为 `not_applicable`。随后停止 deploy，在两个独立子克隆各运行完整 16 项 T1，均需无失败、跳过或重试；对继承历史命令设定基线，只允许显式无效签名的 `t1-ui-synthetic` 新夹具，其余新增命令为零。
5. 停止全部新进程，核验备份哈希后只恢复本次拥有的主克隆。恢复摘要必须与原快照一致，再启动上一版 V25 JAR，核对健康、就绪、结构与账号；旧包不支持前端托管，报告明确标注。精确摘要证明发生在旧包启动前，启动后的会话/健康等可变事实不冒充原字节。

最终 `result.json` 必须 `passed=true`，业务库前后摘要相同；主克隆/vhost、两轮 T1 的 schema/vhost/进程清理均成功。主流程保留私有备份、TLS 材料、日志、回放和 `SHA256SUMS`；T1 子克隆的 SQL 和凭据在脱敏后随 `private/` 删除。任一步失败即停止并进入清理；业务库末次快照若不可读，报告失败且不能宣称业务库未变。SIGTERM 会触发清理；强杀或掉电后按本轮准确记录核对，禁止按前缀批量删除。

R1 通过只证明克隆集成与回退。五服务安装/重启、现场采集健康、真实资产与 r6 激活、PF 演示及业务库 V26/V27 迁移仍属于 W4/A23。

## Broker 验收

```sh
sh executor/python.sh -B scripts/p8/broker_acceptance.py --work .cache/p8/broker-isolated-01
sh executor/python.sh -B scripts/p8/broker_acceptance.py --existing --work .cache/p8/broker-existing-01
```

- 默认启动同一正式 RabbitMQ 安装下的临时独立节点，独立端口、数据、凭据与 cookie；完整进程重启只作用于该节点。原共享节点不重启。节点运行目录保留为故障证据。
- `--existing` 在 `127.0.0.1` 的现有 broker 创建随机 vhost，使用 `RABBITMQ_IT_USERNAME`/`RABBITMQ_IT_PASSWORD`，只声明、清空和删除自己的消息对象。该结果不单独证明进程重启。
- 每组强制连续两轮；使用生产 publisher/listener/消费者与随机 MySQL schema。包括真实发布确认、丢确认帧造成的超时、TTL 重试、非法消息死信、重试耗尽、重复投递幂等、持久未确认消息恢复。
- `result.json` 必须 `passed=true`，两轮检查及生产类哈希一致、消息为空、其他拓扑不变、vhost 删除，独立节点已停止；`SHA256SUMS` 绑定 JSON 证据。任何失败保留日志和结论，不当作通过。

## r6 完整登记

脚本只适用于未登记的 r6；已经登记时拒绝重复创建。不要靠改 policyId 重跑来回避失败。先构建并冻结已验证 JAR，两个模式必须使用相同 JAR、脚本、策略、r5 final 和信任文件。

```sh
sh executor/python.sh -B scripts/p8/register_alert_only.py --mode rehearsal \
  --work .cache/p8/r6-rehearsal-01 --jar .cache/p8/backend.jar \
  --policy .cache/p1-20261015/r6/policy-alert-only.json
sh executor/python.sh -B scripts/p8/register_alert_only.py --mode business \
  --work .cache/p8/r6-business-01 --jar .cache/p8/backend.jar \
  --policy .cache/p1-20261015/r6/policy-alert-only.json \
  --rehearsal .cache/p8/r6-rehearsal-01/result.json
```

1. 业务库无人连接、Flyway V25、来源策略 reviewed、r5 正式 final 签名和哈希有效；只关闭模式和自动开关，其他字段完全相同。
2. 整库转储含 routines/triggers/events，恢复到随机库；全部表的有效结构、主键对应行摘要和行数必须一致。DOUBLE/FLOAT 按 IEEE 位摘要；JSON 数字经 MySQL 8 文本解析可能漂移 1 ULP，随 dump 另存 `json-double-fidelity.sql`，用 SQL DOUBLE + JSON_SET 在恢复库精确还原。两份 SQL 均须保存、核对 SHA 并按顺序恢复；不放宽逐行比较、不改源库。备份在 MySQL 服务的 `backups/`，不会放入仓库。
3. 演练在随机库；业务模式在新的恢复演练后才写 `cyber_security`，并核对业务库与成功演练开始时逐表一致。
4. 启动临时回环 mTLS 后端，真实登录 `g3-operator` 与 `guard-reviewer`；策略登记、独立审查、组合登记、签发/导入正式 final、仅 final 封存、独立批准。每步保存响应；r6 停在 approved，无资产绑定。
5. 比较所有表：业务增量仅策略 +1、组合 +1、组合能力 +4、评价 +1，另允许幂等、审计、会话、登录变化。已有业务/审计记录必须逐行不变，所有用户身份/凭据不变（仅两位操作账号登录时间允许变化）。业务增量还须与演练一致。
6. 停止本次后端并核对端口关闭，删除本次随机 schema，保留 dump、报告、日志与摘要。失败不自动恢复业务库；从已保存的步骤定位，禁止盲目重跑。

final 复用 r5 的 `evaluation` 和 `provenance`，`sourceEligibility=[]`，模型与规则来源分别标记 `alert_only`；绑定新 subject、策略与 health 1.0.0，不产生新模型成绩、PF 证据或现场能力结论。

## 独立备份与恢复验证

```sh
sh executor/python.sh -B scripts/p8/backup_restore.py
```

该入口调用同一整库备份/恢复实现，要求业务库无人连接；恢复到随机库、逐表核对后删除随机库，保留受控备份。它不能覆盖或回滚业务库。需要实际恢复时执行手册中的停写、额外备份、审批及恢复后验收流程。

## B3 初版部署工具链（2026-10-14）

B3 交付代码与临时目录/克隆验收；P1/A23 才执行实际安装、业务库迁移、真实采集及 lab PF 演示。命令从仓库根运行。外部路径用绝对路径；秘密只放 Keychain 或 0700 目录内的 0600 文件，不写 plist、命令行、Git 或终端。下面的环境变量只表示路径，不承载口令。

### 构建、生成与安装

```sh
sh executor/python.sh -B scripts/p8/launchd.py build --release "$SERVICE_ROOT" --java "$JDK25/bin/java"
sh executor/python.sh -B scripts/p8/launchd.py render --root "$SERVICE_ROOT" --release "$RELEASE" --java "$JDK25/bin/java" --mode alert-only --dry-run
sh executor/python.sh -B scripts/p8/launchd.py render --root "$SERVICE_ROOT" --release "$RELEASE" --java "$JDK25/bin/java" --mode alert-only
sh executor/python.sh -B scripts/p8/launchd.py install --root "$SERVICE_ROOT" --release "$RELEASE" --java "$JDK25/bin/java" --mode alert-only --dry-run
```

- `SERVICE_ROOT` 是独立服务根；`build` 要求干净的已提交源码和 JDK 25，执行 Maven 打包、`npm ci`/生产构建及 Go 构建，输出 `program/releases/<完整提交>/`。`RELEASE` 指向该目录。`release.json` 记录提交、UTC 构建时间及工具链版本；`SHA256SUMS` 绑定全部发布文件。安装验证文件集合与摘要，额外文件或缺失/变化均拒绝。相同目录不覆盖。
- 解释器默认采用调用脚本的 Python，须安装 `executor/requirements.txt`；生产可用 `--python` 指定受控解释器。plist 保存明确的动态库路径、绝对程序/配置/日志路径和 `Umask=0077`。管理员审核解释器与依赖后才安装 PF 服务。
- 默认 `alert-only`：五个普通用户 LaunchAgent；executor/recovery 使用零能力 `observer_executor.py`，只发心跳，不领取命令、不调用 PF、不签发清理证明。不能拿此入口证明 PF 已清空。发现旧执行器 SQLite 账本即拒绝使用。
- `--mode pf`：复用 `executor.services.launchd` 的参数契约，executor/recovery 只生成 LaunchDaemon 文件与说明，工具不 sudo。用户域只安装 backend、targets 和未启动的 sensor。管理员按生成说明先装 recovery 再装 executor；两者须使用独立 lab 配置与批准范围，不能套用真实主机只告警配置。
- 顺序：backend（等待真实 TLS 就绪）→ targets → recovery → executor → sensor。sensor 的 `RunAtLoad=false`、`KeepAlive=false`；在批准窗口内显式 `launchctl kickstart gui/<uid>/com.xyh.cyber-security.sensor`。`sensor_service.py` 每次生成新 bootId/spool，采集最长 30 分钟且不超过授权截止；崩溃或重启不会自动续采。BPF 权限准备仍属 P1。
- `render --dry-run` 输出 JSON，其中 `plists` 的值为完整 XML；不建目录、不读秘密、不调用 launchctl。正式 render 同时生成分服务 stdout/stderr 日志路径、newsyslog 轮转配置（每日或 10 MiB、保留 7 份；仅生成，不安装）。
- 实际 install/uninstall 要求 `--authorization-reference`，该参数是执行记录，不替代用户对 P1 的明确授权。安装不覆盖同名服务；卸载前核对全部 plist 是否仍为本工具生成的内容，遇到不同文件拒绝。只删除匹配的 LaunchAgent 文件，保留发布、配置、日志、账本。
- 卸载使用相同参数，把命令改为 `uninstall`；先用 `--dry-run` 审核逆序。PF 模式必须先由管理员停 executor、执行原 `executor cleanup/status` 核验零规则，再停 recovery；用户工具不会自动提权，无法读取/清理 root 账本时显式失败，按生成的管理员说明完成。失败时保留恢复器与账本，不把文件删除等同规则清理。

### P1.2 登记机器前的后端阶段（2026-10-16）

当本轮不包含 P1.5 机器登记时，使用 `launchd.py install --backend-only`，只安装后端 LaunchAgent；其他四个角色只生成配置模板，不启动。卸载同一阶段使用 `uninstall --backend-only`，只停止并移除匹配的后端 plist，保留全部运行材料。它不替代完整五服务安装或 D2 重启验收。

在 `config/backend-health.json` 中配置 `{"baseUrl":"https://127.0.0.1:18082","caFile":"<绝对 CA 文件路径>"}`，文件 0600、目录 0700。探针只允许回环 HTTPS、TLS 1.3 和私有 CA；安装在 bootstrap 前检查探针配置，缺项时不会先启动 Flyway。旧的完整安装仍兼容 `sensor.json` 的 upload 配置。分段状态用以下命令核验，不需要虚构 assetId 或机器凭据：

```sh
sh executor/python.sh -B scripts/p8/status.py --backend-root "$SERVICE_ROOT" --format json
```

结果的 `ok` 只表示后端阶段，固定 `mode=backend-only`、`fullDeploymentReady=false`，列明未验收服务、重启和 PF。之后进入完整安装时，先按原参数卸载本阶段后端入口，再用完成登记后的配置执行完整 install；数据库已到 V27，不重新执行旧迁移。传感器仍只能在另行批准窗口显式启动，不开机续采。

本轮运行制品复用 R1 已验证的 `cca4da0` release，完整 SHA 清单保持不变；分段安装和巡检工具从当前仓库运行，版本独立记录，不把已部署应用谎称为本轮工具提交重新构建。

### 真实主机登记与克隆验收

`enroll.py` 只用 v2 API。所需 plan 为私有 JSON（0600），包含：

| 字段 | 说明 |
|---|---|
| `bundleId`、`subjectSha256`、`profileSha256` | 固定 r6 ID `aa35ae6e-3b41-461d-8b54-cb4bb4726349`，从当前 approved/active 组合核对完整摘要，策略必须 `alert_only` |
| `assetKey`、`owner`、`root` | 本次独占的新资产名称、负责人、绝对服务目录 |
| `interface`、`localAddresses` | 一个明确接口及同一地址族的本机地址；不推定默认网卡或全网覆盖 |
| `validFrom`、`validUntil`、`evidenceRef`、`approvalReason` | 明确授权起止、依据与独立批准理由；时间归一为 UTC RFC3339；过期拒绝 |
| `applicant`、`reviewer` | 各含 `username`、`keychainService`，可选 `keychainAccount`；默认以 username 查 Keychain account，必须为两个不同人工身份 |
| `guardliveBinary` | 已构建二进制绝对路径，配置审批绑定实际 SHA |
| `targetPort` | 可选的回环 targets 端口，默认 18083 |
| `baseUrl`、`backendCA`、`backendTls` | 仅 authorized 模式使用；明确回环 HTTPS 入口；backendTls 含 `caFile`、`certificateFile`、`keyFile`，用于既有管理连接 |

```sh
sh executor/python.sh -B scripts/p8/enroll.py --target clone --plan "$PLAN" --work "$WORK" \
  --mysql-service "$MYSQL_SERVICE" --java "$JDK25/bin/java" --jar "$BACKEND_JAR" \
  --report-trust "$REPORT_TRUST" --artifacts "$ARTIFACTS"
```

默认来源为业务库，只读制作精确保真备份（含 JSON DOUBLE 补偿）并恢复到随机 `cyber_b3_clone_*`，新 JAR **只启动该隔离库**，Flyway V26 仅在克隆执行。`--source-schema` 可指定已准备的源库。复用同一 work/plan 重入；配置计划、请求内容、人工身份、幂等键与已取得结果持久化到 0600 `journal/state.json`。连接丢失时复用原键；机器凭据已签发但回包丢失时，查找本次独占资产的唯一机器并调用 B2 的 `credential-rotations`，不重复登记身份。该恢复分支依赖 B2 接口合入，接口缺失时停止并保留现场。多次轮换仍丢包会保存新轮换键，下一次重入再撤销未保存凭据。

按顺序：资产 → 观察授权（执行范围为空）→ 独立批准 → 传感器/执行器身份 → 配置及独立批准 → r6 激活 → 配置文件。输出 `config/sensor.json`、`targets.json`、`executor-observer.json`、0600 凭据、独立 collector/executor IPC 证书。`machine-tls.properties` 提供 `DEPLOY_TLS_CLIENT_CA` 引用，须纳入部署配置；传感器与观察执行器使用分离客户端证书，服务端 CA 仍由计划提供。deploy 机器接口要求 TLS 客户端证书及原 Bearer 凭据，浏览器可不持客户端证书。

克隆后端退出时停止本次 PID 并验证端口关闭；克隆与备份默认保留供重入和审查。验收收尾只删除 `clone.json` 记录、且确认由本次创建的随机 schema，不能按前缀批量删除。真实接入时换 `--target authorized --authorization-reference <与 evidenceRef 一致>`；仅在 P1 明确授权后执行。脚本始终停在配置生成，不启动抓包。

### lab 演示、巡检与备份

```sh
sh executor/python.sh -B scripts/p8/lab_demo.py --dry-run
sh executor/python.sh -B scripts/p8/status.py --plan "$STATUS_PLAN" --format json
sh executor/python.sh -B scripts/p8/status.py --plan "$STATUS_PLAN" --format text
sh executor/python.sh -B scripts/p8/backup_restore.py --schedule
```

`lab_demo.py` 复用 `lab_formal.py` 的正式组件，但只选第一个冻结 brute_force 场景，授权窗口严格 ≤30 分钟；核验同一命令的已投影 `applied` 与 `expired`、执行器零规则与 root 清理结果。无论成功/失败都尝试撤销本次授权、暂停组合并保存收尾结果；不生成/导入 G3 报告、不调用资格登记。r5 有其他仍有效的活动资产绑定时拒绝演示，避免暂停影响其他任务。

实际运行沿用 `scripts/p7/lab.md` 的显式 JAR、冻结场景、selection、r5 import plan、r5 subject、platform/final、report trust、克隆/业务库和 rendezvous 参数，另加 `--root-plan <0600 JSON>`。root plan 包含 `launcher`、`launcherSha256`、`stage`、`manifestSha256`、`runId`、`authorizationReference`、`evidenceCopy`；`--stage-manifest` 与 `--authorization-reference` 必须逐字匹配。先核验摘要，再由 macOS 密码框让用户批准 root 暂存启动器；口令不进入脚本。root 的 `g3-executor` 最长 1800 秒，原执行器代码与 r5 冻结证据不变。**B3 只验证 dry-run 和流程替身，真实 root/PF 留待 P1/U5。**

巡检计划含 `root`、`assetId`、`executorId`、`mode`（`alert-only`/`pf`）、`baseUrl`、`backendCA`、`reader`（同 Keychain 身份字段，可用 auditor）；可设 `minFreeBytes`、`maxLogBytes`。巡检五服务、现有 `/health/ready`、v2 `ops/status`、最新心跳/健康、本执行器专属 PF anchor（`pfctl -s rules` 只读）及磁盘/日志。机器状态完整读取游标分页（最多 100 页，重复游标拒绝）；按每个传感器查询最新接收的一个健康窗口，历史窗口超过 200 条不影响当前状态，缺失的传感器窗口不能被其他传感器掩盖。无权限读取 PF、缺数据、心跳陈旧、机器分页未覆盖或异常均非零退出；不会把 unknown 或 `replay_healthy` 当现场 healthy。PF 查询需要相应系统权限，B3 未执行该查询。

`backup_restore.py --schedule` 仅显示维护窗口、备份保留和核验建议，不取密、不连库、不安装定时任务。
