# lab 验证会话契约 v1.1

2026-10-12，B4/L1—L4 与阶段 0 K5—K7。当前结构版本 `host-guard-lab/1.1`，兼容 `host-guard-lab/1.0`，报告口径 `host-guard-g3-report/1.0`。这是独立的会话协议，不修改 rc.2 观察、rc.4 策略或 J1 v9 评分规则。开发只使用合成事实；真实 G3 仍须 J1/J2、P5/P6、专项授权和网络层隔离。

## 身份、摘要及准入

创建请求为 `{sessionRef, sha256, runnerIdentity}`。引用必须在后端配置的 artifact-root 中；`sha256` 是**签名封装文件原字节** SHA-256。封装沿用 `GuardSignatures` 的 `{payload,keyId,algorithm,signature}`，Ed25519 签署 payload 的 RFC8785 JCS；runner 必须在现有 report-trust-file 登记。`sessionSha256` 则是 payload 的 JCS 摘要，二者不能互换。

payload 的字段见 [合成示例](examples/lab-session.json)。身份绑定包括外部 sessionId、lab assetId、lab bundleId/subjectSha256、authorizationId/revision、sensorId/bootId、executorId/executorBootId、runnerIdentity、有效期和超时秒数。会话一经创建不可换输入、身份或时间偏移；恢复使用同一会话，换 boot 必须另建会话。同一 sensor/boot 只能绑定一个会话，避免历史观察跨会话复用。

`scenarioRef/scenarioSha256` 与 `mappingRef/mappingSha256` 绑定两个原字节文件：

- 场景：`{contractVersion, scenarios:[{scenarioId,family,source,ruleId,trialAutoEligible,autoIneligibleReason,pcapRef,pcapSha256,sourceStart,sourceEnd}]}`。family 为 normal 或四攻击类；source 为 model/rule，rule 来源必须给 ruleId，model 为 null。`trialAutoEligible` 只表示本次试验拟验证的来源资格，不是 G3 已通过或平台自动资格。
- 映射：`{contractVersion,mappingId,sessionId,entries:[{scenarioId,targetBindingId,peerKey,keyEpoch,captureScopeId,targetRef}]}`。v1.0 每场景一个登记目标；v1.1 攻击场景仍一个，normal 场景可按原始对端登记多个独立目标（全会话最多 256 条）；原始 peer 的脱敏映射由签名 runner 与隔离证明核验，不接收任意地址或 shell 命令。既有目标绑定负责协议、方向、端口、预算目标及执行器身份；与授权 executionScopes 同时匹配才可准入。normal 和 attack 不可共享 targetRef。

  targetBindingId/targetRef 是初始租约锚点，并不延长现有 15 秒租约。后续可换 targetRef，但必须属于同一稳定预算目标、scopeDigest、sensor/boot、executor/boot；每条观察/命令按其实际发生时刻复核租约。开始/恢复读取该稳定目标的最新有效租约。续租由传感器/执行器线负责，本线不会制造或延长租约。
- `provenance` 固定 datasetSha256、splitSha256、labelRulesSha256、codeSha256、modelSha256、policySha256、extractorSha256、executorSha256。模型/策略/提取器/评价计划摘要与 release subject/登记事实复核；数据、切分和标签规则由签名 P6 证据绑定。
- `proofs` 的 p5/p6/isolation/admission 都为 `{ref,sha256,runnerIdentity}` 签名文件。p5/p6 沿用 platform/final 报告 subject 和 protocolVersions；p5 绑定 executorSha256，p6 绑定 provenance 中的数据/切分/标签摘要与 sourceEligibility。隔离证明绑定 sessionId、assetId、mappingSha256、executorId、validUntil、networkIsolationVerified=true；必须由不同于 runner 的预配隔离核验身份签署。admission 绑定 sessionId/subjectSha256、J1/J2 已通过、M2 至少两类且含 brute_force。合成模式也核验签名及绑定，但不要求 J1/J2 已通过；执行门始终拒绝其真实动作，报告永远 `passed=false`。

创建、批准、开始和恢复都复核当前授权、资产、机器、输入和签名。`evaluation.run` 仅能申请/运行评价；批准另需 `authorization.approve` 且申请人与批准人不同。本线不会激活 bundle、调用适配器或创建/领取命令。已登记会话的 sensor 在既有 GuardEligibility 判定与领取路径附加会话门：资格/运行/授权到期、撤销、超时或换 boot 时拒绝新动作；清理和回执继续可用。未登记过会话的旧 P5 平台测试入口保留兼容。发布组合必须是 lab 环境且已独立批准（status 为 approved，或批准后已激活的 active；approved_by 非空）——candidate、evaluated、suspended、retired 及任何 research 组合一律以 `LAB_ENVIRONMENT_INVALID`/`LAB_BUNDLE_NOT_APPROVED` 拒绝。批准组合不等于已取得本次 G3 要证明的 `lab_auto` 类别等级；P5/P6 及专项授权仍是必需条件。

## 方案 B：联合封存与类别等级分开

方案 B 的目标状态路径为 candidate → 导入同 subject 的 final、platform、canary → evaluated（封存）→ 独立批准 approved → 仅 lab 资产绑定后 active → 独立批准 lab 会话 → G3 运行 → 追加 G3 报告 → 按来源登记 lab_auto。继续使用 V25，不增加 trial 状态或 V26。P5 platform/canary 是针对该 subject 的平台联合运行证据；G3 报告是后续类别闭环证据。

组合批准、平台能力表中的 lab_auto 和 G3 类别等级分别表示不同事实。G3 导入允许 approved/active 的 lab 组合；其他环境或已撤销组合拒绝。只有正式 lab 会话已 completed、正常时长与误封恢复通过、命令/决策无未关联项、全部命令已核验清理，才为同一来源全部登记场景通过且明确 trialAutoEligible 的类别/来源追加 lab_auto。未通过类别不会抹掉其他通过来源；synthetic 永不登记等级。登记保存到不可变 report 事件并引用 guard_evaluation_run，不改写冻结策略或平台能力表。GET /lab-validation-runs/{id}/qualifications 返回来源、评价引用、subject 和组合当前是否可用。

K6 subject_report.py 必须重算完整 subject 的 JCS，并核对运行前冻结的 subject 与 root 运行记录、实际执行配置一致。正式 platform/canary 还须由 `--execution-context` 提供 `cloneSchema`、至少两份 `{sha256,keyId}` 引导报告原字节摘要、`businessBefore/businessAfter` 逐表 `{rows,sha256}`、`sourceBundle/cloneBundle` 的 `{bundleId,subjectSha256}` 及 `subjectMatchesSource=true`。生成与验签均要求源库前后逐表一致、两个 bundle 绑定与本次完整 subject 一致；原有真实 PF、root 记录和运行时绑定门禁不变。上下文摘要由编排器对源库读取生成，报告工具不以自报布尔值代替数据库读取。旧平台证据缺失该绑定时只能保留其历史含义，不得事后补签为 r4 证据。正式报告仍须 A6 真实运行后签发；隔离 schema 的专用 synthetic 信任文件不进入业务库。

`/release-bundles/{id}/imports` 在验签后显式拒绝 `evidenceKind=bootstrap` 或 `synthetic`，错误码 `REPORT_EVIDENCE_KIND_NOT_ALLOWED`；仅隔离克隆启动时可显式设置 `cyber.guard.bootstrap-reports-enabled=true`。该开关缺省为 false，lab profile 和业务库启动方式均不默认开启。K7-R 隔离演练显式开启它；正式 K6 `subject_report.py` 的报告固定为 `evidenceKind=real_pf`，不得带引导或合成类别。报告身份验签和既有封存、独立批准检查仍须逐项通过。

### E3/r4 前置闭环与 K9 引导克隆（2026-10-12）

2026-10-12 用户采纳 K9，并确认“不得绕过批准或激活”只约束业务库。

**闭环**：真实 E3 由后端经 `GuardEligibility.authorized` 签发命令，要求被测组合已 active；r4 封存需要同 subject 的 platform 报告，而该报告只能来自 r4 已 active 时的 E3。`pf_engine_canary` 使用本地签名命令，只核对执行配置的 subject 绑定，不经过组合状态，不在闭环内。K6 工具可测，但旧组合的 E3 结果不能标为 r4；在 K9 交付前，`lab_run.py --mode pf` 继续在任何副作用前返回 `LAB_PF_BLOCKED_BY_R4_E3_PRECONDITION`。

**可解环的依据**：subject 是模型/清单、策略、profile、提取器、评价计划、能力 ID 与环境的 JCS，不含 bundleId、状态和审批记录。K7-R 在业务库克隆中新建的组合 subject `f02022ba…` 与 J2-3 的 r4 subject 逐位一致。因此同一 subject 可以先在隔离克隆中激活，而业务库的治理顺序保持不变。

**K9 路径**（仍属方案 B，不改状态机，不新增 trial 或 V26）：

1. A18 完成后，r4 在业务库为 candidate，已导入重新签发的正式 final。将业务库克隆到随机 schema，并沿用 J2-3/K7 的克隆和前后摘要核对。克隆中 r4 的 bundleId 与 subject 均与业务库相同。
2. 克隆中由 E3 引导专用签名身份签发 platform/canary 引导报告（`evidenceKind=bootstrap`），这些报告只受克隆后端的引导 trust 文件信任。随后导入、封存，由克隆内独立审批人批准，并只绑定克隆中的回环 lab 资产后激活。
3. 在 A6 授权轮次内，经 root 暂存副本运行真实 E3（`peer_service`/`peer_inbound` × revoke/disconnect/receipt_loss）并连接克隆后端；同轮运行 `pf_engine_canary`。`HOSTGUARD_SUBJECT_BINDING` 为业务库 r4 的 bundleId 与完整 subject，执行器在执行前核验。
4. K6 `subject_report.py` 以正式 runner 身份生成、签名并验签 platform 与 canary 报告。报告附 `executionContext`，包括克隆 schema、引导报告摘要、克隆前后业务库摘要，审查人可见运行时组合状态来自引导。
5. 删除克隆 schema，核对业务库前后一致。
6. 业务库：导入正式 platform/canary → 封存 → `guard-reviewer` 独立批准 → 仅 lab 资产激活（另行授权）→ 独立批准会话 → G3 → 追加报告并按来源登记 lab_auto。

**不属于禁止的绕过**：业务库的证据、封存、批准、激活顺序不变，引导报告无法进入业务库；正式报告证明的是真实 PF 对该 subject 命令的执行，克隆中的激活只是测试台状态，与现有 E3 夹具用夹具签名报告激活夹具组合同性质；不复用旧 subject 证据，不改冻结策略、阈值或片段。引导报告、克隆审批记录和克隆内 G3 结果一律不得作为正式证据。若用户不接受克隆内引导激活，则只能改走方案 A（trial 状态 + V26）。

**实施状态（2026-10-12，无授权部分已完成）**：

- 入口为 `scripts/p5/e3_bootstrap.py`。所有拒绝都发生在建目录或克隆之前：rehearse 只接受 `cyber_guard_*` 隔离源，pf 只接受业务库、A6 引用和正式 final。克隆中由 `GuardE3SubjectTest#subjectBootstrap` 导入 `e3-bootstrap-*` 报告，然后封存，并由克隆内独立审批人批准；`#subjectMatrix` 每轮新建回环 lab 资产并只对它激活。
- 执行器配置登记组合的全部能力。`peer_service` 的服务端口取冻结片段的原端口（brute_force-1 为 21），capabilityHash 与控制面重算结果一致。
- 观察由 `guardlive` 以 research 模式 1 倍速实时回放冻结片段生成，采集起点用登记的 `captureStart`（与 lab 回放相同的预热，上下文覆盖从此起算）。上传侧只改 `environment`、`peerKey`（canary 对端键，由执行器启动时提供）、`targetRef`/`targetExpiresAt` 和 `quality.clockSkewMs`（由上传心跳实测）；执行引用的判定规则与 `guardlab.MapEmission` 相同，且满足观察契约 `targetExpiresAt ∈ [lastPacketAt, lastPacketAt+15s]`。租约在首条可执行报文出现时按该报文时刻申请；之后按批次最新报文刷新同一引用的最近报文时刻，不重复登记，也不延长控制面登记的截止。特征和上下文原样上送；回放原件与映射后的 JSONL 都保留摘要。
- **K9-6 第 10 次演练通过（2026-10-12，synthetic）**：S2 克隆内六轮 E3 全部通过。`peer_service` 用 brute_force-1，模型来源，约 4.7 秒形成动作；`peer_inbound` 用 port_scan-1，模型来源，首批 500 条观察约 2.8 秒形成动作。决策都绑定 subject `f02022ba…`，执行前已核验，规则全部清理。K6 synthetic platform 生成并验签。S1 中开关关闭时引导报告与 synthetic 报告都以 `REPORT_EVIDENCE_KIND_NOT_ALLOWED` 被拒；开关开启后用 K6 platform 封存并由独立审批人批准，`lab_run` 复用该组合只在 lab 资产激活，port_scan-1 会话完成并导入报告。业务库前后一致，S1、S2 与 lab 克隆都已删除。第 1—9 次的失败原因逐次记录在 `.cache/k9-20261012/k9-6/attempts.json`。
- **K9-B1（2026-10-12 用户选 (a) 并已实施）**：`GuardEligibility.matchingCapability` 要求能力的 `profile` 与触发观察的 `profile` 完全相同。r4 的 4 条 lab_auto 能力（T3.8b 登记）都是 `flow-prefix-v1`，但 r4 策略的 `acceptedProfiles` 同时接受 `flow-final-v1`，而端口扫描连接极短，只产生 `flow-final-v1` 快照。因此 port_scan 的模型和 `scan-ports` 规则在 T1 一律得到 `CAPABILITY_NOT_SUPPORTED`，真实部署中不可能自动封禁。K7-R 第 15 次的 port_scan 候选（模型 69、规则 67）全部由 final 快照触发，只是 hypothetical 投影不评估能力门，所以没有暴露。brute_force、dos_slow 的多数候选来自 prefix 快照，不受影响。处理方式：能力 profile 改为按已审查策略的 `acceptedProfiles` 兼容（规则见[契约说明](README.md#可选-acceptedprofiles2026-10-11)）。模型交付包、策略、能力登记与 r4 subject 都不变，只是让策略已接受的 final 快照也能走到后续执行门。

## 时钟

time 包含 sourceStart、labStart、offsetMicros、warmupStart、scoringStart、scoringEnd。后三者是原始时间域，满足 sourceStart ≤ warmupStart ≤ scoringStart < scoringEnd；`labStart = sourceStart + offsetMicros`，speed 固定 1。各场景 sourceStart/sourceEnd 在评分窗口内。v1.0 观察使用同一固定偏移；v1.1 增加 time.scenarioOffsets（完整 scenarioId → 微秒偏移）与场景 captureStart，每场景各冻结一个偏移。该场景的全部报文和因果时间同量平移，保留原间隔/特征；所有场景并发，正常评分窗口覆盖攻击评分窗口。captureStart 不晚于 sourceStart，平移后的完整采集窗口必须在授权内。恢复不得重新选择任何偏移。接收、命令及执行回执使用真实 UTC 墙钟。开始时必须尚未越过平移后的 warmupStart；恢复不重置偏移。没有时间的事件保留 null，不以 now 补齐发生时刻。

## API、权限与状态

所有人工写接口使用原有 session/CSRF 与 UUID `Idempotency-Key`；除创建外需 `If-Match`（正整数 revision）。重复请求先核验当前权限，再读取幂等结果；新键也受自然唯一键及合法迁移约束。

| 方法/路径（前缀 /api/v2） | 权限与语义 |
|---|---|
| POST /lab-validation-runs | evaluation.run，201；创建 pending 资格 / registered 运行 |
| GET /lab-validation-runs | evaluation.read；`cursor,limit(1—200),status`（运行状态），资产范围谓词在 LIMIT 前执行，不可见游标 404 |
| GET /lab-validation-runs/{id} | evaluation.read，资产范围内返回脱敏状态、引用和摘要 |
| POST /lab-validation-runs/{id}/decisions | authorization.approve；`{decision:approve/reject,reason}`，独立批准 |
| POST /lab-validation-runs/{id}/starts | evaluation.run；`{}`，active 资格才能 registered→running |
| POST /lab-validation-runs/{id}/interruptions | evaluation.run；`{reason}`，running→interrupted |
| POST /lab-validation-runs/{id}/resumptions | evaluation.run；`{}`，复核后 interrupted→running，不换身份/时钟 |
| POST /lab-validation-runs/{id}/completions | evaluation.run；`{outcome:completed/failed,reason}`，运行结束不等于 G3 通过 |
| POST /lab-validation-runs/{id}/revocations | automation.stop；`{reason}`，即任务单的“作废”：撤销资格、未终态运行置 cancelled 并记停止请求，不声称规则已清理 |
| POST /lab-validation-runs/{id}/reconciliations | evaluation.run；`{}`，过期→expired，运行超时→interrupted；不发送动作 |
| POST /lab-validation-runs/{id}/events | evaluation.run；登记下节的事实引用，追加，不修改终态 |
| GET /lab-validation-runs/{id}/qualifications | evaluation.read；已登记来源等级及当前组合可用性 |
| GET /lab-validation-runs/{id}/events?after=0&limit=50 | evaluation.read；会话内递增序号游标，limit 1—200 |
| GET /lab-validation-runs/{id}/report-input | evaluation.read；导出固定格式快照供纯离线报告工具 |
| POST /lab-validation-runs/{id}/reports | evaluation.run；`{reportRef,sha256,runnerIdentity}`，验签且逐字段对比服务端重算结果 |
| GET /machine/sensors/{sensorId}/lab-validation-runs/{id} | machine.sensor.read；仅本会话 sensor/asset/boot，可读交接契约 |

机器查询的 `state` 增加 `runnable` 和 `reasonCodes`。消费端必须检查 `runnable === true`，不能只看 active/running。当前授权、修订、资产环境、执行身份、发布组合或冻结元数据/签名失效时，仍返回该结构但 runnable=false，reasonCodes 包含原稳定码；归属或 boot 不符仍顶层拒绝。非活动资格为 LAB_ELIGIBILITY_INACTIVE，运行非 running 为 LAB_RUN_NOT_RUNNING，超时为 LAB_RUN_TIMED_OUT，合成模式为 LAB_SYNTHETIC_ONLY。此轮询不检查短租约，也不重复读取整个 PCAP；租约由独立链路逐包核验，PCAP 在首次登记及开始/恢复时校验原件。

V20 `status` 仍仅 pending/active/revoked；过期返回独立 effectiveEligibility=expired，底层授权被撤销或版本变化返回 blocked/blockedReason，不把 completed 塞入资格列。运行状态 registered/running/interrupted/completed/failed/cancelled/expired。终态不倒退，允许迟到的清理证据追加。GET 不写库；有效期和超时即时影响可运行性，显式 reconciliation 追加状态事实。停止请求、规则清理和报告导入彼此独立。非法迁移（未开始就完成、完成后再开始/恢复、终态后再中断）统一 422 `STATE_CONFLICT`。

research 与 lab 互不混用：`/replay-runs` 只接受白名单字段（多余的 environment/runKind 等字段 400 `UNKNOWN_FIELD`）和已批准 research 组合，lab 组合以 `REPLAY_BUNDLE_NOT_APPROVED` 拒绝，开始时绑定的传感器所属资产也必须是 research；`/lab-validation-runs` 只接受 environment=lab 的签名清单、lab 资产和 lab 组合，research 资产/组合以 `LAB_ENVIRONMENT_INVALID` 拒绝。两条路由的 ID 分属不同表，交叉引用返回 404。会话报告导入固定 run_kind=canary，通用 release-bundles/imports 拒绝 G3 报告版本。

## 运行事实

事件请求：`{eventId,scenarioId,kind,referenceId}`；kind 为 observation/decision/command/receipt/verified_receipt。referenceId 引用已有后台事实；不接收客户端自报 applied/cleared 或任意时间。decision 的触发观察与所有选择观察必须属于当前绑定、时间窗和目标，command/action 必须沿同一 decision 链。verified_receipt 还须已有 projected=true、同 executor/boot 的有效 reconciliation；使用实际核验时刻。普通 receipt 保持 unverified，dispatched/issued 不作 applied；撤销请求和 TTL 到时不作 cleared。事件保留 source/rule/family、外部链路 ID、拒绝原因、原发生时间、接收时间和摘要。

采集与事件采用不同口径：传感器继续上传全部合法观察，包括预热、低质量、过期或空 targetRef；中央 observation 事件只引用该场景 sourceStart/sourceEnd 内且有可用 targetRef 的观察。预热/评分窗外观察进入 `quality.outsideScoringWindow`，不进入评分分母或执行证据。已知身份且触发观察在窗外的决策列入 `outsideScoringDecisionIds`；身份或时刻未知的决策仍需关联。所有命令始终检查，不因窗外而隐藏。

预热观察的执行引用在传感器发射时清空；上下文和完整遥测仍保留。正式 G3 编排在签名前冻结错峰的 scenarioOffsets：扫描起点评分延后 0/20/40 秒，暴力破解 120/140/160 秒，慢速 300/320/340 秒，洪泛 480/500/520 秒；六段正常分别延后 0/60/120/180/240/300 秒。每段原始预热时长、评分长度、PCAP 字节及 1 倍速不变，不修改共享资产预算；既有 research/合成替身默认时钟不变，恢复仍只复用原签名偏移。

`quality.qualified` 与 `qualifiedCoverage` 保留纯采集质量含义。新增 `executionQualified`/`executionQualifiedCoverage` 还要求评分窗、有效引用和接收时效；`nonExecutable`、`missingTargetRef`、`expiredTargetRef`、`staleEvidence`、`invalidTiming` 分别保留拒绝原因计数（可重叠）。10 秒时效按观察 asOf 到不可变后端入库 created_at 计算，不用报告生成时刻，也不补造未知时间或新租约。空引用或已登记但到期的引用不使诊断报告失败；非空引用的跨资产、稳定目标、scopeDigest 或 boot 冲突仍硬拒绝。executionQualified 只表示当时具备这些必要关联条件，不代表已执行动作。拟自动来源没有合资格执行观察时不能通过。

场景结束另用 `{eventId,scenarioId,kind:scenario_result,reportRef,sha256}`，只接受本 session runner 签名的 `{contractVersion,sessionId,sessionSha256,scenarioId,mappingSha256,startedAt,endedAt,completed}`；起止必须覆盖预登记场景且不在未来。此证据仅说明 runner 的回放结束，质量计数和观察数量由后端事实重算，不接受 runner 自报成功或误封禁数。缺失场景结束证据不计正常完整时长。

重复 eventId 或同 kind/referenceId 自然键必须内容一致；冲突 409。不因乱序回执倒退运行终态。映射/身份/作用域拒绝使用稳定错误码，错误日志不含原始端点。输入快照有界且超限明确报错，不静默截断报告；unlinkedCommandIds/unlinkedDecisionIds 列出遗漏事实，任一非空不能判通过。

## 报告

采用健康 1.1.0 的正式文件回放，G3 报告及 closeout 必须声明：健康门为文件回放口径（1.1.0 file_replay），证明回放完整、无容量丢弃，不证明现场采集健康；现场健康观察器接入仍属 P8 B5.4。另列评分窗口内 `replay_healthy` 覆盖及观察质量覆盖；回放健康不能用于预算恢复，r3/r4 的历史证据不改标为 r5。

报告为现有签名封装中的 canary payload，带 `reportVersion`、protocolVersions、subjectSha256、evaluationPlanSha256、sessionId/sessionSha256、inputSha256、provenance、每场景时间线（labStart→firstAlertAt→firstIssuedAt→firstAppliedAt→lastClearedAt 及 alert/issue/application/cleanupLatencyMs）、`classes` 逐类结果（四攻击类按名称排序；场景、来源、最差状态、首个告警/生效时延，无场景为 not_evaluated）和 `unverifiedItems` 未验证项（场景缺口、缺类、未关联命令/决策、正常时长缺失、运行未完成、合成证据，顺序固定）。生成、签名、验签、导入、封存、批准、激活是独立步骤。签名复用 P5 报告的 Ed25519/JCS 封装与私钥规则，验签只信任既有 report-trust-file。导入复用 guard_evaluation_run；合成或不完整报告可保存诊断，但不具有 passed 状态。

四类告警、所有拟自动来源的 verified applied/cleared、每条已签发命令的清理、正常累计 ≥1800000ms 且误封禁率≤1次/小时为计算项。正常时长按已完成场景相加，另列同一资产时间区间并集，不能说成单主机连续观测；边界频率用整数交叉乘法判断。质量同时给出合格快照比例 qualifiedCoverage。正常误封禁必须有 expired 核验来证明 TTL 恢复，单独 revoked 只证明人工清理。误封禁按 normal 场景实际核验 applied 的不同 command 计数；缺失 applied 但已核验清理的命令保持不确定，不当作零误封。

质量由原始观察重算：quality 标志全 false 且时钟可信才计合格；offload、不可判定及分母明确列出。洪泛/慢速无合格覆盖不得宣称类别自动资格。攻击起点到告警/生效时延只报告，不套用 J1 的 2 秒门槛。结果区分 passed/failed/not_evaluated/unverified，合成数据额外标 synthetic，不形成正式 G3 通过。固定保留 L3 慢速 0/29、困难良性 0/42、L2 未评估和测试集范围局限。

## 存储与并行集成

本线按任务单使用 V25（紧接 V24）；不修改 V1—V24 的 SQL 原字节或 Flyway 历史。V20 保存不可变资格；V25 新增 guard_lab_run 状态投影与 guard_lab_event 追加事实，复用既有观察/动作/回执与 guard_evaluation_run。JCS 原件以 LONGTEXT 保存并 JSON_VALID 检查，避免 MySQL JSON 数值改写。迁移测试覆盖空库到 V25 与 V24→V25 单步，已随 PR #29—#31 集成验证；本次阶段 0 的复验结果记录在受控交接目录。

独立 GuardLab* 控制器/服务/mapper 避开 GuardQueries、GuardReplay、GuardDetection、GuardIngest 和 GuardMapper/Store 的并行修改。GuardEligibility 仅追加可选注入的会话门及一次授权前置检查，GuardCatalog 仅增加 G3 报告分流拒绝。其他并行线如需迁移应另取 V26 及以上；若版本号冲突，不开 outOfOrder 绕过，由集成人重新分配尚未落库的迁移号。业务库迁移、真实 lab、报告批准和激活均需后续独立授权。
