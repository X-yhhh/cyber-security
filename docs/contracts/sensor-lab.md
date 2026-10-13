# 传感器 lab 接入与隔离验证

更新于 2026-10-11。传感器接入线（任务单 6.3 L3）S-A—S-D 的设计与代码边界，已于 2026-10-11 合入 main：`mvn test` 445 项 0 失败（含 `GuardSensorHealthIntegrationTest`），相关 Go 包 `-race` 通过，`guardtargets` 已重编译、执行器 mTLS/engine 51 项通过；未部署、未在真实 lab 运行。本线以 `d103cfd` 为基线，在独立 worktree `feat/l3-sensor-lab` 开发；没有修改 K2 的上传/spool 实现、业务数据库迁移、模型、特征公式、PF/WFP 或前端。

## 1. 入口与身份

新增模块 `sensor/internal/guardlab`，由 `guardlive` 使用。沿用 rc.2 观察，不增加观察字段；会话关联通过固定的 sensor/boot、映射和旁路事件完成。

机器接口为 `GET /api/v2/machine/sensors/{sensorId}/lab-validation-runs/{id}`，权限仍为 `machine.sensor.read`，响应为 `{state,manifest,mapping,scenarios}`。消费 `host-guard-lab/1.0` 和 `host-guard-lab/1.1`（完整定义由该线的 `docs/contracts/lab-validation.md` 提供）。本线要求：

- `state.runnable=true`、`reasonCodes=[]`、`blockedReason=null`、active/running、无停止请求、未超时/结束；`evidenceKind=lab`。合成会话默认拒绝；显式 lab.rehearsal=true 时仅接受 reasonCodes=[LAB_SYNTHETIC_ONLY] 且其余准入正常的 synthetic 会话，真实执行门仍关闭。
- `sessionSha256` 必须同时等于配置中的固定摘要、服务端摘要和 manifest 的 JCS 摘要。它不是签名封装原字节的 `manifestSha256`。
- 配置的 `runId` 必须等于 `state.id` 与 `manifest.sessionId`；配置的 `mappingSha256` 必须等于 `manifest.mappingSha256` 及私有映射中的 `mappingSha256`。任一缺失或不符即 `LAB_ADMISSION_REJECTED`/`LAB_MAPPING_REJECTED`，不开始回放。
- 场景 `scenarioId` 格式、`family`（normal/port_scan/brute_force/dos_flood/dos_slow）与 `source`（model/rule）按 lab 线同一规则复核；传感器另要求各映射条目 `peerKey` 互不相同（比 lab 线只要求 targetRef 唯一更严）。
- asset/sensor/boot、有效期、映射、场景与程序绑定相符。后台 `runnable` 负责当前资产授权修订、执行器、bundle、冻结文件和签名证据的复核，不能仅凭 active/running 放行。
- 开始前及之后每秒读取机器接口；请求最多等待 1 秒。拒绝、断连或不可变内容变化立即取消回放及上传。当前进程失败后不自动恢复。

lab 后端与传感器已由 PR #29—#31 合入，wire 字段与 `GuardLabSessions.machine/view` 对齐（见第 6 节）。缺少 `runnable` 的旧后端仍不可放行。GET 和传感器均不改变 session 的运行状态、不激活模型或签发命令。

## 2. 私有映射

`guardlive` 配置新增可选 `lab`：

| 字段 | 语义 |
|---|---|
| runId / sessionSha256 | 中央会话 ID（= manifest.sessionId = 机器接口路径 `{id}`）/ 不可变 payload JCS 摘要 |
| mappingSha256 | 中央映射文件原字节 SHA-256（= manifest.mappingSha256）；交接只给 JCS 内容，传感器无法重算原字节，故由运维显式填写并与后台及私有映射三方核对 |
| scenarioId | 本次首个场景 |
| mappingFile / trustFile | 本机签名映射、预配 runner 公钥表的绝对路径 |
| eventsFile | 不存在的私有 JSONL 路径，保存待登记的观察引用 |
| targets | `baseUrl/caFile/certificateFile/keyFile`，仅回环 HTTPS collector 身份 |
| inputs（可选） | `{scenarioId,path}` 列表，配合 `-lab-plan`；v1.0 按原事件时间排序，v1.1 按各场景冻结时钟并发 |

映射文件使用与 `GuardSignatures` 一致的 `{payload,keyId,algorithm,signature}`。`algorithm=Ed25519`，签名是 payload JCS 的无填充 base64url；trustFile 将 runner 名称映射为标准 base64 编码的 X.509 DER 公钥。签名者必须是 manifest.runnerIdentity。映射和 trustFile 均为 0600 普通文件，不接受符号链接。

payload 的 contractVersion 与会话对应，为 `host-guard-sensor-mapping/1.0` 或 `host-guard-sensor-mapping/1.1`，必填：

- `sessionId,sessionSha256,mappingId,mappingSha256,scenarioSha256`：绑定中央登记。
- `buildSha256`：本次独立 guardlive 可执行文件原字节摘要；`extractorSha256`：与中央 provenance 一致。
- `entries`：v1.0 每场景一个对象；v1.1 normal 按对端拆成多个对象，攻击场景仍一个。字段为 `scenarioId,originalLocal,originalPeer,canaryLocal,canaryPeer,peerKey,direction,transport,addressFamily,scope,servicePort`。

当前可信解析器仅按 TCP/IPv4 实现，因此其他协议/地址族明确拒绝。方向与服务端口必须保持；`peer_inbound` 只允许 inbound。不同来源、不同 canary 一一对应，不允许把 normal 与 attack 合并：运行中每个 targetRef 只能归属一个场景，解析器返回其他场景已使用的引用或其他场景登记的初始锚点 targetRef 时，会话以 `LAB_TARGET_LEASE_UNAVAILABLE` 粘性失败。`peerKey` 必须等于当前 asset/sensor/keyEpoch 和密钥对 canary 地址算出的既有域分离 HMAC。

PCAP 仅读取，启动前后校验原字节摘要，并逐包核验登记端点、方向对应的服务端口、协议及范围。未经登记的来源、混杂源或坏头不修补、不忽略后继续。原始地址和 canary 地址只用于本机解析及映射，不加入模型输入。映射仅替换上送的 peerKey 和本机解析端点，数值特征、类别特征及因果提取公式保持原样。

## 3. 独立可信登记器

`guardtargets` 配置可增加 `registration`。该对象只放在独立可信解析器进程，不能放到传感器配置：

| 字段 | 语义 |
|---|---|
| backend | 后端 HTTPS 根地址及 mTLS CA/证书/私钥文件 |
| credentialFile | 具有 `machine.target.bind` 的独立机器身份；不需要 command.claim |
| executorId | 与 scope.executorBootId 对应的登记执行身份 |
| budgetKeyFile | 与既有执行器一致的稳定预算 HMAC 密钥 |
| identityFile | 本登记器私有连续性文件；绑定 asset/environment/executor/密钥摘要 |
| allowed | 可信安装者登记的 canary 白名单；每项 `local,peer,peerKey,direction,scope,servicePort` |

collector 仍只请求 `/v1/targets/lease`。注册表确认本机身份、报文新鲜度及 scope 后，登记器使用独立身份调用现有 `/machine/executors/{id}/target-bindings`；得到后台确认才把引用交给 collector。sensor 不读取预算密钥、稳定 token 或执行器凭据。此进程没有命令领取、PF 或预算清零代码。

新登记模式下，同一 targetRef 的 expiresAt 保持不变；过期后才换引用。引用按执行范围复用：同一 peer_inbound 目标的 TCP 临时端口不拆分租约；peer_service 的服务端口仍隔离。执行范围、地址、方向、传感器和启动身份不同均不得共用。定时快照在租约过期后清空执行引用，不以无新包快照续租；新包租约失败仍停止会话。每次新包更新解析器看到的 lastPacketAt，但不延长同一已持久绑定。后台登记使用由 targetRef 确定的 bindingId 和相同请求字节；响应丢失最多重试一次，4xx 不重试。未确认的引用不能解析为可执行目标。旧 `NewTargetRegistry` 和未配置 registration 的使用方式保持原行为。

稳定 token 与 Python `Engine.stable_target` 使用同一 JCS/HMAC 算法，忽略 boot/keyEpoch/短期引用。稳定密钥变化不能复用 identityFile；后台仍以既有 scopeDigest、历史身份和预算验证拒绝不连续登记。新引用不代表新额度。

会话创建前所需的初始 targetBinding/targetRef 由已授权 runner/可信解析器流程建立并登记；传感器不会伪造新鲜观察来跨过初始准入。正式使用须先具备相应场景的授权、隔离与有效 canary 注册。

## 4. 时间、场景与恢复

单场景使用 `guardlive -config ... -pcap ... -out ... -report ...`；多场景使用 `-lab-plan`，从 `lab.inputs` 读取文件。lab 模式不接受命令行另传 start/end/capture-start，以免覆盖登记的窗口。

`labTime=sourceTime+manifest.time.offsetMicros`。v1.0 该偏移在整个 session 内固定；v1.1 使用 manifest.time.scenarioOffsets[scenarioId]，该场景的采集从 captureStart 开始，各场景偏移在创建时冻结，不因迟到重新取 now。原始起点、预热、评分窗口、每文件原首末包时间、真实墙钟、最大积压分别记录。`emittedAt`、接收和清理沿用真实墙钟及既有新鲜度门禁。

v1.0 多场景入口只接受按时间顺序、不重叠的场景。v1.1 为每段建立独立因果引擎并按签名时钟并发回放，共享上传器、boot、sequence 与全会话引用归属锁；每段使用自身登记的本机地址和固定偏移。normal 的各原始对端映射到不同 canary，不能通过共享 targetRef 合并。预热期也逐包登记映射，不能仅使用评分连接清单删掉预热对端；预热观察保留上下文与质量遥测，但 guardlive 必须清空 targetRef/targetExpiresAt，不得取得执行资格或占用动作预算。通过 session/scenario 对原 ID 做 HMAC 命名空间隔离，保证 parent/flow 关联与快照顺序稳定；这个 ID 差异需从特征对拍中剔除。登记输入不满足时拒绝，不重排文件或重截冻结数据。

注册租约的截止时间不随新包延长。两包之间租约到期时，定时快照保留原时刻和特征，清空 targetRef/targetExpiresAt 并计入不可执行遥测；它不能请求新租约或使整段回放中断。新包取租约失败仍是粘性错误，后续发射与回放停止。

`spool/<bootId>/lab-binding.json` 在上传线程启动前冻结 session、映射、场景/输入列表、程序及 offset。`-drain` 只在同一准入仍有效且绑定完全一致时重放已有批次原字节，不重做映射、重取租约、改 emittedAt 或更换 batchId/Idempotency-Key。过期/撤销会话的旧 spool 保留但不发送。同一 boot 不得重新从头采集；进程中断后的 drain 仅恢复已落盘批次，不声称补回尚未采集的文件尾部。

`eventsFile` 只对评分窗口内且引用在 asOf 有效的观察逐条保存 `{eventId,scenarioId,kind:observation,referenceId}`，eventId 使用观察 ID，供具备 evaluation.run 的 runner 等待观察落库后登记。预热、无引用和不合格观察仍完整上传，进入后端质量统计，不作为合格评分事件。传感器不请求人工事件 API，不自报 applied/cleared 或 G3 通过。失败摘要保留稳定原因和会话关联；没有原始端点、稳定 token 或密钥。

lab 线的质量统计区分采集质量 `qualified/qualifiedCoverage` 与可执行性 `executionQualified/executionQualifiedCoverage`，保留 `nonExecutable/missingTargetRef/expiredTargetRef/staleEvidence/invalidTiming`；原因计数可重叠。时效按观察 asOf 到后端接收时间判定，不按事后报告时间判定。暖机/窗外数据单列 `outsideScoringWindow`，不进入评分分母；任何实际命令仍须进入完整性核验。无引用/到期只能降低可执行性，跨稳定目标、scope 或启动身份的非空引用仍拒绝。

## 5. 健康接线与验证层级

S4 窗口继续使用 `host-guard-capture-health/1.0.0`：最长 5 秒、10 秒接收上限、前序 JCS 摘要、计数连续性、配置/程序/捕获域身份不变。文件回放的 kernelDrops 始终未知，不能作为现场连续健康或预算恢复证明。

仅 `guardlive -lab-plan` 且正式 v1.1 会话清单绑定健康 1.1.0 时，观察器输出 `host-guard-capture-health/1.1.0` 与必填 `captureSource=file_replay`。此口径 kernelDrops=null 表示不适用；packetsSeen/capacityDrops 已知、计数/摘要链连续、无容量丢弃、缺口或不可信时钟才得到 `replay_healthy`。T2 判定和领取还须核验 1.1.0 subject、lab 观察和该 sensor/boot 的 running 正式 lab 归属。评分窗口等待及空闲期间仍持续采样，真实采样停顿须留 gap；research 和现场默认输出原 1.0.0 字节，不自动恢复预算。

并发回放每段只更新自己的累计样本，由统一的 100 ms 节拍汇总并调用健康观察器。相同墙钟时间戳只更新计数，不据此声明缺口；真实时间倒退、显式 gap 或未完成场景超过 5 秒没有样本仍产生缺口。两次汇总之间出现的 gap 锁存到下一次汇总，场景完成也不能丢弃末次缺口或累计计数。

本线已在 PR #31 合入时完成离线和替身后端验证，2026-10-11 集成 mvn test 445 项无失败，相关 Go 竞态与执行器 51 项通过。阶段 0 新增多场景、v1.1 与预热映射，单独复验记录见交接。既有验证覆盖：

- `internal/guardup/health_e2e_test.go`：真实 Go 观察器 → 上传器 → 回环 TLS 1.3 mTLS 替身后端。替身以 `SetStrictHealth` 按 `GuardHealth.accept/verify` 的顺序判定，覆盖窗口首尾相接与摘要串链、采集缺口、未知计数为 null（含停顿 7 秒切分）、已受理但断连后原键重发不重复入库、后端整体 503 后重连续链、原窗口幂等重放不新增证明、陈旧窗口冒充后续序号判 `HEALTH_CHAIN_INCOMPLETE`、同会话同序号换 ID 返回 409 并使上传器以 `IDEMPOTENCY_CONFLICT` 停止。替身默认模式保持原行为，既有 K2 上传测试不受影响。
- `GuardSensorHealthIntegrationTest`（已合入，需 `DB_TEST_BASE_URL` 隔离 MySQL）：Go 合成窗口 → 机器接口 → GuardHealth → GuardBudget 恢复；只在随机 schema 内运行，结束删除该 schema。
- `internal/replaydiff` 与 `cmd/guardlive/lab_test.go`：同一合成 PCAP 的 research 离线提取与 lab 回放经 `guardreplaydiff` 同一实现逐字段对拍，只忽略登记差异字段 `emittedAt,environment,peerKey,targetRef,targetExpiresAt,quality.clockSkewMs`（`-lab-plan` 另加 `observationId,flowId,parentConnectionId`），并验证篡改特征会被发现；normal/attack 共用 targetRef 时入口以稳定错误码失败。
- `internal/guardlab` 单测：准入/映射 fail-closed、撤销与断连粘性失败、spool 绑定、严格 JSON、PCAP 预检、事件过滤、跨场景引用拒绝、稳定 token 跨语言向量、mTLS 登记原字节重试。

`guardreplaydiff` 用法不变；摘要为 `lab_pcap_replay` 时自动进入 lab 对拍，离线侧须为 research、回放侧须为 lab，否则报错。research 模式输出与原实现一致。

本线不启动真实抓包、不运行真实 PF/WFP、不生成/注入攻击流量、不训练、不读取封存 test、不部署或重启常驻服务、不提交/推送。新 lab 后端/K2 合并后的联合服务测试、真实接口长期健康、真实可执行 canary 和 G3 仍是单独运行验收项；代码及合成联调通过也不自动授予这些资格。

## 6. 与 lab 后端的接口对齐

| 项 | lab 线 | 传感器 |
|---|---|---|
| 机器路径 | `GET /api/v2/machine/sensors/{sensorId}/lab-validation-runs/{id}`，`machine.sensor.read` | `guardup.Client.LabRun` 同路径，mTLS + Bearer |
| 响应 | `{state,manifest,mapping,scenarios}`，state 为 view 的 18 个字段加 `runnable,reasonCodes` | `guardlab.Handoff/State` 同名 20 字段，未知字段拒绝 |
| sessionSha256 | `content_sha256 = hash(payload)`，payload 的 RFC 8785 JCS SHA-256 | `jcs.SHA256(manifest)`，与配置、state 三方一致 |
| mappingSha256 | 映射文件原字节 SHA-256（`artifacts.json(ref,sha)`） | 配置显式提供，与 manifest 和签名私有映射一致 |
| 签名 | `{payload,keyId,algorithm,signature}`，Ed25519 签 JCS，签名 base64url 无填充 | 私有映射同一封装与算法 |
| 时钟 | v1.0 单一 offset；v1.1 每场景一个不可变 offset，captureStart ≤ sourceStart | 同式校验，按版本串行或并发回放 |
| 映射 | v1.0 每场景一条；v1.1 normal 可多条；peerKey/targetRef 全局唯一 | 同上，每个运行中 targetRef 只属一个场景 |
| 事件 | `{eventId,scenarioId,kind,referenceId}` 由具 evaluation.run 的 runner 登记 | `eventsFile` 只输出该结构，传感器不调用人工接口 |

两端均要求 peerKey/targetRef 全局唯一并按版本校验映射。synthetic 仅在显式 rehearsal 开关下回放，仍不能签发真实命令。新增 wire 字段须两端同步更新，严格 JSON 解析拒绝未知字段。
