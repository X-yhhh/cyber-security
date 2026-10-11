# 传感器 lab 接入与隔离验证

更新于 2026-10-11。传感器接入线（任务单 6.3 L3）S-A—S-D 的设计与代码草稿边界，**待合并验证**：代码尚未经主会话统一编译/测试（含 -race），未合并、未部署、未在真实 lab 运行。本线以 `d103cfd` 为基线，在独立 worktree `feat/l3-sensor-lab` 开发；没有修改 K2 的上传/spool 实现、业务数据库迁移、模型、特征公式、PF/WFP 或前端。

## 1. 入口与身份

新增模块 `sensor/internal/guardlab`，由 `guardlive` 使用。沿用 rc.2 观察，不增加观察字段；会话关联通过固定的 sensor/boot、映射和旁路事件完成。

机器接口为 `GET /api/v2/machine/sensors/{sensorId}/lab-validation-runs/{id}`，权限仍为 `machine.sensor.read`，响应为 `{state,manifest,mapping,scenarios}`。消费 lab 线的 `host-guard-lab/1.0`（完整定义由该线的 `docs/contracts/lab-validation.md` 提供）。本线要求：

- `state.runnable=true`、`reasonCodes=[]`、`blockedReason=null`、active/running、无停止请求、未超时/结束；`evidenceKind=lab`。合成会话不能运行这个入口。
- `sessionSha256` 必须同时等于配置中的固定摘要、服务端摘要和 manifest 的 JCS 摘要。它不是签名封装原字节的 `manifestSha256`。
- 配置的 `runId` 必须等于 `state.id` 与 `manifest.sessionId`；配置的 `mappingSha256` 必须等于 `manifest.mappingSha256` 及私有映射中的 `mappingSha256`。任一缺失或不符即 `LAB_ADMISSION_REJECTED`/`LAB_MAPPING_REJECTED`，不开始回放。
- 场景 `scenarioId` 格式、`family`（normal/port_scan/brute_force/dos_flood/dos_slow）与 `source`（model/rule）按 lab 线同一规则复核；传感器另要求各映射条目 `peerKey` 互不相同（比 lab 线只要求 targetRef 唯一更严）。
- asset/sensor/boot、有效期、映射、场景与程序绑定相符。后台 `runnable` 负责当前资产授权修订、执行器、bundle、冻结文件和签名证据的复核，不能仅凭 active/running 放行。
- 开始前及之后每秒读取机器接口；请求最多等待 1 秒。拒绝、断连或不可变内容变化立即取消回放及上传。当前进程失败后不自动恢复。

lab 线草稿（并行 worktree `cyber-security-l2-lab`，未合并）提供上述 wire 字段；本线按其 `GuardLabSessions.machine/view` 的字段名逐一对齐（见第 6 节）。集成者须按 K2→查询线→lab 线→本线的依赖顺序复验，不能在缺少 `runnable` 的旧后端上放行。GET 和传感器均不改变 session 的运行状态、不激活模型或签发命令。

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
| inputs（可选） | 按原事件时间排列的 `{scenarioId,path}` 列表，配合 `-lab-plan` |

映射文件使用与 `GuardSignatures` 一致的 `{payload,keyId,algorithm,signature}`。`algorithm=Ed25519`，签名是 payload JCS 的无填充 base64url；trustFile 将 runner 名称映射为标准 base64 编码的 X.509 DER 公钥。签名者必须是 manifest.runnerIdentity。映射和 trustFile 均为 0600 普通文件，不接受符号链接。

payload 的 `contractVersion=host-guard-sensor-mapping/1.0`，必填：

- `sessionId,sessionSha256,mappingId,mappingSha256,scenarioSha256`：绑定中央登记。
- `buildSha256`：本次独立 guardlive 可执行文件原字节摘要；`extractorSha256`：与中央 provenance 一致。
- `entries`：每场景一个对象，字段为 `scenarioId,originalLocal,originalPeer,canaryLocal,canaryPeer,peerKey,direction,transport,addressFamily,scope,servicePort`。

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

新登记模式下，同一 targetRef 的 expiresAt 保持不变；过期后才换引用。每次新包更新解析器看到的 lastPacketAt，但不延长同一已持久绑定。后台登记使用由 targetRef 确定的 bindingId 和相同请求字节；响应丢失最多重试一次，4xx 不重试。未确认的引用不能解析为可执行目标。旧 `NewTargetRegistry` 和未配置 registration 的使用方式保持原行为。

稳定 token 与 Python `Engine.stable_target` 使用同一 JCS/HMAC 算法，忽略 boot/keyEpoch/短期引用。稳定密钥变化不能复用 identityFile；后台仍以既有 scopeDigest、历史身份和预算验证拒绝不连续登记。新引用不代表新额度。

会话创建前所需的初始 targetBinding/targetRef 由已授权 runner/可信解析器流程建立并登记；传感器不会伪造新鲜观察来跨过初始准入。正式使用须先具备相应场景的授权、隔离与有效 canary 注册。

## 4. 时间、场景与恢复

单场景使用 `guardlive -config ... -pcap ... -out ... -report ...`；多场景使用 `-lab-plan`，从 `lab.inputs` 读取文件。lab 模式不接受命令行另传 start/end/capture-start，以免覆盖登记的窗口。

`labTime=sourceTime+manifest.time.offsetMicros`。该偏移在整个 session 内固定；不会因迟到重新取 now。原始起点、预热、评分窗口、每文件原首末包时间、真实墙钟、最大积压分别记录。`emittedAt`、接收和清理沿用真实墙钟及既有新鲜度门禁。

多场景入口只接受按时间顺序、不重叠的场景。每场景使用新的因果引擎及其登记的本机地址，共享同一个上传器、boot、sequence 和固定偏移。通过 session/scenario 对原 ID 做 HMAC 命名空间隔离，保证 parent/flow 关联与快照顺序稳定；这个 ID 差异需从特征对拍中剔除。重叠场景不能用该串行入口冒充同时发生，应先由 lab 编排明确独立捕获域。登记输入不满足时拒绝，不重排文件或重截冻结数据。

`spool/<bootId>/lab-binding.json` 在上传线程启动前冻结 session、映射、场景/输入列表、程序及 offset。`-drain` 只在同一准入仍有效且绑定完全一致时重放已有批次原字节，不重做映射、重取租约、改 emittedAt 或更换 batchId/Idempotency-Key。过期/撤销会话的旧 spool 保留但不发送。同一 boot 不得重新从头采集；进程中断后的 drain 仅恢复已落盘批次，不声称补回尚未采集的文件尾部。

`eventsFile` 只对评分窗口内且引用在 asOf 有效的观察逐条保存 `{eventId,scenarioId,kind:observation,referenceId}`，eventId 使用观察 ID，供具备 evaluation.run 的 runner 等待观察落库后登记。预热、无引用和不合格观察仍完整上传，进入后端质量统计，不作为合格评分事件。传感器不请求人工事件 API，不自报 applied/cleared 或 G3 通过。失败摘要保留稳定原因和会话关联；没有原始端点、稳定 token 或密钥。

lab 线的质量统计区分采集质量 `qualified/qualifiedCoverage` 与可执行性 `executionQualified/executionQualifiedCoverage`，保留 `nonExecutable/missingTargetRef/expiredTargetRef/staleEvidence/invalidTiming`；原因计数可重叠。时效按观察 asOf 到后端接收时间判定，不按事后报告时间判定。暖机/窗外数据单列 `outsideScoringWindow`，不进入评分分母；任何实际命令仍须进入完整性核验。无引用/到期只能降低可执行性，跨稳定目标、scope 或启动身份的非空引用仍拒绝。

## 5. 健康接线与验证层级

S4 窗口继续使用 `host-guard-capture-health/1.0.0`：最长 5 秒、10 秒接收上限、前序 JCS 摘要、计数连续性、配置/程序/捕获域身份不变。文件回放的 kernelDrops 始终未知，不能作为现场连续健康或预算恢复证明。

本线补充的离线验证（均为合成数据与替身后端，**待主会话统一编译测试**，结果未记录前不得写成已通过）：

- `internal/guardup/health_e2e_test.go`：真实 Go 观察器 → 上传器 → 回环 TLS 1.3 mTLS 替身后端。替身以 `SetStrictHealth` 按 `GuardHealth.accept/verify` 的顺序判定，覆盖窗口首尾相接与摘要串链、采集缺口、未知计数为 null（含停顿 7 秒切分）、已受理但断连后原键重发不重复入库、后端整体 503 后重连续链、原窗口幂等重放不新增证明、陈旧窗口冒充后续序号判 `HEALTH_CHAIN_INCOMPLETE`、同会话同序号换 ID 返回 409 并使上传器以 `IDEMPOTENCY_CONFLICT` 停止。替身默认模式保持原行为，既有 K2 上传测试不受影响。
- `GuardSensorHealthIntegrationTest`（草稿，需 `DB_TEST_BASE_URL` 隔离 MySQL）：Go 合成窗口 → 机器接口 → GuardHealth → GuardBudget 恢复；只在随机 schema 内运行，结束删除该 schema。
- `internal/replaydiff` 与 `cmd/guardlive/lab_test.go`：同一合成 PCAP 的 research 离线提取与 lab 回放经 `guardreplaydiff` 同一实现逐字段对拍，只忽略登记差异字段 `emittedAt,environment,peerKey,targetRef,targetExpiresAt,quality.clockSkewMs`（`-lab-plan` 另加 `observationId,flowId,parentConnectionId`），并验证篡改特征会被发现；normal/attack 共用 targetRef 时入口以稳定错误码失败。
- `internal/guardlab` 单测：准入/映射 fail-closed、撤销与断连粘性失败、spool 绑定、严格 JSON、PCAP 预检、事件过滤、跨场景引用拒绝、稳定 token 跨语言向量、mTLS 登记原字节重试。

`guardreplaydiff` 用法不变；摘要为 `lab_pcap_replay` 时自动进入 lab 对拍，离线侧须为 research、回放侧须为 lab，否则报错。research 模式输出与原实现一致。

本线不启动真实抓包、不运行真实 PF/WFP、不生成/注入攻击流量、不训练、不读取封存 test、不部署或重启常驻服务、不提交/推送。新 lab 后端/K2 合并后的联合服务测试、真实接口长期健康、真实可执行 canary 和 G3 仍是单独运行验收项；代码及合成联调通过也不自动授予这些资格。

## 6. 与 lab 线（L2 草稿）的接口对齐

| 项 | lab 线 | 传感器 |
|---|---|---|
| 机器路径 | `GET /api/v2/machine/sensors/{sensorId}/lab-validation-runs/{id}`，`machine.sensor.read` | `guardup.Client.LabRun` 同路径，mTLS + Bearer |
| 响应 | `{state,manifest,mapping,scenarios}`，state 为 view 的 18 个字段加 `runnable,reasonCodes` | `guardlab.Handoff/State` 同名 20 字段，未知字段拒绝 |
| sessionSha256 | `content_sha256 = hash(payload)`，payload 的 RFC 8785 JCS SHA-256 | `jcs.SHA256(manifest)`，与配置、state 三方一致 |
| mappingSha256 | 映射文件原字节 SHA-256（`artifacts.json(ref,sha)`） | 配置显式提供，与 manifest 和签名私有映射一致 |
| 签名 | `{payload,keyId,algorithm,signature}`，Ed25519 签 JCS，签名 base64url 无填充 | 私有映射同一封装与算法 |
| 时钟 | `labStart = sourceStart + offsetMicros`，warmup ≤ scoring 窗口 | 同式校验，固定偏移回放 |
| 映射 | scenarioId、targetRef 唯一；条目数 = 场景数 | 同上，另要求 peerKey 唯一、每个运行中 targetRef 只属一个场景 |
| 事件 | `{eventId,scenarioId,kind,referenceId}` 由具 evaluation.run 的 runner 登记 | `eventsFile` 只输出该结构，传感器不调用人工接口 |

已知差异（以 lab 线为准、传感器更严或待对方补充）：lab 线允许 `evidenceKind=synthetic` 会话，传感器入口拒绝（与 `LAB_SYNTHETIC_ONLY` 一致）；lab 线不要求 peerKey 唯一，传感器要求；lab 线新增 state 字段时传感器会因未知字段拒绝，需同步更新。
