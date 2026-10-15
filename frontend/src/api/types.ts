/** v2 会话、事件状态与共享显示标签；业务视图字段与后端 v2 投影一致。 */

export type Severity = 'critical' | 'high' | 'medium' | 'low'

export type EventStatus = 'open' | 'investigating' | 'contained' | 'resolved' | 'false_positive' | 'closed'

export interface SessionUser { id: number; username: string; displayName: string; roles: string[]; permissions: string[]; bindings?: import('./v2/iam').RoleBinding[] }

export const policyStatusLabel: Record<string, string> = { draft: '草稿', pending: '待审批', approved: '已批准', active: '生效', rejected: '已驳回', retired: '已退役' }

export const userStatusLabel: Record<string, string> = { active: '正常', disabled: '已冻结', locked: '已锁定' }

export const severityLabel: Record<string, string> = { critical: '严重', high: '高', medium: '中', low: '低' }

export const eventStatusLabel: Record<string, string> = { open: '待处理', investigating: '研判中', contained: '已遏制', resolved: '已解决', false_positive: '误报', closed: '已关闭' }

export const eventTransitions: Record<string, EventStatus[]> = {
  open: ['investigating'],
  investigating: ['contained', 'resolved', 'false_positive', 'closed'],
  contained: ['investigating', 'resolved', 'closed'],
  resolved: ['closed'],
  false_positive: ['closed'],
  closed: [],
}

/** 后端 UTC 时间按浏览器当地时区显示；缺失值显示空占位，非法值原样返回。 */
export function fmtTime(v: string | null | undefined, withDate = true) {
  if (!v) return '—'
  const d = new Date(v.endsWith('Z') ? v : v + 'Z')
  if (Number.isNaN(d.getTime())) return v
  const p = (n: number) => String(n).padStart(2, '0')
  const t = `${p(d.getHours())}:${p(d.getMinutes())}`
  return withDate ? `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${t}` : t
}

/* ------------------------------------------------------------------ *
 * host-guard v5 控制面（/api/v2，P4）视图类型。
 *
 * 字段名与后端 GuardQueries.view 的投影一致：外部主键统一为 `id`（UUID 字符串），
 * 外键列返回目标行的 public_id，`*_json` 列去掉后缀并已递归脱敏
 * （stableTargetToken / scopeDigest / credential / privateKey 永不返回），
 * 时间为带 Z 的 Instant 字符串。创建人/审批人 ID 属 HIDDEN，前端拿不到。
 * ------------------------------------------------------------------ */

/** 采集身份（sensor）与执行身份（executor）的绑定资产。 */
export interface GuardAsset {
  id: string; assetKey: string; assetType: string; environment: string; criticality: string; owner: string
  status: string; labels: unknown; revision: number; createdAt: string; updatedAt: string
}
export interface GuardSensor {
  id: string; assetId: string; agentKey: string; platform: string; agentVersion: string; capabilities: unknown
  status: string; registeredAt: string; lastHeartbeatAt: string | null; revision: number; guardBootId: string | null; createdAt: string
}
export interface GuardExecutor {
  id: string; assetId: string; platform: string; adapterVersion: string; capabilityHash: string; bootId: string | null
  status: string; lastHeartbeat: string | null; health: string | null; revision: number
}
/** 登记机器身份后的唯一一次凭据交付；重放同一幂等键会得到 409 CREDENTIAL_ALREADY_ISSUED。 */
export interface GuardMachineCredential { id: string; clientId: string; credential: string; status: string }

export interface GuardModel {
  id: string; modelKey: string; version: string; manifestRef: string; manifestSha256: string; artifactSha256: string
  contractId: string | null; manifest: unknown; validationStatus: string | null; validation: unknown; createdAt: string
}
export interface GuardDataset { id: string; datasetKey: string; version: string; manifestRef: string; manifestSha256: string; payload: unknown; createdAt: string }
export interface GuardEvaluationPlan { id: string; planKey: string; version: string; planSha256: string; payload: unknown; createdAt: string }
/** runKind 为 development / final / replay / canary / platform；报告只登记引用与哈希，不抓取任意 URL。 */
export interface GuardEvaluation {
  id: string; planId: string; bundleId: string | null; runKind: string; runnerIdentity: string; status: string
  reportRef: string | null; reportSha256: string | null; payload: unknown; createdAt: string
}
/** 决策策略：draft → reviewed → retired；draft 不能进入活动发布组合。 */
export interface GuardDecisionPolicy {
  id: string; policyKey: string; version: string; modelId: string | null; planId: string | null
  definition: unknown; definitionSha256: string; status: string; revision: number; createdAt: string
}
/** 发布组合：candidate → evaluated → approved → active → suspended/retired，审批与激活分开。 */
export interface GuardReleaseBundle {
  id: string; bundleKey: string; version: string; modelId: string; policyId: string; contractId: string | null
  planId: string | null; environment: string; subjectSha256: string; subject: unknown
  sealedManifestSha256: string | null; sealedManifest: unknown; status: string; revision: number; createdAt: string
}
/** 能力登记：research / alert_only / lab_auto / authorized_auto。 */
export interface GuardCapability {
  id: string; capabilityKey: string; version: string; platform: string; level: string; payload: unknown; createdAt: string
}

/** 观察批次：202 只表示持久化受理，不代表检测或阻断已完成。 */
export interface GuardObservationBatch {
  id: string; sensorId: string; assetId: string; bootId: string; sequenceNo: number; configId: string | null
  requestSha256: string; result: unknown; createdAt: string
}
export interface GuardObservation {
  id: string; batchId: string; sensorId: string; assetId: string; bootId: string; captureScopeId: string | null
  flowId: string; parentConnectionId: string | null; snapshotIndex: number | null; profile: string | null
  asOf: string | null; lastPacketAt: string | null; peerKey: string | null; keyEpoch: string | null
  direction: string | null; transport: string | null; servicePort: number | null; environment: string | null
  payload: unknown; contentSha256: string; createdAt: string
}
/**
 * 推理结论；不成功的推理不带攻击概率（score 为 null）。
 * familyScores 为模型双输出中的四类分数（类别 → 0—1），推理失败时为空对象或 null。
 */
export interface GuardDetection {
  id: string; observationId: string; assetId: string; modelId: string | null; status: string; score: number | null
  family: string | null; familyScores?: Record<string, number> | null; applicability: string | null
  manifestSha256: string | null; completedAt: string | null; errorCode: string | null; createdAt: string
}
/**
 * 证据迹（episode）：按 parent 去重，30 秒桶归并；同主机其他 peer 不升级本 episode。
 * 来源 × 类别 × 规则编号彼此隔离：source 为 model 或 rule，模型来源的 ruleId 为空串。
 */
export interface GuardEpisode {
  id: string; assetId: string; sensorId: string; bootId: string; peerKey: string; keyEpoch: string | null
  direction: string; transport: string; servicePort: number; family: string | null; bundleId: string | null
  scope?: string | null; source?: string | null; ruleId?: string | null
  bucketStart: string; revision: number; createdAt: string
}
export interface GuardEpisodeEvidence {
  id: string; episodeId: string; parentConnectionId: string | null; observationId: string
  inferenceId: string | null; score: number | null; asOf: string | null; createdAt: string
  family?: string | null; source?: string | null; ruleId?: string | null; ruleMatched?: boolean | null
  familyScores?: Record<string, number> | null
}
/** 决策事实：observe / alert / block_candidate；reasonCode 与展示风险分开。 */
export interface GuardDecision {
  id: string; episodeId: string; assetId: string; bundleId: string | null; decisionRevision: number
  decisionContractVersion: string | null; decision: string; reasonCode: string; budgetTargetId: string | null
  budgetRevision: number | null; evidenceSha256: string | null; evidence: unknown; decidedAt: string | null; createdAt: string
}
export interface GuardAction {
  id: string; decisionId: string | null; assetId: string; executorId: string | null; budgetTargetId: string | null
  budgetRevision: number | null; bundleId: string | null; authorizationId: string | null; authorizationRevision: number | null
  mode: string; desiredState: string; desiredRevision: number; observedState: string; idempotencyKey: string | null
  targetSnapshot: unknown; blockUntil: string | null; revision: number; createdAt: string
}
export interface GuardActionReceipt {
  id: string; commandId: string; executorId: string; assetId: string; revocationId: string | null; status: string
  observedAt: string; stateDigest: string; contentSha256: string; payload: unknown; projected: boolean; createdAt: string
}
/**
 * 稳定目标预算。列表项与详情字段不同：
 * 详情读 guard_target_budget，返回 chargedMs / cycleStartedAt 等账本事实，且不返回 token 与真实端点。
 */
export interface GuardBudgetTarget {
  id: string; assetId: string; environment: string | null; resolverExecutorId: string | null
  identityStatus: string | null; createdAt: string
}
export interface GuardBudgetLedger {
  id: string; chargedMs: number | null; lastBlockEndAt: string | null; lastEvidenceAt: string | null
  healthProofSha256: string | null; cycleStartedAt: string | null; revision: number; createdAt: string
}
export interface GuardGuardEvent {
  id: string; guardAssetId: string | null; revision: number; eventKey: string; title: string; category: string
  severity: Severity; status: string; assigneeId?: string | null
  riskScore: number | null; riskRuleVersion: string | null
  firstSeenAt: string | null; lastSeenAt: string | null; createdAt: string; updatedAt?: string | null; closedAt: string | null
  episodeIds?: string[]; decisionIds?: string[]
  actionable?: boolean; budgetTargetId?: string | null; policyId?: string | null
  actionEpisodeId?: string | null; targetRef?: string | null; actionableReasonCode?: string | null
}
export interface GuardAssignableUser {
  id: string; assetId: string; userKey: string; username: string; displayName: string; status: string
}
export interface GuardTimelineEntry {
  id: string; eventId: string; occurredAt: string; entryType: string; actorType: string; actorId: string | null
  summary: string; evidenceRef: string | null; details: unknown; createdAt: string
}
export interface GuardFeedback {
  id: string; createdAt: string; assetId: string | null; observationId: string; label: string; evidenceRef: string
  status: string; reviewReason: string | null; revision: number
  createdBy?: number | string | null; reviewedBy?: number | string | null
}

/** 机器身份台账（GET /machine-clients）。 */
export interface GuardMachineClient {
  id: string; clientKey: string; clientType: string; sensorId: string | null; executorId: string | null
  status: string; expiresAt: string | null; revokedAt: string | null; createdAt: string
}

/** v2 状态显示标签。未知值一律原样显示，不猜测语义。 */
export const guardAssetEnvLabel: Record<string, string> = { research: '研究', lab: '靶场', authorized: '授权' }
export const guardCapabilityLevelLabel: Record<string, string> = {
  research: '研究', alert_only: '仅告警', lab_auto: '靶场自动', authorized_auto: '授权自动', suspended: '已暂停',
}
export const guardDecisionLabel: Record<string, string> = { observe: '观察', alert: '告警', block_candidate: '阻断候选' }
/** 决策主原因码（契约 T1—T9 次序），细分诊断另附 detailCode。 */
export const guardReasonLabel: Record<string, string> = {
  CAPABILITY_NOT_SUPPORTED: '能力不支持', QUALITY_UNSUPPORTED: '质量不达标', CLOCK_UNTRUSTED: '时钟不可信',
  TARGET_REF_STALE: '目标引用过期', EVIDENCE_STALE: '证据过期', SCORE_BELOW_AUTO: '分数低于自动阈值',
  EVIDENCE_INSUFFICIENT: '证据不足', CONTEXT_CONDITION_UNMET: '上下文条件未满足',
  AUTHORIZATION_INACTIVE: '授权失效', PROTECTION_OR_BUDGET_BLOCKED: '保护范围或预算受限',
  FAMILY_AUTO_DISABLED: '类别未开自动', MODEL_AUTO_DISABLED: '模型来源未开自动',
}
export const guardBudgetDetailLabel: Record<string, string> = {
  PROTECTED_TARGET: '受保护目标', PROTECTED_SERVICE: '受保护服务', PROTECTION_SET_UNVERIFIED: '保护集未核验',
  TTL_OR_UNCERTAIN_DEDUP: 'TTL 或不确定态去重', TARGET_CONTINUOUS_BUDGET: '目标连续预算',
  ASSET_CONCURRENT_LIMIT: '资产并发上限', ASSET_RATE_LIMIT: '资产速率上限',
}
export const guardInferenceStatusLabel: Record<string, string> = {
  succeeded: '推理成功', not_applicable: '不适用', rejected: '已拒绝', failed: '失败', expired: '已过期',
}
export const guardBundleStatusLabel: Record<string, string> = {
  candidate: '候选', evaluated: '已评价', approved: '已批准', active: '已激活', suspended: '已暂停', retired: '已退役', rejected: '已驳回',
}
export const guardIdentityStatusLabel: Record<string, string> = {
  verified: '已核验', unverified: '未核验', rotated: '已轮换', conflict: '标识冲突',
}
export const guardMachineClientTypeLabel: Record<string, string> = { sensor: '采集身份', executor: '执行身份' }
/** feedback：未复核的标注不自动成为训练真值。 */
/** v5 动作期望 / 观测状态的中文名；期望不等于执行，两者分开显示。未知值原样显示。 */
export const guardActionStateLabel: Record<string, string> = {
  pending: '待处理', dispatched: '已下发', active: '生效意图', revoked: '已撤销', applied: '已生效', cleared: '已清理', failed: '失败',
  rejected: '已驳回', uncertain: '待核对', recovery_failed: '恢复失败', expired: '已过期',
}
export const guardActionModeLabel: Record<string, string> = { auto: '自动', manual: '人工' }
export const guardFeedbackLabel: Record<string, string> = { benign: '正常', attack: '攻击', ambiguous: '存疑' }
export const guardFeedbackStatusLabel: Record<string, string> = { pending: '待复核', reviewed: '已复核', rejected: '已驳回' }
export const guardTimelineTypeLabel: Record<string, string> = {
  'guard.decision': '追加证据判定',
  'guard.transition': '状态迁移',
  'guard.assignment': '负责人指派',
  'guard.note': '研判记录',
}
export const guardActionableReasonLabel: Record<string, string> = {
  ...guardReasonLabel,
  EVENT_NOT_OPEN: '事件已结案或关闭，不可申请处置',
  ACTION_EVIDENCE_REQUIRED: '尚无阻断候选判定，仅告警或观察不产生可执行目标',
  ACTION_ALREADY_ACTIVE: '该阻断候选已存在待处理或生效中的处置动作',
}

/* ------------------------------------------------------------------ *
 * 演示最小集（FE-1—FE-3）：来源 × 类别、lab 验证与 G3 报告、健康与审计。
 *
 * 判定证据、lab 事实与 G3 报告都是后端已签名或已摘要的事实，前端只读取并按字段展示；
 * 资格与健康结论一律以后端字段为准，不在前端推断「可自动」「已健康」。
 * ------------------------------------------------------------------ */

/** 四个攻击类（契约类别映射 host-guard-class-map/1 的展示顺序）；normal 只出现在分数与场景中。 */
export const GUARD_FAMILIES = ['port_scan', 'brute_force', 'dos_flood', 'dos_slow'] as const
export const guardFamilyLabel: Record<string, string> = {
  port_scan: '端口扫描', brute_force: '暴力破解', dos_flood: '洪泛 DoS', dos_slow: '慢速 DoS', normal: '正常',
}
/** 检测来源：模型或某条规则；模型来源的 ruleId 为空串或 null。 */
export function guardSourceKey(source: string | null | undefined, ruleId: string | null | undefined) {
  return source === 'rule' ? `rule:${ruleId ?? ''}` : (source ?? 'model')
}
export function guardSourceLabel(source: string | null | undefined, ruleId?: string | null) {
  if (source === 'rule') return ruleId ? `规则 ${ruleId}` : '规则'
  if (source?.startsWith('rule:')) return `规则 ${source.slice(5)}`
  return source === 'model' || !source ? '模型' : source
}

/** 判定证据（evidence_json，guard-evidence/1）中前端展示的字段；其余字段按原样列出。 */
export interface GuardDecisionEvidence {
  family?: string; source?: string; ruleId?: string; scope?: string | null; environment?: string | null
  reasonCode?: string | null; detailCode?: string | null; bundleId?: string | null; bundleSubjectSha256?: string | null
  capabilityId?: string | null; authorizationId?: string | null; authorizationRevision?: number | null
  budgetTargetId?: string | null; policySha256?: string | null; modelId?: string | null; triggerObservationId?: string | null
  protocolVersions?: Record<string, string> | null; labSession?: unknown
  selectedObservations?: { observationId: string; family?: string; source?: string; ruleId?: string; asOf?: string; parentConnectionId?: string | null }[]
}

/** lab 验证会话（GET /lab-validation-runs）：资格状态与运行状态分开，effectiveEligibility 已计入到期与授权失效。 */
export interface GuardLabRun {
  id: string; eligibilityStatus: string; effectiveEligibility: string; blockedReason: string | null
  runStatus: string; timedOut: boolean; revision: number; assetId: string | null; bundleId: string | null
  sessionSha256: string; manifestSha256: string; evidenceKind: string; validUntil: string
  startedAt: string | null; endedAt: string | null; stopRequestedAt: string | null
  cleanupStatus: string; executionAuthority: boolean
}
/** 会话事实：按追加序号 after 翻页；fact 为已摘要的原始事实（JCS）。 */
export interface GuardLabEvent { eventId: string; sequence: number; sha256: string; fact: Record<string, unknown> & { kind?: string } }
export interface GuardLabEventPage { items: GuardLabEvent[]; nextAfter: number | null }
/** 已登记的来源等级：只来自已验签导入的 G3 报告，组合不可用时 bundleUsable 为 false。 */
export interface GuardLabQualifications {
  sessionId: string; bundleId: string; bundleUsable: boolean
  sources: { family: string; source: string; level: string; evaluationId: string; subjectSha256: string }[]
}
/** G3 报告（guard_evaluation_run.payload，签名报告原文）中前端展示的部分。 */
export interface GuardG3Class {
  family: string; status: string; sources: string[]; scenarioIds: string[]; trialAutoEligible: boolean
  firstAlertLatencyMs: number | null; firstApplicationLatencyMs: number | null
}
export interface GuardG3Command {
  commandId: string; issuedAt: string | null; appliedAt: string | null; clearedAt: string | null; installation: string; cleanup: string
}
export interface GuardG3Scenario {
  scenarioId: string; family: string; source: string; ruleId: string | null; status: string; completed: boolean
  trialAutoEligible?: boolean; autoIneligibleReason?: string | null
  alertLatencyMs: number | null; issueLatencyMs: number | null; applicationLatencyMs: number | null; cleanupLatencyMs: number | null
  qualifiedCoverage?: number | null; executionQualifiedCoverage?: number | null
  commands: GuardG3Command[]; missing: string[]; rejectionReasons?: string[]
}
export interface GuardG3Report {
  reportVersion?: string; sessionId: string; status: string; passed: boolean; runStatus: string; evidenceKind: string
  classes: GuardG3Class[]; scenarios: GuardG3Scenario[]
  normal: { passed: boolean; perHour: number; cumulativeMs: number; singleAssetUnionMs?: number; verifiedFalseBlocks: number; falseBlocksTtlRestored: boolean }
  limitations: string[]; missingClasses: string[]; unlinkedCommandIds: string[]; unlinkedDecisionIds: string[]
  unverifiedItems: unknown[]; outsideScoringDecisionIds?: string[]; latencyIsReportOnly: boolean
  subjectSha256: string; evaluationPlanSha256: string; inputSha256: string; sessionSha256: string
  protocolVersions?: Record<string, string>; provenance?: Record<string, string>
}

/** B5 只读查询的统一外形：asOf 固定本次查询时刻，nextCursor 绑定筛选与身份。 */
export interface GuardReadPage<T> { asOf: string; items: T[]; nextCursor: string | null }
/**
 * 健康窗口：verificationStatus 是写入时的服务端判定，healthState 再叠加 10 秒新鲜度。
 * replay_healthy 只证明文件回放窗口完整，不证明现场采集健康，也不用于预算恢复。
 */
export interface GuardHealthWindow {
  id: string; assetId: string | null; sensorId: string | null; captureScopeId: string | null; sequence: number
  observerSessionId: string | null; intervalStart: string | null; intervalEnd: string | null; receivedAt: string | null
  verificationStatus: string | null; serverVerifiedHealthy: boolean | null; failureReason: string | null
  freshness: string; healthState: string; healthBasis: string; healthVersion: string | null; captureSource: string | null
  captureGap: boolean | null; clockSkewMs: number | null
  counterStart: { packetsSeen: number | null; kernelDrops: number | null; capacityDrops: number | null }
  counterEnd: { packetsSeen: number | null; kernelDrops: number | null; capacityDrops: number | null }
}
/** 心跳只表示机器存活与状态投影，不代表采集健康。 */
export interface GuardHeartbeat {
  id: string; assetId: string | null; status: string; revision: number; receivedAt: string | null; bootId: string | null
  freshness: string; healthState: string; agentVersion?: string | null; adapterVersion?: string | null; capabilityHash?: string | null
  currentConfig?: { id: string; configVersion: string; contentSha256: string; buildSha256: string | null } | null
  reported?: { pendingRecovery: boolean | null; activeRuleCount: number | null; clockSkewMs: number | null } | null
}
export interface GuardOpsAsset {
  id: string; status: string; sensorCount: number; executorCount: number; lastSensorHeartbeatAt: string | null
  lastExecutorHeartbeatAt: string | null; healthWindowCount: number; lastHealthReceivedAt: string | null
  budgetTargetCount: number; budgetResetCount: number; lastBudgetResetAt: string | null
}
export interface GuardAuditEntry {
  id: string; occurredAt: string; actorType: string; action: string; resourceType: string | null
  requestId: string | null; outcome: string; resourceId: string | null
}

export const guardLabRunStatusLabel: Record<string, string> = {
  registered: '已登记', running: '运行中', interrupted: '已中断', completed: '已完成', failed: '失败', cancelled: '已取消', expired: '已过期',
}
export const guardLabEligibilityLabel: Record<string, string> = {
  pending: '待批准', active: '有效', blocked: '受阻', expired: '已到期', revoked: '已撤销',
}
export const guardLabEventKindLabel: Record<string, string> = {
  lifecycle: '生命周期', observation: '观察', decision: '判定', command: '命令', receipt: '回执',
  verified_receipt: '核验回执', scenario_result: '场景结果', report: '报告导入',
}
/** 健康窗口服务端判定；未列出的判定码原样显示。 */
export const guardVerificationLabel: Record<string, string> = {
  healthy: '现场健康', replay_healthy: '文件回放健康', REPLAY_KERNEL_DROPS_INVALID: '回放内核丢包字段无效',
  HEALTH_DELAY_EXCEEDED: '上报延迟超限', CLOCK_UNTRUSTED: '时钟不可信', CAPTURE_GAP: '采集缺口', COUNTER_UNKNOWN: '计数未知',
  CAPTURE_DROPS: '采集丢包', HEALTH_CHAIN_INCOMPLETE: '哈希链不完整', HEALTH_IDENTITY_CHANGED: '采集身份变化',
}
export const guardHealthStateLabel: Record<string, string> = {
  healthy: '健康', replay_healthy: '文件回放健康', stale: '已过期', unhealthy: '不健康', unknown: '未知',
}
export const guardMachineStatusLabel: Record<string, string> = {
  pending: '待审批', active: '有效', offline: '离线', suspended: '已暂停', revoked: '已吊销',
}
