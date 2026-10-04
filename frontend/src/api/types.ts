/**
 * 后端视图类型与显示标签。字段与后端 record 一一对应（Jackson 默认驼峰），
 * 时间均为 UTC 的 LocalDateTime 字符串（无时区后缀）。
 */

import type { Page } from './client'

export type Severity = 'critical' | 'high' | 'medium' | 'low'
export type EventStatus = 'open' | 'investigating' | 'contained' | 'resolved' | 'false_positive' | 'closed'

export interface SessionUser { id: number; userKey: string; username: string; displayName: string; roles: string[]; permissions: string[] }
/** 告警视图；V13 起带来源追溯（模型/规则版本、契约版本与哈希、分级策略）和评分依据快照 basisJson。 */
export interface AlertView {
  id: number; alertKey: string; alertType: string; severity: Severity; status: string; score: number | null; detectedAt: string; dataSourceId: number; assetId: number | null
  modelVersionId: number | null; modelKey: string | null; modelVersion: string | null; contractVersion: string | null; contractSha256: string | null
  detectionRuleId: number | null; ruleKey: string | null; ruleVersion: string | null; severityPolicyVersion: string | null; thresholdVersion: string | null; basisJson: string | null
  /** V18：alert 进入人工队列；signal 为低等级模型命中，默认不进列表/事件计数，可被关联策略提升。 */
  alertLayer?: 'alert' | 'signal' | string; correlationPolicyVersion?: string | null; promotedAt?: string | null
}
export interface EventView {
  id: number; eventKey: string; title: string; category: string; severity: Severity; status: EventStatus; riskScore: number | null; firstSeenAt: string; lastSeenAt: string; assigneeId: number | null; alertCount: number; assetCount: number
  riskRuleVersion: string | null; riskBasisJson: string | null; correlationKey: string | null; correlationPolicyVersion: string | null
}
export interface EventAssetView { assetId: number; assetKey: string; relationType: string; evidenceCount: number }
export interface TimelineView { id: number; occurredAt: string; entryType: string; actorType: string; actorId: string | null; summary: string; evidenceRef: string | null; detailsJson: string | null }
/** 事件详情：alerts / timeline 只内嵌第一页（按时间倒序，带总数），后续页读 /events/{id}/alerts、/events/{id}/timeline。 */
export interface EventDetail { event: EventView; alerts: Page<AlertView>; assets: EventAssetView[]; timeline: Page<TimelineView> }
export interface AssetView { id: number; assetKey: string; assetType: string; environment: string; criticality: string; owner: string; status: string }
export interface AuthorizationView {
  id: number; assetId: number; authorizationRef: string; status: string; validFrom: string; validUntil: string; requestedBy: string | null; approvedBy: string | null; createdAt: string
  revokedBy: string | null; revokedAt: string | null; revokeReason: string | null
}
export interface SensorView { id: number; agentKey: string; assetId: number; assetKey: string; platform: string; agentVersion: string; status: string; lastHeartbeatAt: string | null; configVersion: string | null; flowWindowSeconds: number | null; healthWindowEnd: string | null; flowsSeen: number | null; flowsEmitted: number | null; flowsDropped: number | null; queueDepthMax: number | null }
export interface DataSourceView { id: number; sourceKey: string; sourceType: string; environment: string; schemaVersion: string; status: string; lastSuccessAt: string | null }
export interface IngestSummary { dataSourceId: number; batches: number; accepted: number; rejected: number; lastBatchAt: string | null; mappingVersion: string | null; mappingStatus: string | null }
/** 响应策略版本（M6）。版本不可变；status 为 draft/pending/active/rejected/retired（approved 仅历史兼容）。 */
export interface PolicyView {
  id: number; policyKey: string; version: string; environment: string; match: Record<string, unknown> | null; actionType: string
  actionParams: { maxTtlSeconds?: number; allowedTargets?: string[] } | null; riskLimit: number | null
  autoExecute: boolean; approvalRequired: boolean; maxDurationSeconds: number; status: string; approved: boolean
  createdBy: number | null; basedOnPolicyId: number | null; changeReason: string | null; contentSha256: string | null
  submittedAt: string | null; approvedBy: number | null; reviewedBy: number | null; reviewedAt: string | null
  decisionReason: string | null; retiredAt: string | null; retiredBy: number | null; createdAt: string
}
export const policyStatusLabel: Record<string, string> = { draft: '草稿', pending: '待审批', approved: '已批准', active: '生效', rejected: '已驳回', retired: '已退役' }
export interface LedgerView { id: number; eventId: number; eventKey: string; assetId: number; assetKey: string; actionRequest: { actionType?: string; parameters?: { targetAddress?: string; ttlSeconds?: number }; policyKey?: string; policyVersion?: string; reason?: string }; status: string; requester: string; reviewer: string | null; decisionReason: string | null; expiresAt: string; createdAt: string; reviewedAt: string | null; executionStatus: string | null; withdrawReason?: string | null; withdrawnAt?: string | null }
export interface ModelView { id: number; modelKey: string; version: string; taskType: string; manifestVersion: string; manifest: Record<string, unknown>; artifactRef: string; artifactSha256: string; featureContractVersion: string; approvalStatus: string; createdAt: string }
export interface ReleaseView { id: number; releaseStatus: string; reviewStatus: string; requester: string | null; approver: string | null; requestReason: string | null; decisionReason: string | null; reviewedAt: string | null; createdAt: string }
export interface DeploymentView { id: number; environment: string; mode: string; modelVersionId: number; modelKey: string; version: string; runtimeType: string; status: string; activatedAt: string | null }
export interface DriftView { id: number; dataSourceId: number; modelKey: string; version: string; windowStart: string; windowEnd: string; featureStats: Record<string, unknown> | null; scoreStats: Record<string, unknown> | null; qualityRejectRate: number | null; driftStatus: string }
export interface FeedbackView { id: number; alertId: number | null; alertKey: string | null; label: string; labelSource: string; reviewer: string | null; reviewedAt: string | null; datasetVersion: string | null; trainingEligible: boolean }
export interface TrainingJobView { id: number; jobKey: string; datasetVersion: string; sampleManifestRef: string; trainHostRef: string; status: string; requester: string | null; startedAt: string | null; finishedAt: string | null; resultManifestRef: string | null; failureReason: string | null }
export interface ReplayScenarioView { id: number; scenarioKey: string; name: string; datasetRef: string; environment: string; safetyProfile: string; status: string; lastRunKey: string | null; lastRunStatus: string | null; lastRunSpeed: number | null; lastRunProgress: number | null; lastRunStartedAt: string | null; lastRunFinishedAt: string | null; lastRunSummary: Record<string, unknown> | null }
export interface AuditView { id: number; occurredAt: string; actorType: string; action: string; resourceType: string; resourceId: string | null; requestId: string | null; outcome: string }
export interface UserSummary { id: number; userKey: string; username: string; displayName: string; status: string }
/** 用户详情（GET /users/{id}）；时间为带 Z 的 Instant，不含口令哈希。 */
export interface UserDetail extends UserSummary { lastLoginAt: string | null; passwordChangedAt: string | null; createdAt: string; updatedAt: string }
/** 机器客户端台账（GET /machine-clients）；不含任何凭据值、摘要或密钥引用。 */
export interface MachineClientView {
  id: number; clientKey: string; clientType: string; sensorId: number | null; status: string
  expiresAt: string | null; rotatedAt: string | null; revokedAt: string | null; revokeReason: string | null; createdAt: string
}
/** POST /machine-clients 响应：凭据只在本次返回，页面不持久化。 */
export interface IssuedMachineClient {
  id: number; clientKey: string; clientType: string; scopes: { scopeType: string; scopeId: string }[]
  sourceAssetBindings: { dataSourceId: number; assetId: number }[]; credential: string; issuedAt: string
}
/** 确定性检测规则版本（GET /detection-rules）。驳回在库中记为 retired 且无批准人。 */
export interface DetectionRuleView {
  id: number; ruleKey: string; version: string; scopeJson: string; conditionJson: string; severity: Severity
  status: string; requestedBy: number | null; approvedBy: number | null; createdAt: string; updatedAt: string
}
/**
 * 检测策略版本（GET /detection-policies，V18）。configJson 为规范化 JSON 字符串；时间为带 Z 的 Instant。
 * draft → pending → active | rejected；draft/pending 可由起草人撤回为 retired，active 由审批人退役。
 */
export type DetectionPolicyType = 'severity_mapping' | 'correlation' | 'risk_score'
export interface DetectionPolicyView {
  id: number; policyType: DetectionPolicyType | string; version: string; configJson: string; status: string; createdBy: number | null
  basedOnPolicyId: number | null; changeReason: string | null; contentSha256: string | null; submittedAt: string | null
  reviewedBy: number | null; reviewedAt: string | null; decisionReason: string | null; retiredBy: number | null; retiredAt: string | null; createdAt: string
}
export const detectionPolicyTypeLabel: Record<string, string> = { severity_mapping: '分级映射', correlation: '事件关联', risk_score: '风险评分' }
export const alertLayerLabel: Record<string, string> = { alert: '告警', signal: '模型信号' }
/** 来源映射版本（GET /data-sources/{id}/mappings）；JSON 字段为后端规范化后的字符串。 */
export interface MappingView {
  id: number; mappingVersion: string; sourceSchemaJson: string; mappingJson: string; status: string; approvedBy: number | null
  featureContractVersion: string | null; featureContractSha256: string | null; requestedBy: number | null
  reviewedBy: number | null; decisionReason: string | null; retiredBy: number | null; retiredAt: string | null; createdAt: string
}
/** 传感器配置版本（开发路线 §4.1）：pending → approved | rejected，approved → active，active → retired。 */
export interface SensorConfigView {
  id: number; sensorId: number; configVersion: string; interfaceScopeJson: string; filterPolicyJson: string; flowWindowSeconds: number
  featureContractVersion: string; featureContractSha256: string | null; samplingPolicyJson: string; status: string
  requestedBy: number | null; requestedByName: string | null; changeReason: string | null; approvedBy: number | null; approvedByName: string | null
  reviewedBy: number | null; reviewedAt: string | null; decisionReason: string | null; activatedAt: string | null; activatedBy: number | null
  retiredAt: string | null; createdAt: string
}
export interface SensorCredentialStatus { clientId: number; clientKey: string; status: string; expiresAt: string | null; rotatedAt: string | null; revokedAt: string | null; revokeReason: string | null; createdAt: string }
/** 传感器详情（GET /sensors/{id}）：身份、配置版本历史与凭据状态，不含凭据值。 */
export interface SensorDetail {
  sensor: { id: number; agentKey: string; assetId: number; assetKey: string; platform: string; agentVersion: string; capabilitiesJson: string; status: string; registeredAt: string; lastHeartbeatAt: string | null; createdAt: string; updatedAt: string }
  configs: SensorConfigView[]; credential: SensorCredentialStatus | null
}
/** 只返回一次的机器凭据（登记传感器、轮换凭据、签发连接器）。 */
export interface IssuedCredentialView { credential: string; expiresAt?: string | null }
export const userStatusLabel: Record<string, string> = { active: '正常', disabled: '已冻结', locked: '已锁定' }
export const lifecycleStatusLabel: Record<string, string> = {
  active: '生效', disabled: '停用', retired: '已退役', pending: '待审批', approved: '已批准', rejected: '已驳回', draft: '草稿',
  revoked: '已吊销', expired: '已过期', offline: '离线',
}
export interface RoleSummary { roleKey: string; name: string; description: string; permissions: string[] }
export interface RoleBindingView { roleKey: string; roleName: string; scopeType: string; scopeId: string }
export interface OverviewView { hourlyAlerts: { hour: string; count: number }[]; quality24h: { accepted: number; manualReview: number; rejected: number } }
export interface OpsStatusView {
  outboxPending: number
  outboxFailed: number
  outboxDeadLetter: number
  oldestPendingAgeSeconds: number
  averagePublishedDelaySeconds24h: number
  sensorsOnline: number
  sensorsHeartbeatTimeout: number
  ingestRejectionRatio24h: number
  loginThrottleBlocked: number
  loginThrottleFailures15m: number
}

/**
 * 告警人工标注（阶段 7 人工抽检），对应后端 IncidentMapper.FeedbackView。
 * 与模型页 /feedback-samples 用的 FeedbackView 是不同契约，不要混用。
 * reviewedAt / secondReviewedAt 为 UTC LocalDateTime；reviewStatus 为 rejected 时标注已失效。
 */
export interface AlertFeedbackView {
  id: number; alertId: number; alertKey: string; alertType: string; label: 'false_positive' | 'true_positive'; note: string
  reviewedBy: number; reviewerName: string; reviewedAt: string; reviewStatus: 'pending' | 'training_approved' | 'rejected'
  secondReviewedBy: number | null; secondReviewerName: string | null; secondReviewedAt: string | null; secondReviewReason: string | null
  trainingEligible: boolean; dataSourceId: number; assetId: number
}

/** 影子验证按日覆盖；date 为所选时区下的 LocalDate（原样显示），observed 表示当天覆盖 ≥ 12 小时。 */
export interface ShadowDay { date: string; weekend: boolean; coveredHours: number; observed: boolean; modelAlerts: number }
/** 停机段；start / end 为带 Z 的 Instant。 */
export interface ShadowGap { start: string; end: string; minutes: number }
export interface ShadowCoverage {
  sensors: number; healthWindows: number; coveredHours: number; rangeHours: number; coverageRatio: number
  observedDays: number; observedWeekdays: number; observedWeekendDays: number; days: ShadowDay[]
  gapCount: number; gapHours: number; gaps: ShadowGap[]; flowsSeen: number; flowsEmitted: number; flowsDropped: number; queueDepthMax: number
}
/** 记录与契约：contractRejectRate =（接入拒绝 + 推理契约拒绝）/ 全部记录，运行故障单列不计入。 */
export interface ShadowRecords {
  total: number; ingestRejected: number; manualReview: number; ingestIssueCodes: Record<string, number>
  notInferred: number; inferenceStatus: Record<string, number>; rejectReasons: Record<string, number>
  contractRejected: number; operationalFailed: number; contractRejectRate: number | null; notInModelScope: number
  scored: number; scoredAttack: number; scopeAttackRatio: number | null
  outOfVocabulary: Record<string, number>; outOfVocabularyRatio: Record<string, number | null>
}
/** maxDay 为 LocalDate。 */
export interface ShadowAlerts { modelAlerts: number; assetsWithAlerts: number; meanPerAssetDay: number | null; maxPerAssetDay: number; maxDay: string | null }
/** 抽检样本；detectedAt 为 UTC LocalDateTime，label / reviewStatus 为 null 表示尚未标注。 */
export interface ShadowReviewItem { alertId: number; alertKey: string; detectedAt: string; severity: string; score: number | null; label: string | null; reviewStatus: string | null }
/** sample 只在调用者有 alert.read 时返回，且已按告警可见性过滤；计数不受过滤影响。 */
export interface ShadowReview {
  rule: string; population: number; sampleSize: number; labeled: number; falsePositive: number; truePositive: number
  falsePositiveRate: number | null; sample: ShadowReviewItem[]
}
export interface ShadowModelUse { modelVersionId: number; version: string; artifactSha256: string; scored: number }
export type ShadowDriftStatus = 'computed' | 'insufficient_samples' | 'baseline_unavailable' | 'mixed_artifacts' | 'no_samples'
export interface ShadowDrift {
  status: ShadowDriftStatus; baselineModelVersionId: number | null; baselineVersion: string | null; models: ShadowModelUse[]
  samples: number; minSamples: number; psi: Record<string, number | null>; otherRatio: Record<string, number | null>
  invalid: Record<string, number>; fieldsAboveWarning: string[]; maxPsi: number | null
}
/** 端到端延迟：批次接收 → 该批最后一条推理完成，仅含有推理成功记录的批次。 */
export interface ShadowPerformance {
  batches: number; p50Ms: number | null; p95Ms: number | null; p99Ms: number | null; maxMs: number | null
  deadLetters: number; consumerRetrying: number; outboxPending: number; oldestPendingSeconds: number | null
}
export type CriterionStatus = 'pass' | 'fail' | 'pending' | 'not_evaluable'
export interface ShadowCriterion { key: string; title: string; threshold: string; value: string; status: CriterionStatus; note: string | null }
export type ShadowVerdict = 'pass' | 'fail' | 'incomplete'
/**
 * 影子验证汇总（GET /data-sources/{id}/shadow-report），对应后端 record ShadowReport。
 * 只含计数、比例与分布统计；generatedAt / from / to 为带 Z 的 Instant。
 * verdict：任一 fail 为 fail；否则任一 pending / not_evaluable 为 incomplete；全部 pass 为 pass。
 */
export interface ShadowReport {
  reportVersion: string; thresholdsVersion: string; generatedAt: string; dataSourceId: number; from: string; to: string; timeZone: string
  coverage: ShadowCoverage; records: ShadowRecords; alerts: ShadowAlerts; review: ShadowReview; drift: ShadowDrift
  performance: ShadowPerformance; criteria: ShadowCriterion[]; verdict: ShadowVerdict; limitations: string[]
}

export const feedbackLabel: Record<string, string> = { false_positive: '误报', true_positive: '真报' }
export const feedbackReviewLabel: Record<string, string> = { pending: '待复核', training_approved: '可用于训练', rejected: '已驳回' }
export const criterionLabel: Record<string, string> = { pass: '达标', fail: '未达标', pending: '待定', not_evaluable: '无法判定' }
export const verdictLabel: Record<string, string> = { pass: '通过', fail: '未通过', incomplete: '未完成' }
export const driftStatusLabel: Record<string, string> = { computed: '已计算', insufficient_samples: '样本不足', baseline_unavailable: '无基线', mixed_artifacts: '制品混用', no_samples: '无样本' }

export const severityLabel: Record<string, string> = { critical: '严重', high: '高', medium: '中', low: '低' }
export const eventStatusLabel: Record<string, string> = { open: '待处理', investigating: '研判中', contained: '已遏制', resolved: '已解决', false_positive: '误报', closed: '已关闭' }
/** security_event 合法迁移，与后端 IncidentService 状态机一致；最终是否允许以后端为准。 */
export const eventTransitions: Record<string, EventStatus[]> = {
  open: ['investigating'],
  investigating: ['contained', 'resolved', 'false_positive', 'closed'],
  contained: ['investigating', 'resolved', 'closed'],
  resolved: ['closed'],
  false_positive: ['closed'],
  closed: [],
}
export const alertTypeLabel: Record<string, string> = { model: '模型', rule: '规则' }
/** 告警来源：模型告警为「模型键@版本」，规则告警为「规则键@版本」。 */
export function alertSource(a: AlertView): string {
  if (a.alertType === 'model' && a.modelKey) return `${a.modelKey}@${a.modelVersion ?? '?'}`
  if (a.alertType === 'rule' && a.ruleKey) return `${a.ruleKey}@${a.ruleVersion ?? '?'}`
  return '—'
}
/** 解析后端保存的评分依据快照；缺失或不是对象时返回空列表，不猜测内容。 */
export function basisEntries(json: string | null): [string, string][] {
  if (!json) return []
  try {
    const value: unknown = JSON.parse(json)
    if (!value || typeof value !== 'object' || Array.isArray(value)) return []
    return Object.entries(value as Record<string, unknown>).map(([k, v]) => [k, typeof v === 'object' ? JSON.stringify(v) : String(v)])
  } catch {
    return []
  }
}
export const approvalLabel: Record<string, string> = { pending: '待审批', approved: '已批准', rejected: '已驳回', expired: '已过期', cancelled: '已撤销' }
export const execLabel: Record<string, string> = { queued: '排队', running: '执行中', succeeded: '已生效', failed: '失败', timed_out: '超时', rollback_pending: '待回滚', rolled_back: '已回滚', rollback_failed: '回滚失败' }
export const modelStageLabel: Record<string, string> = { candidate: '候选', validated: '已校验', approved: '已批准', rejected: '已驳回', retired: '已退役' }

/** 后端返回 UTC LocalDateTime，按本地时区显示到分钟。 */
export function fmtTime(v: string | null | undefined, withDate = true) {
  if (!v) return '—'
  const d = new Date(v.endsWith('Z') ? v : v + 'Z')
  if (Number.isNaN(d.getTime())) return v
  const p = (n: number) => String(n).padStart(2, '0')
  const t = `${p(d.getHours())}:${p(d.getMinutes())}`
  return withDate ? `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${t}` : t
}
