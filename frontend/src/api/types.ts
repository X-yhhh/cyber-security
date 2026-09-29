/**
 * 后端视图类型与显示标签。字段与后端 record 一一对应（Jackson 默认驼峰），
 * 时间均为 UTC 的 LocalDateTime 字符串（无时区后缀）。
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low'
export type EventStatus = 'open' | 'investigating' | 'contained' | 'resolved' | 'false_positive' | 'closed'

export interface SessionUser { id: number; userKey: string; username: string; displayName: string; roles: string[]; permissions: string[] }
/** 告警视图；V13 起带来源追溯（模型/规则版本、契约版本与哈希、分级策略）和评分依据快照 basisJson。 */
export interface AlertView {
  id: number; alertKey: string; alertType: string; severity: Severity; status: string; score: number | null; detectedAt: string; dataSourceId: number; assetId: number | null
  modelVersionId: number | null; modelKey: string | null; modelVersion: string | null; contractVersion: string | null; contractSha256: string | null
  detectionRuleId: number | null; ruleKey: string | null; ruleVersion: string | null; severityPolicyVersion: string | null; thresholdVersion: string | null; basisJson: string | null
}
export interface EventView {
  id: number; eventKey: string; title: string; category: string; severity: Severity; status: EventStatus; riskScore: number | null; firstSeenAt: string; lastSeenAt: string; assigneeId: number | null; alertCount: number; assetCount: number
  riskRuleVersion: string | null; riskBasisJson: string | null; correlationKey: string | null; correlationPolicyVersion: string | null
}
export interface EventAssetView { assetId: number; assetKey: string; relationType: string; evidenceCount: number }
export interface TimelineView { id: number; occurredAt: string; entryType: string; actorType: string; actorId: string | null; summary: string; evidenceRef: string | null; detailsJson: string | null }
export interface EventDetail { event: EventView; alerts: AlertView[]; assets: EventAssetView[]; timeline: TimelineView[] }
export interface AssetView { id: number; assetKey: string; assetType: string; environment: string; criticality: string; owner: string; status: string }
export interface AuthorizationView { id: number; assetId: number; authorizationRef: string; status: string; validFrom: string; validUntil: string; requestedBy: string | null; approvedBy: string | null; createdAt: string }
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
export interface LedgerView { id: number; eventId: number; eventKey: string; assetId: number; assetKey: string; actionRequest: { actionType?: string; parameters?: { targetAddress?: string; ttlSeconds?: number }; policyKey?: string; policyVersion?: string; reason?: string }; status: string; requester: string; reviewer: string | null; decisionReason: string | null; expiresAt: string; createdAt: string; reviewedAt: string | null; executionStatus: string | null }
export interface ModelView { id: number; modelKey: string; version: string; taskType: string; manifestVersion: string; manifest: Record<string, unknown>; artifactRef: string; artifactSha256: string; featureContractVersion: string; approvalStatus: string; createdAt: string }
export interface ReleaseView { id: number; releaseStatus: string; reviewStatus: string; requester: string | null; approver: string | null; requestReason: string | null; decisionReason: string | null; reviewedAt: string | null; createdAt: string }
export interface DeploymentView { id: number; environment: string; mode: string; modelVersionId: number; modelKey: string; version: string; runtimeType: string; status: string; activatedAt: string | null }
export interface DriftView { id: number; dataSourceId: number; modelKey: string; version: string; windowStart: string; windowEnd: string; featureStats: Record<string, unknown> | null; scoreStats: Record<string, unknown> | null; qualityRejectRate: number | null; driftStatus: string }
export interface FeedbackView { id: number; alertId: number | null; alertKey: string | null; label: string; labelSource: string; reviewer: string | null; reviewedAt: string | null; datasetVersion: string | null; trainingEligible: boolean }
export interface TrainingJobView { id: number; jobKey: string; datasetVersion: string; sampleManifestRef: string; trainHostRef: string; status: string; requester: string | null; startedAt: string | null; finishedAt: string | null; resultManifestRef: string | null; failureReason: string | null }
export interface ReplayScenarioView { id: number; scenarioKey: string; name: string; datasetRef: string; environment: string; safetyProfile: string; status: string; lastRunKey: string | null; lastRunStatus: string | null; lastRunSpeed: number | null; lastRunProgress: number | null; lastRunStartedAt: string | null; lastRunFinishedAt: string | null; lastRunSummary: Record<string, unknown> | null }
export interface AuditView { id: number; occurredAt: string; actorType: string; action: string; resourceType: string; resourceId: string | null; requestId: string | null; outcome: string }
export interface UserSummary { id: number; userKey: string; username: string; displayName: string; status: string }
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
