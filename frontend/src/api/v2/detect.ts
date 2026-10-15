/**
 * 威胁检测分组（F1）API 封装与表单字段常量（/api/v2）。
 *
 * 统一在此定义请求体字段名常量、客户端 UUID 校验与读写调用，
 * 页面组件不散落手写路径或请求体字面量键名。
 */
import { guard, type Cursor } from '@/api/client'
import type {
  EventStatus, GuardAction, GuardAsset, GuardAssignableUser,
  GuardEpisode, GuardEpisodeEvidence, GuardFeedback, GuardGuardEvent,
  GuardObservation, GuardReadPage, GuardTimelineEntry,
} from '@/api/types'

/**
 * 检测记录（F1R）的列表筛选：资产与时间区间由后端筛选（B4 通用列表参数 `from`/`until`，筛选先于 LIMIT、绑定游标）；
 * 判定、推理、观察、批次四个集合没有登记搜索列，后端对 `q` 返回 400，因此这里不提供 `q`。
 */
export interface RecordQuery { assetId?: string; from?: string; until?: string; cursor?: string; limit?: number }

/** 时间范围预设（URL 参数 `range`）；`from` 在筛选变化时计算一次并保存，翻页沿用同一值，避免游标绑定失配。 */
export const RANGES = [
  { value: '1h', label: '最近 1 小时', ms: 3_600_000 },
  { value: '24h', label: '最近 24 小时', ms: 86_400_000 },
  { value: '7d', label: '最近 7 天', ms: 7 * 86_400_000 },
] as const
export type RangeKey = (typeof RANGES)[number]['value']
export const isRange = (v: unknown): v is RangeKey => RANGES.some((r) => r.value === v)
/** 后端只接受 `YYYY-MM-DDTHH:MM:SS(.fff)Z`，`toISOString()` 恰好满足。 */
export const rangeFrom = (range: RangeKey | '', now = Date.now()): string | undefined => {
  const hit = RANGES.find((r) => r.value === range)
  return hit ? new Date(now - hit.ms).toISOString() : undefined
}

/** B4 起资产带可编辑的显示名；没有显示名时退回 assetKey，界面不显示 UUID。 */
export type NamedAsset = GuardAsset & { displayName?: string | null }
export const assetName = (a: NamedAsset) => a.displayName || a.assetKey

const recordParams = (q: RecordQuery = {}) => ({ assetId: q.assetId, from: q.from, until: q.until, cursor: q.cursor, limit: q.limit ?? 50 })

export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
export const isUuid = (v: string): boolean => UUID_RE.test(v.trim())

export const FEEDBACK_FIELDS = {
  observationId: 'observationId',
  label: 'label',
  evidenceRef: 'evidenceRef',
} as const

export const REVIEW_FIELDS = {
  decision: 'decision',
  reason: 'reason',
} as const

export const TRANSITION_FIELDS = {
  expectedRevision: 'expectedRevision',
  to: 'to',
  reason: 'reason',
} as const

export const ASSIGN_FIELDS = {
  userId: 'userId',
  reason: 'reason',
} as const

export const NOTE_FIELDS = {
  note: 'note',
} as const

export const ACTION_FIELDS = {
  episodeId: 'episodeId',
  targetRef: 'targetRef',
  policyId: 'policyId',
  reason: 'reason',
} as const

export const detectApi = {
  /** 检测记录四个分段的列表读取（带资产与时间筛选）。 */
  records: <T>(collection: 'decisions' | 'detections' | 'observations' | 'observation-batches', q?: RecordQuery): Promise<Cursor<T>> =>
    guard.read<Cursor<T>>(collection, recordParams(q)),
  getAsset: (id: string): Promise<NamedAsset> => guard.get<NamedAsset>('assets', id),

  getObservation: (id: string): Promise<GuardObservation> =>
    guard.get<GuardObservation>('observations', id),
  listEpisodeEvidence: (episodeId: string): Promise<{ items: GuardEpisodeEvidence[] }> =>
    guard.child<{ items: GuardEpisodeEvidence[] }>('evidence-episodes', episodeId, 'evidence'),

  /** 事件列表：状态、资产、时间由后端筛选；`q` 按事件标题前缀搜索（security_event 登记了搜索列）。 */
  listEvents: (q: RecordQuery & { status?: string; q?: string } = {}): Promise<Cursor<GuardGuardEvent>> =>
    guard.read<Cursor<GuardGuardEvent>>('events', { ...recordParams(q), status: q.status, q: q.q }),
  getEvent: (id: string): Promise<GuardGuardEvent> =>
    guard.get<GuardGuardEvent>('events', id),
  listEventTimeline: (id: string): Promise<{ items: GuardTimelineEntry[] }> =>
    guard.child<{ items: GuardTimelineEntry[] }>('events', id, 'timeline'),
  listEventEpisodes: (id: string): Promise<{ items: GuardEpisode[] }> =>
    guard.child<{ items: GuardEpisode[] }>('events', id, 'episodes'),
  listEventActions: (id: string): Promise<{ items: GuardAction[] }> =>
    guard.child<{ items: GuardAction[] }>('events', id, 'actions'),
  listAssignableUsers: (assetId: string): Promise<GuardReadPage<GuardAssignableUser>> =>
    guard.read<GuardReadPage<GuardAssignableUser>>('assignable-users', { assetId, limit: 200 }),

  transitionEvent: (id: string, revision: number, to: EventStatus, reason: string) =>
    guard.op(
      'events',
      id,
      'transitions',
      {
        [TRANSITION_FIELDS.expectedRevision]: revision,
        [TRANSITION_FIELDS.to]: to,
        [TRANSITION_FIELDS.reason]: reason,
      },
      revision,
    ),

  assignEvent: (id: string, revision: number, userId: string | null, reason?: string) => {
    const body: Record<string, unknown> = { [ASSIGN_FIELDS.userId]: userId }
    if (reason) body[ASSIGN_FIELDS.reason] = reason
    return guard.put('events', id, 'assignee', body, revision)
  },

  addEventNote: (id: string, note: string) =>
    guard.op('events', id, 'notes', { [NOTE_FIELDS.note]: note }),

  requestManualAction: (episodeId: string, targetRef: string, policyId: string, reason: string) =>
    guard.create('actions', {
      [ACTION_FIELDS.episodeId]: episodeId,
      [ACTION_FIELDS.targetRef]: targetRef,
      [ACTION_FIELDS.policyId]: policyId,
      [ACTION_FIELDS.reason]: reason,
    }),

  /** 反馈列表：状态、资产与时间由后端筛选（feedback 没有搜索列，不提供 `q`）。 */
  listFeedback: (q: RecordQuery & { status?: string } = {}): Promise<Cursor<GuardFeedback>> =>
    guard.read<Cursor<GuardFeedback>>('feedback', { ...recordParams(q), status: q.status }),

  createFeedback: (observationId: string, label: string, evidenceRef: string) =>
    guard.create<{ id: string }>('feedback', {
      [FEEDBACK_FIELDS.observationId]: observationId,
      [FEEDBACK_FIELDS.label]: label,
      [FEEDBACK_FIELDS.evidenceRef]: evidenceRef,
    }),

  reviewFeedback: (id: string, revision: number, decision: 'approve' | 'reject', reason: string) =>
    guard.op(
      'feedback',
      id,
      'reviews',
      {
        [REVIEW_FIELDS.decision]: decision,
        [REVIEW_FIELDS.reason]: reason,
      },
      revision,
    ),
}
