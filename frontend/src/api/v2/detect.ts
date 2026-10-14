/**
 * 威胁检测分组（F1）API 封装与表单字段常量（/api/v2）。
 *
 * 统一在此定义请求体字段名常量、客户端 UUID 校验与读写调用，
 * 页面组件不散落手写路径或请求体字面量键名。
 */
import { guard, type Cursor, type CursorQuery } from '@/api/client'
import type {
  EventStatus, GuardAction, GuardAssignableUser, GuardDecision, GuardDetection,
  GuardEpisode, GuardEpisodeEvidence, GuardFeedback, GuardGuardEvent,
  GuardObservation, GuardObservationBatch, GuardReadPage, GuardTimelineEntry,
} from '@/api/types'

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
  listBatches: (q?: CursorQuery): Promise<Cursor<GuardObservationBatch>> =>
    guard.list<GuardObservationBatch>('observation-batches', q),
  listObservations: (q?: CursorQuery): Promise<Cursor<GuardObservation>> =>
    guard.list<GuardObservation>('observations', q),
  getObservation: (id: string): Promise<GuardObservation> =>
    guard.get<GuardObservation>('observations', id),
  listDetections: (q?: CursorQuery): Promise<Cursor<GuardDetection>> =>
    guard.list<GuardDetection>('detections', q),
  listEpisodes: (q?: CursorQuery): Promise<Cursor<GuardEpisode>> =>
    guard.list<GuardEpisode>('evidence-episodes', q),
  listEpisodeEvidence: (episodeId: string): Promise<{ items: GuardEpisodeEvidence[] }> =>
    guard.child<{ items: GuardEpisodeEvidence[] }>('evidence-episodes', episodeId, 'evidence'),
  listDecisions: (q?: CursorQuery): Promise<Cursor<GuardDecision>> =>
    guard.list<GuardDecision>('decisions', q),

  listEvents: (q?: CursorQuery): Promise<Cursor<GuardGuardEvent>> =>
    guard.list<GuardGuardEvent>('events', q),
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

  listFeedback: (q?: CursorQuery): Promise<Cursor<GuardFeedback>> =>
    guard.list<GuardFeedback>('feedback', q),

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
