/**
 * 威胁检测（F1）msw 处理器：覆盖观测与推理、判定与来源、事件研判（含详情/时间线/证据组/动作/可指派人员）、
 * 反馈与复核的读取与写操作，并校验写请求的 Idempotency-Key 与 If-Match。
 */
import { http, HttpResponse } from 'msw'
import type {
  GuardAction, GuardAsset, GuardAssignableUser, GuardDecision, GuardDetection,
  GuardEpisode, GuardEpisodeEvidence, GuardFeedback, GuardGuardEvent,
  GuardObservation, GuardObservationBatch, GuardTimelineEntry,
} from '@/api/types'
import { currentUser } from './auth'
import { singleRoleUsers } from '@/test/roles'

export const ASSET_1 = '10000000-0000-4000-8000-000000000001'
export const ASSET_2 = '10000000-0000-4000-8000-000000000002'
export const OBS_1 = '20000000-0000-4000-8000-000000000001'
export const OBS_2 = '20000000-0000-4000-8000-000000000002'
export const EP_1 = '30000000-0000-4000-8000-000000000001'
export const DEC_1 = '40000000-0000-4000-8000-000000000001'
export const DEC_2 = '40000000-0000-4000-8000-000000000002'
export const EVENT_OPEN = '50000000-0000-4000-8000-000000000001'
export const EVENT_ALERT_ONLY = '50000000-0000-4000-8000-000000000002'
export const POLICY_1 = '60000000-0000-4000-8000-000000000001'
export const BUDGET_1 = '70000000-0000-4000-8000-000000000001'
export const TARGET_REF_1 = '80000000-0000-4000-8000-000000000001'
export const FB_OTHER = '90000000-0000-4000-8000-000000000001'
export const FB_SELF_REVIEWER = '90000000-0000-4000-8000-000000000002'

export interface RecordedWrite {
  body: unknown
  ifMatch: string | null
  idempotencyKey: string | null
}

export interface DetectFixtureState {
  assets: GuardAsset[]
  batches: GuardObservationBatch[]
  observations: GuardObservation[]
  detections: GuardDetection[]
  episodes: GuardEpisode[]
  episodeEvidence: Record<string, GuardEpisodeEvidence[]>
  decisions: GuardDecision[]
  events: GuardGuardEvent[]
  timelines: Record<string, GuardTimelineEntry[]>
  eventActions: Record<string, GuardAction[]>
  assignableUsers: GuardAssignableUser[]
  feedbacks: GuardFeedback[]
  writes: Record<string, RecordedWrite>
}

function defaultState(): DetectFixtureState {
  return {
    assets: [
      { id: ASSET_1, assetKey: 'host-lab-01', assetType: 'host', environment: 'lab', criticality: 'high', owner: 'sec', status: 'active', labels: {}, revision: 1, createdAt: '2026-10-13T10:00:00Z', updatedAt: '2026-10-13T10:00:00Z' },
      { id: ASSET_2, assetKey: 'host-auth-02', assetType: 'host', environment: 'authorized', criticality: 'high', owner: 'sec', status: 'active', labels: {}, revision: 1, createdAt: '2026-10-13T10:00:00Z', updatedAt: '2026-10-13T10:00:00Z' },
    ],
    batches: [
      {
        id: 'b0000000-0000-4000-8000-000000000001',
        assetId: ASSET_1,
        sensorId: 's-1',
        bootId: 'boot-0001-aaaa',
        sequenceNo: 12,
        configId: 'cfg-1',
        requestSha256: 'a'.repeat(64),
        result: { acceptedCount: 3, rejectedCount: 0 },
        createdAt: '2026-10-13T10:01:00Z',
      },
    ],
    observations: [
      {
        id: OBS_1,
        batchId: 'b0000000-0000-4000-8000-000000000001',
        assetId: ASSET_1,
        sensorId: 's-1',
        captureScopeId: 'scope-1',
        bootId: 'boot-0001-aaaa',
        flowId: 'flow-ssh-brute-01',
        parentConnectionId: 'parent-01',
        snapshotIndex: 1,
        profile: 'unsw-nb15-flow-v4',
        asOf: '2026-10-13T10:01:00Z',
        lastPacketAt: '2026-10-13T10:00:59Z',
        peerKey: 'peer-hmac-01',
        keyEpoch: 'epoch-1',
        direction: 'inbound',
        transport: 'tcp',
        servicePort: 22,
        environment: 'lab',
        contentSha256: 'b'.repeat(64),
        payload: { spkts: 18, dpkts: 12 },
        createdAt: '2026-10-13T10:01:00Z',
      },
      {
        id: OBS_2,
        batchId: 'b0000000-0000-4000-8000-000000000001',
        assetId: ASSET_2,
        sensorId: 's-2',
        captureScopeId: 'scope-2',
        bootId: 'boot-0002-bbbb',
        flowId: 'flow-scan-02',
        parentConnectionId: 'parent-02',
        snapshotIndex: 0,
        profile: 'unsw-nb15-flow-v4',
        asOf: '2026-10-13T10:02:00Z',
        lastPacketAt: '2026-10-13T10:01:58Z',
        peerKey: 'peer-hmac-02',
        keyEpoch: 'epoch-1',
        direction: 'inbound',
        transport: 'tcp',
        servicePort: 443,
        environment: 'authorized',
        contentSha256: 'c'.repeat(64),
        payload: { spkts: 4, dpkts: 0 },
        createdAt: '2026-10-13T10:02:00Z',
      },
    ],
    detections: [
      {
        id: 'd0000000-0000-4000-8000-000000000001',
        observationId: OBS_1,
        assetId: ASSET_1,
        modelId: 'm-1',
        manifestSha256: 'd'.repeat(64),
        status: 'succeeded',
        applicability: 'applicable',
        score: 0.962,
        family: 'brute_force',
        familyScores: { normal: 0.038, brute_force: 0.92, port_scan: 0.02, dos_flood: 0.01, dos_slow: 0.012 },
        errorCode: null,
        completedAt: '2026-10-13T10:01:01Z',
        createdAt: '2026-10-13T10:01:01Z',
      },
      {
        id: 'd0000000-0000-4000-8000-000000000002',
        observationId: OBS_2,
        assetId: ASSET_2,
        modelId: 'm-1',
        manifestSha256: 'd'.repeat(64),
        status: 'not_applicable',
        applicability: 'unsupported_profile',
        score: null,
        family: null,
        familyScores: null,
        errorCode: 'PROFILE_UNSUPPORTED',
        completedAt: '2026-10-13T10:02:01Z',
        createdAt: '2026-10-13T10:02:01Z',
      },
    ],
    episodes: [
      {
        id: EP_1,
        assetId: ASSET_1,
        sensorId: 's-1',
        bootId: 'boot-0001-aaaa',
        peerKey: 'peer-hmac-01',
        keyEpoch: 'epoch-1',
        direction: 'inbound',
        transport: 'tcp',
        servicePort: 22,
        family: 'brute_force',
        source: 'rule',
        ruleId: 'R-BF-1',
        scope: 'peer_service',
        bundleId: 'b-1',
        bucketStart: '2026-10-13T10:01:00Z',
        revision: 2,
        createdAt: '2026-10-13T10:01:02Z',
      },
    ],
    episodeEvidence: {
      [EP_1]: [
        {
          id: 'ee-1',
          episodeId: EP_1,
          observationId: OBS_1,
          inferenceId: 'd0000000-0000-4000-8000-000000000001',
          parentConnectionId: 'parent-01',
          source: 'rule',
          ruleId: 'R-BF-1',
          ruleMatched: true,
          score: 0.962,
          family: 'brute_force',
          asOf: '2026-10-13T10:01:00Z',
          createdAt: '2026-10-13T10:01:02Z',
        },
      ],
    },
    decisions: [
      {
        id: DEC_1,
        episodeId: EP_1,
        assetId: ASSET_1,
        bundleId: 'b-1',
        decisionRevision: 1,
        budgetTargetId: BUDGET_1,
        budgetRevision: 1,
        decision: 'block_candidate',
        reasonCode: '',
        evidenceSha256: 'e'.repeat(64),
        evidence: {
          family: 'brute_force',
          source: 'rule',
          ruleId: 'R-BF-1',
          scope: 'peer_service',
          environment: 'lab',
          bundleId: 'b-1',
          capabilityId: 'cap-1',
          authorizationId: 'auth-1',
          authorizationRevision: 1,
          budgetTargetId: BUDGET_1,
          triggerObservationId: OBS_1,
          selectedObservations: [
            { observationId: OBS_1, parentConnectionId: 'parent-01', family: 'brute_force', source: 'rule', ruleId: 'R-BF-1', asOf: '2026-10-13T10:01:00Z' },
          ],
        },
        decisionContractVersion: 'host-guard-decision/1',
        decidedAt: '2026-10-13T10:01:03Z',
        createdAt: '2026-10-13T10:01:03Z',
      },
      {
        id: DEC_2,
        episodeId: EP_1,
        assetId: ASSET_1,
        bundleId: 'b-1',
        decisionRevision: 2,
        budgetTargetId: BUDGET_1,
        budgetRevision: 1,
        decision: 'alert',
        reasonCode: 'MODEL_AUTO_DISABLED',
        evidenceSha256: 'f'.repeat(64),
        evidence: {
          family: 'brute_force',
          source: 'model',
          ruleId: null,
          scope: 'peer_service',
          environment: 'lab',
          detailCode: 'SOURCE_LEVEL_ALERT_ONLY',
          selectedObservations: [],
        },
        decisionContractVersion: 'host-guard-decision/1',
        decidedAt: '2026-10-13T10:01:05Z',
        createdAt: '2026-10-13T10:01:05Z',
      },
    ],
    events: [
      {
        id: EVENT_OPEN,
        guardAssetId: ASSET_1,
        revision: 2,
        eventKey: 'EVT-LAB-001',
        title: 'SSH 暴力破解阻断候选事件',
        category: 'brute_force',
        severity: 'high',
        status: 'open',
        assigneeId: null,
        riskScore: 0.92,
        riskRuleVersion: 'v5',
        firstSeenAt: '2026-10-13T10:01:00Z',
        lastSeenAt: '2026-10-13T10:01:05Z',
        createdAt: '2026-10-13T10:01:03Z',
        closedAt: null,
        episodeIds: [EP_1],
        decisionIds: [DEC_1, DEC_2],
        actionable: true,
        budgetTargetId: BUDGET_1,
        policyId: POLICY_1,
        actionEpisodeId: EP_1,
        targetRef: TARGET_REF_1,
        actionableReasonCode: null,
      },
      {
        id: EVENT_ALERT_ONLY,
        guardAssetId: ASSET_2,
        revision: 1,
        eventKey: 'EVT-AUTH-002',
        title: '端口扫描只告警事件',
        category: 'port_scan',
        severity: 'medium',
        status: 'investigating',
        assigneeId: 'usr-analyst',
        riskScore: 0.65,
        riskRuleVersion: 'v5',
        firstSeenAt: '2026-10-13T10:02:00Z',
        lastSeenAt: '2026-10-13T10:02:05Z',
        createdAt: '2026-10-13T10:02:03Z',
        closedAt: null,
        episodeIds: [],
        decisionIds: [],
        actionable: false,
        budgetTargetId: null,
        policyId: null,
        actionEpisodeId: null,
        targetRef: null,
        actionableReasonCode: 'ACTION_EVIDENCE_REQUIRED',
      },
    ],
    timelines: {
      [EVENT_OPEN]: [
        {
          id: 'tl-1',
          eventId: EVENT_OPEN,
          occurredAt: '2026-10-13T10:01:03Z',
          entryType: 'guard.decision',
          actorType: 'system',
          actorId: 'guard',
          summary: '规则 R-BF-1 生成阻断候选判定',
          evidenceRef: DEC_1,
          details: { decision: 'block_candidate' },
          createdAt: '2026-10-13T10:01:03Z',
        },
      ],
      [EVENT_ALERT_ONLY]: [],
    },
    eventActions: {
      [EVENT_OPEN]: [
        {
          id: 'act-0001-aaaa',
          decisionId: DEC_1,
          assetId: ASSET_1,
          executorId: 'ex-1',
          budgetTargetId: BUDGET_1,
          budgetRevision: 1,
          bundleId: 'b-1',
          authorizationId: 'auth-1',
          authorizationRevision: 1,
          mode: 'manual',
          desiredState: 'active',
          observedState: 'pending',
          desiredRevision: 1,
          idempotencyKey: 'idem-1',
          targetSnapshot: { servicePort: 22 },
          blockUntil: '2026-10-13T10:02:03Z',
          revision: 1,
          createdAt: '2026-10-13T10:01:10Z',
        },
      ],
      [EVENT_ALERT_ONLY]: [],
    },
    assignableUsers: [
      {
        id: 'usr-analyst',
        assetId: ASSET_1,
        userKey: 'usr-analyst',
        username: singleRoleUsers.security_analyst.username,
        displayName: singleRoleUsers.security_analyst.displayName,
        status: 'active',
      },
      {
        id: 'usr-analyst-2',
        assetId: ASSET_1,
        userKey: 'usr-analyst-2',
        username: 'sec-analyst-2',
        displayName: '二线安全分析员',
        status: 'active',
      },
    ],
    feedbacks: [
      {
        id: FB_OTHER,
        createdAt: '2026-10-13T10:05:00Z',
        assetId: ASSET_1,
        observationId: OBS_1,
        label: 'attack',
        evidenceRef: 'sha256:bbbbbbbbbbbbbbbb',
        status: 'pending',
        reviewReason: null,
        revision: 1,
        createdBy: singleRoleUsers.security_analyst.id,
      },
      {
        id: FB_SELF_REVIEWER,
        createdAt: '2026-10-13T10:06:00Z',
        assetId: ASSET_1,
        observationId: OBS_2,
        label: 'benign',
        evidenceRef: 'sha256:cccccccccccccccc',
        status: 'pending',
        reviewReason: null,
        revision: 1,
        createdBy: singleRoleUsers.evidence_reviewer.id,
      },
      {
        id: '90000000-0000-4000-8000-000000000003',
        createdAt: '2026-10-13T09:50:00Z',
        assetId: ASSET_1,
        observationId: OBS_1,
        label: 'attack',
        evidenceRef: 'obs:verified-01',
        status: 'reviewed',
        reviewReason: '流量时间窗与握手机制核实为真实暴破',
        revision: 2,
        createdBy: singleRoleUsers.security_analyst.id,
      },
    ],
    writes: {},
  }
}

export let detectState: DetectFixtureState = defaultState()
export const resetDetectState = () => { detectState = defaultState() }

const ok = <T>(data: T, status = 200) => HttpResponse.json({ requestId: 'req-detect', data, error: null }, { status })
const fail = (status: number, code: string, message: string, requestId = 'req-detect-err') =>
  HttpResponse.json({ requestId, data: null, error: { code, message } }, { status })

function recordWrite(request: Request, body: unknown) {
  const key = `${request.method} ${new URL(request.url).pathname}`
  detectState.writes[key] = {
    body,
    ifMatch: request.headers.get('If-Match'),
    idempotencyKey: request.headers.get('Idempotency-Key'),
  }
}

function filterByAsset<T extends { assetId?: string | null; guardAssetId?: string | null }>(rows: T[], assetId: string | null): T[] {
  if (!assetId) return rows
  return rows.filter((r) => (r.assetId ?? r.guardAssetId) === assetId)
}

export const detectHandlers = [
  http.get('/api/v2/assets', () => ok({ items: detectState.assets, nextCursor: null })),

  http.get('/api/v2/observation-batches', ({ request }) => {
    const u = new URL(request.url)
    return ok({ items: filterByAsset(detectState.batches, u.searchParams.get('assetId')), nextCursor: null })
  }),

  http.get('/api/v2/observations', ({ request }) => {
    const u = new URL(request.url)
    return ok({ items: filterByAsset(detectState.observations, u.searchParams.get('assetId')), nextCursor: null })
  }),

  http.get('/api/v2/observations/:id', ({ params }) => {
    const hit = detectState.observations.find((o) => o.id === params.id)
    return hit ? ok(hit) : fail(404, 'RESOURCE_NOT_FOUND', '观察记录不存在')
  }),

  http.get('/api/v2/detections', ({ request }) => {
    const u = new URL(request.url)
    return ok({ items: filterByAsset(detectState.detections, u.searchParams.get('assetId')), nextCursor: null })
  }),

  http.get('/api/v2/evidence-episodes', ({ request }) => {
    const u = new URL(request.url)
    return ok({ items: filterByAsset(detectState.episodes, u.searchParams.get('assetId')), nextCursor: null })
  }),

  http.get('/api/v2/evidence-episodes/:id/evidence', ({ params }) => {
    const items = detectState.episodeEvidence[String(params.id)] ?? []
    return ok({ items })
  }),

  http.get('/api/v2/decisions', () => ok({ items: detectState.decisions, nextCursor: null })),

  http.get('/api/v2/events', ({ request }) => {
    const u = new URL(request.url)
    const status = u.searchParams.get('status')
    const assetId = u.searchParams.get('assetId')
    let items = filterByAsset(detectState.events, assetId)
    if (status) items = items.filter((e) => e.status === status)
    return ok({ items, nextCursor: null })
  }),

  http.get('/api/v2/events/:id', ({ params }) => {
    const hit = detectState.events.find((e) => e.id === params.id)
    return hit ? ok(hit) : fail(404, 'RESOURCE_NOT_FOUND', '事件不存在')
  }),

  http.get('/api/v2/events/:id/timeline', ({ params }) => {
    const items = detectState.timelines[String(params.id)] ?? []
    return ok({ items })
  }),

  http.get('/api/v2/events/:id/episodes', ({ params }) => {
    const ev = detectState.events.find((e) => e.id === params.id)
    if (!ev) return fail(404, 'RESOURCE_NOT_FOUND', '事件不存在')
    const items = detectState.episodes.filter((ep) => ev.episodeIds?.includes(ep.id))
    return ok({ items })
  }),

  http.get('/api/v2/events/:id/actions', ({ params }) => {
    const user = currentUser()
    if (!user?.permissions.includes('action.read')) return fail(403, 'SCOPE_DENIED', '缺少动作读取权限')
    return ok({ items: detectState.eventActions[String(params.id)] ?? [] })
  }),

  http.get('/api/v2/assignable-users', ({ request }) => {
    const u = new URL(request.url)
    const assetId = u.searchParams.get('assetId')
    const items = assetId ? detectState.assignableUsers.filter((x) => x.assetId === assetId) : detectState.assignableUsers
    return ok({ asOf: '2026-10-13T10:10:00Z', items, nextCursor: null })
  }),

  http.post('/api/v2/events/:id/transitions', async ({ params, request }) => {
    if (!request.headers.get('Idempotency-Key')) return fail(400, 'INVALID_IDEMPOTENCY_KEY', '缺少幂等键')
    const ev = detectState.events.find((e) => e.id === params.id)
    if (!ev) return fail(404, 'RESOURCE_NOT_FOUND', '事件不存在')
    const ifMatch = request.headers.get('If-Match')
    if (ifMatch !== String(ev.revision)) return fail(409, 'REVISION_CONFLICT', '事件已被其他操作更新')
    const body = (await request.json()) as { expectedRevision?: number; to?: string; reason?: string }
    recordWrite(request, body)
    if (!body.to || !body.reason) return fail(400, 'INVALID_REQUEST', '缺少目标状态或理由')
    ev.status = body.to
    ev.revision += 1
    detectState.timelines[ev.id] = [
      {
        id: `tl-${Date.now()}`,
        eventId: ev.id,
        occurredAt: '2026-10-13T10:15:00Z',
        entryType: 'guard.transition',
        actorType: 'human',
        actorId: String(currentUser()?.id ?? 102),
        summary: body.reason,
        evidenceRef: null,
        details: body,
        createdAt: '2026-10-13T10:15:00Z',
      },
      ...(detectState.timelines[ev.id] ?? []),
    ]
    return ok({ id: ev.id, status: ev.status, revision: ev.revision })
  }),

  http.put('/api/v2/events/:id/assignee', async ({ params, request }) => {
    if (!request.headers.get('Idempotency-Key')) return fail(400, 'INVALID_IDEMPOTENCY_KEY', '缺少幂等键')
    const ev = detectState.events.find((e) => e.id === params.id)
    if (!ev) return fail(404, 'RESOURCE_NOT_FOUND', '事件不存在')
    const ifMatch = request.headers.get('If-Match')
    if (ifMatch !== String(ev.revision)) return fail(409, 'REVISION_CONFLICT', '事件已被其他操作更新')
    const body = (await request.json()) as { userId: string | null; reason?: string }
    recordWrite(request, body)
    ev.assigneeId = body.userId
    ev.revision += 1
    detectState.timelines[ev.id] = [
      {
        id: `tl-assign-${Date.now()}`,
        eventId: ev.id,
        occurredAt: '2026-10-13T10:16:00Z',
        entryType: 'guard.assignment',
        actorType: 'human',
        actorId: String(currentUser()?.id ?? 102),
        summary: body.reason ?? (body.userId ? `指派给 ${body.userId}` : '取消指派'),
        evidenceRef: null,
        details: body,
        createdAt: '2026-10-13T10:16:00Z',
      },
      ...(detectState.timelines[ev.id] ?? []),
    ]
    return ok({ id: ev.id, assigneeId: ev.assigneeId, revision: ev.revision })
  }),

  http.post('/api/v2/events/:id/notes', async ({ params, request }) => {
    if (!request.headers.get('Idempotency-Key')) return fail(400, 'INVALID_IDEMPOTENCY_KEY', '缺少幂等键')
    const ev = detectState.events.find((e) => e.id === params.id)
    if (!ev) return fail(404, 'RESOURCE_NOT_FOUND', '事件不存在')
    const body = (await request.json()) as { note?: string }
    recordWrite(request, body)
    if (!body.note) return fail(400, 'INVALID_REQUEST', '缺少研判记录内容')
    const item: GuardTimelineEntry = {
      id: `tl-note-${Date.now()}`,
      eventId: ev.id,
      occurredAt: '2026-10-13T10:17:00Z',
      entryType: 'guard.note',
      actorType: 'human',
      actorId: String(currentUser()?.id ?? 102),
      summary: body.note,
      evidenceRef: null,
      details: body,
      createdAt: '2026-10-13T10:17:00Z',
    }
    detectState.timelines[ev.id] = [item, ...(detectState.timelines[ev.id] ?? [])]
    return ok({ id: item.id }, 201)
  }),

  http.post('/api/v2/actions', async ({ request }) => {
    if (!request.headers.get('Idempotency-Key')) return fail(400, 'INVALID_IDEMPOTENCY_KEY', '缺少幂等键')
    const body = (await request.json()) as { episodeId?: string; targetRef?: string; policyId?: string; reason?: string }
    recordWrite(request, body)
    if (!body.episodeId || !body.targetRef || !body.policyId || !body.reason) {
      return fail(400, 'INVALID_REQUEST', '处置申请字段不完整')
    }
    const created: GuardAction = {
      id: 'act-0002-bbbb',
      decisionId: DEC_1,
      assetId: ASSET_1,
      executorId: 'ex-1',
      budgetTargetId: BUDGET_1,
      budgetRevision: 2,
      bundleId: 'b-1',
      authorizationId: 'auth-1',
      authorizationRevision: 1,
      mode: 'manual',
      desiredState: 'active',
      observedState: 'pending',
      desiredRevision: 1,
      idempotencyKey: request.headers.get('Idempotency-Key'),
      targetSnapshot: { targetRef: body.targetRef, servicePort: 22 },
      blockUntil: '2026-10-13T10:25:00Z',
      revision: 1,
      createdAt: '2026-10-13T10:18:00Z',
    }
    detectState.eventActions[EVENT_OPEN] = [created, ...(detectState.eventActions[EVENT_OPEN] ?? [])]
    return ok({ id: created.id, observedState: 'pending', desiredState: 'active', revision: 1 }, 201)
  }),

  http.get('/api/v2/feedback', ({ request }) => {
    const u = new URL(request.url)
    const status = u.searchParams.get('status')
    const assetId = u.searchParams.get('assetId')
    let items = filterByAsset(detectState.feedbacks, assetId)
    if (status) items = items.filter((f) => f.status === status)
    return ok({ items, nextCursor: null })
  }),

  http.post('/api/v2/feedback', async ({ request }) => {
    if (!request.headers.get('Idempotency-Key')) return fail(400, 'INVALID_IDEMPOTENCY_KEY', '缺少幂等键')
    const body = (await request.json()) as { observationId?: string; label?: string; evidenceRef?: string }
    recordWrite(request, body)
    if (!body.observationId || !body.label || !body.evidenceRef) {
      return fail(400, 'INVALID_REQUEST', '标注字段不完整')
    }
    const item: GuardFeedback = {
      id: `fb-${Date.now()}`,
      createdAt: '2026-10-13T10:20:00Z',
      assetId: ASSET_1,
      observationId: body.observationId,
      label: body.label,
      evidenceRef: body.evidenceRef,
      status: 'pending',
      reviewReason: null,
      revision: 1,
      createdBy: currentUser()?.id ?? null,
    }
    detectState.feedbacks = [item, ...detectState.feedbacks]
    return ok({ id: item.id, status: 'pending', revision: 1, trainingEligible: false }, 201)
  }),

  http.post('/api/v2/feedback/:id/reviews', async ({ params, request }) => {
    if (!request.headers.get('Idempotency-Key')) return fail(400, 'INVALID_IDEMPOTENCY_KEY', '缺少幂等键')
    const fb = detectState.feedbacks.find((f) => f.id === params.id)
    if (!fb) return fail(404, 'RESOURCE_NOT_FOUND', '反馈记录不存在')
    if (request.headers.get('If-Match') !== String(fb.revision)) {
      return fail(409, 'REVISION_CONFLICT', '反馈版本冲突')
    }
    if (fb.createdBy != null && String(fb.createdBy) === String(currentUser()?.id)) {
      return fail(403, 'APPROVAL_SEPARATION_REQUIRED', '本人标注须由其他复核人决定')
    }
    const body = (await request.json()) as { decision?: 'approve' | 'reject'; reason?: string }
    recordWrite(request, body)
    if (!body.decision || !body.reason) return fail(400, 'INVALID_DECISION', '缺少复核结论或理由')
    fb.status = body.decision === 'approve' ? 'reviewed' : 'rejected'
    fb.reviewReason = body.reason
    fb.revision += 1
    return ok({ id: fb.id, status: fb.status, trainingEligible: false, revision: fb.revision })
  }),
]
