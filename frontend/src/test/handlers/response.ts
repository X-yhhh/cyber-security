/**
 * F2 处置接口的合成 MSW：范围裁剪、列表筛选/游标、修订冲突、自批拒绝与幂等重放。
 * 不签发命令、不操作防火墙；202 不生成清理回执，也不替代后端硬约束和真实联调。
 */
import { http } from 'msw'
import type { GuardAction, GuardActionReceipt, GuardBudgetLedger, GuardBudgetTarget } from '@/api/types'
import type { ActionState } from '@/api/v2/response'
import { currentUser } from './auth'
import { ASSET_1, ASSET_2, BUDGET_1, DEC_1, TARGET_REF_1 } from './detect'
import { fixtureCan, fixtureDenied, fixtureFail, fixtureNotFound, fixtureOk, fixtureUnauthenticated } from './access'
import { singleRoleUsers } from '@/test/roles'

export const RESPONSE_NOW = Date.parse('2026-10-15T04:00:00Z')
export const ACTION_PENDING = 'a2000000-0000-4000-8000-000000000001'
export const ACTION_APPLIED = 'a2000000-0000-4000-8000-000000000002'
export const ACTION_EXPIRED = 'a2000000-0000-4000-8000-000000000003'
export const BUDGET_2 = '70000000-0000-4000-8000-000000000002'

export interface ActionFixture { action: GuardAction; createdBy: number; approvedBy: number | null; hasCommand: boolean }
export interface ResponseWrite { path: string; body: unknown; ifMatch: string | null; idempotencyKey: string }
interface ResponseFixtureState {
  now: number
  actions: ActionFixture[]
  targets: GuardBudgetTarget[]
  ledgers: Record<string, GuardBudgetLedger>
  receipts: Record<string, GuardActionReceipt[]>
  writes: ResponseWrite[]
}

function initialState(): ResponseFixtureState {
  const base: GuardAction = {
    id: ACTION_PENDING, decisionId: DEC_1, assetId: ASSET_1, executorId: 'e2000000-0000-4000-8000-000000000001',
    budgetTargetId: BUDGET_1, budgetRevision: 2, bundleId: null, authorizationId: null, authorizationRevision: null,
    mode: 'manual', desiredState: 'active', desiredRevision: 1, observedState: 'pending', idempotencyKey: null,
    targetSnapshot: { targetRef: TARGET_REF_1, servicePort: 22 }, blockUntil: '2026-10-15T04:05:00Z', revision: 1, createdAt: '2026-10-15T03:59:00Z',
  }
  const target = (id: string, assetId: string): GuardBudgetTarget => ({
    id, assetId, environment: 'lab', resolverExecutorId: base.executorId, identityStatus: 'verified', createdAt: '2026-10-14T04:00:00Z',
  })
  const ledger = (id: string): GuardBudgetLedger => ({
    id, chargedMs: 30_000, lastBlockEndAt: null, lastEvidenceAt: '2026-10-15T03:59:00Z', healthProofSha256: null,
    cycleStartedAt: '2026-10-15T03:55:00Z', revision: 2, createdAt: '2026-10-14T04:00:00Z',
  })
  return {
    now: RESPONSE_NOW,
    actions: [
      { action: base, createdBy: singleRoleUsers.security_analyst.id, approvedBy: null, hasCommand: false },
      { action: { ...base, id: ACTION_APPLIED, mode: 'auto', observedState: 'applied', createdAt: '2026-10-15T03:58:00Z' }, createdBy: 1, approvedBy: null, hasCommand: true },
      { action: { ...base, id: ACTION_EXPIRED, assetId: ASSET_2, budgetTargetId: BUDGET_2, observedState: 'expired', blockUntil: '2026-10-15T03:55:00Z', createdAt: '2026-10-15T03:50:00Z' }, createdBy: 1, approvedBy: null, hasCommand: false },
    ],
    targets: [target(BUDGET_1, ASSET_1), target(BUDGET_2, ASSET_2)],
    ledgers: { [BUDGET_1]: ledger(BUDGET_1), [BUDGET_2]: ledger(BUDGET_2) },
    receipts: { [ACTION_APPLIED]: [{
      id: 'c2000000-0000-4000-8000-000000000001', commandId: 'c2000000-0000-4000-8000-000000000002',
      executorId: base.executorId!, assetId: ASSET_1, revocationId: null, status: 'applied',
      observedAt: '2026-10-15T03:58:02Z', stateDigest: 'a'.repeat(64), contentSha256: 'b'.repeat(64),
      payload: { status: 'applied' }, projected: true, createdAt: '2026-10-15T03:58:03Z',
    }] },
    writes: [],
  }
}

export let responseState = initialState()
const replays = new Map<string, { fingerprint: string; data: unknown; status: number }>()
export function resetResponseState() { responseState = initialState(); replays.clear() }

const states: readonly ActionState[] = ['pending', 'dispatched', 'applied', 'revoked', 'expired', 'rejected', 'uncertain', 'recovery_failed']
const invalidQuery = () => fixtureFail(400, 'INVALID_QUERY', '查询参数不合法')

/** 合成游标绑定主体、集合与筛选；它只服务于测试，不模拟生产游标签名或数据库事务。 */
function list<T extends { id: string; assetId: string; createdAt: string }>(request: Request, rows: T[], actions: boolean) {
  const user = currentUser()
  if (!user) return fixtureUnauthenticated()
  if (!fixtureCan(user, 'action.read')) return fixtureDenied()
  const url = new URL(request.url)
  const q = url.searchParams
  const allowed = ['assetId', 'from', 'until', 'sort', 'cursor', 'limit', ...(actions ? ['status', 'active'] : [])]
  if ([...q.keys()].some((k) => !allowed.includes(k) || q.getAll(k).length !== 1 || !q.get(k))) return invalidQuery()
  if (q.has('active') && q.get('active') !== 'true') return invalidQuery()
  if (q.has('status') && !states.some((s) => s === q.get('status'))) return invalidQuery()
  if (q.has('sort') && !['createdAt', 'updatedAt'].includes(q.get('sort')!)) return invalidQuery()
  const from = q.get('from'), until = q.get('until')
  if ([from, until].some((v) => v !== null && (!/^\d{4}-\d{2}-\d{2}T.+Z$/.test(v) || !Number.isFinite(Date.parse(v))))) return invalidQuery()
  if (from && until && Date.parse(from) >= Date.parse(until)) return invalidQuery()
  const limit = Number(q.get('limit') ?? 50)
  if (!Number.isInteger(limit) || limit < 1 || limit > 200) return fixtureFail(400, 'INVALID_PAGE_SIZE', '分页大小不合法')
  const assetId = q.get('assetId')
  if (assetId && (!responseState.targets.some((t) => t.assetId === assetId) || !fixtureCan(user, 'action.read', assetId))) return fixtureNotFound()
  let items = rows.filter((r) => fixtureCan(user, 'action.read', r.assetId) && (!assetId || r.assetId === assetId)
    && (!from || Date.parse(r.createdAt) >= Date.parse(from)) && (!until || Date.parse(r.createdAt) < Date.parse(until)))
  if (actions) items = items.filter((r) => {
    const action = r as unknown as GuardAction
    return (!q.has('status') || action.observedState === q.get('status'))
      && (!q.has('active') || (action.desiredState === 'active' && action.blockUntil !== null && Date.parse(action.blockUntil) > responseState.now))
  })
  items.sort((a, b) => b.createdAt.localeCompare(a.createdAt) || b.id.localeCompare(a.id))
  const filters = [...q.entries()].filter(([k]) => k !== 'cursor').sort(([a], [b]) => a.localeCompare(b))
  const binding = JSON.stringify([user.id, url.pathname, filters])
  let offset = 0
  if (q.has('cursor')) {
    try {
      const position = JSON.parse(atob(q.get('cursor')!)) as { binding: string; after: string }
      const index = items.findIndex((i) => i.id === position.after)
      if (position.binding !== binding || index < 0) throw new Error('cursor')
      offset = index + 1
    } catch { return fixtureFail(400, 'INVALID_CURSOR', '游标与查询不匹配') }
  }
  const page = items.slice(offset, offset + limit)
  return fixtureOk({ items: page, nextCursor: offset + limit < items.length ? btoa(JSON.stringify({ binding, after: page[page.length - 1]!.id })) : null })
}

function actionAccess(id: string, permission: string) {
  const user = currentUser()
  if (!user) return { error: fixtureUnauthenticated() }
  if (!fixtureCan(user, permission)) return { error: fixtureDenied() }
  const row = responseState.actions.find((r) => r.action.id === id)
  if (!row) return { error: fixtureNotFound() }
  if (!fixtureCan(user, permission, row.action.assetId)) return { error: permission === 'action.read' ? fixtureNotFound() : fixtureDenied() }
  return { user, row }
}

/** 记录并校验协议头；同一主体/路径/键只接受同一请求体和 If-Match。 */
function write(request: Request, body: unknown, status: number, run: () => unknown) {
  const key = request.headers.get('Idempotency-Key') ?? ''
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(key)) return fixtureFail(400, 'INVALID_UUID', '幂等键必须为 UUID')
  if (!request.headers.has('X-CSRF-TOKEN')) return fixtureFail(403, 'CSRF_INVALID', '请求校验失败')
  const ifMatch = request.headers.get('If-Match')
  const path = new URL(request.url).pathname
  const replayKey = `${currentUser()!.id}:${path}:${key}`
  const fingerprint = JSON.stringify({ body, ifMatch })
  const previous = replays.get(replayKey)
  if (previous) return previous.fingerprint === fingerprint ? fixtureOk(previous.data, previous.status) : fixtureFail(409, 'IDEMPOTENCY_CONFLICT', '幂等键已用于其他请求')
  const result = run()
  if (result instanceof Response) return result
  responseState.writes.push({ path, body, ifMatch, idempotencyKey: key })
  replays.set(replayKey, { fingerprint, data: result, status })
  return fixtureOk(result, status)
}

function revoke(row: ActionFixture) {
  if (row.action.desiredState === 'revoked') return
  row.action.desiredState = 'revoked'
  row.action.desiredRevision++
  row.action.revision++
  if (!row.hasCommand) row.action.observedState = 'revoked'
}

export const responseHandlers = [
  http.get('/api/v2/actions', ({ request }) => list(request, responseState.actions.map((r) => r.action), true)),
  http.get('/api/v2/actions/:id', ({ params }) => {
    const access = actionAccess(String(params.id), 'action.read')
    return access.error ?? fixtureOk(access.row!.action)
  }),
  http.get('/api/v2/actions/:id/receipts', ({ params }) => {
    const access = actionAccess(String(params.id), 'action.read')
    return access.error ?? fixtureOk({ items: responseState.receipts[String(params.id)] ?? [] })
  }),
  http.get('/api/v2/budget-targets', ({ request }) => list(request, responseState.targets, false)),
  http.get('/api/v2/budget-targets/:id', ({ params }) => {
    const user = currentUser()
    if (!user) return fixtureUnauthenticated()
    if (!fixtureCan(user, 'action.read')) return fixtureDenied()
    const row = responseState.targets.find((t) => t.id === params.id)
    if (!row || !fixtureCan(user, 'action.read', row.assetId)) return fixtureNotFound()
    return fixtureOk(responseState.ledgers[row.id])
  }),
  http.post('/api/v2/actions/:id/decisions', async ({ request, params }) => {
    const access = actionAccess(String(params.id), 'authorization.approve')
    if (access.error) return access.error
    const { row, user } = access
    const body = await request.json() as { decision?: string; reason?: string }
    return write(request, body, 200, () => {
      if (request.headers.get('If-Match') !== String(row!.action.revision)) return fixtureFail(409, 'REVISION_CONFLICT', '动作已被更新')
      if (!['approve', 'reject'].includes(body.decision ?? '') || !body.reason?.trim()) return fixtureFail(422, 'INVALID_REQUEST', '缺少审批决定或理由')
      if (row!.action.mode !== 'manual' || row!.action.observedState !== 'pending' || row!.approvedBy !== null) return fixtureFail(422, 'STATE_CONFLICT', '动作不在待审批状态')
      if (row!.createdBy === user!.id) return fixtureFail(403, 'APPROVAL_SEPARATION_REQUIRED', '本人申请须由其他审核人决定')
      row!.action.revision++
      if (body.decision === 'reject') { row!.action.observedState = 'rejected'; return { id: row!.action.id, observedState: 'rejected' } }
      row!.approvedBy = user!.id
      return { id: row!.action.id, observedState: 'pending', revision: row!.action.revision }
    })
  }),
  http.post('/api/v2/actions/:id/revocations', async ({ request, params }) => {
    const access = actionAccess(String(params.id), 'action.revoke')
    if (access.error) return access.error
    const row = access.row!
    const body = await request.json() as { reason?: string }
    return write(request, body, 202, () => {
      if (request.headers.get('If-Match') !== String(row.action.revision)) return fixtureFail(409, 'REVISION_CONFLICT', '动作已被更新')
      if (!body.reason?.trim()) return fixtureFail(422, 'INVALID_REQUEST', '请填写撤销理由')
      revoke(row)
      return { id: row.action.id, desiredState: 'revoked', observedState: row.action.observedState }
    })
  }),
  http.post('/api/v2/automation-stops', async ({ request }) => {
    const user = currentUser()
    if (!user) return fixtureUnauthenticated()
    if (!fixtureCan(user, 'automation.stop')) return fixtureDenied()
    const body = await request.json() as { assetIds?: string[]; reason?: string; revokeExisting?: boolean }
    if (!Array.isArray(body.assetIds) || !body.assetIds.length || body.assetIds.length > 32 || !body.reason?.trim() || typeof body.revokeExisting !== 'boolean') return fixtureFail(422, 'INVALID_REQUEST', '资产、原因和撤销选项不完整')
    for (const id of body.assetIds) {
      if (!responseState.targets.some((t) => t.assetId === id)) return fixtureNotFound()
      if (!fixtureCan(user, 'automation.stop', id)) return fixtureDenied()
    }
    return write(request, body, 202, () => {
      if (body.revokeExisting) for (const row of responseState.actions) {
        if (body.assetIds!.includes(row.action.assetId) && !['revoked', 'expired', 'rejected'].includes(row.action.observedState)) revoke(row)
      }
      return { status: 'accepted' }
    })
  }),
]
