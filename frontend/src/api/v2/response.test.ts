/** F2 真实客户端到 MSW 的协议测试：筛选、范围、写入并发与受理语义。 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { http, HttpResponse } from 'msw'
import { api, guard, resetCsrf } from '@/api/client'
import { errText } from '@/composables/load'
import { server } from '@/test/handlers'
import { signIn } from '@/test/handlers/auth'
import { ASSET_1, ASSET_2, BUDGET_1 } from '@/test/handlers/detect'
import { ACTION_APPLIED, ACTION_EXPIRED, ACTION_PENDING, BUDGET_2, resetResponseState, responseState } from '@/test/handlers/response'
import { me, singleRoleUsers } from '@/test/roles'
import { responseApi } from './response'

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }))
afterAll(() => server.close())
beforeEach(() => { resetResponseState(); resetCsrf(); signIn(singleRoleUsers.security_reviewer) })
afterEach(() => { server.resetHandlers(); signIn(null) })

describe('处置读取', () => {
  it('当前封禁按后端 active=true 筛选，待批仍为 pending，不推断为已生效', async () => {
    const page = await responseApi.listActions({ active: true })
    expect(page.items.map((a) => a.id)).toEqual([ACTION_PENDING, ACTION_APPLIED])
    expect(page.items[0]).toMatchObject({ desiredState: 'active', observedState: 'pending' })
    expect((await responseApi.listActions()).items.map((a) => a.id)).toContain(ACTION_EXPIRED)
  })

  it('状态、资产、时间、排序、游标和 limit 原样带到 v2 URL，不发送 active=false', async () => {
    let seen!: URL
    server.use(http.get('/api/v2/actions', ({ request }) => {
      seen = new URL(request.url)
      return HttpResponse.json({ data: { items: [], nextCursor: 'next' }, error: null })
    }))
    const query = { assetId: ASSET_1, status: 'applied' as const, from: '2026-10-15T03:00:00Z', until: '2026-10-15T04:00:00Z', sort: 'updatedAt' as const, cursor: 'cursor+/=', limit: 12, active: true as const }
    expect((await responseApi.listActions(query)).nextCursor).toBe('next')
    expect(Object.fromEntries(seen.searchParams)).toEqual({ ...query, active: 'true', limit: '12' })
    await responseApi.listActions({})
    expect(Object.fromEntries(seen.searchParams)).toEqual({ limit: '50' })
  })

  it('时间采用左闭右开，分页的筛选或主体变化后旧游标拒绝', async () => {
    const page = await responseApi.listActions({ limit: 1 })
    expect(page.nextCursor).toBeTruthy()
    expect((await responseApi.listActions({ limit: 1, cursor: page.nextCursor! })).items[0].id).toBe(ACTION_APPLIED)
    await expect(responseApi.listActions({ limit: 1, cursor: page.nextCursor!, status: 'applied' })).rejects.toMatchObject({ status: 400, code: 'INVALID_CURSOR' })
    signIn(singleRoleUsers.auditor)
    await expect(responseApi.listActions({ limit: 1, cursor: page.nextCursor! })).rejects.toMatchObject({ code: 'INVALID_CURSOR' })
    expect((await responseApi.listActions({ from: '2026-10-15T03:58:00Z', until: '2026-10-15T03:59:00Z' })).items.map((a) => a.id)).toEqual([ACTION_APPLIED])
  })

  it('无命令返回空回执；已生效动作保留回执和只读预算账本事实', async () => {
    expect(await responseApi.listReceipts(ACTION_PENDING)).toEqual({ items: [] })
    expect((await responseApi.listReceipts(ACTION_APPLIED)).items[0]).toMatchObject({ status: 'applied', projected: true })
    expect((await responseApi.getAction(ACTION_APPLIED)).observedState).toBe('applied')
    expect((await responseApi.listBudgetTargets({ assetId: ASSET_1 })).items.map((t) => t.id)).toEqual([BUDGET_1])
    expect(await responseApi.getBudgetLedger(BUDGET_1)).toMatchObject({ chargedMs: 30000, cycleStartedAt: '2026-10-15T03:55:00Z' })
    expect(Object.keys(responseApi)).not.toContain('resetBudget')
  })

  it('资产范围同时约束列表、动作、回执和预算；范围外返回 404', async () => {
    const user = me(['security_reviewer'])
    user.bindings[0] = { ...user.bindings[0], scopeType: 'asset', scopeId: '1' }
    signIn(user)
    expect((await responseApi.listActions()).items.every((a) => a.assetId === ASSET_1)).toBe(true)
    await expect(responseApi.getAction(ACTION_EXPIRED)).rejects.toMatchObject({ status: 404 })
    await expect(responseApi.listReceipts(ACTION_EXPIRED)).rejects.toMatchObject({ status: 404 })
    await expect(responseApi.listBudgetTargets({ assetId: ASSET_2 })).rejects.toMatchObject({ status: 404 })
    await expect(responseApi.getBudgetLedger(BUDGET_2)).rejects.toMatchObject({ status: 404 })
    await expect(responseApi.revokeAction(ACTION_EXPIRED, 1, '越权撤销')).rejects.toMatchObject({ status: 403, code: 'SCOPE_DENIED' })
  })

  it('只读审计员不能写动作；未登录请求失败且保留 request-id', async () => {
    signIn(singleRoleUsers.auditor)
    await expect(responseApi.revokeAction(ACTION_APPLIED, 1, '核对后撤销')).rejects.toMatchObject({ status: 403, code: 'SCOPE_DENIED' })
    signIn(null)
    try { await responseApi.listActions(); expect.fail('应返回 401') } catch (e) { expect(errText(e)).toContain('request-id req-f2-error') }
  })
})

describe('处置写请求', () => {
  it('审批发送 CSRF、幂等键与 If-Match；批准仍为 pending，且不生成回执', async () => {
    const result = await responseApi.decideAction(ACTION_PENDING, 1, 'approve', '已核对授权与目标')
    expect(result).toEqual({ id: ACTION_PENDING, observedState: 'pending', revision: 2 })
    expect(responseState.writes[0]).toMatchObject({ body: { decision: 'approve', reason: '已核对授权与目标' }, ifMatch: '1' })
    expect(responseState.writes[0].idempotencyKey).toMatch(/^[0-9a-f-]{36}$/)
    expect((await responseApi.listReceipts(ACTION_PENDING)).items).toEqual([])
  })

  it('拒绝自批和过期修订，不修改动作', async () => {
    responseState.actions[0].createdBy = singleRoleUsers.security_reviewer.id
    await expect(responseApi.decideAction(ACTION_PENDING, 1, 'approve', '审核')).rejects.toMatchObject({ status: 403, code: 'APPROVAL_SEPARATION_REQUIRED' })
    responseState.actions[0].createdBy = singleRoleUsers.security_analyst.id
    await expect(responseApi.decideAction(ACTION_PENDING, 9, 'reject', '驳回')).rejects.toMatchObject({ status: 409, code: 'REVISION_CONFLICT' })
    expect(responseState.actions[0].action.revision).toBe(1)
    expect(responseState.writes).toEqual([])
  })

  it('同一次提交允许按原键和原修订重放，换内容或修订返回幂等冲突', async () => {
    const key = crypto.randomUUID()
    const first = await responseApi.decideAction(ACTION_PENDING, 1, 'approve', '审核', key)
    expect(await responseApi.decideAction(ACTION_PENDING, 1, 'approve', '审核', key)).toEqual(first)
    expect(responseState.writes).toHaveLength(1)
    await expect(responseApi.decideAction(ACTION_PENDING, 1, 'reject', '审核', key)).rejects.toMatchObject({ code: 'IDEMPOTENCY_CONFLICT' })
    await expect(responseApi.decideAction(ACTION_PENDING, 2, 'approve', '审核', key)).rejects.toMatchObject({ code: 'IDEMPOTENCY_CONFLICT' })
  })

  it('驳回与撤销分别建新幂等键，撤销已生效动作只改变期望状态', async () => {
    expect((await responseApi.decideAction(ACTION_PENDING, 1, 'reject', '授权不满足条件')).observedState).toBe('rejected')
    const result = await responseApi.revokeAction(ACTION_APPLIED, 1, '停止封禁')
    expect(result).toEqual({ id: ACTION_APPLIED, desiredState: 'revoked', observedState: 'applied' })
    expect((await responseApi.listReceipts(ACTION_APPLIED)).items.map((r) => r.status)).toEqual(['applied'])
    expect(new Set(responseState.writes.map((w) => w.idempotencyKey)).size).toBe(2)
  })

  it.each([false, true])('停用走集合路径，显式传 revokeExisting=%s，无 If-Match，不伪造规则已清理', async (revokeExisting) => {
    expect(await responseApi.stopAutomation({ assetIds: [ASSET_1], reason: '人工核对', revokeExisting })).toEqual({ status: 'accepted' })
    expect(responseState.writes[0]).toMatchObject({ path: '/api/v2/automation-stops', ifMatch: null, body: { assetIds: [ASSET_1], reason: '人工核对', revokeExisting } })
    expect((await responseApi.getAction(ACTION_APPLIED)).desiredState).toBe(revokeExisting ? 'revoked' : 'active')
    expect((await responseApi.getAction(ACTION_APPLIED)).observedState).toBe('applied')
  })

  it('停用混入越权或未知资产、空列表时拒绝整个请求', async () => {
    const user = me(['security_reviewer'])
    user.bindings[0] = { ...user.bindings[0], scopeType: 'asset', scopeId: '1' }
    signIn(user)
    await expect(responseApi.stopAutomation({ assetIds: [ASSET_1, ASSET_2], reason: '检查', revokeExisting: true })).rejects.toMatchObject({ status: 403 })
    await expect(responseApi.stopAutomation({ assetIds: [ASSET_1, crypto.randomUUID()], reason: '检查', revokeExisting: true })).rejects.toMatchObject({ status: 404 })
    await expect(responseApi.stopAutomation({ assetIds: [], reason: '检查', revokeExisting: true })).rejects.toMatchObject({ status: 422 })
    expect(responseState.writes).toEqual([])
    expect(responseState.actions[1].action.desiredState).toBe('active')
  })

  it('MSW 拒绝缺失/非法协议头', async () => {
    await expect(guard.op('actions', ACTION_PENDING, 'decisions', { decision: 'approve', reason: '审核' })).rejects.toMatchObject({ code: 'REVISION_CONFLICT' })
    await expect(api.post(`/api/v2/actions/${ACTION_PENDING}/decisions`, { decision: 'approve', reason: '审核' }, { 'Idempotency-Key': 'invalid', 'If-Match': '1' })).rejects.toMatchObject({ code: 'INVALID_UUID' })
  })
})
