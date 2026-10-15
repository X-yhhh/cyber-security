/** F2 待办协议与六个单角色投影；只验证合成 HTTP 契约，不声称浏览器页面已接入。 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { guard } from '@/api/client'
import { server } from '@/test/handlers'
import { signIn } from '@/test/handlers/auth'
import { ASSET_1, ASSET_2 } from '@/test/handlers/detect'
import { resetTodoState, todoState, type TodoFixture } from '@/test/handlers/todos'
import { humanRoles, me, singleRoleUsers, type HumanRole } from '@/test/roles'
import { fetchTodos, type TodoKind } from './todos'

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }))
afterAll(() => server.close())
beforeEach(() => { resetTodoState(); signIn(singleRoleUsers.security_reviewer) })
afterEach(() => { server.resetHandlers(); signIn(null) })
const row = (kind: TodoKind) => todoState.rows.find((r) => r.item.kind === kind)!

const expected: Record<HumanRole, Record<string, TodoKind[]>> = {
  platform_admin: { other: ['expiring_authorization', 'device'] },
  security_analyst: { triage: ['event'] },
  security_reviewer: { approve: ['authorization', 'sensor_config', 'action', 'lab', 'policy', 'bundle_approval'], other: ['device'] },
  model_operator: { other: ['model', 'bundle_sealing'] },
  evidence_reviewer: { triage: ['feedback'] },
  auditor: { other: ['device'] },
}

describe('待办可见性', () => {
  it.each(humanRoles)('%s 的分组与十二类权限映射一致', async (role) => {
    signIn(singleRoleUsers[role])
    const result = await fetchTodos()
    expect(Object.fromEntries(result.groups.map((g) => [g.kind, g.items.map((i) => i.kind)]))).toEqual(expected[role])
    for (const group of result.groups) {
      expect(group.count).toBe(group.items.length)
      for (const item of group.items) {
        expect(item.id).toMatch(/^[0-9a-f-]{36}$/)
        expect(item.route).toMatch(/^\/console\//)
        expect(item.createdAt).toMatch(/Z$/)
        expect(Object.keys(item).sort()).toEqual(['assetId', 'createdAt', 'id', 'kind', 'route', 'title'])
      }
    }
  })

  it('无任何可见类别仍能登录读取空响应；可见零计数组保留', async () => {
    signIn(me([]))
    expect(await fetchTodos()).toEqual({ groups: [], truncated: false })
    signIn(singleRoleUsers.security_analyst)
    todoState.rows = []
    expect(await fetchTodos()).toEqual({ groups: [{ kind: 'triage', count: 0, items: [] }], truncated: false })
  })

  it('排除本人发起的待批对象；approved 组合属于待激活，仍保留', async () => {
    for (const r of todoState.rows.filter((r) => ['authorization', 'sensor_config', 'action', 'lab', 'policy', 'bundle_approval'].includes(r.item.kind))) r.ownerId = singleRoleUsers.security_reviewer.id
    expect((await fetchTodos()).groups.find((g) => g.kind === 'approve')).toMatchObject({ count: 0, items: [] })
    row('bundle_approval').status = 'approved'
    const items = (await fetchTodos()).groups.find((g) => g.kind === 'approve')!.items
    expect(items.map((i) => i.kind)).toEqual(['bundle_approval'])
    expect(items[0].title).toBe('待激活发布组合')
  })

  it('排除本人标注与他人指派事件，仅列本人 candidate 封存', async () => {
    signIn(singleRoleUsers.evidence_reviewer)
    row('feedback').ownerId = singleRoleUsers.evidence_reviewer.id
    expect((await fetchTodos()).groups[0].count).toBe(0)
    signIn(singleRoleUsers.security_analyst)
    row('event').assigneeId = 999
    expect((await fetchTodos()).groups[0].count).toBe(0)
    row('event').assigneeId = singleRoleUsers.security_analyst.id
    expect((await fetchTodos()).groups[0].count).toBe(1)
    signIn(singleRoleUsers.model_operator)
    row('bundle_sealing').ownerId = 999
    expect((await fetchTodos()).groups[0].items.map((i) => i.kind)).toEqual(['model'])
  })

  it('资产范围过滤且全局类别不能借用资产权限；不同绑定不能拼接权限与范围', async () => {
    const scoped = me(['security_reviewer'])
    scoped.bindings[0] = { ...scoped.bindings[0], scopeType: 'asset', scopeId: '1' }
    row('authorization').item.assetId = ASSET_2
    signIn(scoped)
    const data = await fetchTodos()
    expect(data.groups[0].items.map((i) => i.kind)).toEqual(['sensor_config', 'action', 'lab'])
    const combo = me(['security_reviewer', 'auditor'])
    combo.bindings[0] = { ...combo.bindings[0], scopeType: 'asset', scopeId: '2' }
    combo.bindings[1] = { ...combo.bindings[1], scopeType: 'asset', scopeId: '1' }
    row('authorization').item.assetId = ASSET_1
    signIn(combo)
    expect((await fetchTodos()).groups[0].count).toBe(0)
  })

  it('已过时动作、已批准动作、无关联运行的 lab、unknown 设备不进入待办', async () => {
    row('action').validUntil = new Date(todoState.now).toISOString()
    row('lab').hasLabRun = false
    row('device').status = 'unknown'
    const kinds = (await fetchTodos()).groups.flatMap((g) => g.items.map((i) => i.kind))
    for (const kind of ['action', 'lab', 'device']) expect(kinds).not.toContain(kind)
    row('action').validUntil = new Date(todoState.now + 60_000).toISOString()
    row('action').approvedBy = 1
    expect((await fetchTodos()).groups[0].items.map((i) => i.kind)).not.toContain('action')
  })

  it('即将到期包含七天边界，排除尚未生效与已经到期的授权', async () => {
    signIn(singleRoleUsers.platform_admin)
    const auth = row('expiring_authorization')
    auth.validUntil = new Date(todoState.now + 7 * 86_400_000).toISOString()
    expect((await fetchTodos()).groups[0].items.map((i) => i.kind)).toContain('expiring_authorization')
    auth.validUntil = new Date(todoState.now + 7 * 86_400_000 + 1).toISOString()
    expect((await fetchTodos()).groups[0].items.map((i) => i.kind)).not.toContain('expiring_authorization')
    auth.validUntil = new Date(todoState.now).toISOString()
    expect((await fetchTodos()).groups[0].items.map((i) => i.kind)).not.toContain('expiring_authorization')
    auth.validUntil = new Date(todoState.now + 60_000).toISOString()
    auth.validFrom = new Date(todoState.now + 1).toISOString()
    expect((await fetchTodos()).groups[0].items.map((i) => i.kind)).not.toContain('expiring_authorization')
  })

  it('未登录和任何查询参数均拒绝', async () => {
    await expect(guard.read('todos', { limit: 100 })).rejects.toMatchObject({ status: 400, code: 'INVALID_QUERY', requestId: 'req-f2-error' })
    signIn(null)
    await expect(fetchTodos()).rejects.toMatchObject({ status: 401 })
  })
})

describe('待办上限与排序', () => {
  function clone(source: TodoFixture, n: number): TodoFixture {
    return { ...source, item: { ...source.item, id: `a4000000-0000-4000-8000-${n.toString(16).padStart(12, '0')}` } }
  }
  it('跨类别按时间归并，所有组共享上限，后续组保留完整计数', async () => {
    const source = row('authorization')
    row('policy').item.createdAt = new Date(todoState.now).toISOString()
    todoState.rows.push(...Array.from({ length: 100 }, (_, i) => clone(source, i + 1)))
    const result = await fetchTodos()
    expect(result.truncated).toBe(true)
    expect(result.groups.map((g) => [g.kind, g.count, g.items.length])).toEqual([['approve', 106, 100], ['other', 1, 0]])
    expect(result.groups[0].items[0].kind).toBe('policy')
    const ids = result.groups[0].items.filter((i) => i.kind === 'authorization').map((i) => i.id)
    expect(ids).toEqual([...ids].sort().reverse())
  })
  it('恰好 100 条不截断，approve 优先于更新的 other', async () => {
    const auth = row('authorization'), device = row('device')
    device.item.createdAt = new Date(todoState.now + 1000).toISOString()
    todoState.rows = [...Array.from({ length: 99 }, (_, i) => clone(auth, i + 1)), device]
    const result = await fetchTodos()
    expect(result.truncated).toBe(false)
    expect(result.groups.map((g) => g.items.length)).toEqual([99, 1])
  })
})
