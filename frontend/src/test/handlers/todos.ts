/**
 * F2 待办 MSW：按权限设计 7.4 的十二类合成对象投影当前用户待办。
 * 覆盖同一角色绑定内的权限/范围、排除本人待批对象、分组优先级和共享 100 条上限；
 * 这是前端测试夹具，不替代后端 SQL、事务快照或浏览器联调验收。
 */
import { http } from 'msw'
import type { TodoEntry, TodoGroupKind, TodoKind, TodosResponse } from '@/api/v2/todos'
import { singleRoleUsers, type MeFixture } from '@/test/roles'
import { currentUser } from './auth'
import { ASSET_1 } from './detect'
import { fixtureCan, fixtureFail, fixtureOk, fixtureUnauthenticated } from './access'

export const TODOS_NOW = Date.parse('2026-10-15T04:00:00Z')
interface KindRule { group: TodoGroupKind; permission: string; global: boolean; title: string }
const rules: Record<TodoKind, KindRule> = {
  authorization: { group: 'approve', permission: 'authorization.approve', global: false, title: '待批资产授权' },
  sensor_config: { group: 'approve', permission: 'authorization.approve', global: false, title: '待批采集配置' },
  action: { group: 'approve', permission: 'authorization.approve', global: false, title: '待批处置申请' },
  lab: { group: 'approve', permission: 'authorization.approve', global: false, title: '待批 lab 资格' },
  policy: { group: 'approve', permission: 'policy.approve', global: true, title: '待审决策策略' },
  bundle_approval: { group: 'approve', permission: 'bundle.approve', global: true, title: '待批或待激活发布组合' },
  feedback: { group: 'triage', permission: 'feedback.review', global: false, title: '待复核标注' },
  event: { group: 'triage', permission: 'event.manage', global: false, title: '待研判事件：来源异常' },
  model: { group: 'other', permission: 'model.validate', global: true, title: '待校验模型' },
  bundle_sealing: { group: 'other', permission: 'bundle.request', global: true, title: '待封存发布组合' },
  expiring_authorization: { group: 'other', permission: 'authorization.request', global: false, title: '授权即将到期' },
  device: { group: 'other', permission: 'ops.read', global: false, title: '设备异常' },
}

/** 私有元数据仅供模拟筛选，响应只序列化 item，不能泄漏申请人或内部范围 ID。 */
export interface TodoFixture {
  item: TodoEntry
  ownerId: number
  status: string
  assigneeId: number | null
  approvedBy: number | null
  desiredState: string
  validFrom: string
  validUntil: string
  hasLabRun: boolean
}

function route(kind: TodoKind, id: string): string {
  switch (kind) {
    case 'authorization': case 'expiring_authorization': return `/console/assets/list?assetId=${ASSET_1}&tab=authorizations&id=${id}`
    case 'sensor_config': return `/console/assets/agents?tab=configs&sensorId=b2000000-0000-4000-8000-000000000001&id=${id}`
    case 'action': return `/console/response/actions?id=${id}`
    case 'lab': return `/console/release/bundles?tab=validation&id=${id}`
    case 'policy': return `/console/release/bundles?tab=policies&id=${id}`
    case 'bundle_approval': case 'bundle_sealing': return `/console/release/bundles?tab=bundles&id=${id}`
    case 'feedback': return `/console/detect/feedback?id=${id}`
    case 'event': return `/console/detect/events/${id}`
    case 'model': return `/console/release/models?tab=models&id=${id}`
    case 'device': return `/console/assets/agents?tab=sensors&id=${id}`
  }
}

function initialRows(): TodoFixture[] {
  return (Object.keys(rules) as TodoKind[]).map((kind, i) => {
    const id = `a3000000-0000-4000-8000-${(i + 1).toString(16).padStart(12, '0')}`
    const status: Partial<Record<TodoKind, string>> = {
      policy: 'draft', bundle_approval: 'evaluated', event: 'open', bundle_sealing: 'candidate', expiring_authorization: 'active', device: 'stale',
    }
    return {
      item: { kind, id, title: rules[kind].title, assetId: rules[kind].global ? null : ASSET_1, createdAt: new Date(TODOS_NOW - (i + 1) * 60_000).toISOString(), route: route(kind, id) },
      ownerId: kind === 'bundle_sealing' ? singleRoleUsers.model_operator.id : 1,
      status: status[kind] ?? 'pending', assigneeId: null, approvedBy: null, desiredState: 'active',
      validFrom: new Date(TODOS_NOW - 3_600_000).toISOString(), validUntil: new Date(TODOS_NOW + 3_600_000).toISOString(), hasLabRun: true,
    }
  })
}
export let todoState = { now: TODOS_NOW, rows: initialRows() }
export const resetTodoState = () => { todoState = { now: TODOS_NOW, rows: initialRows() } }

function actionable(row: TodoFixture, user: MeFixture): boolean {
  const other = row.ownerId !== user.id
  const validUntil = Date.parse(row.validUntil)
  switch (row.item.kind) {
    case 'authorization': return row.status === 'pending' && other
    case 'sensor_config': return ['draft', 'pending'].includes(row.status) && other
    case 'action': return row.status === 'pending' && row.desiredState === 'active' && row.approvedBy === null && validUntil > todoState.now && other
    case 'lab': return row.status === 'pending' && row.hasLabRun && validUntil > todoState.now && other
    case 'policy': return row.status === 'draft' && other
    case 'bundle_approval': return (row.status === 'evaluated' && other) || row.status === 'approved'
    case 'feedback': return row.status === 'pending' && other
    case 'event': return ['open', 'investigating'].includes(row.status) && (row.assigneeId === null || row.assigneeId === user.id)
    case 'model': return row.status === 'pending'
    case 'bundle_sealing': return row.status === 'candidate' && row.ownerId === user.id
    case 'expiring_authorization': return row.status === 'active' && Date.parse(row.validFrom) <= todoState.now && validUntil > todoState.now && validUntil <= todoState.now + 7 * 86_400_000
    case 'device': return ['stale', 'unhealthy'].includes(row.status)
  }
}

export const todoHandlers = [
  http.get('/api/v2/todos', ({ request }) => {
    const user = currentUser()
    if (!user || request.headers.has('Authorization')) return fixtureUnauthenticated()
    if (new URL(request.url).searchParams.size) return fixtureFail(400, 'INVALID_QUERY', '待办接口不接受查询参数')
    const data: TodosResponse = { groups: [], truncated: false }
    let remaining = 100
    let total = 0
    for (const group of ['approve', 'triage', 'other'] as const) {
      const visibleKinds = (Object.keys(rules) as TodoKind[]).filter((kind) => rules[kind].group === group
        && fixtureCan(user, rules[kind].permission, rules[kind].global ? null : undefined))
      if (!visibleKinds.length) continue
      const rows = todoState.rows.filter((r) => visibleKinds.includes(r.item.kind)
        && fixtureCan(user, rules[r.item.kind].permission, r.item.assetId) && actionable(r, user))
      rows.sort((a, b) => Date.parse(b.item.createdAt) - Date.parse(a.item.createdAt)
        || (a.item.kind < b.item.kind ? -1 : a.item.kind > b.item.kind ? 1 : 0) || b.item.id.localeCompare(a.item.id))
      const items = rows.slice(0, remaining).map((r) => r.item.kind === 'bundle_approval' && r.status === 'approved'
        ? { ...r.item, title: '待激活发布组合' } : r.item)
      data.groups.push({ kind: group, count: rows.length, items })
      remaining -= items.length
      total += rows.length
    }
    data.truncated = total > 100
    return fixtureOk(data)
  }),
]
