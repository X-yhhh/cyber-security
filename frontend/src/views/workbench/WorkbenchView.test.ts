/**
 * 待办中心（任务单 F2）：逐条待办来自 /todos 并按组显示，顶部计数来自 /summary 且缺省字段不补 0；
 * 未上线或无权访问的目标不给进入按钮；超过 100 条写明只显示最近 100 条；错误附带 request-id。
 */
import { flushPromises, mount } from '@vue/test-utils'
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { createMemoryHistory } from 'vue-router'
import { http, HttpResponse } from 'msw'
import { session } from '@/api/session'
import { createAppRouter } from '@/router'
import { requests, server } from '@/test/handlers'
import { signIn } from '@/test/handlers/auth'
import { resetTodoState } from '@/test/handlers/todos'
import { singleRoleUsers, type MeFixture } from '@/test/roles'
import WorkbenchView from './WorkbenchView.vue'

async function render(user: MeFixture) {
  signIn(user)
  session.user = { ...user, permissions: [...user.permissions] }
  session.checked = true
  const w = mount(WorkbenchView, { global: { plugins: [createAppRouter(createMemoryHistory())] } })
  for (let i = 0; i < 6; i++) { await flushPromises(); await new Promise((r) => setTimeout(r, 0)) }
  return w
}
const groupTitles = (w: ReturnType<typeof mount>) => w.findAll('[data-todo-group] h3').map((h) => h.text().replace(/\d+$/, ''))
const statLabels = (w: ReturnType<typeof mount>) => w.findAll('[data-stat]').map((s) => s.find('p').text())

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }))
afterAll(() => server.close())
beforeEach(() => { requests.length = 0; resetTodoState() })
afterEach(() => server.resetHandlers())

describe('待办中心', () => {
  it('审核员按「需要批准 → 需要研判 → 其他」分组，处置申请可进入处置记录详情', async () => {
    const w = await render(singleRoleUsers.security_reviewer)
    expect(requests).toContain('GET /api/v2/todos')
    expect(requests).toContain('GET /api/v2/summary')
    expect(groupTitles(w)[0]).toBe('需要批准')
    const action = w.findAll('[data-todo-group="approve"] li').find((li) => li.text().includes('待批处置申请'))!
    expect(action.get('a').attributes('href')).toMatch(/^\/console\/response\/actions\?id=/)
    w.unmount()
  })

  it('顶部计数只显示接口返回的字段，不补 0', async () => {
    server.use(http.get('/api/v2/summary', () => HttpResponse.json({ requestId: 'r', error: null, data: { pendingApprovals: { actions: 0 }, recentAuditCount24h: 3 } })))
    const w = await render(singleRoleUsers.auditor)
    expect(statLabels(w)).toEqual(['待我审批', '近 24 小时审计'])
    w.unmount()
  })

  it('F3 合并菜单后，待办仍指向发布分段和模型入口并保留对象 ID', async () => {
    const reviewer = await render(singleRoleUsers.security_reviewer)
    for (const [title, tab] of [
      ['待批 lab 资格', 'validation'],
      ['待审决策策略', 'policies'],
      ['待批或待激活发布组合', 'bundles'],
    ] as const) {
      const row = reviewer.findAll('[data-todo-group="approve"] li').find((li) => li.text().includes(title))!
      expect(row.get('a').attributes('href')).toMatch(new RegExp(`^/console/release/bundles\\?tab=${tab}&id=`))
    }
    reviewer.unmount()

    const operator = await render(singleRoleUsers.model_operator)
    const model = operator.findAll('[data-todo-group="other"] li').find((li) => li.text().includes('待校验模型'))!
    expect(model.get('a').attributes('href')).toMatch(/^\/console\/release\/models\?tab=models&id=/)
    operator.unmount()
  })

  it('超过 100 条时写明只显示最近 100 条', async () => {
    server.use(http.get('/api/v2/todos', () => HttpResponse.json({ requestId: 'r', error: null, data: {
      groups: [{ kind: 'other', count: 140, items: [{ kind: 'device', id: 'a3000000-0000-4000-8000-000000000001', title: '设备异常', assetId: null, createdAt: '2026-10-15T03:00:00Z', route: '/console/ops/health' }] }],
      truncated: true,
    } })))
    const w = await render(singleRoleUsers.auditor)
    expect(w.text()).toContain('仅显示最近 100 条')
    w.unmount()
  })

  it('待办读取失败时显示错误与 request-id', async () => {
    server.use(http.get('/api/v2/todos', () => HttpResponse.json({ requestId: 'req-boom', data: null, error: { code: 'INTERNAL_ERROR', message: '服务暂时无法处理请求' } }, { status: 500 })))
    const w = await render(singleRoleUsers.auditor)
    expect(w.get('[role="alert"]').text()).toBe('服务暂时无法处理请求（request-id req-boom）')
    w.unmount()
  })
})
