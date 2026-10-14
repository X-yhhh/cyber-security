/**
 * 工作台框架（任务单 F0.7）：卡片按 anyOf 渲染；汇总字段按 B2.5 契约缺省即不显示（不补 0）；
 * 卡片行带状态筛选跳到已上线且有权访问的列表；没有可见卡片时不请求汇总；错误附带 request-id。
 */
import { flushPromises, mount, RouterLinkStub, type VueWrapper } from '@vue/test-utils'
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { http, HttpResponse } from 'msw'
import { session } from '@/api/session'
import { dataRequests, requests, server } from '@/test/handlers'
import { signIn } from '@/test/handlers/auth'
import { humanRoles, me, singleRoleUsers, type HumanRole, type MeFixture } from '@/test/roles'
import WorkbenchView from './WorkbenchView.vue'
import { cards, linker } from './cards'
import { nav, routeName } from '@/router/nav'

async function render(user: MeFixture) {
  signIn(user)
  session.user = { ...user, permissions: [...user.permissions] }
  session.checked = true
  const w = mount(WorkbenchView, { global: { stubs: { RouterLink: RouterLinkStub } } })
  for (let i = 0; i < 5; i++) { await flushPromises(); await new Promise((r) => setTimeout(r, 0)) }
  return w
}
const cardTitles = (w: ReturnType<typeof mount>) => w.findAll('section[aria-label]').map((s) => s.attributes('aria-label'))

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }))
afterAll(() => server.close())
beforeEach(() => { requests.length = 0 })
afterEach(() => server.resetHandlers())

/** 权限设计第 7.4 节推导的各角色可见卡片。 */
const expectedCards: Record<HumanRole, string[]> = {
  platform_admin: ['运行健康', '最近审计'],
  security_analyst: ['待研判事件'],
  security_reviewer: ['待我审批', '运行健康'],
  model_operator: ['发布进度'],
  evidence_reviewer: ['待复核标注'],
  auditor: ['运行健康', '最近审计'],
}

describe('工作台卡片', () => {
  it.each(humanRoles)('%s 只看到有权限的卡片', async (role) => {
    const w = await render(singleRoleUsers[role])
    expect(cardTitles(w)).toEqual(expectedCards[role])
    expect(dataRequests()).toEqual(['GET /api/v2/summary'])
    w.unmount()
  })

  it('没有可见卡片时不请求汇总', async () => {
    const w = await render(me([], 300, 'nobody'))
    expect(w.text()).toContain('当前身份没有可显示的工作台卡片')
    expect(dataRequests()).toEqual([])
    w.unmount()
  })

  it('审核员的待我审批只显示接口返回的字段，数字不补 0', async () => {
    server.use(http.get('/api/v2/summary', () => HttpResponse.json({ requestId: 'r', error: null, data: { pendingApprovals: { actions: 0, bundles: 2 } } })))
    const w = await render(singleRoleUsers.security_reviewer)
    const card = w.get('section[aria-label="待我审批"]')
    const rows = card.findAll('li').map((li) => li.text())
    expect(rows).toHaveLength(2)
    expect(rows[0]).toContain('人工动作')
    expect(rows[0]).toContain('0')
    expect(rows[1]).toContain('发布组合')
    expect(card.text()).not.toContain('资产授权')
    expect(card.text()).toContain('不含本人发起的对象')
    // 运行健康卡片可见但接口未返回 ops：只剩标题，不显示 0。
    expect(w.get('section[aria-label="运行健康"]').findAll('li')).toHaveLength(0)
    w.unmount()
  })

  it('卡片行带状态筛选跳到已上线且有权访问的列表；未上线的只显示数字', async () => {
    const w = await render(singleRoleUsers.security_reviewer)
    const card = w.get('section[aria-label="待我审批"]')
    const links = (card.findAllComponents(RouterLinkStub) as VueWrapper<any>[]).map((l) => l.props('to'))
    expect(links).toContainEqual({ name: 'release-bundles', query: { status: 'evaluated' } })
    expect(links).toContainEqual({ name: 'release-policies', query: { status: 'draft' } })
    expect(links).toContainEqual({ name: 'response-actions', query: { status: 'pending' } })
    expect(links).toContainEqual({ name: 'release-lab', query: { status: 'pending' } })
    // 资产授权、传感器与执行器尚未上线（ready=false），只显示数字，不给链接。
    expect(card.findAll('li')).toHaveLength(6)
    expect(links).toHaveLength(4)
    w.unmount()
  })

  it('汇总失败时显示错误与 request-id', async () => {
    server.use(http.get('/api/v2/summary', () => HttpResponse.json({ requestId: 'req-boom', data: null, error: { code: 'INTERNAL_ERROR', message: '服务暂时无法处理请求' } }, { status: 500 })))
    const w = await render(singleRoleUsers.auditor)
    expect(w.get('[role="alert"]').text()).toBe('服务暂时无法处理请求（request-id req-boom）')
    w.unmount()
  })
})

describe('卡片链接', () => {
  it('全部二级项上线后，每条链接都指向已登记的二级项', () => {
    const names = new Set(nav.map(routeName))
    const all = me(['platform_admin', 'model_operator'])
    const everything = [...new Set(humanRoles.flatMap((r) => singleRoleUsers[r].permissions))]
    for (const c of cards) {
      for (const line of c.lines({}, (group, key, status) => ({ name: routeName({ group, key }), query: status ? { status } : undefined }))) {
        const to = line.to as { name: string } | undefined
        if (to) expect(names.has(to.name)).toBe(true)
      }
    }
    // 无权访问的目标不给链接。
    expect(linker(all.permissions)('detect', 'events', 'open')).toBeUndefined()
    expect(linker(everything)('system', 'audit')).toEqual({ name: 'system-audit', query: undefined })
  })
})
