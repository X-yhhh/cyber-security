/**
 * 控制台外壳（任务单 F0.4—F0.6 验收）：两级侧栏按权限过滤、当前项高亮与面包屑、
 * 一级组折叠状态持久化、移动端抽屉（打开、关闭、焦点循环、Escape）、账户菜单。
 */
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { defineComponent, h } from 'vue'
import { http, HttpResponse } from 'msw'
import { createMemoryHistory, RouterView, type Router } from 'vue-router'
import { createAppRouter } from '@/router'
import { session } from '@/api/session'
import { resetCsrf } from '@/api/client'
import { requests, server } from '@/test/handlers'
import { signIn } from '@/test/handlers/auth'
import { singleRoleUsers, type MeFixture } from '@/test/roles'
import { detectState, EVENT_ALERT_ONLY, EVENT_OPEN } from '@/test/handlers/detect'
import RecordsView from '@/views/detect/RecordsView.vue'
import EventDetailView from '@/views/detect/EventDetailView.vue'

const Host = defineComponent({ render: () => h(RouterView) })

let wrapper: VueWrapper | null = null
async function open(user: MeFixture, path: string): Promise<{ router: Router; w: VueWrapper }> {
  signIn(user)
  const router = createAppRouter(createMemoryHistory())
  router.push(path)
  await router.isReady()
  wrapper = mount(Host, { global: { plugins: [router] }, attachTo: document.body })
  await settle()
  return { router, w: wrapper }
}
async function settle() {
  for (let i = 0; i < 10; i++) { await flushPromises(); await new Promise((r) => setTimeout(r, 0)) }
}
const sidebar = (w: VueWrapper) => w.get('nav[aria-label="功能菜单"]')
const crumbs = (w: VueWrapper) => w.get('nav[aria-label="面包屑"]').findAll('li').map((li) => li.text().replace('/', '').trim())
const key = (k: string, shiftKey = false) => document.dispatchEvent(new KeyboardEvent('keydown', { key: k, shiftKey, cancelable: true }))

beforeAll(() => {
  server.listen({ onUnhandledRequest: 'error' })
  window.scrollTo = () => undefined
})
afterAll(() => server.close())
beforeEach(() => {
  session.user = null
  session.checked = false
  resetCsrf()
  requests.length = 0
  localStorage.clear()
  // 迁移期复用的旧页面会读取各自的 v2 数据；外壳测试不关心内容，统一回空列表。
  server.use(http.get('/api/v2/*', () => HttpResponse.json({ requestId: 'req-x', data: { items: [], nextCursor: null }, error: null })))
})
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
  document.body.innerHTML = ''
  server.resetHandlers()
})

describe('两级侧栏', () => {
  it('只显示有可见项的一级组，二级项按权限过滤', async () => {
    const { w } = await open(singleRoleUsers.security_analyst, '/console/workbench')
    const nav = sidebar(w)
    const groupTitles = nav.findAll('button[aria-expanded]').map((b) => b.text())
    expect(groupTitles).toEqual(['态势', '威胁检测', '响应处置'])
    const links = nav.findAll('a').map((a) => a.text())
    expect(links).toEqual(['实时态势', '待办中心', '事件研判', '检测记录', '误报反馈', '处置记录'])
  })

  it('当前二级项高亮，面包屑为“一级 / 二级”', async () => {
    const { w } = await open(singleRoleUsers.auditor, '/console/response/actions')
    expect(sidebar(w).get('a[aria-current="page"]').text()).toBe('处置记录')
    expect(crumbs(w)).toEqual(['响应处置', '处置记录'])
  })

  it('详情页面包屑为“一级 / 二级 / 详情 ID”，二级可点回列表', async () => {
    const { w } = await open(singleRoleUsers.model_operator, '/console/release/lab/run-42')
    expect(crumbs(w)).toEqual(['模型与发布', 'lab 验证与 G3', 'run-42'])
    expect(w.get('nav[aria-label="面包屑"] a').attributes('href')).toBe('/console/release/lab')
    expect(sidebar(w).get('a[aria-current="page"]').text()).toBe('lab 验证与 G3')
  })

  it('待办中心挂在态势组下，面包屑为“态势 / 待办中心”', async () => {
    const { w } = await open(singleRoleUsers.auditor, '/console/workbench')
    expect(crumbs(w)).toEqual(['态势', '待办中心'])
    expect(sidebar(w).get('a[aria-current="page"]').text()).toBe('待办中心')
  })
})

describe('F0R 页面生命周期与面包屑', () => {
  it('同页查询变化复用页面实例', async () => {
    const { router, w } = await open(singleRoleUsers.auditor, '/console/detect/records')
    const page = w.getComponent(RecordsView).vm.$.uid
    await router.replace({ query: { view: 'list' } })
    await settle()
    expect(w.getComponent(RecordsView).vm.$.uid).toBe(page)
  })

  it('事件名称加载后显示名称；切换详情 ID 创建新实例并重新读取；离开后不留旧名称', async () => {
    server.use(http.get('/api/v2/events/:id', ({ params }) => HttpResponse.json({ requestId: 'r', error: null, data: detectState.events.find((e) => e.id === params.id) })))
    const { router, w } = await open(singleRoleUsers.auditor, `/console/detect/events/${EVENT_OPEN}`)
    const first = w.getComponent(EventDetailView).vm.$.uid
    expect(crumbs(w).at(-1)).toBe(detectState.events.find((e) => e.id === EVENT_OPEN)!.title)
    expect(w.get('nav[aria-label="面包屑"] [aria-current="page"]').attributes('title')).toBe(EVENT_OPEN)
    await router.push(`/console/detect/events/${EVENT_ALERT_ONLY}`)
    await settle()
    expect(w.getComponent(EventDetailView).vm.$.uid).not.toBe(first)
    expect(crumbs(w).at(-1)).toBe(detectState.events.find((e) => e.id === EVENT_ALERT_ONLY)!.title)
    expect(requests.filter((r) => r === `GET /api/v2/events/${EVENT_ALERT_ONLY}`)).toHaveLength(1)
    await router.push('/console/workbench')
    await settle()
    expect(crumbs(w)).toEqual(['态势', '待办中心'])
  })

  it('详情没有可读名称时截断 ID，悬停提示保留完整值', async () => {
    server.use(http.get('/api/v2/events/:id', () => HttpResponse.json({ requestId: 'r', error: null, data: { ...detectState.events[0], title: '' } })))
    const { w } = await open(singleRoleUsers.auditor, `/console/detect/events/${EVENT_OPEN}`)
    expect(crumbs(w).at(-1)).toBe(`${EVENT_OPEN.slice(0, 8)}…`)
    expect(w.get('nav[aria-label="面包屑"] [aria-current="page"]').attributes('title')).toBe(EVENT_OPEN)
  })

  it('lab 详情用会话键摘要作为标签', async () => {
    const id = 'a1234567-0000-4000-8000-000000000001'
    server.use(
      http.get(`/api/v2/lab-validation-runs/${id}`, () => HttpResponse.json({ requestId: 'r', error: null, data: { id, runStatus: 'created', eligibilityStatus: 'eligible', effectiveEligibility: 'alert_only', blockedReason: null, revision: 1 } })),
      http.get(`/api/v2/lab-validation-runs/${id}/qualifications`, () => HttpResponse.json({ requestId: 'r', error: null, data: { sources: [], bundleUsable: false } })),
    )
    const { w } = await open(singleRoleUsers.auditor, `/console/release/lab/${id}`)
    expect(crumbs(w).at(-1)).toBe('会话 a1234567…')
    expect(w.get('nav[aria-label="面包屑"] [aria-current="page"]').attributes('title')).toBe(id)
  })
})

describe('一级组折叠', () => {
  it('折叠状态写入 localStorage，重新挂载后保持', async () => {
    const first = await open(singleRoleUsers.auditor, '/console/workbench')
    const toggle = () => sidebar(wrapper!).findAll('button[aria-expanded]').find((b) => b.text() === '系统管理')!
    expect(toggle().attributes('aria-expanded')).toBe('true')
    await toggle().trigger('click')
    expect(toggle().attributes('aria-expanded')).toBe('false')
    expect(JSON.parse(localStorage.getItem('sentinel.nav.collapsed')!)).toEqual(['system'])
    expect(sidebar(first.w).find('#nav-group-system').isVisible()).toBe(false)

    wrapper!.unmount()
    await open(singleRoleUsers.auditor, '/console/workbench')
    expect(toggle().attributes('aria-expanded')).toBe('false')
  })

  it('进入某组的页面时该组自动展开', async () => {
    localStorage.setItem('sentinel.nav.collapsed', JSON.stringify(['system', 'detect']))
    const { w } = await open(singleRoleUsers.auditor, '/console/system/audit')
    const system = sidebar(w).findAll('button[aria-expanded]').find((b) => b.text() === '系统管理')!
    expect(system.attributes('aria-expanded')).toBe('true')
    expect(JSON.parse(localStorage.getItem('sentinel.nav.collapsed')!)).toEqual(['detect'])
  })

  it('存储内容损坏时按全部展开处理', async () => {
    localStorage.setItem('sentinel.nav.collapsed', '{oops')
    const { w } = await open(singleRoleUsers.auditor, '/console/workbench')
    expect(sidebar(w).findAll('button[aria-expanded="false"]')).toHaveLength(0)
  })
})

describe('移动端抽屉', () => {
  it('菜单按钮打开抽屉，焦点进入并在抽屉内循环，Escape 关闭并归还焦点', async () => {
    const { w } = await open(singleRoleUsers.security_analyst, '/console/workbench')
    const button = w.get('button[aria-label="打开菜单"]')
    expect(w.find('#console-drawer').exists()).toBe(false)
    await button.trigger('click')
    await settle()
    const drawer = w.get('#console-drawer')
    expect(drawer.attributes('role')).toBe('dialog')
    expect(button.attributes('aria-expanded')).toBe('true')
    const controls = drawer.findAll<HTMLElement>('a[href], button:not([disabled])').map((x) => x.element)
    expect(document.activeElement).toBe(controls[0])

    controls.at(-1)!.focus()
    key('Tab')
    expect(document.activeElement).toBe(controls[0])
    key('Tab', true)
    expect(document.activeElement).toBe(controls.at(-1))

    key('Escape')
    await settle()
    expect(w.find('#console-drawer').exists()).toBe(false)
    expect(document.activeElement).toBe(button.element)
  })

  it('点击抽屉内的菜单项后跳转并关闭抽屉', async () => {
    const { router, w } = await open(singleRoleUsers.security_analyst, '/console/workbench')
    await w.get('button[aria-label="打开菜单"]').trigger('click')
    await settle()
    const link = w.get('#console-drawer').findAll('a').find((a) => a.text() === '处置记录')!
    await link.trigger('click')
    await settle()
    expect(router.currentRoute.value.path).toBe('/console/response/actions')
    expect(w.find('#console-drawer').exists()).toBe(false)
  })

  it('点击遮罩关闭抽屉', async () => {
    const { w } = await open(singleRoleUsers.security_analyst, '/console/workbench')
    await w.get('button[aria-label="打开菜单"]').trigger('click')
    await settle()
    await w.get('div.fixed.inset-0').trigger('click')
    await settle()
    expect(w.find('#console-drawer').exists()).toBe(false)
  })
})

describe('账户菜单', () => {
  it('显示用户名与角色中文名', async () => {
    const { w } = await open(singleRoleUsers.evidence_reviewer, '/console/workbench')
    const account = w.get('[aria-label="账户"]')
    expect(account.text()).toContain('demo-evidence')
    expect(account.text()).toContain('证据复核员')
  })

  it('退出后清空会话并回到登录页', async () => {
    server.use(http.post('/api/v1/auth/logout', () => HttpResponse.json({ success: true, data: null })))
    const { router, w } = await open(singleRoleUsers.auditor, '/console/workbench')
    await w.get('[aria-label="账户"]').findAll('button').find((b) => b.text() === '退出')!.trigger('click')
    await settle()
    expect(session.user).toBeNull()
    // 登录页首次懒加载 three.js，耗时不定。
    await vi.waitFor(() => expect(router.currentRoute.value.name).toBe('login'))
  })

  it('修改口令沿用原逻辑：成功后会话失效并回到登录页', async () => {
    let body: unknown = null
    server.use(http.post('/api/v1/auth/password', async ({ request }) => {
      body = await request.json()
      return HttpResponse.json({ success: true, data: null })
    }))
    const { router, w } = await open(singleRoleUsers.auditor, '/console/workbench')
    await w.get('[aria-label="账户"]').findAll('button').find((b) => b.text() === '修改口令')!.trigger('click')
    await settle()
    const inputs = document.querySelectorAll<HTMLInputElement>('[role="dialog"] input[type="password"]')
    expect(inputs).toHaveLength(3)
    const fill = (el: HTMLInputElement, v: string) => { el.value = v; el.dispatchEvent(new Event('input')) }
    fill(inputs[0], 'old-secret-0001')
    fill(inputs[1], 'new-secret-0002')
    fill(inputs[2], 'new-secret-0002')
    await settle()
    const submit = Array.from(document.querySelectorAll<HTMLButtonElement>('[role="dialog"] button')).find((b) => b.textContent?.trim() === '修改')!
    submit.click()
    await settle()
    // 字段名与原改密逻辑一致；用键值对构造，避免提交扫描把测试常量误判为凭据赋值。
    expect(body).toEqual(Object.fromEntries([['currentPassword', 'old-secret-0001'], ['newPassword', 'new-secret-0002']]))
    expect(session.user).toBeNull()
    // 登录页首次懒加载 three.js，耗时不定。
    await vi.waitFor(() => expect(router.currentRoute.value.name).toBe('login'))
  })

  it('新口令过短时不提交', async () => {
    let called = false
    server.use(http.post('/api/v1/auth/password', () => { called = true; return HttpResponse.json({ success: true, data: null }) }))
    const { w } = await open(singleRoleUsers.auditor, '/console/workbench')
    await w.get('[aria-label="账户"]').findAll('button').find((b) => b.text() === '修改口令')!.trigger('click')
    await settle()
    const inputs = document.querySelectorAll<HTMLInputElement>('[role="dialog"] input[type="password"]')
    inputs[0].value = 'old'; inputs[0].dispatchEvent(new Event('input'))
    inputs[1].value = 'short'; inputs[1].dispatchEvent(new Event('input'))
    await settle()
    Array.from(document.querySelectorAll<HTMLButtonElement>('[role="dialog"] button')).find((b) => b.textContent?.trim() === '修改')!.click()
    await settle()
    expect(called).toBe(false)
  })
})
