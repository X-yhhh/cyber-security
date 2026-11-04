/**
 * FE-16b 系统管理三页（用户、角色、审计）的页面行为验收：三态、URL 同步、写后回读、不能管理本人、
 * 互斥角色 409、六角色可见性。每个写操作断言实际发出的请求（方法、路径、幂等键、If-Match）；
 * MSW 夹具不替代后端事务、会话撤销与授权验收。
 */
import { DOMWrapper, flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { defineComponent, h } from 'vue'
import { http, HttpResponse } from 'msw'
import { createMemoryHistory, RouterView } from 'vue-router'
import { createAppRouter } from '@/router'
import { resetCsrf } from '@/api/client'
import { session } from '@/api/session'
import { roleNames } from '@/api/v2/roles'
import { resetSummaryCache } from '@/composables/summary'
import { alerts, toasts } from '@/composables/toast'
import { server, requests } from '@/test/handlers'
import { signIn } from '@/test/handlers/auth'
import { resetDetectState } from '@/test/handlers/detect'
import { resetAssetsState } from '@/test/handlers/assets'
import { IAM_UNUSED_USER, IAM_USER, iamState, resetIamState } from '@/test/handlers/iam'
import { humanRoles, me, singleRoleUsers, type MeFixture } from '@/test/roles'
import { SELF_REASON } from './shared'

const Host = defineComponent({ render: () => h(RouterView) })
let wrapper: VueWrapper | null = null
async function settle() {
  for (let i = 0; i < 8; i++) { await flushPromises(); await new Promise((r) => setTimeout(r, 0)) }
}
function dispose() { wrapper?.unmount(); wrapper = null; document.body.innerHTML = '' }
async function open(user: MeFixture, path: string) {
  dispose()
  signIn(user); session.user = { ...user, permissions: [...user.permissions] }; session.checked = true
  const router = createAppRouter(createMemoryHistory())
  await router.push(path); await router.isReady()
  wrapper = mount(Host, { global: { plugins: [router] }, attachTo: document.body })
  await settle()
  return { router, w: wrapper }
}
const dialog = () => new DOMWrapper(document.body.querySelector<HTMLElement>('[role="dialog"]')!)
const button = (text: string, root: ParentNode = document.body) => Array.from(root.querySelectorAll('button')).find((b) => b.textContent?.trim() === text)
async function click(text: string, root?: ParentNode) {
  const el = button(text, root); expect(el, `缺少按钮 ${text}`).toBeTruthy(); el!.click(); await settle()
}
/** 按可见中文标签填写，避免依赖表单字段顺序。 */
async function fill(label: string, value: string) {
  const field = dialog().findAll('label').find((l) => l.find('.label').exists() && l.find('.label').text() === label)
  expect(field, `缺少字段 ${label}`).toBeTruthy()
  await field!.get('input,select,textarea').setValue(value)
}
/** 勾选或取消角色表单里的权限（按中文说明定位）。 */
async function permission(text: string, checked = true) {
  const box = dialog().findAll('label.check').find((l) => l.text() === text)
  expect(box, `缺少权限 ${text}`).toBeTruthy()
  await box!.get('input').setValue(checked); await settle()
}
const count = (line: string) => requests.filter((r) => r === line).length
const UUID = /^[\da-f]{8}-[\da-f]{4}-[\da-f]{4}-[\da-f]{4}-[\da-f]{12}$/i
const admin = singleRoleUsers.platform_admin
const usersPath = '/console/system/users'
const rolesPath = '/console/system/roles'
const auditPath = '/console/system/audit'
/** 测试内临时生成的口令，不把固定口令写进源码。 */
const secret = () => `T-${crypto.randomUUID()}`

beforeAll(() => { server.listen({ onUnhandledRequest: 'error' }); window.scrollTo = () => undefined; Element.prototype.scrollIntoView = () => undefined })
afterAll(() => server.close())
beforeEach(() => {
  resetIamState(); resetDetectState(); resetAssetsState(); resetCsrf(); resetSummaryCache()
  session.user = null; session.checked = false; requests.length = 0; toasts.length = 0; alerts.length = 0
  localStorage.clear(); sessionStorage.clear()
})
afterEach(() => { dispose(); server.resetHandlers() })

const readCases = [
  { title: '用户管理', path: usersPath, endpoint: 'users', emptyData: { items: [], nextCursor: null }, empty: '还没有用户账号。', text: 'demo-target' },
  { title: '角色管理', path: rolesPath, endpoint: 'roles', emptyData: [], empty: '角色目录为空。', text: roleNames.security_reviewer },
  { title: '审计日志', path: auditPath, endpoint: 'audit', emptyData: { items: [], nextCursor: null, asOf: null }, empty: '你的审计范围内还没有记录。', text: 'iam.user.create' },
]

describe('FE-16b 读取三态', () => {
  it.each(readCases)('$title 加载、空态、错误 request-id 和正常数据均如实显示', async (c) => {
    let mode: 'empty' | 'error' | 'normal' = 'empty'
    let release!: () => void
    const gate = new Promise<void>((resolve) => { release = resolve })
    server.use(http.get(`/api/v2/${c.endpoint}`, async () => {
      await gate
      if (mode === 'normal') return
      return mode === 'empty'
        ? HttpResponse.json({ requestId: 'req-empty', error: null, data: c.emptyData })
        : HttpResponse.json({ requestId: 'req-system-read', data: null, error: { code: 'READ_FAILED', message: '读取失败' } }, { status: 503 })
    }))
    try {
      const { w } = await open(admin, c.path)
      expect(w.find('[aria-busy="true"]').exists()).toBe(true)
      release(); await settle()
      expect(w.text()).toContain(c.empty)
      expect(w.text()).not.toContain(c.text)
    } finally { release() }
    mode = 'error'
    const failed = await open(admin, c.path)
    expect(failed.w.findAll('[role="alert"]').some((a) => a.text().includes('request-id req-system-read'))).toBe(true)
    mode = 'normal'
    const loaded = await open(admin, c.path)
    expect(loaded.w.text()).toContain(c.text)
    expect(iamState.writes).toHaveLength(0)
  })
})

describe('FE-16b 用户管理', () => {
  it('搜索与状态筛选同步 URL 并交给后端；地址栏筛选首屏即生效', async () => {
    const queries: URLSearchParams[] = []
    server.use(http.get('/api/v2/users', ({ request }) => { queries.push(new URL(request.url).searchParams) }))
    const { router, w } = await open(admin, usersPath)
    expect(w.findAll('tbody tr')).toHaveLength(4)
    await w.get('input[aria-label="搜索用户"]').setValue('demo-t')
    await new Promise((r) => setTimeout(r, 380)); await settle()
    expect(router.currentRoute.value.query.q).toBe('demo-t')
    expect(queries.at(-1)?.get('q')).toBe('demo-t')
    expect(w.findAll('tbody tr')).toHaveLength(1)
    await click('已停用')
    expect(router.currentRoute.value.query).toMatchObject({ q: 'demo-t', status: 'disabled' })
    expect(queries.at(-1)?.get('status')).toBe('disabled')
    expect(w.text()).toContain('当前筛选条件下没有用户。')
    await click('清除筛选')
    expect(router.currentRoute.value.query).toEqual({})
    expect(queries.at(-1)?.has('q')).toBe(false); expect(queries.at(-1)?.has('status')).toBe(false)
    queries.length = 0
    await open(admin, `${usersPath}?q=demo-u&status=active`)
    expect(queries).toHaveLength(1)
    expect(queries[0].get('q')).toBe('demo-u'); expect(queries[0].get('status')).toBe('active')
  })

  it('新建用户先做客户端校验，提交带幂等键，成功后重读列表并打开新用户', async () => {
    const { router, w } = await open(admin, usersPath)
    await click('新建用户')
    await click('新建用户', dialog().element)
    expect(dialog().text()).toContain('请填写用户名'); expect(count('POST /api/v2/users')).toBe(0)
    const pw = secret()
    await fill('用户名', 'zhang.wei'); await fill('显示名', '张伟'); await fill('初始口令', pw); await fill('再次输入', `${pw}x`)
    await click('新建用户', dialog().element)
    expect(dialog().text()).toContain('两次输入的口令不一致'); expect(count('POST /api/v2/users')).toBe(0)
    await fill('再次输入', pw)
    const listReads = count('GET /api/v2/users')
    await click('新建用户', dialog().element)
    expect(iamState.writes).toEqual([{ method: 'POST', path: '/api/v2/users', key: expect.stringMatching(UUID), ifMatch: null }])
    const created = iamState.users.find((r) => r.user.username === 'zhang.wei')!.user
    expect(count('GET /api/v2/users')).toBe(listReads + 1)
    expect(count(`GET /api/v2/users/${created.id}`)).toBe(1)
    expect(router.currentRoute.value.query.id).toBe(String(created.id))
    expect(dialog().text()).toContain('没有角色绑定')
    expect(w.findAll('tbody tr').some((r) => r.text().includes('张伟'))).toBe(true)
    expect(JSON.stringify(iamState)).not.toContain(pw)
  })

  it('停用须进入确认并填写理由，带 If-Match 提交后重读用户', async () => {
    await open(admin, `${usersPath}?id=${IAM_USER}`)
    await click('停用账号')
    expect(dialog().text()).toContain('停用后该用户立即不能登录')
    expect(count(`POST /api/v2/users/${IAM_USER}/status-changes`)).toBe(0)
    await click('确认停用')
    expect(dialog().text()).toContain('请填写理由'); expect(count(`POST /api/v2/users/${IAM_USER}/status-changes`)).toBe(0)
    await fill('理由', '离岗停用')
    const reads = count(`GET /api/v2/users/${IAM_USER}`)
    await click('确认停用')
    expect(iamState.writes).toEqual([{ method: 'POST', path: `/api/v2/users/${IAM_USER}/status-changes`, key: expect.stringMatching(UUID), ifMatch: '1' }])
    expect(count(`GET /api/v2/users/${IAM_USER}`)).toBe(reads + 1)
    expect(dialog().text()).toContain('已停用：不能登录')
    expect(button('启用账号')).toBeTruthy(); expect(button('停用账号')).toBeUndefined()
  })

  it('本人账号：所有管理入口不可用并说明原因，不发写请求', async () => {
    const { w } = await open(admin, `${usersPath}?id=${admin.id}`)
    expect(w.findAll('tbody tr').find((r) => r.text().includes(admin.username))!.text()).toContain('本人')
    expect(dialog().text()).toContain(SELF_REASON)
    for (const text of ['停用账号', '删除账号', '编辑资料', '重置口令', '添加绑定', '撤销']) {
      const el = button(text, dialog().element)
      expect(el, `缺少按钮 ${text}`).toBeTruthy()
      expect(el!.disabled, `${text} 应不可用`).toBe(true)
      expect(el!.title).toBe(SELF_REASON)
      el!.click(); await settle()
    }
    expect(button('确认停用')).toBeUndefined(); expect(button('添加绑定', dialog().element)!.disabled).toBe(true)
    expect(requests.filter((r) => !r.startsWith('GET '))).toEqual([])
  })

  it('停用最后一名全局管理员被后端拒绝：显示错误码文案与 request-id，不假装成功', async () => {
    await open(me(['platform_admin'], 999, 'demo-admin-2'), `${usersPath}?id=${admin.id}`)
    await click('停用账号'); await fill('理由', '尝试停用唯一管理员'); await click('确认停用')
    expect(count(`POST /api/v2/users/${admin.id}/status-changes`)).toBe(1)
    const error = dialog().get('[role="alert"]').text()
    expect(error).toContain('必须保留至少一位有效的全局平台管理员'); expect(error).toContain('request-id req-f2-error')
    expect(iamState.writes).toHaveLength(0)
    expect(iamState.users.find((r) => r.user.id === admin.id)!.user.status).toBe('active')
    expect(button('确认停用')).toBeTruthy(); expect(toasts.some((t) => t.text.includes('已停用'))).toBe(false)
  })
})

describe('FE-16b 用户详情：角色绑定', () => {
  const bindPath = `POST /api/v2/users/${IAM_USER}/role-bindings`

  it('全局绑定提交 roleKey 与 global/*，成功后重读绑定', async () => {
    await open(admin, `${usersPath}?id=${IAM_USER}`)
    await click('添加绑定'); await fill('角色', 'model_operator')
    expect(dialog().text()).toContain('未发现职责冲突')
    const reads = count(`GET /api/v2/users/${IAM_USER}/role-bindings`)
    await click('添加绑定', dialog().element)
    expect(iamState.writes).toEqual([{ method: 'POST', path: `/api/v2/users/${IAM_USER}/role-bindings`, key: expect.stringMatching(UUID), ifMatch: null }])
    expect(count(`GET /api/v2/users/${IAM_USER}/role-bindings`)).toBe(reads + 1)
    expect(dialog().text()).toContain(roleNames.model_operator)
    expect(iamState.users.find((r) => r.user.id === IAM_USER)!.bindings.map((b) => `${b.roleKey}:${b.scopeType}:${b.scopeId}`))
      .toEqual(['security_analyst:global:*', 'model_operator:global:*'])
  })

  it('资产范围编号不是正整数时就地报错且不发请求；合法编号按 asset 范围提交', async () => {
    await open(admin, `${usersPath}?id=${IAM_USER}`)
    await click('添加绑定'); await fill('角色', 'model_operator')
    await dialog().get('input[type="radio"][value="asset"]').setValue(true)
    for (const bad of ['0', '-1', 'abc', '1.5']) {
      await fill('资产内部编号', bad); await click('添加绑定', dialog().element)
      expect(dialog().get('[role="alert"]').text()).toBe('资产内部编号须为正整数。')
    }
    expect(count(bindPath)).toBe(0)
    await fill('资产内部编号', '1'); await click('添加绑定', dialog().element)
    expect(count(bindPath)).toBe(1)
    expect(iamState.users.find((r) => r.user.id === IAM_USER)!.bindings.at(-1)).toMatchObject({ roleKey: 'model_operator', scopeType: 'asset', scopeId: '1' })
    expect(dialog().text()).toContain('资产 #1')
  })

  it('重复绑定在前端提示且不发请求', async () => {
    await open(admin, `${usersPath}?id=${IAM_USER}`)
    await click('添加绑定'); await fill('角色', 'security_analyst'); await click('添加绑定', dialog().element)
    expect(dialog().get('[role="alert"]').text()).toContain('已有相同角色与范围的绑定')
    expect(count(bindPath)).toBe(0)
  })

  it('互斥角色事前提示，提交后显示后端 409 ROLE_CONFLICT 的文案与 request-id，绑定不变', async () => {
    await open(admin, `${usersPath}?id=${IAM_USER}`)
    await click('添加绑定'); await fill('角色', 'security_reviewer')
    expect(dialog().get('[role="status"]').text()).toContain('职责冲突')
    await click('添加绑定', dialog().element)
    expect(count(bindPath)).toBe(1)
    const error = dialog().get('[role="alert"]').text()
    expect(error).toContain('角色职责冲突'); expect(error).toContain('request-id req-f2-error')
    expect(iamState.writes).toHaveLength(0)
    expect(iamState.users.find((r) => r.user.id === IAM_USER)!.bindings).toHaveLength(1)
    expect(toasts.some((t) => t.text.includes('已添加绑定'))).toBe(false)
  })
})

describe('FE-16b 角色管理', () => {
  const custom = (roleKey: string, permissions: string[]) => {
    iamState.roles.push({ roleKey, name: '值班主管', description: '值班复核', status: 'active', builtin: false, revision: 1, permissions })
  }

  it('内置角色只读：抽屉无编辑、停用与删除入口', async () => {
    await open(admin, `${rolesPath}?role=platform_admin`)
    expect(dialog().text()).toContain('内置角色只读')
    for (const text of ['编辑角色', '删除角色', '停用角色', '启用角色']) expect(button(text), text).toBeUndefined()
    expect(count('GET /api/v2/roles/platform_admin/members')).toBe(1)
  })

  it('新建自定义角色写后回读并打开；编辑权限带 If-Match，保存后重读', async () => {
    const { router } = await open(admin, rolesPath)
    await click('新建自定义角色')
    await click('新建角色', dialog().element)
    expect(dialog().get('[role="alert"]').text()).toContain('角色键后缀'); expect(count('POST /api/v2/roles')).toBe(0)
    await fill('角色键', 'shift_lead'); await fill('名称', '值班主管'); await fill('职责说明', '只读查看对象与安全数据')
    await permission('查看对象元数据')
    const reads = count('GET /api/v2/roles')
    await click('新建角色', dialog().element)
    expect(iamState.writes).toEqual([{ method: 'POST', path: '/api/v2/roles', key: expect.stringMatching(UUID), ifMatch: null }])
    expect(count('GET /api/v2/roles')).toBe(reads + 1)
    expect(router.currentRoute.value.query.role).toBe('custom_shift_lead')
    expect(dialog().text()).toContain('值班主管'); expect(dialog().text()).toContain('自定义')
    await click('编辑角色')
    await permission('查看安全数据')
    await click('保存角色', dialog().element)
    expect(iamState.writes.at(-1)).toEqual({ method: 'PATCH', path: '/api/v2/roles/custom_shift_lead', key: expect.stringMatching(UUID), ifMatch: '1' })
    expect(count('GET /api/v2/roles')).toBe(reads + 2)
    expect(iamState.roles.find((r) => r.roleKey === 'custom_shift_lead')!.permissions).toEqual(['resource.read', 'detection.read'])
    expect(dialog().text()).toContain('查看安全数据')
  })

  it('冲突权限对就地提示并禁止提交，不发请求', async () => {
    await open(admin, rolesPath)
    await click('新建自定义角色')
    await fill('角色键', 'mixed'); await fill('名称', '混合'); await fill('职责说明', '不应创建')
    await permission('起草决策策略'); await permission('审核决策策略')
    expect(dialog().get('[role="alert"]').text()).toContain('职责冲突：「起草决策策略」与「审核决策策略」不能同时持有。')
    expect(button('新建角色', dialog().element)!.disabled).toBe(true)
    await permission('审核决策策略', false)
    expect(dialog().find('[role="alert"]').exists()).toBe(false)
    expect(count('POST /api/v2/roles')).toBe(0)
  })

  it('有成员的角色删除被拒：已读到成员时禁用确认；成员读数过期时显示后端 409 ROLE_IN_USE', async () => {
    custom('custom_duty', ['resource.read'])
    iamState.users.find((r) => r.user.id === IAM_UNUSED_USER)!.bindings.push({ id: 4000, roleKey: 'custom_duty', scopeType: 'global', scopeId: '*' })
    await open(admin, `${rolesPath}?role=custom_duty`)
    expect(dialog().text()).toContain('demo-unused')
    await click('删除角色')
    expect(dialog().get('[role="alert"]').text()).toContain('该角色仍有成员绑定')
    expect(button('确认删除')!.disabled).toBe(true)
    expect(count('DELETE /api/v2/roles/custom_duty')).toBe(0)
    server.use(http.get('/api/v2/roles/:key/members', () => HttpResponse.json({ requestId: 'req-stale', error: null, data: { items: [], nextCursor: null } })))
    await open(admin, `${rolesPath}?role=custom_duty`)
    await click('删除角色'); await click('确认删除')
    expect(count('DELETE /api/v2/roles/custom_duty')).toBe(1)
    const error = dialog().get('[role="alert"]').text()
    expect(error).toContain('角色仍有绑定'); expect(error).toContain('request-id req-f2-error')
    expect(iamState.roles.some((r) => r.roleKey === 'custom_duty')).toBe(true)
  })
})

describe('FE-16b 审计日志', () => {
  it('动作、请求编号与时间范围同步 URL 并交给后端；非法动作就地报错；地址栏筛选首屏即生效', async () => {
    const queries: URLSearchParams[] = []
    server.use(http.get('/api/v2/audit', ({ request }) => { queries.push(new URL(request.url).searchParams) }))
    const { router, w } = await open(singleRoleUsers.auditor, auditPath)
    await w.get('input[aria-label="动作（精确匹配）"]').setValue('bad action!')
    const before = queries.length
    await click('筛选')
    expect(w.text()).toContain('动作只含字母'); expect(queries).toHaveLength(before)
    await w.get('input[aria-label="动作（精确匹配）"]').setValue('iam.user.create')
    await w.get('input[aria-label="请求编号"]').setValue('req-fixture-create')
    await click('筛选')
    expect(router.currentRoute.value.query).toMatchObject({ action: 'iam.user.create', requestId: 'req-fixture-create' })
    expect(queries.at(-1)?.get('action')).toBe('iam.user.create'); expect(queries.at(-1)?.get('requestId')).toBe('req-fixture-create')
    await click('近 24 小时')
    expect(router.currentRoute.value.query.range).toBe('24h')
    const from = Date.parse(queries.at(-1)!.get('from')!)
    expect(Math.abs(Date.now() - 864e5 - from)).toBeLessThan(60_000)
    await click('全部清除')
    expect(router.currentRoute.value.query).toEqual({})
    expect(['action', 'requestId', 'from'].some((k) => queries.at(-1)!.has(k))).toBe(false)
    queries.length = 0
    await open(singleRoleUsers.auditor, `${auditPath}?action=asset.update&range=7d`)
    expect(queries).toHaveLength(1)
    expect(queries[0].get('action')).toBe('asset.update'); expect(queries[0].has('from')).toBe(true)
  })

  it('游标翻页：下一页带后端不透明游标，上一页回到首页不带游标', async () => {
    const queries: URLSearchParams[] = []
    const entry = (id: string, action: string) => ({ id, occurredAt: '2026-10-15T03:00:00Z', actorType: 'human', action, resourceType: 'user', resourceId: null, requestId: `req-${action}`, outcome: 'success' })
    server.use(http.get('/api/v2/audit', ({ request }) => {
      const q = new URL(request.url).searchParams; queries.push(q)
      return HttpResponse.json({ requestId: 'req-audit-page', error: null, data: q.get('cursor')
        ? { items: [entry('ab000000-0000-4000-8000-0000000000b2', 'page.two')], nextCursor: null, asOf: null }
        : { items: [entry('ab000000-0000-4000-8000-0000000000b1', 'page.one')], nextCursor: 'opaque-audit', asOf: null } })
    }))
    const { w } = await open(singleRoleUsers.auditor, auditPath)
    expect(w.text()).toContain('page.one')
    await click('下一页')
    expect(queries.at(-1)?.get('cursor')).toBe('opaque-audit'); expect(w.text()).toContain('page.two'); expect(w.text()).not.toContain('page.one')
    expect(button('下一页')!.disabled).toBe(true)
    await click('上一页')
    expect(queries.at(-1)?.has('cursor')).toBe(false); expect(w.text()).toContain('page.one')
  })

  it('没有 audit.read 的账户进入 403 页，不读取审计', async () => {
    const { w } = await open(singleRoleUsers.security_analyst, auditPath)
    expect(w.text()).toContain('无权访问此页面')
    expect(count('GET /api/v2/audit')).toBe(0)
  })
})

describe('FE-16b 六角色可见性', () => {
  it.each(humanRoles)('%s：只有平台管理员能管理用户与角色，审计员只读', async (role) => {
    const user = singleRoleUsers[role]
    const admin = role === 'platform_admin', auditor = role === 'auditor'
    const { router, w } = await open(user, usersPath)
    if (admin) { expect(button('新建用户')).toBeTruthy(); expect(w.text()).toContain('demo-target') }
    else { expect(w.text()).toContain('无权访问此页面'); expect(count('GET /api/v2/users')).toBe(0) }

    await router.push(rolesPath); await settle()
    if (admin || auditor) {
      expect(w.text()).toContain('权限矩阵')
      expect(!!button('新建自定义角色')).toBe(admin)
      const members = count('GET /api/v2/roles/security_analyst/members')
      await router.push(`${rolesPath}?role=security_analyst`); await settle()
      expect(button('编辑角色')).toBeUndefined()
      expect(dialog().text().includes('查看成员需要身份与访问管理权限')).toBe(auditor)
      expect(count('GET /api/v2/roles/security_analyst/members') - members).toBe(admin ? 1 : 0)
    } else { expect(w.text()).toContain('无权访问此页面'); expect(count('GET /api/v2/roles')).toBe(0) }

    await router.push(auditPath); await settle()
    if (admin || auditor) expect(w.text()).toContain('审计记录')
    else { expect(w.text()).toContain('无权访问此页面'); expect(count('GET /api/v2/audit')).toBe(0) }
    expect(iamState.writes).toHaveLength(0)
    expect(requests.filter((r) => !r.startsWith('GET '))).toEqual([])
  })
})
