/** F4 已有页面的行为验收：四态、范围/权限、职责分离、写后回读与一次性凭据；不证明真实采集或 PF 执行。 */
import { DOMWrapper, flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { defineComponent, h } from 'vue'
import { http, HttpResponse } from 'msw'
import { createMemoryHistory, RouterView } from 'vue-router'
import { createAppRouter } from '@/router'
import { resetCsrf } from '@/api/client'
import { session } from '@/api/session'
import { resetSummaryCache } from '@/composables/summary'
import { toasts } from '@/composables/toast'
import { server, requests } from '@/test/handlers'
import { signIn } from '@/test/handlers/auth'
import { ASSET_1, ASSET_2, detectState, resetDetectState } from '@/test/handlers/detect'
import { assetsState, resetAssetsState } from '@/test/handlers/assets'
import { resetReleaseState } from '@/test/handlers/release'
import { F4_IDS } from '@/test/fixtures/assets'
import { humanRoles, me, singleRoleUsers, type MeFixture } from '@/test/roles'

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
  const field = dialog().findAll('label').find((l) => l.find('.label').text() === label)
  expect(field, `缺少字段 ${label}`).toBeTruthy()
  await field!.get('input,select,textarea').setValue(value)
}
const assetPath = `/console/assets/list/${ASSET_1}`
const agentsPath = '/console/assets/agents'
const count = (path: string) => requests.filter((r) => r === `GET /api/v2/${path}`).length

beforeAll(() => { server.listen({ onUnhandledRequest: 'error' }); window.scrollTo = () => undefined; Element.prototype.scrollIntoView = () => undefined })
afterAll(() => server.close())
beforeEach(() => {
  resetDetectState(); resetAssetsState(); resetReleaseState(); resetCsrf(); resetSummaryCache()
  session.user = null; session.checked = false; requests.length = 0; toasts.length = 0
  localStorage.clear(); sessionStorage.clear()
})
afterEach(() => { dispose(); server.resetHandlers() })

const readCases = [
  { title: '资产列表', path: '/console/assets/list', endpoint: 'assets', empty: '你的范围内还没有登记资产。', text: '靶场主机 01' },
  { title: '授权分段', path: `${assetPath}?tab=authorizations`, endpoint: 'authorizations', empty: '该资产还没有授权记录。', text: 'fixture0' },
  { title: '传感器', path: agentsPath, endpoint: 'sensors', empty: '你的资产范围内还没有登记传感器。', text: '合成采集器' },
  { title: '执行器', path: `${agentsPath}?tab=executors`, endpoint: 'executors', empty: '你的资产范围内还没有登记执行器。', text: '合成执行器' },
  { title: '采集配置', path: `${agentsPath}?tab=configs`, endpoint: 'sensor-configs', empty: '你的资产范围内还没有采集配置。', text: 'fixture0' },
  { title: '机器凭据', path: `${agentsPath}?tab=credentials`, endpoint: 'machine-clients', empty: '你的资产范围内没有机器凭据。', text: '合成采集器' },
  { title: '健康窗口', path: `${agentsPath}?tab=health`, endpoint: 'health-windows', empty: '你的资产范围内还没有接收到健康窗口。', text: '不代表现场采集健康' },
]

describe('F4 读取与导航', () => {
  it.each(readCases)('$title 加载、空态、错误 request-id 和正常数据均如实显示', async (c) => {
    let mode: 'empty' | 'error' | 'normal' = 'empty'
    let release!: () => void
    const gate = new Promise<void>((resolve) => { release = resolve })
    server.use(http.get(`/api/v2/${c.endpoint}`, async () => {
      await gate
      if (mode === 'normal') return
      return mode === 'empty'
        ? HttpResponse.json({ requestId: 'req-empty', error: null, data: { items: [], nextCursor: null } })
        : HttpResponse.json({ requestId: 'req-f4-read', data: null, error: { code: 'READ_FAILED', message: '读取失败' } }, { status: 503 })
    }))
    try {
      const { w } = await open(singleRoleUsers.platform_admin, c.path)
      expect(w.find('[aria-busy="true"]').exists()).toBe(true)
      release(); await settle()
      expect(w.text()).toContain(c.empty)
      expect(w.find('tbody tr').exists()).toBe(false)
    } finally { release() }
    mode = 'error'
    const failed = await open(singleRoleUsers.platform_admin, c.path)
    expect(failed.w.findAll('[role="alert"]').some((a) => a.text().includes('request-id req-f4-read'))).toBe(true)
    mode = 'normal'
    const loaded = await open(singleRoleUsers.platform_admin, c.path)
    expect(loaded.w.text()).toContain(c.text)
    expect(loaded.w.findAll('tbody tr').length + loaded.w.findAll('[id^="auth-"]').length).toBeGreaterThan(0)
  })

  it('资产详情显示加载、404、错误证据与可读面包屑', async () => {
    let release!: () => void
    const gate = new Promise<void>((resolve) => { release = resolve })
    server.use(http.get('/api/v2/assets/:id', async () => { await gate; return HttpResponse.json({ requestId: 'req-detail', data: null, error: { code: 'NOT_FOUND', message: '不可见' } }, { status: 404 }) }))
    try {
      const { w } = await open(singleRoleUsers.auditor, assetPath)
      expect(w.find('[aria-busy="true"]').exists()).toBe(true)
      release(); await settle(); expect(w.text()).toContain('不存在')
    } finally { release() }
    server.use(http.get('/api/v2/assets/:id', () => HttpResponse.json({ requestId: 'req-detail-error', data: null, error: { code: 'READ_FAILED', message: '读取失败' } }, { status: 503 })))
    expect((await open(singleRoleUsers.auditor, assetPath)).w.text()).toContain('request-id req-detail-error')
    server.resetHandlers()
    const { w } = await open(singleRoleUsers.auditor, assetPath)
    expect(w.get('nav[aria-label="面包屑"]').text()).toContain('靶场主机 01')
    expect(w.get('nav[aria-label="面包屑"]').text()).not.toContain(ASSET_1)
  })

  it('筛选同步 URL：环境只筛当前页，搜索与状态交给后端；游标翻页不附加环境参数', async () => {
    const queries: URLSearchParams[] = []
    server.use(http.get('/api/v2/assets', ({ request }) => {
      const q = new URL(request.url).searchParams; queries.push(q)
      return HttpResponse.json({ requestId: 'req-page', error: null, data: q.get('cursor')
        ? { items: [detectState.assets[1]], nextCursor: null }
        : { items: [detectState.assets[0]], nextCursor: 'opaque-next' } })
    }))
    const { router, w } = await open(singleRoleUsers.auditor, '/console/assets/list')
    await click('下一页'); expect(queries.at(-1)?.get('cursor')).toBe('opaque-next')
    await click('上一页'); expect(queries.at(-1)?.has('cursor')).toBe(false)
    const before = count('assets')
    await w.findAll('button').find((b) => b.text().startsWith('授权'))!.trigger('click'); await settle()
    expect(count('assets')).toBe(before); expect(router.currentRoute.value.query.env).toBe('authorized')
    expect(w.text()).toContain('当前筛选条件下没有资产。')
    await click('清除筛选')
    await w.get('select[aria-label="资产状态"]').setValue('disabled'); await settle()
    expect(queries.at(-1)?.get('status')).toBe('disabled')
    await w.get('input[aria-label="搜索资产"]').setValue('host-lab')
    await new Promise((r) => setTimeout(r, 380)); await settle()
    expect(router.currentRoute.value.query).toMatchObject({ q: 'host-lab', status: 'disabled' })
    expect(queries.at(-1)?.get('q')).toBe('host-lab'); expect(queries.every((q) => !q.has('environment') && !q.has('env'))).toBe(true)
  })

  it.each(humanRoles)('%s 按六角色矩阵显示管理入口、审批与运行分段', async (role) => {
    const user = singleRoleUsers[role]
    const { router, w } = await open(user, `${assetPath}?tab=authorizations`)
    expect(!!button('编辑资料')).toBe(role === 'platform_admin')
    expect(!!button('申请授权')).toBe(role === 'platform_admin')
    expect(!!button('批准授权')).toBe(role === 'security_reviewer')
    expect(!!button('撤回申请')).toBe(role === 'platform_admin')
    await router.push(agentsPath); await settle()
    if (['security_analyst', 'model_operator', 'evidence_reviewer'].includes(role)) {
      expect(w.text()).toContain('无权访问此页面')
      expect(count('sensors') + count('executors') + count('sensor-configs')).toBe(0)
      return
    }
    const tabs = w.findAll('[role="tab"]').map((t) => t.text())
    expect(tabs).toContain('采集配置')
    expect(tabs.includes('机器凭据')).toBe(role === 'platform_admin')
    expect(tabs.includes('健康窗口')).toBe(['platform_admin', 'security_reviewer', 'auditor'].includes(role))
    expect(!!button('登记设备')).toBe(role === 'platform_admin')
    await router.push(`${agentsPath}?tab=configs&id=${F4_IDS.config}`); await settle()
    expect(!!button('批准配置')).toBe(role === 'security_reviewer')
    expect(button('删除草稿')).toBeUndefined()
    expect(assetsState.writes).toHaveLength(0)
  })

  it('范围身份只见本资产，旧健康地址保留分段，待办直达配置与授权详情', async () => {
    const scoped = me(['platform_admin']); scoped.bindings.forEach((b) => { b.scopeType = 'asset'; b.scopeId = '1' })
    const { router, w } = await open(scoped, '/console/assets/list')
    expect(w.text()).toContain('靶场主机 01'); expect(w.text()).not.toContain('办公主机')
    await router.push(`/console/assets/list/${ASSET_2}`); await settle(); expect(w.text()).toContain('不存在')
    await router.push('/console/ops/health?verification=replay_healthy'); await settle()
    expect(router.currentRoute.value.path).toBe(agentsPath)
    expect(router.currentRoute.value.query).toMatchObject({ tab: 'health', verification: 'replay_healthy' })
    expect(w.text()).toContain('文件回放健康'); expect(w.text()).toContain('内核丢包 不适用')
    expect(w.text()).toContain('不代表现场采集健康')
    await router.push(`${agentsPath}?tab=configs&sensorId=${F4_IDS.sensor}&id=${F4_IDS.ownConfig}`); await settle()
    expect(dialog().text()).toContain('fixture0')
    await router.push(`/console/assets/list?assetId=${ASSET_1}&tab=authorizations&id=${F4_IDS.ownAuthorization}`); await settle()
    expect(router.currentRoute.value.path).toBe(assetPath)
    expect(w.find(`#auth-${F4_IDS.ownAuthorization}`).exists()).toBe(true)
  })

  it('无运行权限的健康直达回退到传感器且不读取健康窗口；未知状态不显示为健康', async () => {
    const limited = { ...singleRoleUsers.platform_admin, permissions: singleRoleUsers.platform_admin.permissions.filter((p) => p !== 'ops.read') }
    const { w } = await open(limited, `${agentsPath}?tab=health`)
    expect(count('health-windows')).toBe(0); expect(w.text()).toContain('无运行状态权限，不显示存活')
    const loaded = await open(singleRoleUsers.auditor, `${agentsPath}?tab=health`)
    const row = loaded.w.findAll('tbody tr').find((r) => r.text().includes('计数未知'))!
    expect(row.text()).toContain('未知'); expect(row.text()).not.toContain('健康')
  })
})

describe('F4 写入、职责分离与凭据', () => {
  it('登记与编辑资产写后回读，停用须二次确认，退役后无启用入口', async () => {
    const { router, w } = await open(singleRoleUsers.platform_admin, '/console/assets/list')
    await click('登记资产'); await click('登记资产', dialog().element)
    expect(dialog().text()).toContain('请填写责任人。'); expect(assetsState.writes).toHaveLength(0)
    await fill('责任人', '合成责任人'); await fill('资产键', 'fixture-new-host'); await fill('显示名', '新资产')
    await click('登记资产', dialog().element)
    const created = detectState.assets.find((a) => a.assetKey === 'fixture-new-host')!
    expect(created).toBeTruthy(); expect(count(`assets/${created.id}`)).toBe(1)
    await router.push(`/console/assets/list/${created.id}`); await settle()
    await click('编辑资料'); await fill('显示名', '更新资产'); await fill('说明', '测试说明'); await click('保存资料')
    expect(w.text()).toContain('更新资产'); expect(count(`assets/${created.id}`)).toBe(2)
    await click('停用资产'); expect(created.status).toBe('active'); expect(dialog().text()).toContain('发布绑定同时暂停')
    await click('确认停用'); expect(w.text()).toContain('新命令已暂停'); expect(created.status).toBe('disabled')
    await click('退役'); await click('确认退役')
    expect(w.text()).toContain('不能再启用'); expect(button('启用资产')).toBeUndefined()
    expect(assetsState.writes.map((r) => r.ifMatch)).toEqual([null, '1', '2', '3'])
  })

  it('修订冲突保留 request-id 和刷新提示，不重复请求或假装保存成功', async () => {
    let calls = 0
    server.use(http.patch('/api/v2/assets/:id', () => { calls++; return HttpResponse.json({ requestId: 'req-f4-conflict', data: null, error: { code: 'REVISION_CONFLICT', message: 'stale' } }, { status: 412 }) }))
    const { w } = await open(singleRoleUsers.platform_admin, assetPath)
    await click('编辑资料'); await fill('显示名', '不能保存的名称'); await click('保存资料')
    expect(toasts.some((t) => t.text.includes('刷新后重试') && t.text.includes('req-f4-conflict'))).toBe(true)
    expect(calls).toBe(1); expect(dialog().exists()).toBe(true)
    expect(w.text()).toContain('靶场主机 01'); expect(toasts.some((t) => t.text.includes('已保存'))).toBe(false)
  })

  it('本人待批授权只可撤回，非本人不可代撤回；独立审批先填写理由后回读', async () => {
    const { w } = await open(singleRoleUsers.platform_admin, `${assetPath}?tab=authorizations`)
    const own = w.get(`#auth-${F4_IDS.ownAuthorization}`), other = w.get(`#auth-${F4_IDS.authorization}`)
    expect(own.text()).toContain('撤回申请'); expect(other.text()).not.toContain('撤回申请')
    await click('撤回申请', own.element); await fill('理由', '本人撤回'); await click('撤回申请', dialog().element)
    expect(assetsState.authorizations.find((a) => a.id === F4_IDS.ownAuthorization)?.status).toBe('revoked')
    const self = await open(me(['security_reviewer'], 999), `${assetPath}?tab=authorizations`)
    expect(self.w.get(`#auth-${F4_IDS.authorization}`).text()).not.toContain('批准授权')
    const reviewer = await open(singleRoleUsers.security_reviewer, `${assetPath}?tab=authorizations`)
    await click('批准授权', reviewer.w.get(`#auth-${F4_IDS.authorization}`).element)
    await click('批准授权', dialog().element); expect(dialog().text()).toContain('请填写理由')
    await fill('理由', '已复核范围'); const before = count('authorizations'); await click('批准授权', dialog().element)
    expect(count('authorizations')).toBeGreaterThan(before)
    expect(reviewer.w.get(`#auth-${F4_IDS.authorization}`).text()).toContain('撤销授权')
    await click('撤销授权', reviewer.w.get(`#auth-${F4_IDS.authorization}`).element); await fill('理由', '收回授权'); await click('确认撤销')
    expect(assetsState.authorizations.find((a) => a.id === F4_IDS.authorization)?.status).toBe('revoked')
  })

  it('配置本人隐藏审批且仅本人草稿可删；独立批准/驳回后重读状态', async () => {
    await open(me(['security_reviewer'], singleRoleUsers.platform_admin.id), `${agentsPath}?tab=configs&id=${F4_IDS.ownConfig}`)
    expect(button('批准配置')).toBeUndefined(); expect(button('驳回')).toBeUndefined()
    const { router } = await open(singleRoleUsers.platform_admin, `${agentsPath}?tab=configs&id=${F4_IDS.config}`)
    expect(button('删除草稿')).toBeUndefined()
    await router.push(`${agentsPath}?tab=configs&id=${F4_IDS.ownConfig}`); await settle()
    await click('删除草稿'); await click('确认删除')
    expect(assetsState.configs.some((c) => c.id === F4_IDS.ownConfig)).toBe(false)
    expect(document.body.querySelector('[role="dialog"]')).toBeNull()
    const reviewer = await open(singleRoleUsers.security_reviewer, `${agentsPath}?tab=configs&id=${F4_IDS.config}`)
    await click('批准配置'); await fill('理由', '独立审批'); const before = count(`sensor-configs/${F4_IDS.config}`); await click('确认批准')
    expect(count(`sensor-configs/${F4_IDS.config}`)).toBeGreaterThan(before)
    expect(assetsState.configs.find((c) => c.id === F4_IDS.config)?.status).toBe('active')
    expect(dialog().text()).toContain('生效中')
    await reviewer.router.push(`${agentsPath}?tab=configs&id=${F4_IDS.otherConfig}`); await settle()
    await click('驳回'); await fill('理由', '需重新起草'); await click('确认驳回')
    expect(dialog().text()).toContain('已驳回，不会下发')
  })

  it('配置批准失败保留草稿与错误证据，不显示成功', async () => {
    assetsState.authorizations.find((a) => a.id === F4_IDS.activeAuthorization)!.validUntil = '2026-01-01T00:00:00Z'
    await open(singleRoleUsers.security_reviewer, `${agentsPath}?tab=configs&id=${F4_IDS.config}`)
    await click('批准配置'); await fill('理由', '检查失效授权'); await click('确认批准')
    expect(dialog().get('[role="alert"]').text()).toContain('request-id')
    expect(assetsState.configs.find((c) => c.id === F4_IDS.config)?.status).toBe('draft')
    expect(toasts.some((t) => t.text.includes('已批准'))).toBe(false)
  })

  it.each(['sensors', 'executors'] as const)('%s 登记默认遮罩；关闭凭据后详情和浏览器存储均不可找回，轮换只显示新凭据', async (kind) => {
    const { router } = await open(singleRoleUsers.platform_admin, `${agentsPath}?tab=${kind}`)
    await click('登记设备'); await fill('资产', ASSET_1); await fill('显示名', '新设备')
    if (kind === 'executors') await fill('能力探针引用', 'fixture-probe-reference')
    await click('登记并签发凭据')
    expect(dialog().get('[data-credential]').text()).toContain('••••')
    await click('显示'); const credential = dialog().get('[data-credential]').text()
    expect(credential).not.toContain('•'); expect(credential.length).toBeGreaterThan(24)
    await click('我已保存，关闭')
    expect(document.body.textContent).not.toContain(credential)
    expect(JSON.stringify(localStorage) + JSON.stringify(sessionStorage) + JSON.stringify(assetsState)).not.toContain(credential)
    const device = assetsState[kind].find((d) => d.displayName === '新设备')!
    await router.push(`${agentsPath}?tab=${kind}&id=${device.id}`); await settle()
    expect(dialog().find('[data-credential]').exists()).toBe(false)
    await click('编辑资料'); await fill('显示名', '更新设备'); await click('保存资料')
    expect(dialog().text()).toContain('更新设备')
    const noun = kind === 'sensors' ? '传感器' : '执行器'
    await click(`停用${noun}`); await fill('理由', '维护停用'); await click('确认停用')
    expect(dialog().text()).toContain('旧凭据已吊销')
    await click(`启用${noun}`); await fill('理由', '恢复登记'); await click('确认启用')
    expect(toasts.some((t) => t.text.includes('须轮换凭据'))).toBe(true)
    await click('轮换凭据'); await click('生成新凭据')
    expect(dialog().get('[data-credential]').text()).toContain('••••')
    await click('显示'); expect(dialog().get('[data-credential]').text()).not.toBe(credential)
    await click('我已保存，关闭')
    expect(document.body.querySelector('[data-credential]')).toBeNull()
  })

  it('采集配置草稿在客户端校验摘要；合法草稿写后跳到新配置，本人不能审批', async () => {
    const { router } = await open(singleRoleUsers.platform_admin, `${agentsPath}?id=${F4_IDS.sensor}`)
    await click('起草采集配置'); await fill('特征档案摘要（SHA-256）', 'bad')
    await click('提交草稿'); expect(dialog().get('[role="alert"]').text()).toContain('64 位')
    expect(assetsState.writes).toHaveLength(0)
    await fill('特征档案摘要（SHA-256）', 'a'.repeat(64)); await click('提交草稿')
    expect(router.currentRoute.value.query).toMatchObject({ tab: 'configs', sensorId: F4_IDS.sensor })
    expect(dialog().text()).toContain('等待起草人以外的审批人批准')
    expect(button('批准配置')).toBeUndefined(); expect(button('删除草稿')).toBeTruthy()
  })

  it('吊销机器凭据二次确认后重读，设备成为终态且隐藏启用和轮换', async () => {
    const { router, w } = await open(singleRoleUsers.platform_admin, `${agentsPath}?tab=credentials`)
    await click('吊销', w.findAll('tbody tr').find((r) => r.text().includes('合成采集器'))!.element)
    expect(assetsState.writes).toHaveLength(0)
    await fill('理由', '凭据泄露演练'); await click('确认吊销')
    expect(assetsState.clients.find((c) => c.id === F4_IDS.sensorClient)?.status).toBe('revoked')
    await router.push(`${agentsPath}?id=${F4_IDS.sensor}`); await settle()
    expect(dialog().text()).toContain('已吊销（终态）')
    expect(button('启用传感器')).toBeUndefined(); expect(button('轮换凭据')).toBeUndefined()
  })
})
