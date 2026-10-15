/**
 * 威胁检测 3 页单元测试（任务单 F1、F1R）：检测记录、事件研判（列表与详情）、误报反馈。
 * - 四态覆盖：加载、空态、错误（含 request-id）、正常渲染；
 * - 权限显隐（权限设计第 8 节）：event.manage、action.request、feedback.label、feedback.review；
 * - 职责分离：待复核列表默认排除本人标注，本人标注详情不显示复核按钮；
 * - 筛选同步到 URL 与请求参数，游标翻页；写操作契约：Idempotency-Key、If-Match，成功后重新从后端读取。
 */
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { defineComponent, h } from 'vue'
import { http, HttpResponse } from 'msw'
import { createMemoryHistory, RouterView } from 'vue-router'
import { createAppRouter } from '@/router'
import { session } from '@/api/session'
import { resetCsrf } from '@/api/client'
import { requests, server } from '@/test/handlers'
import { signIn } from '@/test/handlers/auth'
import {
  ASSET_1, ASSET_2, detectState, EP_1, EVENT_ALERT_ONLY, EVENT_OPEN, FB_OTHER,
  POLICY_1, resetDetectState, TARGET_REF_1,
} from '@/test/handlers/detect'
import { singleRoleUsers, type MeFixture } from '@/test/roles'
import '@/views/detect/EventDetailView.vue'

const Host = defineComponent({ render: () => h(RouterView) })

let wrapper: VueWrapper | null = null
async function settle() {
  for (let i = 0; i < 10; i++) {
    await flushPromises()
    await new Promise((r) => setTimeout(r, 0))
  }
}

async function open(user: MeFixture, path: string) {
  signIn(user)
  session.user = { ...user, permissions: [...user.permissions] }
  session.checked = true
  const router = createAppRouter(createMemoryHistory())
  router.push(path)
  await router.isReady()
  wrapper = mount(Host, { global: { plugins: [router] }, attachTo: document.body })
  await settle()
  return { router, w: wrapper }
}

beforeAll(() => {
  server.listen({ onUnhandledRequest: 'error' })
  window.scrollTo = () => undefined
})
afterAll(() => server.close())
beforeEach(() => {
  resetDetectState()
  session.user = null
  session.checked = false
  resetCsrf()
  requests.length = 0
  localStorage.clear()
})
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
  document.body.innerHTML = ''
  server.resetHandlers()
})

/** 记录某个集合最近一次列表请求的查询参数。 */
function lastQuery(path: string) {
  const seen: URLSearchParams[] = []
  server.events.on('request:start', ({ request }) => {
    const u = new URL(request.url)
    if (u.pathname === path) seen.push(u.searchParams)
  })
  return () => seen[seen.length - 1]
}
const tab = (w: VueWrapper, name: string) => w.findAll('[role="tab"]').find((t) => t.text().includes(name))!
const bodyButton = (text: string) => Array.from(document.body.querySelectorAll('button')).find((b) => b.textContent?.includes(text))

describe('检测记录（/console/detect/records）', () => {
  it('默认打开判定段：矩阵与样本量提示，只请求判定；点单元格下钻到列表并打开判定详情', async () => {
    const { router, w } = await open(singleRoleUsers.security_reviewer, '/console/detect/records')
    expect(w.text()).toContain('检测记录')
    expect(tab(w, '判定').attributes('aria-selected')).toBe('true')
    expect(w.text()).toContain('已加载 2 条')
    expect(w.text()).toContain('规则 R-BF-1')
    expect(requests).toContain('GET /api/v2/decisions')
    expect(requests).not.toContain('GET /api/v2/observation-batches')
    expect(requests).not.toContain('GET /api/v2/observations')

    await w.get('button[aria-label="查看暴力破解·模型的判定"]').trigger('click')
    await settle()
    expect(router.currentRoute.value.query).toMatchObject({ tab: 'decisions', view: 'list', family: 'brute_force', source: 'model' })
    expect(w.text()).toContain('模型来源未开自动')
    // 资产显示名称，不显示 UUID
    expect(w.text()).toContain('靶场主机 01')
    expect(w.text()).not.toContain(ASSET_1)
    await w.get('tbody tr.row-link').trigger('keydown', { key: 'Enter' })
    await settle()
    // 原因码等内部键只在技术细节中
    const tech = document.body.querySelector('details.tech-details')!
    expect(tech.textContent).toContain('SOURCE_LEVEL_ALERT_ONLY')
  })

  it('分段切换：推理显示四类分数且非成功为 —；观察、接入批次按需读取；分段同步到 URL', async () => {
    const { router, w } = await open(singleRoleUsers.security_analyst, '/console/detect/records?tab=detections')
    expect(w.text()).toContain('0.962')
    expect(w.text()).toContain('PROFILE_UNSUPPORTED')
    expect(w.text()).toContain('—')
    expect(requests).not.toContain('GET /api/v2/decisions')

    await tab(w, '接入批次').trigger('click')
    await settle()
    expect(router.currentRoute.value.query.tab).toBe('batches')
    expect(w.get('tbody').text()).toMatch(/3\s*\/\s*0\s*\/\s*—/)
    // 证据组不在本页单独成段
    expect(w.findAll('[role="tab"]').map((t) => t.text())).not.toContain('证据迹')
  })

  it('资产与时间筛选由后端执行并同步到 URL；切换后旧分段重新读取', async () => {
    const query = lastQuery('/api/v2/observations')
    const { router, w } = await open(singleRoleUsers.security_analyst, '/console/detect/records?tab=observations')
    expect(w.findAll('tbody tr.row-link')).toHaveLength(2)

    await w.get('select[aria-label="资产筛选"]').setValue(ASSET_2)
    await settle()
    expect(query().get('assetId')).toBe(ASSET_2)
    expect(w.findAll('tbody tr.row-link')).toHaveLength(1)

    await w.get('select[aria-label="时间范围"]').setValue('24h')
    await settle()
    expect(query().get('from')).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/)
    expect(query().has('q')).toBe(false)
    expect(router.currentRoute.value.query).toMatchObject({ tab: 'observations', assetId: ASSET_2, range: '24h' })
  })

  it('游标翻页：下一页带 nextCursor，上一页回到首页', async () => {
    const query = lastQuery('/api/v2/observation-batches')
    server.use(http.get('/api/v2/observation-batches', ({ request }) => {
      const cursor = new URL(request.url).searchParams.get('cursor')
      const b = detectState.batches[0]
      return HttpResponse.json({ requestId: 'r-page', data: cursor
        ? { items: [{ ...b, id: 'b0000000-0000-4000-8000-000000000002', sequenceNo: 11 }], nextCursor: null }
        : { items: [b], nextCursor: 'c-2' }, error: null })
    }))
    const { w } = await open(singleRoleUsers.auditor, '/console/detect/records?tab=batches')
    await w.findAll('button').find((b) => b.text() === '下一页')!.trigger('click')
    await settle()
    expect(query().get('cursor')).toBe('c-2')
    expect(w.text()).toContain('11')
    await w.findAll('button').find((b) => b.text() === '上一页')!.trigger('click')
    await settle()
    expect(query().has('cursor')).toBe(false)
  })

  it('标注按 feedback.label 显隐：分析员在观察详情中提交成功，403 时显示原因；审计员看不到入口', async () => {
    const { w } = await open(singleRoleUsers.security_analyst, '/console/detect/records?tab=observations')
    await w.get('tbody tr.row-link').trigger('click')
    await settle()
    bodyButton('标注此观察')!.click()
    await settle()
    bodyButton('提交标注')!.click()
    await settle()
    expect(detectState.writes['POST /api/v2/feedback']?.idempotencyKey).toBeTruthy()
    expect(document.body.textContent).toContain('已提交标注')

    server.use(http.post('/api/v2/feedback', () =>
      HttpResponse.json({ requestId: 'req-fb-403', data: null, error: { code: 'SCOPE_DENIED', message: '资产不在授权范围' } }, { status: 403 })))
    bodyButton('提交标注')!.click()
    await settle()
    expect(document.body.querySelector('[role="alert"]')!.textContent).toBe('资产不在授权范围（request-id req-fb-403）')

    wrapper!.unmount()
    document.body.innerHTML = ''
    await open(singleRoleUsers.auditor, '/console/detect/records?tab=observations')
    await wrapper!.get('tbody tr.row-link').trigger('click')
    await settle()
    expect(bodyButton('标注此观察')).toBeUndefined()
  })

  it('空态写明范围，错误态附带 request-id', async () => {
    server.use(http.get('/api/v2/decisions', () => HttpResponse.json({ requestId: 'r-empty', data: { items: [], nextCursor: null }, error: null })))
    const { w } = await open(singleRoleUsers.auditor, '/console/detect/records')
    expect(w.text()).toContain('你可见范围内暂无判定记录')

    wrapper!.unmount()
    server.use(http.get('/api/v2/observation-batches', () => HttpResponse.json({ requestId: 'req-obs-err', data: null, error: { code: 'INTERNAL_ERROR', message: '批次读取失败' } }, { status: 500 })))
    const second = await open(singleRoleUsers.auditor, '/console/detect/records?tab=batches')
    expect(second.w.get('[role="alert"]').text()).toBe('批次读取失败（request-id req-obs-err）')
  })

  it('界面不出现内部编号', async () => {
    const { w } = await open(singleRoleUsers.security_reviewer, '/console/detect/records')
    expect(w.get('main').text()).not.toMatch(/\b(S5|S6|G3|r6)\b|lab_auto/)
  })
})

describe('事件研判列表与详情（/console/detect/events & /console/detect/events/:id）', () => {
  it('列表支持 ?status=open 初始筛选与资产筛选，点击行进入详情', async () => {
    let lastUrl = ''
    server.events.on('request:start', ({ request }) => {
      if (request.url.includes('/api/v2/events?')) lastUrl = request.url
    })
    const { router, w } = await open(singleRoleUsers.security_analyst, '/console/detect/events?status=open')
    expect(lastUrl).toContain('status=open')

    // 标题搜索：回车提交 q，并同步到 URL
    await w.get('input[aria-label="搜索事件标题"]').setValue('SSH')
    await w.get('form[role="search"]').trigger('submit')
    await settle()
    expect(lastUrl).toContain('q=SSH')
    expect(router.currentRoute.value.query.q).toBe('SSH')
    expect(w.text()).toContain('SSH 暴力破解阻断候选事件')
    expect(w.text()).not.toContain('端口扫描只告警事件')

    // 切换资产筛选
    await w.get('select[aria-label="资产筛选"]').setValue(ASSET_2)
    await settle()
    expect(w.text()).toContain('当前筛选条件下没有可见的安全事件')

    // 切回全部状态与全部资产并点击进入详情
    await w.get('select[aria-label="资产筛选"]').setValue('')
    await w.findAll('[aria-label="事件状态筛选"] button').find((b) => b.text() === '全部')!.trigger('click')
    await settle()
    await w.get('tbody tr.row-link').trigger('click')
    await settle()
    expect(router.currentRoute.value.path).toBe(`/console/detect/events/${EVENT_OPEN}`)
  })

  it('事件列表错误态显示 request-id', async () => {
    server.use(http.get('/api/v2/events', () => HttpResponse.json({ requestId: 'req-evt-500', data: null, error: { code: 'INTERNAL_ERROR', message: '事件查询失败' } }, { status: 500 })))
    const { w } = await open(singleRoleUsers.auditor, '/console/detect/events')
    expect(w.get('[role="alert"]').text()).toBe('事件查询失败（request-id req-evt-500）')
  })

  it('详情页：分析员可执行状态迁移、指派负责人、追加研判记录与人工处置申请（均带幂等键与 If-Match）', async () => {
    const { w } = await open(singleRoleUsers.security_analyst, `/console/detect/events/${EVENT_OPEN}`)
    expect(w.text()).toContain('EVT-LAB-001')
    expect(w.text()).toContain('满足人工处置申请条件')
    // 关联资产显示名称；同类型、同主体、5 分钟内的系统记录合并为一条 ×3，可展开
    expect(w.get('header.panel').text()).toContain('靶场主机 01')
    expect(w.get('header.panel').text()).not.toContain(ASSET_1.slice(0, 8))
    const merged = w.get('button[aria-label="展开合并的 3 条记录"]')
    expect(w.text()).not.toContain('第 2 次')
    await merged.trigger('click')
    expect(w.text()).toContain('第 2 次')

    // 1. 状态迁移（POST /api/v2/events/:id/transitions）
    await w.findAll('button').find((b) => b.text() === '标记为研判中')!.trigger('click')
    await w.get('input[aria-label="状态迁移理由"]').setValue('确认存在多次失败认证特征')
    await w.findAll('button').find((b) => b.text() === '确认迁移')!.trigger('submit')
    await settle()
    const trWrite = detectState.writes[`POST /api/v2/events/${EVENT_OPEN}/transitions`]
    expect(trWrite?.ifMatch).toBe('2')
    expect(trWrite?.idempotencyKey).toBeTruthy()
    expect(trWrite?.body).toEqual({
      expectedRevision: 2,
      to: 'investigating',
      reason: '确认存在多次失败认证特征',
    })
    expect(w.text()).toContain('标记为已遏制')

    // 2. 指派负责人（PUT /api/v2/events/:id/assignee）
    await w.findAll('button').find((b) => b.text() === '指派')!.trigger('click')
    await settle()
    const select = document.body.querySelector('select[aria-label="可指派人员"]') as HTMLSelectElement
    select.value = 'usr-analyst-2'
    select.dispatchEvent(new Event('change'))
    await settle()
    const confirmAssign = Array.from(document.body.querySelectorAll('button')).find((b) => b.textContent?.trim() === '确认指派')!
    confirmAssign.click()
    await settle()
    const assignWrite = detectState.writes[`PUT /api/v2/events/${EVENT_OPEN}/assignee`]
    expect(assignWrite?.ifMatch).toBe('3')
    expect(assignWrite?.body).toEqual({ userId: 'usr-analyst-2' })
    expect(w.text()).toContain('二线安全分析员（usr-analyst-2）')

    // 3. 追加研判记录（POST /api/v2/events/:id/notes）
    await w.get('input[aria-label="追加研判记录"]').setValue('已核对父流连接计数与时间戳')
    await w.findAll('button').find((b) => b.text() === '添加记录')!.trigger('submit')
    await settle()
    expect(detectState.writes[`POST /api/v2/events/${EVENT_OPEN}/notes`]?.body).toEqual({ note: '已核对父流连接计数与时间戳' })
    expect(w.text()).toContain('已核对父流连接计数与时间戳')

    // 4. 发起人工处置申请（POST /api/v2/actions，只读引用绑定目标，无 IP/端口输入）
    await w.findAll('button').find((b) => b.text() === '申请处置')!.trigger('click')
    await settle()
    expect(document.body.querySelectorAll('input[placeholder*="IP"]').length).toBe(0)
    const reasonArea = document.body.querySelector('textarea[aria-label="申请理由"]') as HTMLTextAreaElement
    reasonArea.value = '暴破持续命中阈值，申请临时阻断'
    reasonArea.dispatchEvent(new Event('input'))
    await settle()
    const submitAct = Array.from(document.body.querySelectorAll('button')).find((b) => b.textContent?.trim() === '提交处置申请')!
    submitAct.click()
    await settle()
    expect(detectState.writes['POST /api/v2/actions']?.body).toEqual({
      episodeId: EP_1,
      targetRef: TARGET_REF_1,
      policyId: POLICY_1,
      reason: '暴破持续命中阈值，申请临时阻断',
    })
  })

  it('详情页：actionable=false 时申请处置按钮禁用并写出原因码；只读角色不显示任何写操作按钮且无 action.read 时不请求 actions', async () => {
    const { w } = await open(singleRoleUsers.security_analyst, `/console/detect/events/${EVENT_ALERT_ONLY}`)
    const actBtn = w.findAll('button').find((b) => b.text() === '申请处置')!
    expect(actBtn.attributes('disabled')).toBeDefined()
    expect(w.text()).toContain('ACTION_EVIDENCE_REQUIRED')
    expect(w.text()).toContain('尚无阻断候选判定')

    // 证据复核员只有 detection.read（无 event.manage、无 action.request、无 action.read）
    wrapper!.unmount()
    requests.length = 0
    const reviewer = await open(singleRoleUsers.evidence_reviewer, `/console/detect/events/${EVENT_OPEN}`)
    expect(reviewer.w.findAll('button').some((b) => b.text().includes('标记为'))).toBe(false)
    expect(reviewer.w.findAll('button').some((b) => b.text().includes('指派'))).toBe(false)
    expect(reviewer.w.findAll('button').some((b) => b.text() === '申请处置')).toBe(false)
    expect(reviewer.w.find('input[aria-label="追加研判记录"]').exists()).toBe(false)
    expect(requests).not.toContain(`GET /api/v2/events/${EVENT_OPEN}/actions`)
  })

  it('详情页：写操作 409 版本冲突与 403 拒绝时展示错误消息及 request-id', async () => {
    const { w } = await open(singleRoleUsers.security_analyst, `/console/detect/events/${EVENT_OPEN}`)
    // 模拟后端 revision 已变化导致 409 REVISION_CONFLICT
    detectState.events.find((e) => e.id === EVENT_OPEN)!.revision = 99
    await w.findAll('button').find((b) => b.text() === '标记为研判中')!.trigger('click')
    await w.get('input[aria-label="状态迁移理由"]').setValue('并发迁移测试')
    await w.findAll('button').find((b) => b.text() === '确认迁移')!.trigger('submit')
    await settle()
    expect(w.get('[role="alert"]').text()).toBe('事件已被其他操作更新（request-id req-detect-err）')

    // 模拟 403 SCOPE_DENIED
    server.use(http.post(`/api/v2/events/${EVENT_OPEN}/notes`, () =>
      HttpResponse.json({ requestId: 'req-403-note', data: null, error: { code: 'SCOPE_DENIED', message: '资产不在授权范围' } }, { status: 403 })))
    await w.get('input[aria-label="追加研判记录"]').setValue('越权记录测试')
    await w.findAll('button').find((b) => b.text() === '添加记录')!.trigger('submit')
    await settle()
    expect(w.get('[role="alert"]').text()).toBe('资产不在授权范围（request-id req-403-note）')
  })
})

describe('误报反馈（/console/detect/feedback）', () => {
  it('分段按权限显示：复核员有待复核与全部，分析员有我的标注与全部且默认进入我的标注', async () => {
    const { w } = await open(singleRoleUsers.evidence_reviewer, '/console/detect/feedback')
    expect(w.findAll('[role="tab"]').map((t) => t.text())).toEqual(['待复核', '全部'])
    expect(tab(w, '待复核').attributes('aria-selected')).toBe('true')

    wrapper!.unmount()
    const analyst = await open(singleRoleUsers.security_analyst, '/console/detect/feedback')
    expect(analyst.w.findAll('[role="tab"]').map((t) => t.text())).toEqual(['我的标注', '全部'])
    expect(tab(analyst.w, '我的标注').attributes('aria-selected')).toBe('true')
    // 我的标注只保留本人提交的（当前页筛选）
    expect(analyst.w.text()).toContain('sha256:bbbbbbbbbbbbbbbb')
    expect(analyst.w.text()).not.toContain('sha256:cccccccccccccccc')
  })

  it('全部分段按状态、时间筛选，参数同步到 URL 与请求', async () => {
    const query = lastQuery('/api/v2/feedback')
    const { router, w } = await open(singleRoleUsers.evidence_reviewer, '/console/detect/feedback?tab=all')
    await w.findAll('[aria-label="复核状态筛选"] button').find((b) => b.text() === '已复核')!.trigger('click')
    await w.get('select[aria-label="时间范围"]').setValue('7d')
    await settle()
    expect(query().get('status')).toBe('reviewed')
    expect(query().get('from')).toBeTruthy()
    expect(router.currentRoute.value.query).toMatchObject({ tab: 'all', status: 'reviewed', range: '7d' })
    expect(w.text()).toContain('obs:verified-01')
  })

  it('待复核列表默认排除本人标注；本人标注对象在抽屉中不显示复核按钮', async () => {
    const { w } = await open(singleRoleUsers.evidence_reviewer, '/console/detect/feedback?status=pending')
    // evidence_reviewer 无 feedback.label，不显示「新建标注」按钮
    expect(w.findAll('button').some((b) => b.text() === '新建标注')).toBe(false)
    // 默认排除本人标注（FB_SELF_REVIEWER），只显示他人标注（FB_OTHER）
    expect(w.text()).toContain('sha256:bbbbbbbbbbbbbbbb')
    expect(w.text()).not.toContain('sha256:cccccccccccccccc')

    // 取消勾选「默认排除本人标注」后可看到本人标注，但点开后不显示复核按钮
    await w.get('input[type="checkbox"]').setValue(false)
    await settle()
    expect(w.text()).toContain('sha256:cccccccccccccccc')
    const rows = w.findAll('tbody tr.row-link')
    await rows.find((r) => r.text().includes('sha256:cccccccccccccccc'))!.trigger('click')
    await settle()
    expect(document.body.textContent).toContain('本人提交的标注须由其他复核人决定')
    expect(Array.from(document.body.querySelectorAll('button')).some((b) => b.textContent?.includes('提交复核'))).toBe(false)
  })

  it('证据复核员可复核非本人标注（POST /api/v2/feedback/:id/reviews，带 If-Match）并查看关联观察', async () => {
    const { w } = await open(singleRoleUsers.evidence_reviewer, '/console/detect/feedback?status=pending')
    await w.get('tbody tr.row-link').trigger('click')
    await settle()
    expect(document.body.textContent).toContain('flow-ssh-brute-01')

    const reasonInput = document.body.querySelector('textarea[aria-label="复核理由"]') as HTMLTextAreaElement
    reasonInput.value = '核实观察快照包数与方向一致，确认为攻击样本'
    reasonInput.dispatchEvent(new Event('input'))
    await settle()
    const submitBtn = Array.from(document.body.querySelectorAll('button')).find((b) => b.textContent?.includes('提交复核'))!
    submitBtn.click()
    await settle()

    const revWrite = detectState.writes[`POST /api/v2/feedback/${FB_OTHER}/reviews`]
    expect(revWrite?.ifMatch).toBe('1')
    expect(revWrite?.idempotencyKey).toBeTruthy()
    expect(revWrite?.body).toEqual({
      decision: 'approve',
      reason: '核实观察快照包数与方向一致，确认为攻击样本',
    })
    // 复核后重新加载待复核列表，已无待复核项（除本人外为空）
    expect(w.text()).toContain('你可见范围内暂无待你复核的标注')
  })

  it('复核版本冲突（409）在表单中显示原因与 request-id', async () => {
    const { w } = await open(singleRoleUsers.evidence_reviewer, '/console/detect/feedback')
    await w.get('tbody tr.row-link').trigger('click')
    await settle()
    detectState.feedbacks.find((f) => f.id === FB_OTHER)!.revision = 7
    const reasonInput = document.body.querySelector('textarea[aria-label="复核理由"]') as HTMLTextAreaElement
    reasonInput.value = '并发复核'
    reasonInput.dispatchEvent(new Event('input'))
    await settle()
    bodyButton('提交复核')!.click()
    await settle()
    expect(document.body.querySelector('[role="alert"]')!.textContent).toBe('反馈版本冲突（request-id req-detect-err）')
  })

  it('安全分析员可新建标注（校验 UUID 格式）但不能复核；复核 409 与列表错误态附带 request-id', async () => {
    const { w } = await open(singleRoleUsers.security_analyst, '/console/detect/feedback')
    const newBtn = w.findAll('button').find((b) => b.text() === '新建标注')!
    await newBtn.trigger('click')
    await settle()
    const uuidInput = document.body.querySelector('input[aria-label="观察记录 UUID"]') as HTMLInputElement
    uuidInput.value = 'not-a-uuid'
    uuidInput.dispatchEvent(new Event('input'))
    await settle()
    const submitCreateBtn = Array.from(document.body.querySelectorAll('button')).find((b) => b.textContent?.includes('提交标注'))!
    submitCreateBtn.click()
    await settle()
    expect(document.body.textContent).toContain('观察记录 ID 须为有效的 UUID 格式')

    await tab(w, '全部').trigger('click')
    await settle()
    await w.get('tbody tr.row-link').trigger('click')
    await settle()
    // 分析员无 feedback.review，不显示提交复核按钮
    expect(Array.from(document.body.querySelectorAll('button')).some((b) => b.textContent?.includes('提交复核'))).toBe(false)

    wrapper!.unmount()
    document.body.innerHTML = ''
    server.use(http.get('/api/v2/feedback', () => HttpResponse.json({ requestId: 'req-fb-500', data: null, error: { code: 'INTERNAL_ERROR', message: '反馈读取失败' } }, { status: 500 })))
    const errView = await open(singleRoleUsers.security_analyst, '/console/detect/feedback')
    expect(errView.w.get('[role="alert"]').text()).toBe('反馈读取失败（request-id req-fb-500）')
  })
})
