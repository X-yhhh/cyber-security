/**
 * 路由守卫与外壳集成测试（任务单 F0.2、F0.3、F0.7 验收）：msw 模拟 auth/me 与 summary，
 * 用内存历史挂载完整路由，断言 403/404、登录跳转、旧地址重定向，以及无权限地址不发任何数据请求。
 */
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { defineComponent, h } from 'vue'
import { createMemoryHistory, RouterView, type Router } from 'vue-router'
import { createAppRouter } from './index'
import { session } from '@/api/session'
import { resetCsrf } from '@/api/client'
import { dataRequests, requests, server } from '@/test/handlers'
import { signIn } from '@/test/handlers/auth'
import { comboUser, singleRoleUsers } from '@/test/roles'

const Host = defineComponent({ render: () => h(RouterView) })

let wrapper: VueWrapper | null = null
async function open(path: string): Promise<{ router: Router; w: VueWrapper }> {
  const router = createAppRouter(createMemoryHistory())
  router.push(path)
  await router.isReady()
  wrapper = mount(Host, { global: { plugins: [router] }, attachTo: document.body })
  await settle()
  return { router, w: wrapper }
}
/** 懒加载组件与 msw 响应需要多轮微任务。 */
async function settle() {
  for (let i = 0; i < 10; i++) { await flushPromises(); await new Promise((r) => setTimeout(r, 0)) }
}

beforeAll(() => {
  server.listen({ onUnhandledRequest: 'error' })
  // jsdom 未实现滚动；路由 scrollBehavior 会调用它。
  window.scrollTo = () => undefined
})
afterAll(() => server.close())
beforeEach(() => {
  session.user = null
  session.checked = false
  resetCsrf()
  requests.length = 0
  localStorage.clear()
})
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
  server.resetHandlers()
})

describe('登录与默认入口', () => {
  it('未登录访问控制台跳转登录页并带回跳地址', async () => {
    signIn(null)
    const { router } = await open('/console/system/audit')
    expect(router.currentRoute.value.name).toBe('login')
    expect(router.currentRoute.value.query.redirect).toBe('/console/system/audit')
  })

  it('/console 按权限进入默认落地页：有 detection.read 或 ops.read 进实时态势，否则进待办中心', async () => {
    signIn(singleRoleUsers.auditor)
    const first = await open('/console')
    expect(first.router.currentRoute.value.path).toBe('/console/overview/live')
    first.w.unmount()
    session.user = null
    session.checked = false
    signIn(singleRoleUsers.platform_admin)
    const admin = await open('/console')
    expect(admin.router.currentRoute.value.path).toBe('/console/overview/live')
    admin.w.unmount()
    session.user = null
    session.checked = false
    signIn(singleRoleUsers.model_operator)
    const { router, w } = await open('/console')
    expect(router.currentRoute.value.path).toBe('/console/workbench')
    expect(w.text()).toContain('待办中心')
  })
})

describe('403：无权限地址', () => {
  it.each([
    ['security_analyst', '/console/system/audit'],
    ['platform_admin', '/console/detect/records'],
    ['model_operator', '/console/response/actions'],
    ['evidence_reviewer', '/console/assets/agents'],  // health tab falls back to agents root when no ops.read
    ['security_reviewer', '/console/system/audit'],
  ] as const)('%s 直达 %s 显示 403 页且不发数据请求', async (role, path) => {
    signIn(singleRoleUsers[role])
    const { router, w } = await open(path)
    expect(router.currentRoute.value.name).toBe('console-forbidden')
    expect(router.currentRoute.value.path).toBe(path)
    expect(w.text()).toContain('无权访问此页面')
    expect(w.find('[role="tablist"]').exists()).toBe(false)
    expect(dataRequests()).toEqual([])
  })

  it('详情页沿用所属二级项的 anyOf', async () => {
    signIn(singleRoleUsers.platform_admin)
    const { router, w } = await open('/console/release/lab/run-1')
    expect(router.currentRoute.value.name).toBe('console-forbidden')
    expect(w.text()).toContain('无权访问此页面')
    expect(dataRequests()).toEqual([])
  })

  it('站内导航到无权限地址同样被拦截', async () => {
    signIn(singleRoleUsers.model_operator)
    const { router, w } = await open('/console/workbench')
    requests.length = 0
    await router.push('/console/assets/agents')
    await settle()
    expect(w.text()).toContain('无权访问此页面')
    expect(dataRequests()).toEqual([])
  })
})

describe('404 与重定向', () => {
  it('控制台内未知地址显示 404', async () => {
    signIn(singleRoleUsers.auditor)
    const { router, w } = await open('/console/no/such/page')
    expect(router.currentRoute.value.name).toBe('console-not-found')
    expect(w.text()).toContain('页面不存在')
    expect(dataRequests()).toEqual([])
  })

  it('未上线（ready=false）的二级项不注册路由，显示 404', async () => {
    signIn(singleRoleUsers.platform_admin)
    const { router } = await open('/console/system/users')
    expect(router.currentRoute.value.name).toBe('console-not-found')
  })

  it('控制台外未知地址显示 404', async () => {
    const { router, w } = await open('/nowhere')
    expect(router.currentRoute.value.name).toBe('not-found')
    expect(w.text()).toContain('页面不存在')
  })

  it.each([
    ['/console/release', '/console/release/bundles'],
    ['/console/execution', '/console/response/actions'],
    ['/console/lab', '/console/release/lab'],
    ['/console/lab/run-9', '/console/release/lab/run-9'],
    ['/console/health', '/console/assets/agents'],  // was /console/ops/health; now agents default tab
    ['/console/ops/audit', '/console/system/audit'],
  ])('旧地址 %s 重定向到 %s', async (from, to) => {
    signIn(singleRoleUsers.security_reviewer)
    const router = createAppRouter(createMemoryHistory())
    await router.push(from)
    expect(router.currentRoute.value.path).toBe(to)
    expect(router.currentRoute.value.redirectedFrom?.path).toBe(from)
  })

  it.each([
    ['/console/detect/observations?assetId=a-1', 'observations'],
    ['/console/detect/decisions', 'decisions'],
    ['/console/observation', 'observations'],
    ['/console/decisions', 'decisions'],
    ['/console/detect/observations?tab=batches&assetId=a-1', 'batches'],
    ['/console/observation?tab=detections', 'detections'],
    ['/console/detect/observations?tab=observations', 'observations'],
    ['/console/decisions?tab=decisions', 'decisions'],
    ['/console/observation?tab=episodes', 'observations'],
    ['/console/detect/decisions?tab=unknown', 'decisions'],
    ['/console/observation?tab=detections&tab=batches', 'observations'],
  ])('合并进检测记录的旧地址 %s 进入 %s 分段并保留查询参数', async (from, tab) => {
    signIn(singleRoleUsers.security_reviewer)
    const router = createAppRouter(createMemoryHistory())
    await router.push(from)
    expect(router.currentRoute.value.path).toBe('/console/detect/records')
    expect(router.currentRoute.value.query.tab).toBe(tab)
    if (from.includes('assetId')) expect(router.currentRoute.value.query.assetId).toBe('a-1')
  })

  it('检测旧地址保留时间筛选与锚点，重定向后仍由新页面权限拦截', async () => {
    signIn(singleRoleUsers.security_reviewer)
    const router = createAppRouter(createMemoryHistory())
    await router.push('/console/observation?tab=detections&assetId=a-1&range=24h#record')
    expect(router.currentRoute.value.fullPath).toBe('/console/detect/records?tab=detections&assetId=a-1&range=24h#record')

    signIn(singleRoleUsers.platform_admin)
    session.user = null
    session.checked = false
    const denied = await open('/console/detect/observations?tab=batches&range=24h')
    expect(denied.router.currentRoute.value.name).toBe('console-forbidden')
    expect(denied.router.currentRoute.value.query).toEqual({ tab: 'batches', range: '24h' })
    expect(dataRequests()).toEqual([])
  })

  it('v1 地址暂时保留（C1 删除）', async () => {
    const router = createAppRouter(createMemoryHistory())
    for (const p of ['/console/overview', '/console/events', '/console/events/1', '/console/iam']) {
      expect(router.resolve(p).name).not.toBe('console-not-found')
    }
  })
})

describe('有权限地址', () => {
  it('组合角色可以进入两个角色各自的页面', async () => {
    signIn(comboUser)
    const { router } = await open('/console/release/lab')
    expect(router.currentRoute.value.name).toBe('release-lab')
    await router.push('/console/ops/audit')
    expect(router.currentRoute.value.name).toBe('system-audit')
  })

  it('待办中心读取待办与汇总（F2）', async () => {
    signIn(singleRoleUsers.security_reviewer)
    await open('/console/workbench')
    expect([...dataRequests()].sort()).toEqual(['GET /api/v2/assets', 'GET /api/v2/summary', 'GET /api/v2/todos'])
  })
})
