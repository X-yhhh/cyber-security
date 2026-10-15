/** F3 接线回归：旧入口保留筛选与锚点，详情权限独立，复用页面只请求有权读取的分段。 */
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { defineComponent, h } from 'vue'
import { createMemoryHistory, RouterView, type RouteLocationRaw } from 'vue-router'
import { resetCsrf } from '@/api/client'
import { session } from '@/api/session'
import { dataRequests, requests, server } from '@/test/handlers'
import { signIn } from '@/test/handlers/auth'
import { resetReleaseState } from '@/test/handlers/release'
import { me, singleRoleUsers, type MeFixture } from '@/test/roles'
import { createAppRouter } from './index'

const Host = defineComponent({ render: () => h(RouterView) })
let wrapper: VueWrapper | undefined

async function settle() {
  for (let i = 0; i < 6; i++) { await flushPromises(); await new Promise((resolve) => setTimeout(resolve, 0)) }
}

async function navigate(to: RouteLocationRaw, user: MeFixture = singleRoleUsers.model_operator) {
  signIn(user)
  const router = createAppRouter(createMemoryHistory())
  await router.push(to)
  return router
}

async function open(to: string, user?: MeFixture) {
  const router = await navigate(to, user)
  wrapper = mount(Host, { global: { plugins: [router] } })
  await settle()
  return { router, w: wrapper }
}

beforeAll(() => {
  server.listen({ onUnhandledRequest: 'error' })
  window.scrollTo = () => undefined
})
afterAll(() => server.close())
beforeEach(() => {
  session.user = null
  session.checked = false
  resetCsrf()
  resetReleaseState()
  requests.length = 0
})
afterEach(() => {
  wrapper?.unmount()
  wrapper = undefined
  server.resetHandlers()
})

describe('发布旧入口', () => {
  it.each([
    ['/console/release/evaluations', 'validation', 'evaluations'],
    ['/console/release/policies', 'policies', undefined],
    ['/console/release/lab', 'validation', 'lab'],
    ['/console/release', 'bundles', undefined],
    ['/console/lab', 'validation', 'lab'],
  ])('%s 跳到最终分段并保留筛选和锚点', async (path, tab, record) => {
    const router = await navigate(`${path}?status=pending&cursor=next&q=sample&todoId=t-1#details`)
    expect(router.currentRoute.value.name).toBe('release-bundles')
    expect(router.currentRoute.value.path).toBe('/console/release/bundles')
    expect(router.currentRoute.value.query).toEqual({ status: 'pending', cursor: 'next', q: 'sample', todoId: 't-1', tab, ...(record ? { record } : {}) })
    expect(router.currentRoute.value.hash).toBe('#details')
  })

  it('第六个旧入口保留详情 id、查询参数和锚点', async () => {
    const router = await navigate('/console/lab/run-1?after=5#events')
    expect(router.currentRoute.value.name).toBe('release-lab-detail')
    expect(router.currentRoute.value.fullPath).toBe('/console/release/lab/run-1?after=5#events')
  })

  it.each([
    ['release', 'bundles', undefined],
    ['release-evaluations', 'validation', 'evaluations'],
    ['release-policies', 'policies', undefined],
    ['release-lab', 'validation', 'lab'],
    ['lab', 'validation', 'lab'],
  ])('旧路由名 %s 仍可用于站内链接', async (name, tab, record) => {
    const router = await navigate({ name, query: { status: 'draft' } })
    expect(router.currentRoute.value.name).toBe('release-bundles')
    expect(router.currentRoute.value.query).toEqual({ status: 'draft', tab, ...(record ? { record } : {}) })
  })

  it.each([
    ['tab=capabilities', 'capabilities', undefined],
    ['tab=evaluations', 'validation', 'evaluations'],
    ['tab=lab', 'validation', 'lab'],
    ['tab=validation&record=evaluations', 'validation', 'evaluations'],
    ['tab=unknown', 'policies', undefined],
    ['tab=lab&tab=bundles', 'policies', undefined],
    ['tab', 'policies', undefined],
  ])('规范化旧入口参数 %s', async (query, tab, record) => {
    const router = await navigate(`/console/release/policies?${query}`)
    expect(router.currentRoute.value.query.tab).toBe(tab)
    expect(router.currentRoute.value.query.record).toBe(record)
  })
})

describe('发布权限和读取接线', () => {
  it.each([
    '/console/release/evaluations', '/console/release/policies', '/console/release/lab',
    '/console/release', '/console/lab', '/console/lab/run-1',
    '/console/release/models', '/console/release/bundles', '/console/release/lab/run-1',
  ])('无权限直达 %s 不发数据请求', async (path) => {
    const { router, w } = await open(path, me([], 200, 'no-release-permission'))
    expect(router.currentRoute.value.name).toBe('console-forbidden')
    expect(w.text()).toContain('无权访问此页面')
    expect(dataRequests()).toEqual([])
  })

  it('lab 详情不能借发布申请权限进入', async () => {
    const user: MeFixture = { ...me([], 201), permissions: ['resource.read', 'bundle.request'] }
    const { router } = await open('/console/release/lab/run-1', user)
    expect(router.currentRoute.value.name).toBe('console-forbidden')
    expect(dataRequests()).toEqual([])
  })

  it('发布申请方打开组合只读取可见分段，不读取评价集合', async () => {
    const user: MeFixture = { ...me([], 201), permissions: ['resource.read', 'bundle.request'] }
    const { w } = await open('/console/release/bundles', user)
    expect(dataRequests()).toContain('GET /api/v2/release-bundles')
    expect(dataRequests()).not.toContain('GET /api/v2/evaluations')
    expect(dataRequests()).not.toContain('GET /api/v2/evaluation-plans')
    expect(dataRequests()).not.toContain('GET /api/v2/decision-policies')
    expect(w.get('[aria-label="发布管理分段"]').text()).not.toContain('验证记录')
  })

  it('只有评价读取权限时，不读取资源目录', async () => {
    const user: MeFixture = { ...me([], 202), permissions: ['evaluation.read'] }
    await open('/console/release/bundles?tab=validation&record=evaluations', user)
    expect(dataRequests()).toContain('GET /api/v2/evaluations')
    for (const collection of ['models', 'release-bundles', 'decision-policies', 'capabilities']) {
      expect(dataRequests()).not.toContain(`GET /api/v2/${collection}`)
    }
  })

  it('模型与数据集载体按 URL 只读取当前分段，切换后读取一次', async () => {
    const { router } = await open('/console/release/models?tab=datasets')
    expect(dataRequests()).toEqual(['GET /api/v2/datasets'])
    requests.length = 0
    await router.replace('/console/release/models')
    await settle()
    expect(dataRequests()).toEqual(['GET /api/v2/models'])
  })
})
