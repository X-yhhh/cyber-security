/**
 * 实时态势（任务单 F6 验收）：按权限显示各块（只有 ops.read 时只看到设备）、null 点不连线并写明缺口、
 * 切换范围作废旧请求、暂停与页面不可见时停止轮询、最新判定按归并关系进入事件。
 */
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { defineComponent, h } from 'vue'
import { createMemoryHistory, createRouter, RouterView, type Router } from 'vue-router'
import { http, HttpResponse } from 'msw'
import { session } from '@/api/session'
import { requests, server } from '@/test/handlers'
import { signIn } from '@/test/handlers/auth'
import { DEC_1 } from '@/test/handlers/detect'
import { singleRoleUsers, type MeFixture } from '@/test/roles'
import { resetSummaryCache } from '@/composables/summary'
import LiveView from './LiveView.vue'

const Host = defineComponent({ render: () => h(RouterView) })
const Stub = defineComponent({ render: () => h('p', 'stub') })

let wrapper: VueWrapper | null = null
async function settle() {
  for (let i = 0; i < 10; i++) { await flushPromises(); await new Promise((r) => setTimeout(r, 0)) }
}
async function open(user: MeFixture, path = '/console/overview/live'): Promise<{ router: Router; w: VueWrapper }> {
  signIn(user)
  session.user = { ...user, permissions: [...user.permissions] } as unknown as typeof session.user
  session.checked = true
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/console/overview/live', name: 'overview-live', component: LiveView },
      { path: '/console/detect/events', name: 'detect-events', component: Stub },
      { path: '/console/detect/events/:id', name: 'detect-events-detail', component: Stub },
    ],
  })
  router.push(path)
  await router.isReady()
  wrapper = mount(Host, { global: { plugins: [router] }, attachTo: document.body })
  await settle()
  return { router, w: wrapper }
}
const statsCalls = () => requests.filter((r) => r === 'GET /api/v2/stats/live').length
const statsQueries: URLSearchParams[] = []
const heartbeatCalls = () => requests.filter((r) => r === 'GET /api/v2/sensor-heartbeats').length

beforeAll(() => {
  server.listen({ onUnhandledRequest: 'bypass' })
  server.events.on('request:start', ({ request }) => {
    const url = new URL(request.url)
    if (url.pathname === '/api/v2/stats/live') statsQueries.push(url.searchParams)
  })
})
afterAll(() => server.close())
beforeEach(() => {
  requests.length = 0; statsQueries.length = 0; resetSummaryCache()
  Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => 'visible' })
})
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
  server.resetHandlers()
  vi.useRealTimers()
  session.user = null
})

describe('实时态势：按权限显示', () => {
  it('审计员看到今日计数、两张趋势图、设备在线与最新判定', async () => {
    const { w } = await open(singleRoleUsers.auditor)
    expect(requests).toContain('GET /api/v2/stats/live')
    expect(requests).toContain('GET /api/v2/decisions')
    expect(requests).toContain('GET /api/v2/sensor-heartbeats')
    const titles = w.findAll('h2').map((x) => x.text())
    expect(titles).toEqual(expect.arrayContaining(['入站观察', '告警与拦截', '设备在线', '最新判定']))
    expect(w.text()).toContain('今日入站观察')
    expect(w.text()).toContain('今日拦截生效')
    // 采集 1/2 在线（夹具一新一旧），执行 1/1。
    expect(w.text()).toMatch(/1\s*\/ 2 在线/)
    expect(w.findAll('[role="tab"]').map((t) => t.text())).toEqual(['15 分钟', '1 小时', '24 小时', '7 天'])
    expect(w.text()).toContain('实时 · 每 3 秒刷新')
    expect(w.text()).toContain('最近 15 分钟 · 每 3 秒一点')
    expect(w.get('select').element.value).toBe('3')
    expect(w.findAll('select option').map((o) => o.text())).toEqual(['1 秒', '3 秒', '5 秒', '10 秒'])
  })

  it('只有 ops.read 的平台管理员只看到设备在线，不请求统计与判定', async () => {
    const { w } = await open(singleRoleUsers.platform_admin)
    expect(requests).not.toContain('GET /api/v2/stats/live')
    expect(requests).not.toContain('GET /api/v2/decisions')
    expect(w.findAll('h2').map((x) => x.text())).toEqual(['设备在线'])
    expect(w.find('[role="tablist"]').exists()).toBe(false)
  })
})

describe('实时态势：缺口与范围', () => {
  const base = { range: '15m', step: 10, from: '2026-10-14T11:59:10.000Z', to: '2026-10-14T12:00:00.000Z', points: 5 }

  it('null 点断开折线，末尾无数据写明传感器未接入与最后一次数据时间', async () => {
    server.use(http.get('/api/v2/stats/live', () => HttpResponse.json({ requestId: 'r', error: null, data: {
      ...base, asOf: '2026-10-14T11:59:38Z', inbound: [3, 4, null, 5, null], alerts: { port_scan: [0, 1, null, 0, null] }, blocked: [0, 0, null, 1, null],
    } })))
    const { w } = await open(singleRoleUsers.security_analyst)
    const inbound = w.findAll('section').find((s) => s.find('h2').exists() && s.get('h2').text() === '入站观察')!
    // 第一段 0—1 成线，第二段只有一个点（下标 3）画成圆点；null 处不补 0。
    expect(inbound.findAll('[data-series-path]')).toHaveLength(1)
    expect(inbound.get('[data-series-path]').attributes('d')!.match(/M/g)).toHaveLength(1)
    expect(inbound.findAll('[data-series-dot]')).toHaveLength(1)
    expect(w.text()).toContain('最近 10 秒无数据：传感器未接入，最后一次数据')
  })

  it('整段都没有数据时只显示传感器未接入', async () => {
    server.use(http.get('/api/v2/stats/live', () => HttpResponse.json({ requestId: 'r', error: null, data: {
      ...base, asOf: null, inbound: [null, null, null, null, null], alerts: {}, blocked: [null, null, null, null, null],
    } })))
    const { w } = await open(singleRoleUsers.security_analyst)
    expect(w.findAll('[data-series-path]')).toHaveLength(0)
    expect(w.text()).toContain('传感器未接入，最后一次数据 无记录')
  })

  it('切换范围立即重读，慢到的旧范围响应被丢弃', async () => {
    let releaseOld!: () => void
    const gate = new Promise<void>((r) => { releaseOld = r })
    server.use(http.get('/api/v2/stats/live', async ({ request }) => {
      const range = new URL(request.url).searchParams.get('range')
      if (range === '15m') await gate
      return HttpResponse.json({ requestId: 'r', error: null, data: { ...base, range, step: range === '1h' ? 60 : 10, asOf: null, inbound: [1, 2, 3, 4, 5] } })
    }))
    const { router, w } = await open(singleRoleUsers.security_analyst)
    await w.findAll('[role="tab"]').find((t) => t.text() === '1 小时')!.trigger('click')
    await settle()
    expect(router.currentRoute.value.query.range).toBe('1h')
    const lastUrl = () => w.text()
    expect(lastUrl()).toContain('最近 1 小时 · 每 1 分钟一点')
    releaseOld()
    await settle()
    expect(w.text()).toContain('最近 1 小时 · 每 1 分钟一点')
  })
})

describe('实时态势：轮询', () => {
  it.each([['1', 900], ['3', 300], ['5', 180], ['10', 90]])('选择 %s 秒后，桶宽、完整点数与轮询频率一致', async (interval, points) => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] })
    const { router, w } = await open(singleRoleUsers.security_analyst)
    await w.get('select').setValue(interval)
    await settle()
    expect(statsQueries.at(-1)?.get('step')).toBe(interval)
    expect(router.currentRoute.value.query.interval).toBe(interval === '3' ? undefined : interval)
    expect(w.text()).toContain(`最近 15 分钟 · 每 ${interval} 秒一点`)
    expect(w.get('figure[aria-label="入站观察"]').findAll('tbody tr')).toHaveLength(points)
    const before = statsCalls()
    vi.advanceTimersByTime(Number(interval) * 1000 - 1)
    await settle()
    expect(statsCalls()).toBe(before)
    vi.advanceTimersByTime(1)
    await settle()
    expect(statsCalls()).toBe(before + 1)
  })

  it('连续改频率清除旧定时器，设备仍每 30 秒读取，卸载后不再请求', async () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval', 'Date'] })
    const { w } = await open(singleRoleUsers.auditor)
    for (const interval of ['10', '1', '5']) { await w.get('select').setValue(interval); await settle() }
    const before = statsCalls()
    const devicesBefore = heartbeatCalls()
    vi.advanceTimersByTime(4999)
    await settle()
    expect(statsCalls()).toBe(before)
    vi.advanceTimersByTime(1)
    await settle()
    expect(statsCalls()).toBe(before + 1)
    expect(heartbeatCalls()).toBe(devicesBefore)
    vi.advanceTimersByTime(25000)
    await settle()
    expect(statsCalls()).toBe(before + 6)
    expect(heartbeatCalls()).toBe(devicesBefore + 1)
    w.unmount()
    wrapper = null
    vi.advanceTimersByTime(30000)
    await settle()
    expect(statsCalls()).toBe(before + 6)
  })

  it('URL 恢复所选频率，长范围保留聚合且刷新间隔仍生效', async () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] })
    const { router, w } = await open(singleRoleUsers.security_analyst, '/console/overview/live?range=1h&interval=1')
    expect(w.get('select').element.value).toBe('1')
    expect(statsQueries.at(-1)?.get('step')).toBe('60')
    expect(w.text()).toContain('最近 1 小时 · 每 1 分钟一点')
    const before = statsCalls()
    vi.advanceTimersByTime(1000)
    await settle()
    expect(statsCalls()).toBe(before + 1)
    await router.push('/console/overview/live?interval=5&keep=yes#chart')
    await settle()
    expect(statsQueries.at(-1)?.get('step')).toBe('5')
    await w.get('select').setValue('10')
    await settle()
    expect(router.currentRoute.value.query).toEqual({ interval: '10', keep: 'yes' })
    expect(router.currentRoute.value.hash).toBe('#chart')
  })

  it.each(['0', '2', 'abc', '1&interval=5'])('非法或重复 interval=%s 回退 3 秒，不请求非法步长', async (value) => {
    const { w } = await open(singleRoleUsers.security_analyst, `/console/overview/live?interval=${value}`)
    expect(w.get('select').element.value).toBe('3')
    expect(statsQueries.at(-1)?.get('step')).toBe('3')
  })

  it('改频率后慢到的旧响应不能覆盖新桶宽', async () => {
    let releaseOld!: () => void
    const gate = new Promise<void>((r) => { releaseOld = r })
    server.use(http.get('/api/v2/stats/live', async ({ request }) => {
      const step = Number(new URL(request.url).searchParams.get('step'))
      if (step === 3) await gate
      return HttpResponse.json({ requestId: 'r', error: null, data: {
        range: '15m', step, from: '2026-10-17T12:00:00Z', to: '2026-10-17T12:00:03Z', points: 3, asOf: null, inbound: [0, 0, 0],
      } })
    }))
    const { w } = await open(singleRoleUsers.security_analyst)
    await w.get('select').setValue('1')
    await settle()
    expect(w.text()).toContain('最近 15 分钟 · 每 1 秒一点')
    releaseOld()
    await settle()
    expect(w.text()).toContain('最近 15 分钟 · 每 1 秒一点')
  })

  it('手动暂停后改范围、外部回填与恢复缺省均保留暂停状态，范围只重读一次', async () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] })
    const { router, w } = await open(singleRoleUsers.security_analyst)
    await w.findAll('button').find((b) => b.text().includes('暂停'))!.trigger('click')
    const first = statsCalls()
    await w.findAll('[role="tab"]').find((t) => t.text() === '1 小时')!.trigger('click')
    await settle()
    expect(statsCalls()).toBe(first + 1)
    await router.push('/console/overview/live?range=24h&interval=1')
    await settle()
    expect(w.text()).toContain('已暂停')
    expect(w.get('select').element.value).toBe('1')
    expect(statsCalls()).toBe(first + 2)
    await router.push('/console/overview/live')
    await settle()
    expect(router.currentRoute.value.query).toEqual({})
    expect(w.get('select').element.value).toBe('3')
    expect(w.findAll('[role="tab"]').find((t) => t.text() === '15 分钟')!.attributes('aria-selected')).toBe('true')
    vi.advanceTimersByTime(10000)
    await settle()
    expect(statsCalls()).toBe(first + 3)
  })

  it('默认每 3 秒刷新；暂停或页面不可见时停止，恢复后立即重读', async () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] })
    const { w } = await open(singleRoleUsers.security_analyst)
    const first = statsCalls()
    vi.advanceTimersByTime(3000)
    await settle()
    expect(statsCalls()).toBe(first + 1)

    await w.findAll('button').find((b) => b.text().includes('暂停'))!.trigger('click')
    vi.advanceTimersByTime(15000)
    await settle()
    expect(statsCalls()).toBe(first + 1)
    expect(w.text()).toContain('已暂停')

    await w.findAll('button').find((b) => b.text().includes('继续'))!.trigger('click')
    await settle()
    expect(statsCalls()).toBe(first + 2)

    Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => 'hidden' })
    document.dispatchEvent(new Event('visibilitychange'))
    vi.advanceTimersByTime(10000)
    await settle()
    expect(statsCalls()).toBe(first + 2)
    expect(w.text()).toContain('页面不可见，已暂停')
    Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => 'visible' })
    document.dispatchEvent(new Event('visibilitychange'))
    await settle()
    expect(statsCalls()).toBe(first + 3)
  })
})

describe('实时态势：最新判定', () => {
  it('点击判定按归并关系进入所属事件', async () => {
    const { router, w } = await open(singleRoleUsers.security_analyst)
    const feed = w.findAll('section').find((x) => x.find('h2').exists() && x.get('h2').text() === '最新判定')!
    const rows = feed.findAll('button')
    expect(rows.length).toBeGreaterThan(0)
    const idx = (await import('@/test/handlers/detect')).detectState.decisions.findIndex((d) => d.id === DEC_1)
    await rows[idx].trigger('click')
    await settle()
    expect(router.currentRoute.value.name).toBe('detect-events-detail')
  })
})
