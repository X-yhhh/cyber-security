/** F2 轮询生命周期与竞态：通过真实 API 客户端和 MSW 测试，不挂载业务页面。 */
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { defineComponent } from 'vue'
import { http, HttpResponse } from 'msw'
import { session } from '@/api/session'
import { server, requests } from '@/test/handlers'
import { signIn } from '@/test/handlers/auth'
import { resetTodoState } from '@/test/handlers/todos'
import { singleRoleUsers, type MeFixture } from '@/test/roles'
import { TODO_POLL_MS, useTodos } from './todos'

let wrapper: VueWrapper | null = null
let state!: ReturnType<typeof useTodos>
let visibility: ReturnType<typeof vi.spyOn>
const calls = (path: string) => requests.filter((r) => r === `GET /api/v2/${path}`).length
const todosCalls = () => calls('todos')
const summaryCalls = () => calls('summary')
const Host = defineComponent({ setup() { state = useTodos(); return () => null } })

async function settle() {
  for (let i = 0; i < 6; i++) { await flushPromises(); await new Promise((r) => setTimeout(r, 0)) }
}
async function open(user: MeFixture | null = singleRoleUsers.security_reviewer) {
  signIn(user)
  session.user = user ? { ...user, permissions: [...user.permissions] } : null
  wrapper = mount(Host)
  await settle()
}
function setVisibility(value: 'visible' | 'hidden') {
  visibility.mockReturnValue(value)
  document.dispatchEvent(new Event('visibilitychange'))
}
const ok = (data: unknown) => HttpResponse.json({ requestId: 'req-poll', data, error: null })
const failed = (id: string) => HttpResponse.json({ requestId: id, data: null, error: { code: 'INTERNAL_ERROR', message: '读取失败' } }, { status: 500 })
function deferred() {
  let resolve!: () => void
  const promise = new Promise<void>((r) => { resolve = r })
  return { promise, resolve }
}

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }))
afterAll(() => server.close())
beforeEach(() => {
  vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] })
  visibility = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible')
  requests.length = 0
  resetTodoState()
})
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
  session.user = null
  signIn(null)
  server.resetHandlers()
  vi.useRealTimers()
  vi.restoreAllMocks()
})

describe('待办轮询', () => {
  it('挂载立即读取 todos 和 summary，每 30 秒刷新一次', async () => {
    await open()
    expect([todosCalls(), summaryCalls()]).toEqual([1, 1])
    expect(state.loading.value).toBe(false)
    expect(state.todos.value!.groups[0].kind).toBe('approve')
    vi.advanceTimersByTime(TODO_POLL_MS - 1)
    await settle()
    expect(todosCalls()).toBe(1)
    vi.advanceTimersByTime(1)
    await settle()
    expect([todosCalls(), summaryCalls()]).toEqual([2, 2])
    expect(requests).toEqual(expect.arrayContaining(['GET /api/v2/todos', 'GET /api/v2/summary']))
    expect(requests.every((r) => r.startsWith('GET /api/v2/'))).toBe(true)
  })

  it('隐藏时暂停（包括手动刷新），重新可见立即重读并重新计时', async () => {
    await open()
    setVisibility('hidden')
    vi.advanceTimersByTime(90_000)
    await state.refresh()
    await settle()
    expect([todosCalls(), summaryCalls()]).toEqual([1, 1])
    setVisibility('visible')
    await settle()
    expect([todosCalls(), summaryCalls()]).toEqual([2, 2])
    setVisibility('visible')
    await settle()
    expect([todosCalls(), summaryCalls()]).toEqual([2, 2])
    vi.advanceTimersByTime(TODO_POLL_MS)
    await settle()
    expect([todosCalls(), summaryCalls()]).toEqual([3, 3])
  })

  it('初始隐藏或未登录时不发请求、不启动定时器', async () => {
    visibility.mockReturnValue('hidden')
    await open()
    expect(requests).toEqual([])
    setVisibility('visible')
    await settle()
    expect(todosCalls()).toBe(1)
    wrapper!.unmount()
    wrapper = null
    requests.length = 0
    await open(null)
    vi.advanceTimersByTime(TODO_POLL_MS)
    await settle()
    expect(requests).toEqual([])
    expect(state.loading.value).toBe(false)
  })

  it('慢请求期间定时器不叠加，手动刷新复用同一 Promise', async () => {
    const gate = deferred()
    server.use(http.get('/api/v2/todos', async () => { await gate.promise; return ok({ groups: [], truncated: false }) }))
    await open()
    expect(state.loading.value).toBe(true)
    const first = state.refresh()
    expect(state.refresh()).toBe(first)
    vi.advanceTimersByTime(TODO_POLL_MS * 3)
    await settle()
    expect([todosCalls(), summaryCalls()]).toEqual([1, 1])
    gate.resolve()
    await first
    expect(state.loading.value).toBe(false)
    vi.advanceTimersByTime(TODO_POLL_MS)
    await settle()
    expect([todosCalls(), summaryCalls()]).toEqual([2, 2])
  })

  it('隐藏后恢复的请求优先，旧可见周期的迟到响应不覆盖新结果', async () => {
    const gate = deferred()
    let count = 0
    server.use(http.get('/api/v2/todos', async () => {
      const old = ++count === 1
      if (old) await gate.promise
      return ok({ groups: [{ kind: 'approve', count: old ? 99 : 2, items: [] }], truncated: false })
    }))
    await open()
    setVisibility('hidden')
    setVisibility('visible')
    await settle()
    expect(state.todos.value!.groups[0].count).toBe(2)
    gate.resolve()
    await settle()
    expect(state.todos.value!.groups[0].count).toBe(2)
    expect(state.loading.value).toBe(false)
  })

  it('卸载移除定时器和可见性监听，迟到响应和 refresh 不再回写或请求', async () => {
    const gate = deferred()
    server.use(http.get('/api/v2/todos', async () => { await gate.promise; return ok({ groups: [], truncated: false }) }))
    const remove = vi.spyOn(document, 'removeEventListener')
    await open()
    const count = requests.length
    wrapper!.unmount()
    wrapper = null
    expect(remove).toHaveBeenCalledWith('visibilitychange', expect.any(Function))
    expect(vi.getTimerCount()).toBe(0)
    gate.resolve()
    await settle()
    expect(state.todos.value).toBeNull()
    await state.refresh()
    setVisibility('visible')
    vi.advanceTimersByTime(90_000)
    await settle()
    expect(requests).toHaveLength(count)
  })
})

describe('待办状态与失败', () => {
  it('summary 缺省字段保持缺省，显式 0 保留，待办全量 count 不用 items.length 覆盖', async () => {
    server.use(
      http.get('/api/v2/summary', () => ok({ pendingApprovals: { actions: 0 } })),
      http.get('/api/v2/todos', () => ok({ groups: [{ kind: 'approve', count: 103, items: [] }], truncated: true })),
    )
    await open()
    expect(state.summary.value).toEqual({ pendingApprovals: { actions: 0 } })
    expect(state.summary.value).not.toHaveProperty('ops')
    expect(state.todos.value).toEqual({ groups: [{ kind: 'approve', count: 103, items: [] }], truncated: true })
  })

  it('summary 失败保留待办结果，分别暴露含 request-id 的错误', async () => {
    server.use(http.get('/api/v2/summary', () => failed('req-summary-failed')))
    await open()
    expect(state.todos.value!.groups.length).toBeGreaterThan(0)
    expect(state.summary.value).toBeNull()
    expect(state.error.value).toBe('')
    expect(state.summaryError.value).toBe('读取失败（request-id req-summary-failed）')
    expect(state.loading.value).toBe(false)
  })

  it('刷新失败清除旧待办，重试后清除错误并重新读取', async () => {
    await open()
    server.use(http.get('/api/v2/todos', () => failed('req-todos-failed')))
    vi.advanceTimersByTime(TODO_POLL_MS)
    await settle()
    expect(state.todos.value).toBeNull()
    expect(state.error.value).toBe('读取失败（request-id req-todos-failed）')
    expect(state.summary.value).not.toBeNull()
    server.resetHandlers()
    await state.refresh()
    expect(state.error.value).toBe('')
    expect(state.todos.value).not.toBeNull()
  })

  it('退出登录立即清空并停轮询，旧身份的迟到响应不得回填', async () => {
    const gate = deferred()
    server.use(http.get('/api/v2/todos', async () => { await gate.promise; return ok({ groups: [], truncated: false }) }))
    await open()
    expect(state.summary.value).not.toBeNull()
    session.user = null
    signIn(null)
    expect(state.summary.value).toBeNull()
    expect(state.todos.value).toBeNull()
    const count = requests.length
    gate.resolve()
    await settle()
    vi.advanceTimersByTime(90_000)
    await settle()
    expect(state.todos.value).toBeNull()
    expect(requests).toHaveLength(count)
  })

  it('同实例切换身份重新读取，不复用其他角色计数', async () => {
    await open()
    expect(state.todos.value!.groups[0].kind).toBe('approve')
    signIn(singleRoleUsers.security_analyst)
    session.user = { ...singleRoleUsers.security_analyst }
    expect(state.todos.value).toBeNull()
    expect(state.summary.value).toBeNull()
    await settle()
    expect(state.todos.value!.groups.map((g) => g.kind)).toEqual(['triage'])
    expect(state.summary.value).toEqual({ openEvents: 7 })
  })

  it('切换身份后旧请求迟到，不能覆盖新身份的数据和加载状态', async () => {
    const gate = deferred()
    let count = 0
    server.use(http.get('/api/v2/todos', async () => {
      const old = ++count === 1
      if (old) await gate.promise
      return ok({ groups: [{ kind: old ? 'approve' : 'triage', count: old ? 99 : 1, items: [] }], truncated: false })
    }))
    await open()
    signIn(singleRoleUsers.security_analyst)
    session.user = { ...singleRoleUsers.security_analyst }
    await settle()
    expect(state.todos.value!.groups[0]).toMatchObject({ kind: 'triage', count: 1 })
    gate.resolve()
    await settle()
    expect(state.todos.value!.groups[0]).toMatchObject({ kind: 'triage', count: 1 })
    expect(state.loading.value).toBe(false)
  })

  it('原身份的权限变化也清空重读，缺省字段不沿用上次权限', async () => {
    await open()
    signIn({ ...singleRoleUsers.security_reviewer, permissions: [] })
    session.user!.permissions = []
    expect(state.todos.value).toBeNull()
    expect(state.summary.value).toBeNull()
    await settle()
    expect(state.todos.value).toEqual({ groups: [], truncated: false })
    expect(state.summary.value).toEqual({})
  })
})
