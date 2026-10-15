/** v2 会话契约回归：使用真实客户端与 MSW，不把旧 v1 mock 的成功当作切换完成。 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { api, resetCsrf, setUnauthorizedHandler } from './client'
import { changePassword, loadSession, login, logout, session } from './session'
import { server, requests } from '@/test/handlers'
import { authState, fixturePassword, resetAuthState, signIn } from '@/test/handlers/auth'
import { singleRoleUsers } from '@/test/roles'

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }))
afterAll(() => server.close())
afterEach(() => server.resetHandlers())
beforeEach(() => {
  resetAuthState(); resetCsrf(); requests.length = 0
  session.user = null; session.checked = false
  setUnauthorizedHandler(() => undefined)
})
const user = singleRoleUsers.platform_admin

describe('v2 会话', () => {
  it('只从 v2 读取身份；未登录时不触发全局 401 回调', async () => {
    const unauthorized = vi.fn(); setUnauthorizedHandler(unauthorized)
    expect(await loadSession()).toBeNull()
    expect(session.checked).toBe(true)
    signIn(user)
    expect(await loadSession()).toEqual(user)
    expect(unauthorized).not.toHaveBeenCalled()
    expect(requests).toEqual(['GET /api/v2/auth/me', 'GET /api/v2/auth/me'])
  })

  it('登录/退出均发送 v2 幂等请求并在轮换后重取 CSRF', async () => {
    await login(user.username, fixturePassword(user.username))
    expect(session.user).toEqual(user)
    await logout()
    expect(session).toMatchObject({ user: null, checked: true })
    expect(authState.csrfReads).toBe(2)
    expect(authState.writes.map((r) => r.path)).toEqual(['/api/v2/auth/login', '/api/v2/auth/logout'])
    expect(new Set(authState.writes.map((r) => r.key)).size).toBe(2)
    expect(authState.writes.every((r) => /^[\da-f-]{36}$/.test(r.key))).toBe(true)
    expect(requests.some((r) => r.includes('/api/v1/auth/'))).toBe(false)
    expect(await loadSession()).toBeNull()
  })

  it('登录失败清除旧权限，表单保留错误和 request-id，下一次重新取令牌', async () => {
    session.user = user
    const unauthorized = vi.fn(); setUnauthorizedHandler(unauthorized)
    await expect(login(user.username, crypto.randomUUID())).rejects.toMatchObject({ status: 401, code: 'AUTHENTICATION_FAILED', requestId: 'req-auth-error' })
    expect(session.user).toBeNull()
    expect(unauthorized).not.toHaveBeenCalled()
    await login(user.username, fixturePassword(user.username))
    expect(authState.csrfReads).toBe(2)
  })

  it('改密撤销会话，旧口令不能登录，新口令可以；请求内容不留在夹具记录', async () => {
    const previous = fixturePassword(user.username)
    await login(user.username, previous)
    const next = crypto.randomUUID()
    await changePassword(previous, next)
    expect(session.user).toBeNull()
    expect(await loadSession()).toBeNull()
    await expect(login(user.username, previous)).rejects.toMatchObject({ status: 401 })
    await login(user.username, next)
    expect(session.user?.id).toBe(user.id)
    expect(JSON.stringify(authState)).not.toContain(previous)
    expect(JSON.stringify(authState)).not.toContain(next)
  })

  it('改密失败保留当前身份，旧会话可继续使用', async () => {
    await login(user.username, fixturePassword(user.username))
    await expect(changePassword(crypto.randomUUID(), crypto.randomUUID())).rejects.toMatchObject({ status: 401 })
    expect(session.user?.id).toBe(user.id)
    expect((await loadSession())?.id).toBe(user.id)
  })

  it('幂等缓存不能恢复已注销会话；业务 401 仍触发统一处理', async () => {
    const key = crypto.randomUUID()
    const body = { username: user.username, password: fixturePassword(user.username) }
    await api.post('/api/v2/auth/login', body, { 'Idempotency-Key': key })
    await logout()
    await expect(api.post('/api/v2/auth/login', body, { 'Idempotency-Key': key })).rejects.toMatchObject({ status: 401 })
    const unauthorized = vi.fn(); setUnauthorizedHandler(unauthorized)
    await expect(api.get('/api/v2/users')).rejects.toMatchObject({ status: 401 })
    expect(unauthorized).toHaveBeenCalledOnce()
  })
})
