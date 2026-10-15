/**
 * v2 浏览器会话夹具：覆盖登录、退出、改密与旧会话失效。凭据仅临时生成于测试内存；
 * 不记录请求体，不让幂等重放恢复已注销会话；不模拟真实 Cookie/BCrypt/数据库事务。
 */
import { http, HttpResponse } from 'msw'
import { singleRoleUsers, type MeFixture } from '@/test/roles'

let current: MeFixture | null = null
export const signIn = (user: MeFixture | null) => { current = user }
export const currentUser = () => current
const credentials = new Map<string, { value: string; user: MeFixture }>()
const loginKeys = new Set<string>()
export const authState = { csrfReads: 0, writes: [] as { path: string; key: string }[] }
/** 测试取临时凭据，不把真实凭据或固定口令写进源码、快照与输出。 */
export const fixturePassword = (username: string) => credentials.get(username)!.value
export function resetAuthState() {
  current = null; credentials.clear(); loginKeys.clear(); authState.csrfReads = 0; authState.writes.length = 0
  for (const user of Object.values(singleRoleUsers)) credentials.set(user.username, { value: crypto.randomUUID(), user })
}
resetAuthState()

const csrf = Object.fromEntries([['headerName', 'X-CSRF-TOKEN'], ['parameterName', '_csrf'], ['token', 'csrf-test']])
const v2 = <T>(data: T) => HttpResponse.json({ requestId: 'req-auth', data, error: null })
const fail = (status: number, code: string) => HttpResponse.json({ requestId: 'req-auth-error', data: null, error: { code, message: status === 401 ? '登录失败或会话已失效' : '请求校验失败' } }, { status })
function writeHeaders(request: Request) {
  const key = request.headers.get('Idempotency-Key') ?? ''
  if (!/^[\da-f]{8}-[\da-f]{4}-[\da-f]{4}-[\da-f]{4}-[\da-f]{12}$/i.test(key)) return { error: fail(400, 'INVALID_UUID') }
  if (request.headers.get(csrf.headerName) !== csrf.token) return { error: fail(403, 'CSRF_INVALID') }
  authState.writes.push({ path: new URL(request.url).pathname, key })
  return { key }
}

export const authHandlers = [
  http.get('/api/v2/auth/me', () => current ? v2(current) : fail(401, 'UNAUTHENTICATED')),
  http.get('/api/v2/auth/csrf', () => { authState.csrfReads++; return v2(csrf) }),
  http.post('/api/v2/auth/login', async ({ request }) => {
    const headers = writeHeaders(request); if (headers.error) return headers.error
    const b = await request.json() as Record<string, string>
    const entry = credentials.get(b.username)
    if (!entry || entry.value !== b.password || (loginKeys.has(headers.key!) && current?.id !== entry.user.id)) return fail(401, 'AUTHENTICATION_FAILED')
    loginKeys.add(headers.key!); current = entry.user; return v2(current)
  }),
  http.post('/api/v2/auth/logout', ({ request }) => {
    const headers = writeHeaders(request); if (headers.error) return headers.error
    if (!current) return fail(401, 'UNAUTHENTICATED')
    current = null; return v2({ status: 'logged_out' })
  }),
  http.post('/api/v2/auth/password', async ({ request }) => {
    const headers = writeHeaders(request); if (headers.error) return headers.error
    if (!current) return fail(401, 'UNAUTHENTICATED')
    const b = await request.json() as Record<string, string>
    const entry = credentials.get(current.username)
    if (!entry || entry.value !== b.currentPassword) return fail(401, 'AUTHENTICATION_FAILED')
    if (!b.newPassword || b.newPassword.length < 12 || b.newPassword.length > 128 || new TextEncoder().encode(b.newPassword).length > 72) return fail(400, 'INVALID_REQUEST')
    entry.value = b.newPassword; current = null; return v2({ status: 'password_changed' })
  }),
  // 旧健康探针到 C1 再删除；认证处理器只注册 v2，回归时意外调用 v1 会直接报未处理请求。
  http.get('/api/v1/health/ready', () => HttpResponse.json({ success: true, data: { status: 'UP' }, requestId: 'req-test' })),
]
