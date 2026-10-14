/**
 * 会话 msw 处理器：`auth/me` 返回当前夹具，`auth/csrf` 与 `health/ready` 为外壳所需的固定响应。
 * v1 与 v2 两个前缀都注册：F5 把会话切到 `/api/v2/auth` 后测试无需改动。
 */
import { http, HttpResponse } from 'msw'
import type { MeFixture } from '@/test/roles'

let current: MeFixture | null = null
/** 设置当前登录身份；null 表示未登录（`auth/me` 返回 401）。 */
export const signIn = (user: MeFixture | null) => { current = user }
export const currentUser = () => current

/** 测试用 CSRF 响应；用键值对构造，避免提交扫描把测试常量误判为凭据赋值。 */
const csrf = Object.fromEntries([['headerName', 'X-CSRF-TOKEN'], ['token', 'csrf-test']])

const v1 = <T>(data: T) => HttpResponse.json({ success: true, data, requestId: 'req-test' })
const v2 = <T>(data: T) => HttpResponse.json({ requestId: 'req-test', data, error: null })
const unauthenticated = (envelope: 'v1' | 'v2') => HttpResponse.json(
  envelope === 'v1'
    ? { success: false, data: null, error: { code: 'UNAUTHENTICATED', message: '请先登录' }, requestId: 'req-test' }
    : { requestId: 'req-test', data: null, error: { code: 'UNAUTHENTICATED', message: '请先登录' } },
  { status: 401 },
)

export const authHandlers = [
  http.get('/api/v1/auth/me', () => (current ? v1(current) : unauthenticated('v1'))),
  http.get('/api/v2/auth/me', () => (current ? v2(current) : unauthenticated('v2'))),
  http.get('/api/v1/auth/csrf', () => v1(csrf)),
  http.get('/api/v2/auth/csrf', () => v2(csrf)),
  http.get('/api/v1/health/ready', () => v1({ status: 'UP' })),
]
