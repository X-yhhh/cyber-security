/**
 * 后端 API 客户端。
 *
 * 契约（docs/接口设计.md）：所有响应为 { success, data, error, requestId }；
 * 浏览器会话走 HttpOnly Cookie，写请求须带 CSRF 头（从 /auth/csrf 获取）。
 * 失败统一抛出 ApiError，携带稳定错误码与 requestId，页面只展示脱敏消息。
 */

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string, public requestId?: string) {
    super(message)
  }
}

interface Envelope<T> { success: boolean; data: T; error?: { code: string; message: string }; requestId?: string }

let csrf: { headerName: string; token: string } | null = null
/** 会话失效（401）时的回调，由会话模块注册以跳转登录页。 */
let onUnauthorized: (() => void) | null = null
export const setUnauthorizedHandler = (fn: () => void) => { onUnauthorized = fn }

async function ensureCsrf() {
  if (!csrf) csrf = await request<{ headerName: string; token: string }>('GET', '/auth/csrf')
  return csrf
}
/** 登录/注销会轮换会话与 CSRF 令牌，调用后必须重新获取。 */
export const resetCsrf = () => { csrf = null }

async function request<T>(method: string, path: string, body?: unknown, headers: Record<string, string> = {}): Promise<T> {
  const h: Record<string, string> = { Accept: 'application/json', ...headers }
  if (method !== 'GET') {
    const c = await ensureCsrf()
    h[c.headerName] = c.token
  }
  if (body !== undefined) h['Content-Type'] = 'application/json'
  let res: Response
  try {
    res = await fetch(`/api/v1${path}`, { method, headers: h, credentials: 'same-origin', body: body === undefined ? undefined : JSON.stringify(body) })
  } catch {
    throw new ApiError(0, 'NETWORK_UNAVAILABLE', '无法连接后端服务')
  }
  let env: Envelope<T> | null = null
  try { env = await res.json() } catch { /* 非 JSON 响应按失败处理 */ }
  if (!res.ok || !env?.success) {
    if (res.status === 403 && method !== 'GET') csrf = null
    const err = new ApiError(res.status, env?.error?.code ?? 'HTTP_' + res.status, env?.error?.message ?? '请求失败', env?.requestId)
    if (res.status === 401 && !path.startsWith('/auth/')) onUnauthorized?.()
    throw err
  }
  return env.data
}

export const api = {
  get: <T>(path: string) => request<T>('GET', path),
  post: <T>(path: string, body?: unknown, headers?: Record<string, string>) => request<T>('POST', path, body ?? {}, headers),
  put: <T>(path: string, body?: unknown) => request<T>('PUT', path, body ?? {}),
}

export interface Page<T> { totalElements: number; page: number; size: number; items: T[] }
