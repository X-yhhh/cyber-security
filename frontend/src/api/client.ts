/**
 * 后端 API 客户端。
 *
 * 契约（docs/接口设计.md）：v1 响应为 `{ success, data, error, requestId }`；
 * v2（host-guard v5，P4）为 `{ requestId, data, error }`，**没有 success 字段**，
 * 成功以 HTTP 状态与 `error == null` 判定。两者共用同一套会话、CSRF 与 401 处理。
 *
 * 浏览器会话走 HttpOnly Cookie，写请求须带 CSRF 头（从 /auth/csrf 获取）。
 * 失败统一抛出 ApiError，携带稳定错误码与 requestId，页面只展示脱敏消息。
 */

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string, public requestId?: string) {
    super(message)
  }
}

interface V1Envelope<T> { success: boolean; data: T; error?: { code: string; message: string }; requestId?: string }
interface V2Envelope<T> { requestId?: string; data: T; error: { code: string; message: string } | null }

let csrf: { headerName: string; token: string } | null = null
/** 会话失效（401）时的回调，由会话模块注册以跳转登录页。 */
let onUnauthorized: (() => void) | null = null
export const setUnauthorizedHandler = (fn: () => void) => { onUnauthorized = fn }

async function ensureCsrf() {
  if (!csrf) csrf = await request<{ headerName: string; token: string }>('GET', '/api/v1/auth/csrf')
  return csrf
}
/** 登录/注销会轮换会话与 CSRF 令牌，调用后必须重新获取。 */
export const resetCsrf = () => { csrf = null }

/** 路径以 /api 开头时视为已含版本前缀，否则补 v1，保持既有调用点不变。 */
const url = (path: string) => (path.startsWith('/api/') ? path : `/api/v1${path}`)

async function raw(method: string, path: string, body?: unknown, headers: Record<string, string> = {}) {
  const h: Record<string, string> = { Accept: 'application/json', ...headers }
  if (method !== 'GET') {
    const c = await ensureCsrf()
    h[c.headerName] = c.token
  }
  if (body !== undefined) h['Content-Type'] = 'application/json'
  let res: Response
  try {
    res = await fetch(url(path), { method, headers: h, credentials: 'same-origin', body: body === undefined ? undefined : JSON.stringify(body) })
  } catch {
    throw new ApiError(0, 'NETWORK_UNAVAILABLE', '无法连接后端服务')
  }
  let env: V1Envelope<unknown> | V2Envelope<unknown> | null = null
  try { env = await res.json() } catch { /* 非 JSON 响应按失败处理 */ }
  if (!res.ok || !env || ('error' in env && env.error)) {
    if (res.status === 403 && method !== 'GET') csrf = null
    const error = env && 'error' in env ? env.error : undefined
    const err = new ApiError(res.status, error?.code ?? 'HTTP_' + res.status, error?.message ?? '请求失败', env?.requestId)
    if (res.status === 401 && !path.startsWith('/auth/')) onUnauthorized?.()
    throw err
  }
  return { data: (env as V1Envelope<unknown>).data, requestId: env.requestId }
}

async function request<T>(method: string, path: string, body?: unknown, headers: Record<string, string> = {}): Promise<T> {
  return (await raw(method, path, body, headers)).data as T
}

export const api = {
  get: <T>(path: string) => request<T>('GET', path),
  post: <T>(path: string, body?: unknown, headers?: Record<string, string>) => request<T>('POST', path, body ?? {}, headers),
  put: <T>(path: string, body?: unknown) => request<T>('PUT', path, body ?? {}),
}

export interface Page<T> { totalElements: number; page: number; size: number; items: T[] }

/* ------------------------------------------------------------------ *
 * host-guard v5 控制面（/api/v2，P4）
 *
 * 与 v1 的差异：信封无 success 字段；写入必带 Idempotency-Key（UUID 形态）；
 * 并发更新类操作带 If-Match: <revision>；列表用游标分页而非 page/size。
 * 只封装后端 switch 中真实存在的组合，不在前端做兜底猜测。
 * ------------------------------------------------------------------ */

/** 幂等键必须为 UUID 形态，后端对非 UUID 返回 400 INVALID_UUID。 */
export const idempotencyKey = (): string => crypto.randomUUID()

/** v2 列表结果：items 为当前页，nextCursor 为 null 表示已到末页。 */
export interface Cursor<T> { items: T[]; nextCursor: string | null }

export interface CursorQuery { assetId?: string; status?: string; cursor?: string; limit?: number }

function cursorQuery(q: CursorQuery = {}) {
  const p = new URLSearchParams()
  if (q.assetId) p.set('assetId', q.assetId)
  if (q.status) p.set('status', q.status)
  if (q.cursor) p.set('cursor', q.cursor)
  p.set('limit', String(q.limit ?? 50))
  return `?${p}`
}

export const guard = {
  /** 列表（游标分页，limit 1—200，后端默认 50）。 */
  list: <T>(collection: string, q?: CursorQuery) => request<Cursor<T>>('GET', `/api/v2/${collection}${cursorQuery(q)}`),
  /** 详情；跨范围对象返回 404，不泄露存在性。 */
  get: <T>(collection: string, id: string) => request<T>('GET', `/api/v2/${collection}/${encodeURIComponent(id)}`),
  /** 子资源；`models/{id}/validations` 返回校验报告本体而不是 `{items}`。 */
  child: <T>(collection: string, id: string, name: string) => request<T>('GET', `/api/v2/${collection}/${encodeURIComponent(id)}/${name}`),
  /**
   * 只读查询的原样路径与参数（lab 会话事件的 `after`、B5 查询的筛选与游标等）。
   * 空值参数不发送：后端对空白参数返回 INVALID_QUERY，未知参数同样拒绝，前端不做兜底。
   */
  read: <T>(path: string, params: Record<string, string | number | null | undefined> = {}) => {
    const p = new URLSearchParams()
    for (const [k, v] of Object.entries(params)) if (v !== null && v !== undefined && v !== '') p.set(k, String(v))
    const s = p.toString()
    return request<T>('GET', `/api/v2/${path}${s ? `?${s}` : ''}`)
  },
  /** 创建；自动带幂等键，同一次提交的重试不会重复落库。 */
  create: <T>(collection: string, body: unknown, key = idempotencyKey()) =>
    request<T>('POST', `/api/v2/${collection}`, body, { 'Idempotency-Key': key }),
  /**
   * 状态操作。需要乐观并发的操作传 revision 生成 If-Match；
   * 同一幂等键配不同 If-Match 会被后端视为不同请求，因此键必须随提交生成。
   */
  op: <T>(collection: string, id: string, operation: string, body: unknown = {}, revision?: number | string, key = idempotencyKey()) => {
    const headers: Record<string, string> = { 'Idempotency-Key': key }
    if (revision !== undefined && revision !== null) headers['If-Match'] = String(revision)
    return request<T>('POST', `/api/v2/${collection}/${encodeURIComponent(id)}/${operation}`, body, headers)
  },
  /** PUT 子资源（如 PUT /events/{id}/assignee），自动带 Idempotency-Key 与 If-Match。 */
  put: <T>(collection: string, id: string, operation: string, body: unknown = {}, revision?: number | string, key = idempotencyKey()) => {
    const headers: Record<string, string> = { 'Idempotency-Key': key }
    if (revision !== undefined && revision !== null) headers['If-Match'] = String(revision)
    return request<T>('PUT', `/api/v2/${collection}/${encodeURIComponent(id)}/${operation}`, body, headers)
  },
  /** 资料编辑只更新可变字段；必须用读取到的 revision，冲突后由页面重新读取。 */
  patch: <T>(collection: string, id: string, body: unknown, revision: number | string, key = idempotencyKey()) =>
    request<T>('PATCH', `/api/v2/${collection}/${encodeURIComponent(id)}`, body, { 'Idempotency-Key': key, 'If-Match': String(revision) }),
  /** 删除草稿沿用幂等与并发契约；不附带 JSON 请求体，引用与归属仍由服务端校验。 */
  remove: <T>(collection: string, id: string, revision: number | string, key = idempotencyKey()) =>
    request<T>('DELETE', `/api/v2/${collection}/${encodeURIComponent(id)}`, undefined, { 'Idempotency-Key': key, 'If-Match': String(revision) }),
}
