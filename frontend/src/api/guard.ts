/**
 * host-guard v5（P4）控制面客户端：`/api/v2`。
 *
 * 与 v1 的差异（docs/接口设计.md §1）：
 * - 信封为 `{requestId, data, error}`，**没有 `success` 字段**，成功以 HTTP 状态与 `error == null` 判定；
 * - 写入必须带 `Idempotency-Key`（UUID），并发更新类操作另需 `If-Match: <revision>`；
 * - 列表用游标分页（`cursor` + `limit`，`limit` 1—200），而不是 `page`/`size`；
 * - 错误码稳定且脱敏，展示时统一走 `errText`。
 *
 * 会话与 CSRF 复用 v1 的 `/auth/csrf`：v2 人工路由走同一条浏览器安全链，
 * 因此本模块直接复用 client.ts 的 request 能力，不另建 fetch。
 */
import { ApiError } from './client'

interface GuardEnvelope<T> { requestId?: string; data: T; error: { code: string; message: string } | null }

/** 幂等键必须为 UUID 形态，后端对非 UUID 直接返回 400 INVALID_UUID。 */
export function idempotencyKey(): string {
  return crypto.randomUUID()
}

/**
 * 发送 v2 请求。`base` 固定为 v2；CSRF 与 401 处理沿用 v1 客户端注入的钩子。
 * 由 client.ts 暴露的 requestV2 注入实际 fetch，避免两处各写一遍会话逻辑。
 */
export interface GuardRequest {
  <T>(method: 'GET' | 'POST', path: string, body?: unknown, headers?: Record<string, string>): Promise<T>
}
let send: GuardRequest | null = null

/** 由 client.ts 在模块初始化时注入，保证 v1/v2 共用同一套 CSRF、401 与错误处理。 */
export function useRequest(fn: GuardRequest) {
  send = fn
}

function call<T>(method: 'GET' | 'POST', path: string, body?: unknown, headers?: Record<string, string>): Promise<T> {
  if (!send) throw new ApiError(0, 'CLIENT_NOT_READY', '客户端尚未初始化')
  return send<T>(method, `/api/v2${path}`, body, headers)
}

/**
 * v2 列表结果。`nextCursor` 为 null 表示已到末页；稳定按 `(createdAt,id)` 倒序。
 * 后端只暴露外部 UUID，前端不再自行拼接查询串。
 */
export interface Cursor<T> { items: T[]; nextCursor: string | null }

export interface ListQuery { assetId?: string; cursor?: string; limit?: number }

function query(q: ListQuery = {}): string {
  const p = new URLSearchParams()
  if (q.assetId) p.set('assetId', q.assetId)
  if (q.cursor) p.set('cursor', q.cursor)
  if (q.limit) p.set('limit', String(q.limit))
  const s = p.toString()
  return s ? `?${s}` : ''
}

/**
 * v2 人工控制面。写入方法名对应后端 `{collection}` / `{collection}/{id}/{operation}` 路由；
 * 只有后端 switch 分支里存在的组合才可用，其余会返回 404，不在前端做兜底猜测。
 */
export const guard = {
  /** 列表（游标分页）。 */
  list: <T>(collection: string, q?: ListQuery) => call<Cursor<T>>('GET', `/${collection}${query(q)}`),
  /** 详情。 */
  get: <T>(collection: string, id: string) => call<T>('GET', `/${collection}/${encodeURIComponent(id)}`),
  /** 子资源；`models/{id}/validations` 例外，返回的不是 `{items}`。 */
  child: <T>(collection: string, id: string, name: string) => call<T>('GET', `/${collection}/${encodeURIComponent(id)}/${name}`),
  /** 创建；自动带幂等键，同一次提交的重试不会重复落库。 */
  create: <T>(collection: string, body: unknown, key = idempotencyKey()) =>
    call<T>('POST', `/${collection}`, body, { 'Idempotency-Key': key }),
  /**
   * 状态操作。需要乐观并发的操作传 `revision` 生成 `If-Match`；
   * 同一幂等键配不同 `If-Match` 会被后端视为不同请求，因此键必须随提交生成。
   */
  op: <T>(collection: string, id: string, operation: string, body: unknown = {}, revision?: number | string, key = idempotencyKey()) => {
    const headers: Record<string, string> = { 'Idempotency-Key': key }
    if (revision !== undefined && revision !== null) headers['If-Match'] = String(revision)
    return call<T>('POST', `/${collection}/${encodeURIComponent(id)}/${operation}`, body, headers)
  },
}

/** 解析 v2 信封：成功返回 data，失败抛带 requestId 的 ApiError。供 client.ts 复用。 */
export function unwrap<T>(env: GuardEnvelope<T> | null, status: number, ok: boolean, requestId?: string): T {
  if (!env) throw new ApiError(status, 'HTTP_' + status, '请求失败', requestId)
  if (!ok || env.error) {
    throw new ApiError(status, env.error?.code ?? 'HTTP_' + status, env.error?.message ?? '请求失败', env.requestId ?? requestId)
  }
  return env.data
}

export type { GuardEnvelope }
