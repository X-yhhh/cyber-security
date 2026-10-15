/**
 * F5 合成 IAM 状态：用于接口调用、失败边界与后续页面测试，不能替代后端事务/授权验收。
 * 不保存口令、请求体或真实身份；写记录只含方法、路径、幂等键与修订。
 */
import { http } from 'msw'
import type { IamUser, RoleBinding } from '@/api/v2/iam'
import { permissionConflicts, roleLimitReached, bindingWarnings, permissionGroups, roleNames, type IamRole } from '@/api/v2/roles'
import { singleRoleUsers, rolePermissions, humanRoles } from '@/test/roles'
import { currentUser } from './auth'
import { fixtureCan, fixtureDenied, fixtureFail, fixtureNotFound, fixtureOk, fixtureUnauthenticated } from './access'
import { ASSET_1, ASSET_2 } from './detect'

export const IAM_USER = 201
export const IAM_UNUSED_USER = 202
export const IAM_REFERENCED_USER = 203
const createdAt = '2026-10-15T03:00:00Z'
interface UserRow { user: IamUser; bindings: RoleBinding[]; referenced: boolean; createdAt: string }
export interface IamWrite { method: string; path: string; key: string; ifMatch: string | null }
function initialState() {
  const admin = singleRoleUsers.platform_admin
  const user = (id: number, username: string): IamUser => ({ id, username, displayName: username, status: 'active', revision: 1 })
  return {
    roles: humanRoles.map((roleKey): IamRole => ({ roleKey, name: roleNames[roleKey], description: `${roleNames[roleKey]}职责`, status: 'active', builtin: true, revision: 1, permissions: [...rolePermissions[roleKey]] })),
    users: [
      { user: user(admin.id, admin.username), bindings: [...admin.bindings], referenced: true, createdAt },
      { user: user(IAM_USER, 'demo-target'), bindings: [{ id: 2100, roleKey: 'security_analyst', scopeType: 'global' as const, scopeId: '*' }], referenced: false, createdAt },
      { user: user(IAM_UNUSED_USER, 'demo-unused'), bindings: [], referenced: false, createdAt },
      { user: user(IAM_REFERENCED_USER, 'demo-used'), bindings: [], referenced: true, createdAt },
    ] as UserRow[],
    writes: [] as IamWrite[],
    nextUser: 300, nextBinding: 3000,
    audit: [
      { id: 'ab000000-0000-4000-8000-000000000001', occurredAt: createdAt, actorType: 'human', action: 'iam.user.create', resourceType: 'user', resourceId: 'ab000000-0000-4000-8000-000000000002', requestId: 'req-fixture-create', outcome: 'success' },
      { id: 'ab000000-0000-4000-8000-000000000003', occurredAt: createdAt, actorType: 'human', action: 'asset.update', resourceType: 'asset', resourceId: ASSET_1, requestId: 'req-fixture-asset', outcome: 'success' },
      { id: 'ab000000-0000-4000-8000-000000000004', occurredAt: createdAt, actorType: 'system', action: 'legacy.unscoped', resourceType: 'system', resourceId: null, requestId: null, outcome: 'success' },
    ],
    // 范围关联仅用于夹具过滤，不进入审计响应的白名单字段。
    auditScopes: {
      'ab000000-0000-4000-8000-000000000001': [{ scopeType: 'global', scopeId: '*' }],
      'ab000000-0000-4000-8000-000000000003': [{ scopeType: 'asset', scopeId: '1' }],
    } as Record<string, { scopeType: 'global' | 'asset'; scopeId: string }[]>,
  }
}
export let iamState = initialState()
// 测试期仅保留内存指纹；绝不把请求体或口令写进可展示的 writes 状态。
const replays = new Map<string, { fingerprint: string; result: unknown; status: number }>()
export function resetIamState() { iamState = initialState(); replays.clear() }
const fail = (status: number, code: string) => fixtureFail(status, code, '操作未完成')
function access(single = false, roles = false) {
  const user = currentUser()
  if (!user) return fixtureUnauthenticated()
  if (roles) return fixtureCan(user, 'iam.manage', null) || fixtureCan(user, 'audit.read', null) ? null : fixtureDenied()
  return fixtureCan(user, 'iam.manage', null) ? null : single && user.permissions.includes('iam.manage') ? fixtureNotFound() : fixtureDenied()
}
function parameters(request: Request, allowed: string[]) {
  const q = new URL(request.url).searchParams
  if ([...q.keys()].some((k) => !allowed.includes(k) || q.getAll(k).length !== 1 || !q.get(k))) return null
  return q
}
function page<T>(request: Request, rows: T[], q: URLSearchParams) {
  const limit = Number(q.get('limit') ?? 50)
  if (!Number.isInteger(limit) || limit < 1 || limit > 200) return fail(400, 'INVALID_PAGE_SIZE')
  const binding = JSON.stringify([currentUser()!.id, new URL(request.url).pathname, [...q.entries()].filter(([k]) => k !== 'cursor').sort()])
  let offset = 0
  if (q.has('cursor')) {
    try {
      const cursor = JSON.parse(atob(q.get('cursor')!))
      if (cursor.binding !== binding || !Number.isInteger(cursor.offset) || cursor.offset < 0) throw new Error('cursor')
      offset = cursor.offset
    } catch { return fail(400, 'INVALID_CURSOR') }
  }
  return fixtureOk({ items: rows.slice(offset, offset + limit), nextCursor: offset + limit < rows.length ? btoa(JSON.stringify({ binding, offset: offset + limit })) : null })
}
function revision(request: Request, row: { revision: number }) { return request.headers.get('If-Match') === String(row.revision) ? null : fail(409, 'REVISION_CONFLICT') }
function mutableUser(id: number) {
  if (id === currentUser()!.id) return { error: fail(403, 'SELF_ADMINISTRATION_FORBIDDEN') }
  const row = iamState.users.find((r) => r.user.id === id)
  return row ? { row } : { error: fixtureNotFound() }
}
function mutableRole(key: string) {
  const row = iamState.roles.find((r) => r.roleKey === key)
  return !row ? { error: fixtureNotFound() } : row.builtin ? { error: fail(403, 'BUILTIN_ROLE_READONLY') } : { row }
}
/** 不自动重试写入；同一键/修订重放一次，换内容或修订时明确 409。 */
async function write(request: Request, status: number, run: (body: Record<string, unknown>) => { data?: unknown; error?: Response }) {
  const denied = access(true)
  if (denied) return denied
  const key = request.headers.get('Idempotency-Key') ?? ''
  if (!/^[\da-f]{8}-[\da-f]{4}-[\da-f]{4}-[\da-f]{4}-[\da-f]{12}$/i.test(key)) return fail(400, 'INVALID_UUID')
  if (!request.headers.has('X-CSRF-TOKEN')) return fail(403, 'CSRF_INVALID')
  const body = request.method === 'DELETE' ? {} : await request.json() as Record<string, unknown>
  const path = new URL(request.url).pathname
  const ifMatch = request.headers.get('If-Match')
  const replayKey = `${currentUser()!.id}:${request.method}:${path}:${key}`
  // 这里只是测试期指纹，含秘密请求不缓存，模拟只校验协议头而不持久化口令。
  const secret = 'password' in body || 'newPassword' in body
  const fingerprint = secret ? '' : JSON.stringify([body, ifMatch])
  const replay = replays.get(replayKey)
  if (replay) return replay.fingerprint === fingerprint ? fixtureOk(replay.result, replay.status) : fail(409, 'IDEMPOTENCY_CONFLICT')
  const result = run(body)
  if (result.error) return result.error
  iamState.writes.push({ method: request.method, path, key, ifMatch })
  if (!secret) replays.set(replayKey, { fingerprint, result: structuredClone(result.data), status })
  return fixtureOk(result.data, status)
}
const roleBodyConflict = (body: Record<string, unknown>) => !Array.isArray(body.permissions) || body.permissions.some((p) => !permissionGroups.some((g) => g.permissions.some((key) => key === p)))
  ? fail(400, 'INVALID_REQUEST') : permissionConflicts(body.permissions as string[]).length ? fail(422, 'PERMISSION_CONFLICT') : null

/** 编辑权限和重新启用都要检查现有成员；停用角色按拟启用的权限参与校验。 */
function memberConflict(proposed: IamRole) {
  const catalogue = iamState.roles.map((r) => r.roleKey === proposed.roleKey ? { ...proposed, status: 'active' as const } : r)
  return iamState.users.some((u) => u.bindings.some((b) => b.roleKey === proposed.roleKey) && bindingWarnings(u.bindings, proposed.roleKey, catalogue).length > 0)
}

export const iamHandlers = [
  http.get('/api/v2/users', ({ request }) => {
    const denied = access(); if (denied) return denied
    const q = parameters(request, ['q', 'status', 'from', 'until', 'sort', 'limit', 'cursor']); if (!q) return fail(400, 'INVALID_QUERY')
    const rows = iamState.users.filter((r) => (!q.has('q') || [r.user.username, r.user.displayName].some((s) => s.toLowerCase().startsWith(q.get('q')!.toLowerCase()))) && (!q.has('status') || r.user.status === q.get('status')) && (!q.has('from') || r.createdAt >= q.get('from')!) && (!q.has('until') || r.createdAt < q.get('until')!)).sort((a, b) => b.user.id - a.user.id)
    return page(request, rows.map((r) => r.user), q)
  }),
  http.get('/api/v2/users/:id', ({ params }) => {
    const denied = access(true); if (denied) return denied
    const row = iamState.users.find((r) => r.user.id === Number(params.id)); return row ? fixtureOk(row.user) : fixtureNotFound()
  }),
  http.get('/api/v2/users/:id/role-bindings', ({ params }) => {
    const denied = access(true); if (denied) return denied
    const row = iamState.users.find((r) => r.user.id === Number(params.id)); return row ? fixtureOk(row.bindings) : fixtureNotFound()
  }),
  http.post('/api/v2/users', ({ request }) => write(request, 201, (b) => {
    if (typeof b.password !== 'string' || b.password.length < 12 || new TextEncoder().encode(b.password).length > 72 || b.password.length > 128) return { error: fail(400, 'INVALID_REQUEST') }
    if (iamState.users.some((r) => r.user.username === b.username)) return { error: fail(409, 'CONFLICT') }
    const user: IamUser = { id: iamState.nextUser++, username: String(b.username), displayName: String(b.displayName), status: 'active', revision: 1 }
    iamState.users.push({ user, bindings: [], referenced: true, createdAt }); return { data: user }
  })),
  http.patch('/api/v2/users/:id', ({ request, params }) => write(request, 200, (b) => {
    const target = mutableUser(Number(params.id)); if (target.error) return target
    const error = revision(request, target.row!.user); if (error) return { error }
    const user = target.row!.user; if (typeof b.username === 'string') user.username = b.username; if (typeof b.displayName === 'string') user.displayName = b.displayName
    user.revision++; return { data: { ...user } }
  })),
  http.delete('/api/v2/users/:id', ({ request, params }) => write(request, 200, () => {
    const target = mutableUser(Number(params.id)); if (target.error) return target
    const error = revision(request, target.row!.user); if (error) return { error }
    if (target.row!.bindings.length || target.row!.referenced) return { error: fail(409, 'USER_IN_USE') }
    iamState.users = iamState.users.filter((r) => r !== target.row); return { data: { id: Number(params.id), status: 'deleted' } }
  })),
  http.post('/api/v2/users/:id/status-changes', ({ request, params }) => write(request, 200, (b) => {
    const target = mutableUser(Number(params.id)); if (target.error) return target
    const error = revision(request, target.row!.user); if (error) return { error }
    if (!['active', 'disabled'].includes(String(b.status)) || !b.reason) return { error: fail(400, 'INVALID_REQUEST') }
    if (b.status === 'disabled' && target.row!.bindings.some((r) => r.roleKey === 'platform_admin' && r.scopeType === 'global') && !iamState.users.some((r) => r !== target.row && r.user.status === 'active' && r.bindings.some((binding) => binding.roleKey === 'platform_admin' && binding.scopeType === 'global'))) return { error: fail(409, 'LAST_ADMIN_REQUIRED') }
    target.row!.user.status = b.status as IamUser['status']; target.row!.user.revision++; return { data: { ...target.row!.user } }
  })),
  http.post('/api/v2/users/:id/password-resets', ({ request, params }) => write(request, 200, (b) => {
    const target = mutableUser(Number(params.id)); if (target.error) return target
    if (typeof b.newPassword !== 'string' || b.newPassword.length < 12 || new TextEncoder().encode(b.newPassword).length > 72 || !b.reason) return { error: fail(400, 'INVALID_REQUEST') }
    target.row!.user.revision++; return { data: { ...target.row!.user } }
  })),
  http.post('/api/v2/users/:id/role-bindings', ({ request, params }) => write(request, 201, (b) => {
    const target = mutableUser(Number(params.id)); if (target.error) return target
    const role = iamState.roles.find((r) => r.roleKey === b.roleKey)
    if (!role) return { error: fixtureNotFound() }
    if (role.status !== 'active') return { error: fail(422, 'ROLE_DISABLED') }
    if (bindingWarnings(target.row!.bindings, role.roleKey, iamState.roles).length) return { error: fail(409, 'ROLE_CONFLICT') }
    if (!((b.scopeType === 'global' && b.scopeId === '*') || (b.scopeType === 'asset' && /^[1-9][0-9]*$/.test(String(b.scopeId))))) return { error: fail(400, 'INVALID_SCOPE') }
    if (b.scopeType === 'asset' && !['1', '2'].includes(String(b.scopeId))) return { error: fixtureNotFound() }
    if (target.row!.bindings.some((r) => r.roleKey === b.roleKey && r.scopeType === b.scopeType && r.scopeId === b.scopeId)) return { error: fail(409, 'CONFLICT') }
    const binding: RoleBinding = { id: iamState.nextBinding++, roleKey: role.roleKey, scopeType: b.scopeType as RoleBinding['scopeType'], scopeId: String(b.scopeId) }
    target.row!.bindings.push(binding); target.row!.user.revision++; return { data: binding }
  })),
  http.post('/api/v2/role-bindings/:id/revocations', ({ request, params }) => write(request, 200, (b) => {
    const row = iamState.users.find((r) => r.bindings.some((binding) => binding.id === Number(params.id)))
    if (!row) return { error: fixtureNotFound() }
    const target = mutableUser(row.user.id); if (target.error) return target
    if (!b.reason) return { error: fail(400, 'INVALID_REQUEST') }
    const binding = row.bindings.find((r) => r.id === Number(params.id))!
    if (binding.roleKey === 'platform_admin' && binding.scopeType === 'global' && !iamState.users.some((r) => r !== row && r.user.status === 'active' && r.bindings.some((v) => v.roleKey === 'platform_admin' && v.scopeType === 'global'))) return { error: fail(409, 'LAST_ADMIN_REQUIRED') }
    row.bindings = row.bindings.filter((r) => r !== binding); row.user.revision++; return { data: { id: binding.id, status: 'revoked' } }
  })),
  http.get('/api/v2/roles', ({ request }) => {
    const denied = access(false, true); if (denied) return denied
    const q = parameters(request, ['status', 'q', 'from', 'until', 'sort']); if (!q) return fail(400, 'INVALID_QUERY')
    return fixtureOk(iamState.roles.filter((r) => (!q.has('status') || r.status === q.get('status')) && (!q.has('q') || [r.roleKey, r.name, r.description].some((s) => s.includes(q.get('q')!)))))
  }),
  http.get('/api/v2/permissions', () => access() ?? fixtureOk(permissionGroups.flatMap((g) => g.permissions.map((permissionKey) => ({ permissionKey, description: `${g.title}：${permissionKey}` }))))),
  http.get('/api/v2/roles/:key/members', ({ request, params }) => {
    const denied = access(); if (denied) return denied
    if (!iamState.roles.some((r) => r.roleKey === params.key)) return fixtureNotFound()
    const q = parameters(request, ['cursor', 'limit']); if (!q) return fail(400, 'INVALID_QUERY')
    const members = iamState.users.flatMap((r) => r.bindings.filter((b) => b.roleKey === params.key).map((b) => ({ id: r.user.id, username: r.user.username, displayName: r.user.displayName, status: r.user.status, scopeType: b.scopeType, scopeId: b.scopeId, bindingId: b.id })))
    return page(request, members, q)
  }),
  http.post('/api/v2/roles', ({ request }) => write(request, 201, (b) => {
    const error = roleBodyConflict(b); if (error) return { error }
    if (roleLimitReached(iamState.roles)) return { error: fail(409, 'ROLE_LIMIT_REACHED') }
    if (!/^custom_[a-z0-9_]+$/.test(String(b.roleKey)) || String(b.roleKey).length > 64 || !b.name || !b.description) return { error: fail(400, 'INVALID_REQUEST') }
    if (iamState.roles.some((r) => r.roleKey === b.roleKey)) return { error: fail(409, 'CONFLICT') }
    const role: IamRole = { roleKey: String(b.roleKey), name: String(b.name), description: String(b.description), permissions: b.permissions as string[], status: 'active', builtin: false, revision: 1 }
    iamState.roles.push(role); return { data: { ...role } }
  })),
  http.patch('/api/v2/roles/:key', ({ request, params }) => write(request, 200, (b) => {
    const target = mutableRole(String(params.key)); if (target.error) return target
    const row = target.row!; const error = revision(request, row) ?? ('permissions' in b ? roleBodyConflict(b) : null); if (error) return { error }
    const proposed = { ...row, ...b } as IamRole
    if ('permissions' in b && memberConflict(proposed)) return { error: fail(409, 'ROLE_CONFLICT') }
    if (typeof b.name === 'string') row.name = b.name
    if (typeof b.description === 'string') row.description = b.description
    if (Array.isArray(b.permissions)) row.permissions = b.permissions as string[]
    row.revision++; return { data: { ...row } }
  })),
  http.post('/api/v2/roles/:key/status-changes', ({ request, params }) => write(request, 200, (b) => {
    const target = mutableRole(String(params.key)); if (target.error) return target
    const row = target.row!; const error = revision(request, row); if (error) return { error }
    if (!['active', 'disabled'].includes(String(b.status)) || !b.reason) return { error: fail(400, 'INVALID_REQUEST') }
    if (b.status === row.status) return { error: fail(409, 'ROLE_STATUS_CONFLICT') }
    if (b.status === 'active' && row.status !== 'active' && roleLimitReached(iamState.roles)) return { error: fail(409, 'ROLE_LIMIT_REACHED') }
    if (b.status === 'active' && memberConflict(row)) return { error: fail(409, 'ROLE_CONFLICT') }
    row.status = b.status as IamRole['status']; row.revision++; return { data: { ...row } }
  })),
  http.delete('/api/v2/roles/:key', ({ request, params }) => write(request, 200, () => {
    const target = mutableRole(String(params.key)); if (target.error) return target
    const error = revision(request, target.row!); if (error) return { error }
    if (iamState.users.some((r) => r.bindings.some((b) => b.roleKey === params.key))) return { error: fail(409, 'ROLE_IN_USE') }
    iamState.roles = iamState.roles.filter((r) => r !== target.row); return { data: { roleKey: params.key, status: 'deleted' } }
  })),
  http.get('/api/v2/audit', ({ request }) => {
    const user = currentUser(); if (!user) return fixtureUnauthenticated()
    if (!fixtureCan(user, 'audit.read')) return fixtureDenied()
    const q = parameters(request, ['action', 'assetId', 'requestId', 'from', 'until', 'cursor', 'limit']); if (!q) return fail(400, 'INVALID_QUERY')
    const globalAdmin = user.bindings.some((b) => b.roleKey === 'platform_admin' && b.scopeType === 'global' && b.scopeId === '*')
    const rows = iamState.audit.filter((r) => {
      const scopes = iamState.auditScopes[r.id] ?? []
      const assetScopes: Record<string, string> = { [ASSET_1]: '1', [ASSET_2]: '2' }
      // 审计逐项精确匹配范围；普通 global 绑定不自动覆盖 asset 关联。
      return (globalAdmin || (scopes.length > 0 && scopes.every((scope) => user.bindings.some((b) => b.scopeType === scope.scopeType && b.scopeId === scope.scopeId && rolePermissions[b.roleKey].some((p) => p === 'audit.read')))))
        && (!q.has('assetId') || scopes.some((scope) => scope.scopeType === 'asset' && scope.scopeId === assetScopes[q.get('assetId')!]))
        && (!q.has('action') || r.action === q.get('action')) && (!q.has('requestId') || r.requestId === q.get('requestId'))
        && (!q.has('from') || r.occurredAt >= q.get('from')!) && (!q.has('until') || r.occurredAt < q.get('until')!)
    })
    const response = page(request, rows, q)
    return response.json().then((envelope) => response.status === 200 ? fixtureOk({ ...envelope.data, asOf: createdAt }) : response)
  }),
]
