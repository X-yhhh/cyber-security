/** F5 协议与失败边界；后端真实事务/会话由预览联调另行证明。 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { http, HttpResponse } from 'msw'
import { ApiError, api, resetCsrf } from '@/api/client'
import { errText } from '@/composables/load'
import { iamApi } from './iam'
import { rolesApi, bindingWarnings, permissionConflicts, roleLimitReached, roleName, permissionGroups, conflictPairs } from './roles'
import { iamErrorMessages } from './iam-errors'
import { server } from '@/test/handlers'
import { signIn } from '@/test/handlers/auth'
import { iamState, resetIamState, IAM_USER, IAM_UNUSED_USER, IAM_REFERENCED_USER } from '@/test/handlers/iam'
import { me, singleRoleUsers } from '@/test/roles'
import { ASSET_1 } from '@/test/handlers/detect'

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }))
afterAll(() => server.close())
afterEach(() => server.resetHandlers())
beforeEach(() => { resetIamState(); resetCsrf(); signIn(singleRoleUsers.platform_admin) })
const definition = (roleKey = 'custom_reader') => ({ roleKey, name: '资料查询员', description: '只读非敏感资料', permissions: ['resource.read'] })

describe('IAM 查询', () => {
  it('用户列表支持搜索、状态与游标；改变筛选或主体后旧游标拒绝', async () => {
    const first = await iamApi.listUsers({ limit: 1 })
    expect(first.items).toHaveLength(1)
    expect((await iamApi.listUsers({ limit: 1, cursor: first.nextCursor! })).items[0].id).not.toBe(first.items[0].id)
    await expect(iamApi.listUsers({ limit: 1, cursor: first.nextCursor!, q: 'demo' })).rejects.toMatchObject({ code: 'INVALID_CURSOR' })
    const users = await iamApi.listUsers({ q: 'demo-target', status: 'active' })
    expect(users.items.map((r) => r.id)).toEqual([IAM_USER])
    expect((await iamApi.getUser(IAM_USER)).revision).toBe(1)
    expect(await iamApi.listBindings(IAM_USER)).toEqual([{ id: 2100, roleKey: 'security_analyst', scopeType: 'global', scopeId: '*' }])
    expect((await iamApi.listUsers({ until: '2026-10-15T03:00:00Z' })).items).toEqual([])
    signIn(me(['platform_admin'], 999))
    await expect(iamApi.listUsers({ limit: 1, cursor: first.nextCursor! })).rejects.toMatchObject({ code: 'INVALID_CURSOR' })
  })

  it('角色保持数组，权限目录只含 25 个不同的人工键；成员游标携带绑定范围', async () => {
    expect(await rolesApi.listRoles()).toHaveLength(6)
    expect(await rolesApi.listRoles({ status: 'disabled' })).toEqual([])
    const permissions = await rolesApi.listPermissions()
    expect(new Set(permissions.map((p) => p.permissionKey)).size).toBe(25)
    expect((await rolesApi.listMembers('security_analyst')).items[0]).toMatchObject({ id: IAM_USER, bindingId: 2100, scopeType: 'global', scopeId: '*' })
    await expect(rolesApi.listMembers('absent')).rejects.toMatchObject({ status: 404 })
  })

  it('审计只读，完整保留筛选、UTC 时间、游标、asOf 与 requestId 空值', async () => {
    let seen!: URL
    server.use(http.get('/api/v2/audit', ({ request }) => {
      seen = new URL(request.url)
      return HttpResponse.json({ data: { asOf: '2026-10-15T04:00:00Z', items: [{ ...iamState.audit[0], requestId: null }], nextCursor: 'next' }, error: null })
    }))
    const query = { assetId: ASSET_1, action: 'iam.user.create', requestId: 'request+/=', from: '2026-10-15T00:00:00Z', until: '2026-10-16T00:00:00Z', cursor: 'cursor+/=', limit: 12 }
    const result = await iamApi.listAudit(query)
    expect(Object.fromEntries(seen.searchParams)).toEqual({ ...query, limit: '12' })
    expect(result).toMatchObject({ asOf: '2026-10-15T04:00:00Z', nextCursor: 'next' })
    expect(result.items[0].requestId).toBeNull()
    expect(Object.keys(iamApi).filter((k) => /audit/i.test(k))).toEqual(['listAudit'])
  })

  it('审计员只能读角色和审计，不能读用户/成员/权限或写入；资产范围管理员不能管理全局用户', async () => {
    signIn(singleRoleUsers.auditor)
    expect(await rolesApi.listRoles()).toHaveLength(6)
    await expect(iamApi.listAudit()).resolves.toHaveProperty('asOf')
    await expect(iamApi.listUsers()).rejects.toMatchObject({ status: 403 })
    await expect(rolesApi.listPermissions()).rejects.toMatchObject({ status: 403 })
    await expect(rolesApi.listMembers('platform_admin')).rejects.toMatchObject({ status: 403 })
    await expect(rolesApi.createRole(definition())).rejects.toMatchObject({ status: 403 })
    const scoped = me(['platform_admin']); scoped.bindings[0].scopeType = 'asset'; scoped.bindings[0].scopeId = '1'; signIn(scoped)
    await expect(iamApi.listUsers()).rejects.toMatchObject({ status: 403 })
    await expect(iamApi.getUser(IAM_USER)).rejects.toMatchObject({ status: 404 })
    signIn(null)
    await expect(iamApi.listUsers()).rejects.toMatchObject({ status: 401 })
  })

  it('无范围审计仅全局平台管理员可见；资产过滤不能把无范围记录归到该资产', async () => {
    expect((await iamApi.listAudit()).items).toHaveLength(3)
    expect((await iamApi.listAudit({ assetId: ASSET_1 })).items.map((r) => r.action)).toEqual(['asset.update'])
    signIn(singleRoleUsers.auditor)
    expect((await iamApi.listAudit()).items.map((r) => r.action)).toEqual(['iam.user.create'])
    const scoped = me(['auditor'])
    scoped.bindings[0].scopeType = 'asset'; scoped.bindings[0].scopeId = '1'; signIn(scoped)
    expect((await iamApi.listAudit()).items).toHaveLength(1)
    await expect(rolesApi.listRoles()).rejects.toMatchObject({ status: 403 })
    iamState.auditScopes[iamState.audit[1].id].push({ scopeType: 'asset', scopeId: '2' })
    expect((await iamApi.listAudit()).items).toEqual([])
  })
})

describe('IAM 用户与绑定写入', () => {
  it('创建、修改、停用/启用和重置口令逐项符合 B1/B4 路由与修订；口令不留在记录中', async () => {
    const secret = crypto.randomUUID()
    const created = await iamApi.createUser({ username: 'new-user', displayName: '新用户', password: secret })
    expect(created).toMatchObject({ username: 'new-user', status: 'active', revision: 1 })
    expect(await iamApi.listBindings(created.id)).toEqual([])
    expect((await iamApi.updateUser(created.id, 1, { username: 'renamed-user', displayName: '新名称' })).revision).toBe(2)
    await expect(iamApi.setUserStatus(created.id, 1, 'disabled', '停用')).rejects.toMatchObject({ code: 'REVISION_CONFLICT' })
    expect((await iamApi.setUserStatus(created.id, 2, 'disabled', '停用')).revision).toBe(3)
    expect((await iamApi.setUserStatus(created.id, 3, 'active', '启用')).status).toBe('active')
    expect((await iamApi.resetPassword(created.id, crypto.randomUUID(), '重置')).revision).toBe(5)
    expect(iamState.writes.map((r) => [r.method, r.ifMatch])).toEqual([['POST', null], ['PATCH', '1'], ['POST', '2'], ['POST', '3'], ['POST', null]])
    expect(iamState.writes.every((r) => /^[\da-f-]{36}$/.test(r.key))).toBe(true)
    expect(JSON.stringify(iamState)).not.toContain(secret)
  })

  it('仅未使用账号可删除；DELETE 无 body，带原修订与幂等键', async () => {
    expect(await iamApi.deleteUser(IAM_UNUSED_USER, 1)).toEqual({ id: IAM_UNUSED_USER, status: 'deleted' })
    expect(iamState.writes[0]).toMatchObject({ method: 'DELETE', ifMatch: '1' })
    await expect(iamApi.getUser(IAM_UNUSED_USER)).rejects.toMatchObject({ status: 404 })
    await expect(iamApi.deleteUser(IAM_REFERENCED_USER, 1)).rejects.toMatchObject({ code: 'USER_IN_USE' })
    await expect(iamApi.deleteUser(IAM_USER, 1)).rejects.toMatchObject({ code: 'USER_IN_USE' })
  })

  it('绑定和撤销不发送 If-Match；每次提交新键，重放复用原键且只写一次', async () => {
    const body = { roleKey: 'model_operator', scopeType: 'global' as const, scopeId: '*' as const }
    const key = crypto.randomUUID()
    const binding = await iamApi.addBinding(IAM_USER, body, key)
    expect(await iamApi.addBinding(IAM_USER, body, key)).toEqual(binding)
    expect(iamState.writes).toHaveLength(1)
    expect(iamState.writes[0].ifMatch).toBeNull()
    await expect(iamApi.addBinding(IAM_USER, { ...body, roleKey: 'platform_admin' }, key)).rejects.toMatchObject({ code: 'IDEMPOTENCY_CONFLICT' })
    expect(await iamApi.revokeBinding(binding.id, '职责调整')).toEqual({ id: binding.id, status: 'revoked' })
    expect(iamState.writes[1].key).not.toBe(key)
    expect((await iamApi.listBindings(IAM_USER)).map((r) => r.roleKey)).toEqual(['security_analyst'])
  })

  it('拒绝本人管理和互斥角色；资产 UUID 不能伪装成绑定的内部 scopeId', async () => {
    await expect(iamApi.updateUser(singleRoleUsers.platform_admin.id, 1, { displayName: '本人' })).rejects.toMatchObject({ code: 'SELF_ADMINISTRATION_FORBIDDEN' })
    await expect(iamApi.revokeBinding(singleRoleUsers.platform_admin.bindings[0].id, '本人撤权')).rejects.toMatchObject({ code: 'SELF_ADMINISTRATION_FORBIDDEN' })
    await expect(iamApi.addBinding(IAM_USER, { roleKey: 'evidence_reviewer', scopeType: 'asset', scopeId: '2' })).rejects.toMatchObject({ code: 'ROLE_CONFLICT' })
    await expect(iamApi.addBinding(IAM_UNUSED_USER, { roleKey: 'security_analyst', scopeType: 'asset', scopeId: ASSET_1 })).rejects.toMatchObject({ code: 'INVALID_SCOPE' })
    expect((await iamApi.addBinding(IAM_UNUSED_USER, { roleKey: 'security_analyst', scopeType: 'asset', scopeId: '1' })).scopeId).toBe('1')
  })

  it('最后一位全局管理员不可停用或撤销绑定', async () => {
    iamState.users[0].user.status = 'disabled'
    iamState.users[1].bindings = [{ id: 2100, roleKey: 'platform_admin', scopeType: 'global', scopeId: '*' }]
    await expect(iamApi.setUserStatus(IAM_USER, 1, 'disabled', '停用')).rejects.toMatchObject({ code: 'LAST_ADMIN_REQUIRED' })
    await expect(iamApi.revokeBinding(2100, '撤销')).rejects.toMatchObject({ code: 'LAST_ADMIN_REQUIRED' })
    expect((await iamApi.getUser(IAM_USER)).revision).toBe(1)
  })
})

describe('自定义角色与冲突提示', () => {
  it('角色增改停用启用删除；绑定中的角色拒绝删除', async () => {
    let role = await rolesApi.createRole(definition())
    expect(role).toMatchObject({ builtin: false, revision: 1 })
    role = await rolesApi.updateRole(role.roleKey, role.revision, { name: '查询员' })
    expect(roleName(role.roleKey, [role])).toBe('查询员')
    role = await rolesApi.setRoleStatus(role.roleKey, role.revision, 'disabled', '暂停')
    await expect(iamApi.addBinding(IAM_UNUSED_USER, { roleKey: role.roleKey, scopeType: 'global', scopeId: '*' })).rejects.toMatchObject({ code: 'ROLE_DISABLED' })
    role = await rolesApi.setRoleStatus(role.roleKey, role.revision, 'active', '恢复')
    const binding = await iamApi.addBinding(IAM_UNUSED_USER, { roleKey: role.roleKey, scopeType: 'global', scopeId: '*' })
    await expect(rolesApi.deleteRole(role.roleKey, role.revision)).rejects.toMatchObject({ code: 'ROLE_IN_USE' })
    await iamApi.revokeBinding(binding.id, '解除绑定')
    expect(await rolesApi.deleteRole(role.roleKey, role.revision)).toEqual({ roleKey: role.roleKey, status: 'deleted' })
  })

  it('互斥权限 422、内置角色 403，满额后 409；停用自定义角色释放名额', async () => {
    await expect(rolesApi.createRole({ ...definition(), permissions: ['policy.draft', 'policy.approve'] })).rejects.toMatchObject({ code: 'PERMISSION_CONFLICT' })
    await expect(rolesApi.updateRole('platform_admin', 1, { name: '改名' })).rejects.toMatchObject({ code: 'BUILTIN_ROLE_READONLY' })
    const first = await rolesApi.createRole(definition())
    await rolesApi.createRole(definition('custom_second'))
    expect(roleLimitReached(await rolesApi.listRoles())).toBe(true)
    await expect(rolesApi.createRole(definition('custom_third'))).rejects.toMatchObject({ code: 'ROLE_LIMIT_REACHED' })
    await rolesApi.setRoleStatus(first.roleKey, first.revision, 'disabled', '释放名额')
    expect(roleLimitReached(await rolesApi.listRoles())).toBe(false)
  })

  it('角色改权限不得使现有成员发生冲突，失败不改变角色和修订', async () => {
    const role = await rolesApi.createRole(definition())
    await iamApi.addBinding(IAM_USER, { roleKey: role.roleKey, scopeType: 'global', scopeId: '*' })
    await expect(rolesApi.updateRole(role.roleKey, 1, { permissions: ['feedback.review'] })).rejects.toMatchObject({ code: 'ROLE_CONFLICT' })
    expect((await rolesApi.listRoles()).find((r) => r.roleKey === role.roleKey)).toEqual(role)
  })

  it('停用后新增的其他职责也会阻止重新启用冲突角色', async () => {
    let role = await rolesApi.createRole({ ...definition(), permissions: ['feedback.review'] })
    await iamApi.addBinding(IAM_UNUSED_USER, { roleKey: role.roleKey, scopeType: 'global', scopeId: '*' })
    role = await rolesApi.setRoleStatus(role.roleKey, role.revision, 'disabled', '暂停')
    await iamApi.addBinding(IAM_UNUSED_USER, { roleKey: 'security_analyst', scopeType: 'global', scopeId: '*' })
    await expect(rolesApi.setRoleStatus(role.roleKey, role.revision, 'active', '恢复')).rejects.toMatchObject({ code: 'ROLE_CONFLICT' })
    expect((await rolesApi.listRoles()).find((r) => r.roleKey === role.roleKey)).toEqual(role)
  })

  it('七组权限对、审计纯只读、停用角色和缺失目录均提供预先提示', () => {
    for (const pair of conflictPairs) expect(permissionConflicts(pair)).toContainEqual(pair)
    expect(new Set(permissionGroups.flatMap((g) => [...g.permissions])).size).toBe(25)
    expect(bindingWarnings(iamState.users[1].bindings, 'evidence_reviewer', iamState.roles)).not.toEqual([])
    expect(bindingWarnings(iamState.users[1].bindings, 'model_operator', iamState.roles)).toEqual([])
    expect(bindingWarnings([], 'unknown', iamState.roles).join('')).toContain('目录不完整')
    expect(bindingWarnings(iamState.users[1].bindings, 'auditor', iamState.roles).join('')).toContain('纯只读')
    iamState.roles.find((r) => r.roleKey === 'security_analyst')!.status = 'disabled'
    expect(bindingWarnings(iamState.users[1].bindings, 'evidence_reviewer', iamState.roles)).toEqual([])
    expect(bindingWarnings([], 'security_analyst', iamState.roles).join('')).toContain('停用')
  })

  it.each(Object.keys(iamErrorMessages))('错误 %s 转为中文并保留状态与 request-id', (code) => {
    const error = new ApiError(code === 'PERMISSION_CONFLICT' ? 422 : 409, code, 'UNTRANSLATED', 'req-stable')
    expect(errText(error)).toContain(iamErrorMessages[code])
    expect(errText(error)).toContain('req-stable')
    expect(error.code).toBe(code)
  })

  it('缺失幂等键或修订明确失败，客户端不自动重放', async () => {
    await expect(api.post('/api/v2/users', {})).rejects.toMatchObject({ code: 'INVALID_UUID' })
    const role = await rolesApi.createRole(definition())
    await expect(api.patch(`/api/v2/roles/${role.roleKey}`, { name: '改名' }, { 'Idempotency-Key': crypto.randomUUID() })).rejects.toMatchObject({ code: 'REVISION_CONFLICT' })
  })
})
