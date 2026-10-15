import { guard, type Cursor } from '@/api/client'
import type { IamQuery, IamStatus, RoleBinding } from './iam'
import type { Permission } from '@/router/nav'

/**
 * 人工角色的中文名（权限设计第 3.1 节）。账户菜单对所有登录用户显示角色名，
 * 而 `GET /roles` 只对 iam.manage / audit.read 开放，因此名称在前端固定一份；
 * 未登记的键（迁移前遗留的 v1 角色等）原样显示。
 */
export const roleNames: Record<string, string> = {
  platform_admin: '平台管理员',
  security_analyst: '安全分析员',
  security_reviewer: '安全审核员',
  model_operator: '模型操作员',
  evidence_reviewer: '证据复核员',
  auditor: '审计员',
}

export const roleName = (key: string, catalogue: readonly Pick<IamRole, 'roleKey' | 'name'>[] = []) => catalogue.find((r) => r.roleKey === key)?.name ?? roleNames[key] ?? key

export interface IamRole {
  roleKey: string; name: string; description: string; status: IamStatus; builtin: boolean; revision: number; permissions: string[]
}
export interface PermissionEntry { permissionKey: Permission; description: string }
export interface RoleMember { id: number; username: string; displayName: string; status: string; scopeType: RoleBinding['scopeType']; scopeId: string; bindingId: number }
export interface RoleDefinition { roleKey: string; name: string; description: string; permissions: string[] }

/** 角色目录保持数组，不能套用游标列表；成员才使用游标。权限与成员查询需 iam.manage。 */
export const rolesApi = {
  listRoles: (q: IamQuery & { status?: IamStatus } = {}) => guard.read<IamRole[]>('roles', { ...q }),
  listPermissions: () => guard.read<PermissionEntry[]>('permissions'),
  listMembers: (roleKey: string, q: { cursor?: string; limit?: number } = {}) =>
    guard.read<Cursor<RoleMember>>(`roles/${encodeURIComponent(roleKey)}/members`, { ...q, limit: q.limit ?? 50 }),
  createRole: (body: RoleDefinition, key?: string) => guard.create<IamRole>('roles', body, key),
  updateRole: (roleKey: string, revision: number, body: Partial<Omit<RoleDefinition, 'roleKey'>>, key?: string) =>
    guard.patch<IamRole>('roles', roleKey, body, revision, key),
  setRoleStatus: (roleKey: string, revision: number, status: IamStatus, reason: string, key?: string) =>
    guard.op<IamRole>('roles', roleKey, 'status-changes', { status, reason }, revision, key),
  deleteRole: (roleKey: string, revision: number, key?: string) =>
    guard.remove<{ roleKey: string; status: 'deleted' }>('roles', roleKey, revision, key),
}

/** 七组提示与权限设计 3.3 节一致；跨资产范围也不能抵消同一人的职责冲突。 */
export const conflictPairs: readonly (readonly [Permission, Permission])[] = [
  ['authorization.request', 'authorization.approve'], ['sensor.manage', 'authorization.approve'],
  ['policy.draft', 'policy.approve'], ['bundle.request', 'bundle.approve'],
  ['action.request', 'authorization.approve'], ['feedback.label', 'feedback.review'],
  ['evaluation.run', 'authorization.approve'],
]
export const permissionConflicts = (permissions: readonly string[]) => conflictPairs.filter(([a, b]) => permissions.includes(a) && permissions.includes(b))

/** 只做事前提示；目录缺失时明确提示刷新，不假定未知角色无权限。最终以服务端 409/422 为准。 */
export function bindingWarnings(bindings: readonly RoleBinding[], roleKey: string, catalogue: readonly IamRole[]): string[] {
  const keys = [...new Set([...bindings.map((b) => b.roleKey), roleKey])]
  if (keys.some((key) => !catalogue.some((role) => role.roleKey === key))) return ['角色目录不完整，请刷新后核对；最终以服务端校验为准。']
  const roles = keys.map((key) => catalogue.find((r) => r.roleKey === key)!).filter((r) => r.status === 'active')
  const warnings = permissionConflicts(roles.flatMap((r) => r.permissions)).map(([a, b]) => `职责冲突：${a} 与 ${b} 不能同时持有。`)
  if (roles.some((r) => r.roleKey === 'auditor') && roles.length > 1) warnings.push('审计员必须保持纯只读身份，不能兼任其他人工角色。')
  if (catalogue.find((r) => r.roleKey === roleKey)?.status !== 'active') warnings.push('所选角色已停用，不能新增绑定。')
  return warnings
}

/** 两个机器模板占用固定名额；启用人工角色最多 8 个，停用角色不占名额。 */
export const roleLimitReached = (catalogue: readonly IamRole[]) => catalogue.filter((r) => r.status === 'active').length + 2 >= 10

/** 页面按组显示中文说明；权限键仅用于请求与诊断，不作为正文文案堆叠。 */
export const permissionGroups: readonly { title: string; permissions: readonly Permission[] }[] = [
  { title: '查询与研判', permissions: ['resource.read', 'detection.read', 'event.manage', 'feedback.label', 'feedback.review'] },
  { title: '响应处置', permissions: ['action.read', 'action.request', 'action.revoke', 'automation.stop'] },
  { title: '资产与接入', permissions: ['authorization.request', 'authorization.approve', 'asset.manage', 'sensor.manage'] },
  { title: '模型与发布', permissions: ['dataset.manage', 'model.manage', 'model.validate', 'evaluation.read', 'evaluation.run', 'policy.draft', 'policy.approve', 'bundle.request', 'bundle.approve'] },
  { title: '系统管理', permissions: ['audit.read', 'ops.read', 'iam.manage'] },
]
