/**
 * 角色测试夹具（任务单 F0.8）：6 个单角色和 1 个合法组合角色的 `auth/me` 响应。
 * 权限逐格取自权限设计第 5 节矩阵；形状按 B1.3 契约 `{id,username,displayName,roles,bindings,permissions}`。
 */
import { roleNames } from '@/api/v2/roles'
import type { Permission } from '@/router/nav'

export type HumanRole = 'platform_admin' | 'security_analyst' | 'security_reviewer' | 'model_operator' | 'evidence_reviewer' | 'auditor'

export const rolePermissions: Record<HumanRole, readonly Permission[]> = {
  platform_admin: ['resource.read', 'authorization.request', 'asset.manage', 'sensor.manage', 'audit.read', 'ops.read', 'iam.manage'],
  security_analyst: ['resource.read', 'detection.read', 'event.manage', 'feedback.label', 'action.read', 'action.request'],
  security_reviewer: [
    'resource.read', 'detection.read', 'action.read', 'action.revoke', 'automation.stop', 'authorization.approve',
    'evaluation.read', 'policy.approve', 'bundle.approve', 'ops.read',
  ],
  model_operator: ['resource.read', 'dataset.manage', 'model.manage', 'model.validate', 'evaluation.read', 'evaluation.run', 'policy.draft', 'bundle.request'],
  evidence_reviewer: ['resource.read', 'detection.read', 'feedback.review', 'evaluation.read'],
  auditor: ['resource.read', 'detection.read', 'action.read', 'evaluation.read', 'audit.read', 'ops.read'],
}

export const humanRoles = Object.keys(rolePermissions) as HumanRole[]

export interface MeFixture {
  id: number
  userKey: string
  username: string
  displayName: string
  roles: HumanRole[]
  bindings: { id: number; roleKey: HumanRole; scopeType: 'global' | 'asset'; scopeId: string }[]
  permissions: Permission[]
}

const demoName: Record<HumanRole, string> = {
  platform_admin: 'demo-admin',
  security_analyst: 'demo-analyst',
  security_reviewer: 'demo-reviewer',
  model_operator: 'demo-operator',
  evidence_reviewer: 'demo-evidence',
  auditor: 'demo-auditor',
}

/** 组装 `auth/me`：权限为各角色权限的并集，按键排序。 */
export function me(roles: HumanRole[], id = 100, username = roles.map((r) => demoName[r]).join('+')): MeFixture {
  const permissions = [...new Set(roles.flatMap((r) => rolePermissions[r]))].sort()
  return {
    id,
    userKey: `usr-${id}`,
    username,
    displayName: roles.map((r) => roleNames[r]).join(' + '),
    roles: [...roles],
    bindings: roles.map((roleKey, i) => ({ id: id * 10 + i, roleKey, scopeType: 'global', scopeId: '*' })),
    permissions,
  }
}

/** 6 个单角色账号（权限设计第 11 节的演示账号名）。 */
export const singleRoleUsers: Record<HumanRole, MeFixture> = Object.fromEntries(
  humanRoles.map((r, i) => [r, me([r], 101 + i)]),
) as Record<HumanRole, MeFixture>

/** 合法组合（第 3.3 节允许）：platform_admin + model_operator，与 B1.9 夹具一致。 */
export const comboUser = me(['platform_admin', 'model_operator'], 120, 'demo-admin-operator')
