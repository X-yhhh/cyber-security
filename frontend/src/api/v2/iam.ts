/**
 * F5 身份与访问接口，逐项对应 B1/B4 实际契约。用户/绑定 ID 为正整数，角色键为字符串；
 * asset 绑定 scopeId 为内部资产 ID 的十进制字符串，不能把公开 UUID 传入此字段。
 * 只传输请求，不在客户端授予权限；写入成功后的资料、绑定和修订应重新读取。
 */
import { guard, type Cursor } from '@/api/client'
import type { GuardReadPage } from '@/api/types'

export type IamStatus = 'active' | 'disabled'
export type ScopeType = 'global' | 'asset'
export interface RoleBinding { id: number; roleKey: string; scopeType: ScopeType; scopeId: string }
export interface IamUser { id: number; username: string; displayName: string; status: IamStatus | 'locked'; revision: number }
export interface IamQuery { q?: string; from?: string; until?: string; sort?: 'createdAt' | 'updatedAt' }
export interface UserQuery extends IamQuery { status?: IamUser['status']; cursor?: string; limit?: number }
export interface CreateUser { username: string; displayName: string; password: string }
export interface EditUser { username?: string; displayName?: string }
export type CreateBinding = { roleKey: string } & ({ scopeType: 'global'; scopeId: '*' } | { scopeType: 'asset'; scopeId: string })
export interface AuditEntry {
  id: string; occurredAt: string; actorType: string; action: string; resourceType: string
  resourceId: string | null; requestId: string | null; outcome: string
}
export interface AuditQuery { action?: string; assetId?: string; requestId?: string; from?: string; until?: string; cursor?: string; limit?: number }

export const iamApi = {
  listUsers: (q: UserQuery = {}) => guard.read<Cursor<IamUser>>('users', { ...q, limit: q.limit ?? 50 }),
  getUser: (id: number) => guard.get<IamUser>('users', String(id)),
  listBindings: (id: number) => guard.child<RoleBinding[]>('users', String(id), 'role-bindings'),
  createUser: (body: CreateUser, key?: string) => guard.create<IamUser>('users', body, key),
  updateUser: (id: number, revision: number, body: EditUser, key?: string) => guard.patch<IamUser>('users', id, body, revision, key),
  setUserStatus: (id: number, revision: number, status: IamStatus, reason: string, key?: string) =>
    guard.op<IamUser>('users', String(id), 'status-changes', { status, reason }, revision, key),
  resetPassword: (id: number, newPassword: string, reason: string, key?: string) =>
    guard.op<IamUser>('users', String(id), 'password-resets', { newPassword, reason }, undefined, key),
  deleteUser: (id: number, revision: number, key?: string) => guard.remove<{ id: number; status: 'deleted' }>('users', id, revision, key),
  addBinding: (id: number, body: CreateBinding, key?: string) =>
    guard.op<RoleBinding>('users', String(id), 'role-bindings', body, undefined, key),
  revokeBinding: (id: number, reason: string, key?: string) =>
    guard.op<{ id: number; status: 'revoked' }>('role-bindings', String(id), 'revocations', { reason }, undefined, key),
  /** 审计只有只读入口；asOf 与游标来自后端，不在客户端伪造全量统计或审计原文。 */
  listAudit: (q: AuditQuery = {}) => guard.read<GuardReadPage<AuditEntry>>('audit', { ...q, limit: q.limit ?? 50 }),
}
