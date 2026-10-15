import { reactive } from 'vue'
import { api, idempotencyKey, resetCsrf } from './client'
import type { SessionUser } from './types'

/**
 * 当前会话。身份与权限只来自 /api/v2/auth/me，前端据此隐藏无权操作，
 * 但授权判断始终以后端为准（后端会对每个请求重新校验）。
 */
export const session = reactive<{ user: SessionUser | null; checked: boolean }>({ user: null, checked: false })

export async function loadSession() {
  try {
    session.user = await api.get<SessionUser>('/api/v2/auth/me')
  } catch {
    session.user = null
  }
  session.checked = true
  return session.user
}

export async function login(username: string, password: string) {
  session.user = null
  resetCsrf()
  try {
    session.user = await api.post<SessionUser>('/api/v2/auth/login', { username, password }, { 'Idempotency-Key': idempotencyKey() })
    session.checked = true
  } finally { resetCsrf() }
}

export async function logout() {
  try { await api.post('/api/v2/auth/logout', {}, { 'Idempotency-Key': idempotencyKey() }) } catch { /* 会话可能已失效；本地始终撤销权限，不把本地清空当作服务端注销证据。 */ }
  session.user = null
  session.checked = true
  resetCsrf()
}

/** 自助改密成功即撤销本人全部会话；失败保留身份以便修正输入，下一次写入重新取 CSRF。 */
export async function changePassword(currentPassword: string, newPassword: string) {
  try {
    await api.post('/api/v2/auth/password', { currentPassword, newPassword }, { 'Idempotency-Key': idempotencyKey() })
    session.user = null
    session.checked = true
  } finally { resetCsrf() }
}

export const can = (permission: string) => !!session.user?.permissions.includes(permission)
