import { reactive } from 'vue'
import { api, resetCsrf } from './client'
import type { SessionUser } from './types'

/**
 * 当前会话。身份与权限只来自 /auth/me，前端据此隐藏无权操作，
 * 但授权判断始终以后端为准（后端会对每个请求重新校验）。
 */
export const session = reactive<{ user: SessionUser | null; checked: boolean }>({ user: null, checked: false })

export async function loadSession() {
  try {
    session.user = await api.get<SessionUser>('/auth/me')
  } catch {
    session.user = null
  }
  session.checked = true
  return session.user
}

export async function login(username: string, password: string) {
  resetCsrf()
  session.user = await api.post<SessionUser>('/auth/login', { username, password })
  session.checked = true
  resetCsrf()
}

export async function logout() {
  try { await api.post('/auth/logout') } catch { /* 会话可能已失效 */ }
  session.user = null
  resetCsrf()
}

export const can = (permission: string) => !!session.user?.permissions.includes(permission)
