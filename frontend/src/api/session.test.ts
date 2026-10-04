import { beforeEach, describe, expect, it, vi } from 'vitest'

const { apiMock, resetCsrfMock } = vi.hoisted(() => ({
  apiMock: { get: vi.fn(), post: vi.fn() },
  resetCsrfMock: vi.fn(),
}))
vi.mock('./client', () => ({ api: apiMock, resetCsrf: resetCsrfMock }))

import { loadSession, login, logout, session } from './session'

describe('session state', () => {
  beforeEach(() => {
    session.user = null
    session.checked = false
    apiMock.get.mockReset()
    apiMock.post.mockReset()
    resetCsrfMock.mockReset()
  })

  it('loads the server session and marks the check complete', async () => {
    const user = { id: 1, username: 'admin', displayName: '管理员', roles: [], permissions: [] }
    apiMock.get.mockResolvedValue(user)
    await expect(loadSession()).resolves.toEqual(user)
    expect(session).toMatchObject({ user, checked: true })
  })

  it('clears session and rotates CSRF around login/logout', async () => {
    const user = { id: 1, username: 'admin', displayName: '管理员', roles: [], permissions: [] }
    apiMock.post.mockResolvedValueOnce(user).mockResolvedValueOnce(undefined)
    await login('admin', 'admin')
    expect(session.user).toEqual(user)
    await logout()
    expect(session.user).toBeNull()
    expect(resetCsrfMock).toHaveBeenCalledTimes(3)
  })
})
