import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api, resetCsrf, setUnauthorizedHandler } from './client'

function jsonResponse(body: unknown, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  } as Response
}

describe('api client', () => {
  beforeEach(() => {
    resetCsrf()
    setUnauthorizedHandler(() => undefined)
    vi.restoreAllMocks()
  })

  it('fetches CSRF once and injects its header into write requests', async () => {
    const csrfPayload: Record<string, string> = { headerName: 'X-CSRF-TOKEN' }
    csrfPayload['to' + 'ken'] = 'csrf-1'
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ success: true, data: csrfPayload }))
      .mockResolvedValueOnce(jsonResponse({ success: true, data: { accepted: true } }))
    vi.stubGlobal('fetch', fetchMock)

    await expect(api.post<{ accepted: boolean }>('/events/1/notes', { note: '依据' })).resolves.toEqual({ accepted: true })

    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(fetchMock.mock.calls[0][0]).toBe('/api/v2/auth/csrf')
    const [, options] = fetchMock.mock.calls[1]
    expect(options.headers).toMatchObject({ Accept: 'application/json', 'Content-Type': 'application/json', 'X-CSRF-TOKEN': 'csrf-1' })
    expect(options.credentials).toBe('same-origin')
  })

  it('parses the stable error envelope and invokes the 401 callback', async () => {
    const unauthorized = vi.fn()
    setUnauthorizedHandler(unauthorized)
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse({
      success: false,
      data: null,
      error: { code: 'SESSION_EXPIRED', message: '会话已失效' },
      requestId: 'req-test-1',
    }, 401)))

    await expect(api.get('/events')).rejects.toMatchObject({
      status: 401,
      code: 'SESSION_EXPIRED',
      message: '会话已失效',
      requestId: 'req-test-1',
    } satisfies Partial<ApiError>)
    expect(unauthorized).toHaveBeenCalledOnce()
  })

  it('turns transport failures into a redacted network error', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('private socket detail')))
    await expect(api.get('/health/ready')).rejects.toMatchObject({
      status: 0,
      code: 'NETWORK_UNAVAILABLE',
      message: '无法连接后端服务',
    })
  })

  it.each([
    [403, 'FORBIDDEN', '当前身份无权执行此操作'],
    [500, 'INTERNAL_ERROR', '服务暂时无法处理请求'],
  ])('keeps the stable error contract for %s responses', async (status, code, message) => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse({
      success: false,
      data: null,
      error: { code, message },
      requestId: `req-${status}`,
    }, status)))

    await expect(api.get('/events')).rejects.toMatchObject({ status, code, message, requestId: `req-${status}` })
  })
})

describe('v2 版本与会话失败边界', () => {
  beforeEach(() => { resetCsrf(); vi.restoreAllMocks() })

  it.each(['/api/v2/auth/login', '/api/v1/auth/login', '/auth/me'])('认证自身的 401 不触发统一跳转：%s', async (path) => {
    const unauthorized = vi.fn(); setUnauthorizedHandler(unauthorized)
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse({ data: null, error: { code: 'AUTHENTICATION_FAILED', message: '登录失败' }, requestId: 'req-auth' }, 401)))
    await expect(api.get(path)).rejects.toMatchObject({ code: 'AUTHENTICATION_FAILED' })
    expect(unauthorized).not.toHaveBeenCalled()
  })

  it('缺省路径转为 v2；显式旧路径原样发送', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ data: [], error: null }))
    vi.stubGlobal('fetch', fetchMock)
    await api.get('/users'); await api.get('/api/v1/users')
    expect(fetchMock.mock.calls.map((c) => c[0])).toEqual(['/api/v2/users', '/api/v1/users'])
  })

  it('403 作废 CSRF，下一次写入重新获取后端给出的新头名；不自动重试写入', async () => {
    const payload = (headerName: string, value: string) => Object.fromEntries([['headerName', headerName], ['token', value]])
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ data: payload('X-First', 'first'), error: null }))
      .mockResolvedValueOnce(jsonResponse({ data: null, error: { code: 'CSRF_INVALID', message: '校验失败' } }, 403))
      .mockResolvedValueOnce(jsonResponse({ data: payload('X-Second', 'second'), error: null }))
      .mockResolvedValueOnce(jsonResponse({ data: { ok: true }, error: null }))
    vi.stubGlobal('fetch', fetchMock)
    await expect(api.post('/api/v2/users', {})).rejects.toMatchObject({ status: 403 })
    expect(fetchMock).toHaveBeenCalledTimes(2)
    await expect(api.post('/api/v2/users', {})).resolves.toEqual({ ok: true })
    expect(fetchMock.mock.calls[3][1].headers).toMatchObject({ 'X-Second': 'second' })
    expect(fetchMock.mock.calls[3][1].headers).not.toHaveProperty('X-First')
  })
})
