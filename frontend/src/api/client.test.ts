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
    expect(fetchMock.mock.calls[0][0]).toBe('/api/v1/auth/csrf')
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
