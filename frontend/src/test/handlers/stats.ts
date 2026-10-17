/**
 * 实时态势相关的 msw 处理器：`GET /stats/live` 按 B5.2 契约模拟（字段按权限裁剪、缺口为 null），
 * 心跳统一由 F4 assets 处理器提供，避免重复路由绕过范围与权限校验。
 */
import { http, HttpResponse } from 'msw'
import { MAX_LIVE_POINTS, RANGE_SECONDS, RANGE_STEP, type LiveRange } from '@/api/v2/stats'
import { currentUser } from './auth'
import { syntheticLive } from '../fixtures/live'

/** 固定“现在”，让单测的桶与缺口位置稳定。 */
export const LIVE_NOW = Date.parse('2026-10-14T12:00:05Z')

const denied = () => HttpResponse.json({ requestId: 'req-test', data: null, error: { code: 'SCOPE_DENIED', message: '无权访问' } }, { status: 403 })
const ok = <T>(data: T) => HttpResponse.json({ requestId: 'req-live', data, error: null })
const invalid = () => HttpResponse.json({ requestId: 'req-test', data: null, error: { code: 'INVALID_QUERY', message: '参数不合法' } }, { status: 400 })

export const statsHandlers = [
  http.get('/api/v2/stats/live', ({ request }) => {
    const user = currentUser()
    if (!user) return HttpResponse.json({ requestId: 'req-test', data: null, error: { code: 'UNAUTHENTICATED', message: '请先登录' } }, { status: 401 })
    if (!['detection.read', 'action.read', 'ops.read'].some((p) => user.permissions.includes(p as never))) return denied()
    const url = new URL(request.url)
    if ([...url.searchParams.keys()].some((key) => !['range', 'step'].includes(key) || url.searchParams.getAll(key).length !== 1 || !url.searchParams.get(key)?.trim())) return invalid()
    const range = (url.searchParams.get('range') ?? '15m') as LiveRange
    if (!['15m', '1h', '24h', '7d'].includes(range)) return invalid()
    const rawStep = url.searchParams.get('step')
    if (rawStep !== null && !/^[0-9]{1,4}$/.test(rawStep)) return invalid()
    const step = rawStep === null ? RANGE_STEP[range] : Number(rawStep)
    if (step < 1 || step > 3600 || RANGE_SECONDS[range] % step !== 0 || RANGE_SECONDS[range] / step > MAX_LIVE_POINTS) return invalid()
    return ok(syntheticLive(range, user.permissions, LIVE_NOW, step))
  }),
]
