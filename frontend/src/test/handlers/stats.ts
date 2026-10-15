/**
 * 实时态势相关的 msw 处理器：`GET /stats/live` 按 B5.2 契约模拟（字段按权限裁剪、缺口为 null），
 * 心跳统一由 F4 assets 处理器提供，避免重复路由绕过范围与权限校验。
 */
import { http, HttpResponse } from 'msw'
import type { LiveRange } from '@/api/v2/stats'
import { currentUser } from './auth'
import { syntheticLive } from '../fixtures/live'

/** 固定“现在”，让单测的桶与缺口位置稳定。 */
export const LIVE_NOW = Date.parse('2026-10-14T12:00:05Z')

const denied = () => HttpResponse.json({ requestId: 'req-test', data: null, error: { code: 'SCOPE_DENIED', message: '无权访问' } }, { status: 403 })
const ok = <T>(data: T) => HttpResponse.json({ requestId: 'req-live', data, error: null })

export const statsHandlers = [
  http.get('/api/v2/stats/live', ({ request }) => {
    const user = currentUser()
    if (!user) return HttpResponse.json({ requestId: 'req-test', data: null, error: { code: 'UNAUTHENTICATED', message: '请先登录' } }, { status: 401 })
    if (!['detection.read', 'action.read', 'ops.read'].some((p) => user.permissions.includes(p as never))) return denied()
    const url = new URL(request.url)
    const range = (url.searchParams.get('range') ?? '15m') as LiveRange
    if (!['15m', '1h', '24h', '7d'].includes(range)) return HttpResponse.json({ requestId: 'req-test', data: null, error: { code: 'INVALID_QUERY_PARAM', message: '参数不合法' } }, { status: 400 })
    return ok(syntheticLive(range, user.permissions, LIVE_NOW, Number(url.searchParams.get('step')) || undefined))
  }),
]
