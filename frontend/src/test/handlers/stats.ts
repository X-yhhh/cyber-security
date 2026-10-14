/**
 * 实时态势相关的 msw 处理器：`GET /stats/live` 按 B5.2 契约模拟（字段按权限裁剪、缺口为 null），
 * 采集 / 执行心跳返回固定夹具。B5 合入后 stats/live 改为真实联调。
 */
import { http, HttpResponse } from 'msw'
import type { LiveRange } from '@/api/v2/stats'
import type { GuardHeartbeat } from '@/api/types'
import { currentUser } from './auth'
import { syntheticLive } from '../fixtures/live'

/** 固定“现在”，让单测的桶与缺口位置稳定。 */
export const LIVE_NOW = Date.parse('2026-10-14T12:00:05Z')

const beat = (id: string, freshness: string, receivedAt: string): GuardHeartbeat => ({
  id, assetId: 'a1', status: 'active', revision: 1, receivedAt, bootId: 'b1', freshness, healthState: freshness === 'fresh' ? 'healthy' : 'stale',
})
export const sensorBeats = [beat('sensor-1', 'fresh', '2026-10-14T12:00:01Z'), beat('sensor-2', 'stale', '2026-10-14T11:20:00Z')]
export const executorBeats = [beat('executor-1', 'fresh', '2026-10-14T12:00:02Z')]

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
  http.get('/api/v2/sensor-heartbeats', () => ok({ asOf: '2026-10-14T12:00:05Z', items: sensorBeats, nextCursor: null })),
  http.get('/api/v2/executor-heartbeats', () => ok({ asOf: '2026-10-14T12:00:05Z', items: executorBeats, nextCursor: null })),
]
