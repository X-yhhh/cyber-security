/**
 * 实时态势统计 `GET /api/v2/stats/live`（任务单 B5.2 契约，权限设计第 10.5 节）。
 *
 * - 至少需要 `detection.read`、`action.read`、`ops.read` 之一；序列按权限裁剪，**没有权限的字段不返回**：
 *   `inbound`、`alerts`、`today.inbound/alerts/openEvents` 需 `detection.read`，`blocked`、`today.blocked` 需 `action.read`，
 *   `devices` 需 `ops.read`；全部按调用者可见资产范围统计。
 * - 时间桶为 `[from + i·step, from + (i+1)·step)`，共 `points` 个，`step` 为 10—3600 秒、点数上限 500。
 * - 桶值语义：`null` = 该时段没有任何已接收的采集健康窗口覆盖（传感器未接入或数据缺口），**不补 0**；
 *   `0` = 有覆盖但没有事件。`asOf` 为最后一次接收到数据的时间，从未接入时为 null。
 * - 只做聚合，不返回明细；非法 `range`/`step` 返回 400。
 * B5 合入前由 msw 按本契约模拟（`src/test/handlers/stats.ts`）。
 */
import { guard } from '@/api/client'

export type LiveRange = '15m' | '1h' | '24h' | '7d'
export type Series = (number | null)[]

/** 每个范围的默认步长（秒）与点数：15 分钟 10 秒一点、1 小时每分钟、24 小时每 15 分钟、7 天每小时。 */
export const RANGE_STEP: Record<LiveRange, number> = { '15m': 10, '1h': 60, '24h': 900, '7d': 3600 }
export const RANGE_LABEL: Record<LiveRange, string> = { '15m': '15 分钟', '1h': '1 小时', '24h': '24 小时', '7d': '7 天' }

export interface LiveStats {
  range: LiveRange
  step: number
  from: string
  to: string
  points: number
  asOf: string | null
  /** 入站观察记录数（detection.read）。 */
  inbound?: Series
  /** 告警与阻断候选判定数，按攻击类别分序列（detection.read）。 */
  alerts?: Record<string, Series>
  /** 进入“已生效”的处置动作数（action.read）。 */
  blocked?: Series
  /** 今日（服务器本地日）计数，字段按权限裁剪。 */
  today?: { inbound?: number; alerts?: number; blocked?: number; openEvents?: number }
  /** 在线设备（ops.read）：心跳新鲜即在线，不代表采集健康。 */
  devices?: { sensorsOnline: number; sensorsTotal: number; executorsOnline: number; executorsTotal: number }
}

export const fetchLiveStats = (range: LiveRange, step = RANGE_STEP[range]) =>
  guard.read<LiveStats>('stats/live', { range, step })

/** 第 i 个桶的起点时间。 */
export const bucketStart = (s: Pick<LiveStats, 'from' | 'step'>, i: number) => new Date(Date.parse(s.from) + i * s.step * 1000)

/** 序列末尾连续为 null 的桶数（用于提示“最近 N 分钟无数据”）。 */
export function trailingNulls(series: Series | undefined): number {
  if (!series) return 0
  let n = 0
  for (let i = series.length - 1; i >= 0 && series[i] === null; i--) n++
  return n
}
