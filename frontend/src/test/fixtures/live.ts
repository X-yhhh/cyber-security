/**
 * `GET /stats/live` 的合成数据（只用于单测与 B5 合入前的本地预览，不进入生产构建）。
 *
 * - 严格按 `src/api/v2/stats.ts` 的契约：字段按权限裁剪，无覆盖的时段为 null（模拟传感器缺口），有覆盖无事件为 0；
 * - 每个桶的值只由桶的绝对起点时间决定，因此随时间推移曲线向左滚动，像真实的实时数据；
 * - 不读取任何真实数据，预览时界面上的趋势与今日计数都是演示值。
 */
import { RANGE_STEP, type LiveRange, type LiveStats, type Series } from '@/api/v2/stats'

const FAMILIES = ['port_scan', 'brute_force', 'dos_flood', 'dos_slow'] as const

/** 由整数种子得到 [0,1) 的确定性伪随机数。 */
function rnd(seed: number): number {
  let t = (seed + 0x6d2b79f5) | 0
  t = Math.imul(t ^ (t >>> 15), t | 1)
  t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296
}

export function syntheticLive(range: LiveRange, permissions: readonly string[], now = Date.now(), step = RANGE_STEP[range]): LiveStats {
  const span = { '15m': 900, '1h': 3600, '24h': 86400, '7d': 604800 }[range]
  const points = Math.min(500, Math.round(span / step))
  const stepMs = step * 1000
  const end = Math.floor(now / stepMs) * stepMs + stepMs
  const from = end - points * stepMs
  const scale = step / 10
  const cycle = Math.max(24, Math.round(points * 0.7))
  const gap = Math.max(2, Math.round(points * 0.06))
  const ids = Array.from({ length: points }, (_, i) => Math.floor((from + i * stepMs) / stepMs))
  /** 模拟采集缺口：周期性的一小段没有任何健康窗口覆盖。 */
  const covered = ids.map((id) => id % cycle >= gap)
  const series = (f: (id: number) => number): Series => ids.map((id, i) => (covered[i] ? Math.max(0, Math.round(f(id))) : null))

  const has = (p: string) => permissions.includes(p)
  const out: LiveStats = { range, step, from: new Date(from).toISOString(), to: new Date(end).toISOString(), points, asOf: null }
  const lastCovered = covered.lastIndexOf(true)
  if (lastCovered >= 0) out.asOf = new Date(Math.min(now, from + (lastCovered + 1) * stepMs) - 1500).toISOString()

  const inbound = series((id) => (38 + 22 * Math.sin(id / 9) + 14 * rnd(id)) * scale)
  /** 告警按类别成簇出现：每类有自己的周期，簇内先升后降，簇外偶有零星告警。 */
  const SHAPE = [1, 3, 6, 5, 3, 1]
  const alerts = Object.fromEntries(FAMILIES.map((f, k) => [f, series((id) => {
    const pos = (id + k * 11) % (29 + k * 6)
    const burst = pos < SHAPE.length ? SHAPE[pos] * (0.6 + 0.6 * rnd(Math.floor(id / 29) * 7 + k)) : 0
    return (burst + (rnd(id * 4 + k) > 0.94 ? 1 : 0)) * Math.sqrt(scale)
  })]))
  const blocked = series((id) => ((id % 29 >= 2 && id % 29 < 4) ? 1 : 0) * Math.max(1, Math.round(Math.sqrt(scale))))

  if (has('detection.read')) {
    out.inbound = inbound
    out.alerts = alerts
  }
  if (has('action.read')) out.blocked = blocked
  /** 今日计数与所选范围无关，只随当天已过去的时间增长。 */
  const midnight = new Date(now); midnight.setHours(0, 0, 0, 0)
  const tenSec = Math.floor((now - midnight.getTime()) / 10000)
  const today: NonNullable<LiveStats['today']> = {}
  if (has('detection.read')) {
    today.inbound = tenSec * 41
    today.alerts = Math.round(tenSec * 0.42)
    today.openEvents = 12
  }
  if (has('action.read')) today.blocked = Math.round(tenSec / 290)
  if (Object.keys(today).length) out.today = today
  if (has('ops.read')) out.devices = { sensorsOnline: 2, sensorsTotal: 3, executorsOnline: 1, executorsTotal: 2 }
  return out
}
