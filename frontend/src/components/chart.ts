/**
 * TrendChart 的纯函数部分（前端设计文档第 3.6 节，任务单 U0.6），单独成文件便于单测。
 * - 调色板固定为 signal、threat、warn、ok 与中性灰，按类别稳定分配，不随筛选换色；
 * - `null` 表示该时间点无数据：折线在此断开，不补 0、不画平线；
 * - CSV 供答辩与论文引用，空值写空单元格。
 */
export type ChartTone = 'signal' | 'threat' | 'warn' | 'ok' | 'mute'

export const chartPalette: Readonly<Record<ChartTone, string>> = {
  signal: '#2438E8',
  threat: '#E0482A',
  warn: '#B7791F',
  ok: '#2F7D5B',
  mute: '#9A9CA1',
}

/** 同一张图最多 5 条线（第 3.6 节）。 */
export const MAX_SERIES = 5

const order: readonly ChartTone[] = ['signal', 'threat', 'warn', 'ok', 'mute']

/** 未显式指定 tone 时按 key 稳定取色：同一个类别在任何筛选组合下颜色不变。 */
export function toneOf(key: string, tone?: ChartTone): ChartTone {
  if (tone) return tone
  let h = 0
  for (const ch of key) h = (h * 31 + ch.charCodeAt(0)) >>> 0
  return order[h % order.length]
}

/** 不小于 v 的“好看”上界（1、2、2.5、5 × 10ⁿ）；v ≤ 0 时取 1，保证坐标轴有高度。 */
export function niceMax(v: number): number {
  if (!(v > 0) || !Number.isFinite(v)) return 1
  const mag = 10 ** Math.floor(Math.log10(v))
  for (const k of [1, 2, 2.5, 5, 10]) if (k * mag >= v) return k * mag
  return 10 * mag
}

/** 把点列切成连续非空段，返回每段的 [下标, 值] 列表；`null`/非有限值处断开。 */
export function segments(points: readonly (number | null | undefined)[]): [number, number][][] {
  const out: [number, number][][] = []
  let cur: [number, number][] = []
  points.forEach((v, i) => {
    if (v === null || v === undefined || !Number.isFinite(v)) {
      if (cur.length) out.push(cur)
      cur = []
    } else cur.push([i, v])
  })
  if (cur.length) out.push(cur)
  return out
}

function cell(v: string | number | null | undefined): string {
  if (v === null || v === undefined) return ''
  const s = String(v)
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
}

/** 生成 CSV 文本（首行为表头，行尾 `\n`）。 */
export function toCsv(header: readonly string[], rows: readonly (readonly (string | number | null | undefined)[])[]): string {
  return [header, ...rows].map((r) => r.map(cell).join(',')).join('\n') + '\n'
}
