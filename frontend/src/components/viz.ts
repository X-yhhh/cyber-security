/**
 * 概览读数的统计辅助（视觉基线 v2）：把已加载的列表按某个字段计数，生成分布条与排行条的数据。
 * 只统计调用方传入的数据，不推断总量；页面须在说明里写明统计范围（例如“按当前页 N 条统计”）。
 */
import type { Tone } from '@/data/tones'

export interface Segment { key: string; label: string; value: number; tone: Tone }

/** 按 key 计数，按数量降序；label/tone 由页面已有的文案与语义色映射提供。 */
export function tally<T>(items: readonly T[], key: (t: T) => string | null | undefined, label: (k: string) => string, tone: (k: string) => Tone): Segment[] {
  const counts = new Map<string, number>()
  for (const it of items) {
    const k = key(it) ?? '—'
    counts.set(k, (counts.get(k) ?? 0) + 1)
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1]).map(([k, value]) => ({ key: k, label: label(k), value, tone: tone(k) }))
}

/** 满足条件的条数。 */
export const countIf = <T,>(items: readonly T[], pred: (t: T) => boolean) => items.reduce((n, t) => n + (pred(t) ? 1 : 0), 0)

/** 语义色到背景类（完整类名写出，便于 Tailwind 扫描）。 */
export const toneBg: Record<Tone, string> = { threat: 'bg-threat', warn: 'bg-warn', ok: 'bg-ok', signal: 'bg-signal', mute: 'bg-ink-4' }
export const toneText: Record<Tone, string> = { threat: 'text-threat', warn: 'text-warn', ok: 'text-ok', signal: 'text-signal', mute: 'text-ink' }
