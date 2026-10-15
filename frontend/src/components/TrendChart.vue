<script setup lang="ts">
/**
 * 轻量趋势图（前端设计文档第 3.6、5 节，任务单 U0.6）：SVG 折线与横向排行条，不引入图表依赖。
 *
 * - `kind="line"`（默认）：`x` 为时间点标签，`series[].points` 与之等长；`null` 点留空、折线在此断开，
 *   全部为空时只显示「该时段无数据」，不画平线。同图最多 5 条线，多出的丢弃并打印控制台警告。
 * - `kind="rank"`：`items` 按数值降序画横向排行条。
 * - 悬浮读数：指针悬停或聚焦后用左右方向键移动读数位置；另附读屏可用的数值表。
 * - `exportable` 时显示「导出 CSV」，点击触发 `export` 事件并带上 CSV 文本，由页面决定下载或复制。
 * - 颜色只来自固定调色板（chart.ts），按类别稳定分配；坐标轴与网格用发丝线，不加背景色块。
 * - 序列可选 `area`（线下浅色填充，只填有数据的连续段）与 `dashed`（虚线，用于汇总线）；
 *   `live` 时在每条线最后一个有数据的点上画脉冲圆点，提示这是持续刷新的数据。
 */
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { MAX_SERIES, chartPalette, niceMax, segments, toCsv, toneOf, type ChartTone } from './chart'

export interface TrendSeries { key: string; name: string; tone?: ChartTone; points: readonly (number | null)[]; area?: boolean; dashed?: boolean }
export interface RankItem { key: string; name: string; value: number; tone?: ChartTone }

const props = withDefaults(defineProps<{
  title: string
  kind?: 'line' | 'rank'
  x?: readonly string[]
  series?: readonly TrendSeries[]
  items?: readonly RankItem[]
  /** 时间范围说明，如「最近 1 小时」，显示在图例右侧。 */
  range?: string
  unit?: string
  height?: number
  emptyText?: string
  exportable?: boolean
  live?: boolean
}>(), { kind: 'line', x: () => [], series: () => [], items: () => [], height: 180, emptyText: '该时段无数据' })
const emit = defineEmits<{ export: [csv: string] }>()

if (props.series.length > MAX_SERIES) console.warn(`[TrendChart] 「${props.title}」超过 ${MAX_SERIES} 条线，多出的不显示。`)

/* ---------- 折线 ---------- */
const lines = computed(() => props.series.slice(0, MAX_SERIES).map((s) => ({ ...s, color: chartPalette[toneOf(s.key, s.tone)] })))
const count = computed(() => Math.max(props.x.length, ...lines.value.map((s) => s.points.length), 0))
const values = computed(() => lines.value.flatMap((s) => s.points.filter((v): v is number => v !== null && Number.isFinite(v))))
const hasData = computed(() => values.value.length > 0)
const yMax = computed(() => niceMax(Math.max(0, ...values.value)))

const box = ref<HTMLElement>()
const width = ref(640)
let ro: ResizeObserver | undefined
onMounted(() => {
  const measure = () => { if (box.value?.clientWidth) width.value = box.value.clientWidth }
  measure()
  if (typeof ResizeObserver !== 'undefined' && box.value) {
    ro = new ResizeObserver(measure)
    ro.observe(box.value)
  }
})
onBeforeUnmount(() => ro?.disconnect())

const pad = { left: 40, right: 12, top: 10, bottom: 24 }
const innerW = computed(() => Math.max(1, width.value - pad.left - pad.right))
const innerH = computed(() => Math.max(1, props.height - pad.top - pad.bottom))
const px = (i: number) => pad.left + (count.value <= 1 ? innerW.value / 2 : (i * innerW.value) / (count.value - 1))
const py = (v: number) => pad.top + innerH.value * (1 - v / yMax.value)

const fmt = (v: number) => v.toLocaleString('zh-CN', { maximumFractionDigits: 2 })
const ticks = computed(() => [0, yMax.value / 2, yMax.value])
/** x 轴最多标 4 个时间点（首、尾与均分点），避免文字重叠。 */
const xTicks = computed(() => {
  const n = count.value
  if (!n) return []
  const want = Math.min(n, 4)
  const idx = want === 1 ? [0] : Array.from({ length: want }, (_, k) => Math.round((k * (n - 1)) / (want - 1)))
  return [...new Set(idx)].map((i) => ({ i, label: props.x[i] ?? '' }))
})

const paths = computed(() => lines.value.map((s) => {
  const segs = segments(s.points)
  return {
    key: s.key,
    color: s.color,
    d: segs.filter((g) => g.length > 1).map((g) => g.map(([i, v], k) => `${k ? 'L' : 'M'}${px(i).toFixed(1)} ${py(v).toFixed(1)}`).join(' ')).join(' '),
    /** 前后都无数据的孤立点画成小圆点，否则会因为没有线段而看不见。 */
    dots: segs.filter((g) => g.length === 1).map(([[i, v]]) => ({ i, cx: px(i), cy: py(v) })),
    dashed: s.dashed,
    /** 面积只覆盖连续有数据的段，断点处不填充。 */
    area: s.area
      ? segs.filter((g) => g.length > 1).map((g) => {
        const base = py(0).toFixed(1)
        const line = g.map(([i, v], k) => `${k ? 'L' : 'M'}${px(i).toFixed(1)} ${py(v).toFixed(1)}`).join(' ')
        return `${line} L${px(g[g.length - 1][0]).toFixed(1)} ${base} L${px(g[0][0]).toFixed(1)} ${base} Z`
      }).join(' ')
      : '',
    last: (() => {
      const g = segs[segs.length - 1]
      const p = g?.[g.length - 1]
      return p ? { cx: px(p[0]), cy: py(p[1]) } : null
    })(),
  }
}))

const hover = ref<number | null>(null)
function onMove(e: PointerEvent) {
  const svg = e.currentTarget as SVGElement
  const rect = svg.getBoundingClientRect()
  if (!rect.width || !count.value) return
  const xIn = ((e.clientX - rect.left) / rect.width) * width.value
  const i = count.value <= 1 ? 0 : Math.round(((xIn - pad.left) / innerW.value) * (count.value - 1))
  hover.value = Math.min(count.value - 1, Math.max(0, i))
}
function onKey(e: KeyboardEvent) {
  if (!count.value) return
  const cur = hover.value ?? count.value - 1
  if (e.key === 'ArrowLeft') hover.value = Math.max(0, cur - 1)
  else if (e.key === 'ArrowRight') hover.value = Math.min(count.value - 1, cur + 1)
  else if (e.key === 'Escape') hover.value = null
  else return
  e.preventDefault()
}
const readout = computed(() => {
  const i = hover.value
  if (i === null) return null
  const rows = lines.value.map((s) => ({ key: s.key, name: s.name, color: s.color, value: s.points[i] ?? null }))
  return { i, x: px(i), label: props.x[i] ?? `#${i + 1}`, rows, empty: rows.every((r) => r.value === null) }
})

/* ---------- 排行 ---------- */
const ranked = computed(() => [...props.items].sort((a, b) => b.value - a.value).map((it) => ({ ...it, color: chartPalette[toneOf(it.key, it.tone)] })))
const rankMax = computed(() => Math.max(0, ...ranked.value.map((r) => r.value)))

/* ---------- 导出 ---------- */
function csv(): string {
  if (props.kind === 'rank') return toCsv(['名称', props.unit ? `数值（${props.unit}）` : '数值'], ranked.value.map((r) => [r.name, r.value]))
  return toCsv(['时间', ...lines.value.map((s) => s.name)], Array.from({ length: count.value }, (_, i) => [props.x[i] ?? '', ...lines.value.map((s) => s.points[i] ?? null)]))
}
</script>

<template>
  <figure class="min-w-0" :aria-label="title">
    <figcaption v-if="kind === 'line' || range || exportable" class="mb-3 flex flex-wrap items-center justify-between gap-x-6 gap-y-2 text-[12px] text-ink-3">
      <ul v-if="kind === 'line'" class="flex flex-wrap items-center gap-x-4 gap-y-1">
        <li v-for="s in lines" :key="s.key" class="inline-flex items-center gap-1.5"><span class="h-0 w-3 border-t-2" :class="s.dashed ? 'border-dashed' : ''" :style="{ borderColor: s.color }" />{{ s.name }}</li>
      </ul>
      <span v-else>{{ title }}</span>
      <span class="flex items-center gap-4">
        <span v-if="range">{{ range }}<template v-if="unit"> · 单位 {{ unit }}</template></span>
        <button v-if="exportable" type="button" class="link text-[12px] text-ink-3" @click="emit('export', csv())">导出 CSV</button>
      </span>
    </figcaption>

    <!-- 折线 -->
    <div v-if="kind === 'line'" ref="box" class="relative" :style="{ height: `${height}px` }">
      <svg
        :width="width"
        :height="height"
        :viewBox="`0 0 ${width} ${height}`"
        class="block overflow-visible outline-none focus-visible:outline focus-visible:outline-1 focus-visible:outline-ink"
        role="img"
        :aria-label="`${title}折线图`"
        tabindex="0"
        @pointermove="onMove"
        @pointerleave="hover = null"
        @focus="hover = hover ?? (count ? count - 1 : null)"
        @blur="hover = null"
        @keydown="onKey"
      >
        <g aria-hidden="true">
          <template v-for="t in ticks" :key="t">
            <line :x1="pad.left" :x2="width - pad.right" :y1="py(t)" :y2="py(t)" stroke="#EDEBE6" stroke-width="1" />
            <text :x="pad.left - 8" :y="py(t)" dy="0.32em" text-anchor="end" class="num" font-size="11" fill="#6B6E75">{{ fmt(t) }}</text>
          </template>
          <text v-for="t in xTicks" :key="t.i" :x="px(t.i)" :y="height - 6" :text-anchor="count <= 1 ? 'middle' : t.i === 0 ? 'start' : t.i === count - 1 ? 'end' : 'middle'" class="num" font-size="11" fill="#6B6E75">{{ t.label }}</text>
        </g>
        <g v-if="hasData">
          <template v-for="p in paths" :key="p.key">
            <path v-if="p.area" :d="p.area" :fill="p.color" fill-opacity="0.07" stroke="none" data-series-area />
            <path v-if="p.d" :d="p.d" fill="none" :stroke="p.color" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round" :stroke-dasharray="p.dashed ? '4 3' : undefined" data-series-path />
            <template v-if="live && p.last">
              <circle :cx="p.last.cx" :cy="p.last.cy" r="6" :fill="p.color" fill-opacity="0.18" class="chart-pulse" />
              <circle :cx="p.last.cx" :cy="p.last.cy" r="2.5" :fill="p.color" />
            </template>
            <circle v-for="d in p.dots" :key="d.i" :cx="d.cx" :cy="d.cy" r="2" :fill="p.color" data-series-dot />
          </template>
        </g>
        <g v-if="readout" aria-hidden="true">
          <line :x1="readout.x" :x2="readout.x" :y1="pad.top" :y2="height - pad.bottom" stroke="#9A9CA1" stroke-width="1" stroke-dasharray="2 3" />
          <template v-for="r in readout.rows" :key="r.key">
            <circle v-if="r.value !== null" :cx="readout.x" :cy="py(r.value)" r="3" fill="#FFFFFF" :stroke="r.color" stroke-width="1.5" />
          </template>
        </g>
      </svg>
      <p v-if="!hasData" class="pointer-events-none absolute inset-0 flex items-center justify-center pb-6 text-[12.5px] text-ink-3">{{ emptyText }}</p>
      <div
        v-if="readout"
        class="pointer-events-none absolute top-0 z-10 min-w-[8rem] rounded border border-ink-line bg-paper px-3 py-2 text-[12px] shadow-panel"
        :style="readout.x > width / 2 ? { right: `${width - readout.x + 10}px` } : { left: `${readout.x + 10}px` }"
        role="status"
        data-readout
      >
        <p class="num mb-1 text-ink-3">{{ readout.label }}</p>
        <p v-if="readout.empty" class="text-ink-3">该时段无数据</p>
        <template v-else>
          <p v-for="r in readout.rows" :key="r.key" class="flex items-center justify-between gap-4">
            <span class="inline-flex items-center gap-1.5 text-ink-2"><span class="dot" :style="{ background: r.color }" />{{ r.name }}</span>
            <span class="num" :class="r.value === null ? 'text-ink-4' : 'text-ink'">{{ r.value === null ? '无数据' : fmt(r.value) }}</span>
          </p>
        </template>
      </div>
      <!-- 表格的固有宽度不能由 sr-only 直接收缩，使用容器裁切并保留读屏语义。 -->
      <div class="sr-only">
      <table>
        <caption>{{ title }}数值表</caption>
        <thead><tr><th scope="col">时间</th><th v-for="s in lines" :key="s.key" scope="col">{{ s.name }}</th></tr></thead>
        <tbody>
          <tr v-for="i in count" :key="i"><th scope="row">{{ x[i - 1] ?? i }}</th><td v-for="s in lines" :key="s.key">{{ s.points[i - 1] ?? '无数据' }}</td></tr>
        </tbody>
      </table>
      </div>
    </div>

    <!-- 排行 -->
    <template v-else>
      <p v-if="!ranked.length" class="py-6 text-center text-[12.5px] text-ink-3">{{ emptyText }}</p>
      <ol v-else class="space-y-2.5">
        <li v-for="r in ranked" :key="r.key" class="grid grid-cols-[minmax(0,8rem)_1fr_auto] items-center gap-3 text-[12.5px]" :title="`${r.name}：${fmt(r.value)}${unit ? ` ${unit}` : ''}`">
          <span class="truncate text-ink-2">{{ r.name }}</span>
          <span class="h-1.5 overflow-hidden rounded-full bg-paper-soft">
            <span class="block h-full rounded-full" :style="{ width: `${rankMax ? (r.value / rankMax) * 100 : 0}%`, background: r.color }" data-rank-bar />
          </span>
          <span class="num text-ink">{{ fmt(r.value) }}</span>
        </li>
      </ol>
    </template>
  </figure>
</template>
