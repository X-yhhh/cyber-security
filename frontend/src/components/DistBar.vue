<script setup lang="ts">
/**
 * 构成条（视觉基线 v2）：一条分段横条 + 图例，展示某个字段在已加载数据中的构成（如事件状态）。
 * 颜色只来自语义色映射（data/tones.ts）；段宽按数量折算，图例给出条数与占比。没有数据时显示范围化的空态。
 */
import { computed } from 'vue'
import { toneBg, type Segment } from './viz'

const props = withDefaults(defineProps<{ segments: readonly Segment[]; emptyText?: string; max?: number }>(), { emptyText: '暂无可统计的记录', max: 6 })
const total = computed(() => props.segments.reduce((n, s) => n + s.value, 0))
/** 超出 max 的类别并入“其他”，避免图例过长。 */
const shown = computed(() => {
  if (props.segments.length <= props.max) return props.segments
  const head = props.segments.slice(0, props.max - 1)
  const rest = props.segments.slice(props.max - 1).reduce((n, s) => n + s.value, 0)
  return [...head, { key: '__other', label: '其他', value: rest, tone: 'mute' as const }]
})
const pct = (v: number) => (total.value ? Math.round((v / total.value) * 100) : 0)
</script>

<template>
  <div>
    <p v-if="!total" class="py-4 text-[12.5px] text-ink-3">{{ emptyText }}</p>
    <template v-else>
      <div class="flex h-2 gap-0.5 overflow-hidden rounded-full" role="img" :aria-label="shown.map((s) => `${s.label} ${s.value}`).join('，')">
        <span v-for="s in shown" :key="s.key" class="h-full first:rounded-l-full last:rounded-r-full" :class="toneBg[s.tone]" :style="{ width: `${(s.value / total) * 100}%` }" data-dist-seg />
      </div>
      <ul class="mt-3 grid grid-cols-2 gap-x-4 gap-y-1.5 text-[12.5px]">
        <li v-for="s in shown" :key="s.key" class="flex min-w-0 items-center gap-2">
          <span class="dot shrink-0" :class="toneBg[s.tone]" />
          <span class="truncate text-ink-2">{{ s.label }}</span>
          <span class="num ml-auto text-ink">{{ s.value }}</span>
          <span class="num w-9 text-right text-ink-4">{{ pct(s.value) }}%</span>
        </li>
      </ul>
    </template>
  </div>
</template>
