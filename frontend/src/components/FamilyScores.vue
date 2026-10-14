<script setup lang="ts">
/**
 * 四类分数条：按固定类别顺序显示模型 family_scores，最高一类加深。
 * 分数只是模型输出，不代表判定；缺失（推理失败）时整体显示「—」而不是 0。
 */
import { computed } from 'vue'
import { GUARD_FAMILIES, guardFamilyLabel } from '@/api/types'

const props = defineProps<{ scores: Record<string, number> | null | undefined; compact?: boolean }>()
const rows = computed(() => {
  const s = props.scores
  if (!s || !Object.keys(s).length) return []
  const values = GUARD_FAMILIES.map((f) => ({ family: f, value: typeof s[f] === 'number' ? s[f] : null }))
  const top = Math.max(...values.map((v) => v.value ?? -1))
  return values.map((v) => ({ ...v, top: v.value !== null && v.value === top }))
})
const pct = (v: number | null) => `${Math.max(0, Math.min(1, v ?? 0)) * 100}%`
</script>

<template>
  <span v-if="!rows.length" class="num text-ink-4">—</span>
  <ul v-else class="grid gap-1" :class="compact ? 'w-40' : 'w-full max-w-sm'" :aria-label="'四类分数'">
    <li v-for="r in rows" :key="r.family" class="grid grid-cols-[4.5rem_1fr_3.25rem] items-center gap-2 text-[11.5px]">
      <span :class="r.top ? 'text-ink' : 'text-ink-3'">{{ guardFamilyLabel[r.family] }}</span>
      <span class="relative h-1 bg-ink-hair"><span class="absolute inset-y-0 left-0" :class="r.top ? 'bg-ink' : 'bg-ink-4'" :style="{ width: pct(r.value) }" /></span>
      <span class="num text-right" :class="r.top ? 'text-ink' : 'text-ink-4'">{{ r.value === null ? '—' : r.value.toFixed(3) }}</span>
    </li>
  </ul>
</template>
