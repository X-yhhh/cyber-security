<script setup lang="ts">
/**
 * 读数带（视觉基线 v2）：页面顶部一条面板，内含 2—4 个关键计数，借用首屏“读数”的形式（标签 + 等宽数字）。
 *
 * - `value` 为 undefined 的读数不渲染（后端未返回该字段＝无权限，不补 0）；null 显示 `—`。
 * - 字符串值（如时间）用较小字号显示；`tone` 只在数值大于 0 时给数字着色；`to` 使读数可点击进入对应列表。
 * - `hint` 写明统计口径，例如“按当前页 50 条统计”，页面不得把当前页计数说成总量。
 */
import { computed, type Component } from 'vue'
import { RouterLink, type RouteLocationRaw } from 'vue-router'
import { toneText } from './viz'
import type { Tone } from '@/data/tones'

export interface Stat { key: string; label: string; value: number | string | null | undefined; icon?: Component; tone?: Tone; hint?: string; to?: RouteLocationRaw }

const props = defineProps<{ stats: readonly Stat[]; label?: string }>()
const shown = computed(() => props.stats.filter((s) => s.value !== undefined))
</script>

<template>
  <section v-if="shown.length" class="panel grid grid-cols-2 items-stretch overflow-hidden md:grid-cols-[repeat(var(--n),minmax(0,1fr))]" :style="{ '--n': shown.length }" :aria-label="label ?? '概览'">
    <component
      :is="s.to ? RouterLink : 'div'"
      v-for="(s, i) in shown"
      :key="s.key"
      v-bind="s.to ? { to: s.to } : {}"
      class="group flex min-w-0 flex-col justify-center border-ink-hair px-5 py-4"
      :class="[i > 0 ? 'md:border-l' : '', i % 2 === 1 ? 'border-l md:border-l' : '', i >= 2 ? 'border-t md:border-t-0' : '', s.to ? 'transition-colors hover:bg-paper-soft' : '']"
      data-stat
    >
      <p class="flex items-center gap-2 text-[12.5px] text-ink-3">
        <component :is="s.icon" v-if="s.icon" :size="15" :stroke-width="1.5" class="shrink-0 text-ink-3" aria-hidden="true" />
        <span class="truncate">{{ s.label }}</span>
      </p>
      <p v-if="typeof s.value === 'string'" class="num mt-3 text-[15px] leading-tight text-ink">{{ s.value }}</p>
      <p v-else class="num mt-2 text-[1.75rem] font-light leading-none tracking-[-0.02em]" :class="s.value && s.tone ? toneText[s.tone] : 'text-ink'">{{ typeof s.value === 'number' ? s.value.toLocaleString('zh-CN') : '—' }}</p>
      <p v-if="s.hint" class="mt-2 truncate text-[11.5px] text-ink-4" :title="s.hint">{{ s.hint }}</p>
    </component>
  </section>
</template>
