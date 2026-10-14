<script setup lang="ts">
/**
 * 阶段流水线（视觉基线 v2）：用于本身有先后顺序的生命周期（如发布组合 candidate → evaluated → approved → active）。
 * 每段显示阶段名、数量与一句口径；数量为 undefined 时整条不渲染（无权限，不补 0）。点击阶段发出 `select`。
 */
import { ChevronRight } from 'lucide-vue-next'
import type { Tone } from '@/data/tones'
import { toneBg, toneText } from './viz'

export interface Step { key: string; label: string; value: number; note?: string; tone?: Tone }

defineProps<{ steps: readonly Step[]; title: string; current?: string }>()
const emit = defineEmits<{ select: [key: string] }>()
</script>

<template>
  <section class="panel" :aria-label="title">
    <header class="px-5 pt-4 text-[15px] font-medium">{{ title }}</header>
    <ol class="grid gap-2 p-3 sm:grid-cols-2 lg:grid-cols-[repeat(var(--n),minmax(0,1fr))]" :style="{ '--n': steps.length }">
      <li v-for="(s, i) in steps" :key="s.key" class="relative">
        <button
          type="button"
          class="flex h-full w-full flex-col rounded border px-4 py-3 text-left transition-colors"
          :class="current === s.key ? 'border-ink bg-paper' : 'border-ink-hair bg-paper-soft hover:border-ink-line hover:bg-paper'"
          :aria-pressed="current === s.key"
          @click="emit('select', s.key)"
        >
          <span class="flex items-center gap-2 text-[12.5px] text-ink-3">
            <span class="num inline-flex h-5 w-5 items-center justify-center rounded-full border border-ink-line bg-paper text-[11px] text-ink-2">{{ i + 1 }}</span>
            {{ s.label }}
            <span class="dot ml-auto" :class="toneBg[s.tone ?? 'mute']" />
          </span>
          <span class="num mt-2 text-[1.75rem] font-light leading-none" :class="s.value && s.tone ? toneText[s.tone] : 'text-ink'">{{ s.value }}</span>
          <span v-if="s.note" class="mt-1.5 text-[11.5px] leading-snug text-ink-4">{{ s.note }}</span>
        </button>
        <ChevronRight v-if="i < steps.length - 1" :size="14" :stroke-width="1.5" class="absolute -right-[11px] top-1/2 z-10 hidden -translate-y-1/2 rounded-full bg-paper text-ink-4 lg:block" aria-hidden="true" />
      </li>
    </ol>
  </section>
</template>
