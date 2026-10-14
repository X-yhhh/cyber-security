<script setup lang="ts">
/**
 * 待办中心计数卡片：一个面板、若干计数行，可点击跳到对应列表并带上状态筛选。
 *
 * - 数值为 null/undefined 表示汇总接口未返回该字段（调用者无对应权限），该行不显示，不补 0；
 * - 多于一行时，右上角显示本卡合计，每行下方画一条相对本卡最大值的比例条，便于一眼看出积压在哪；
 * - `badge` 为卡片状态标记（如“全部正常 / N 台异常”）。卡片是否渲染由待办中心按 anyOf 决定。
 */
import { computed, type Component } from 'vue'
import { RouterLink, type RouteLocationRaw } from 'vue-router'
import { ChevronRight } from 'lucide-vue-next'
import Panel from './Panel.vue'
import Tag from './Tag.vue'

export interface SummaryLine { label: string; value: number | null | undefined; to?: RouteLocationRaw; tone?: 'threat' | 'signal' }

const props = defineProps<{ title: string; en?: string; lines: SummaryLine[]; note?: string; icon?: Component; badge?: { label: string; tone: 'threat' | 'ok' } }>()
/** 完整类名写出，避免 Tailwind 扫描不到拼接出的类。 */
const toneText = { threat: 'text-threat', signal: 'text-signal' } as const
const toneBar = { threat: 'bg-threat', signal: 'bg-signal' } as const

const shown = computed(() => props.lines.filter((l): l is SummaryLine & { value: number } => typeof l.value === 'number'))
const max = computed(() => Math.max(0, ...shown.value.map((l) => l.value)))
const total = computed(() => shown.value.reduce((n, l) => n + l.value, 0))
</script>

<template>
  <Panel :title="title" :icon="icon" flush>
    <template v-if="badge || shown.length > 1" #actions>
      <Tag v-if="badge" pill :tone="badge.tone" :label="badge.label" />
      <span v-else class="text-[12px] text-ink-3">合计 <span class="num text-[13px] text-ink">{{ total.toLocaleString('zh-CN') }}</span></span>
    </template>
    <ul class="px-2 pb-2">
      <li v-for="l in shown" :key="l.label">
        <component
          :is="l.to ? RouterLink : 'div'"
          v-bind="l.to ? { to: l.to } : {}"
          class="group block rounded px-3 py-2.5"
          :class="l.to ? 'transition-colors hover:bg-paper-soft' : ''"
        >
          <span class="flex items-center justify-between gap-6">
            <span class="text-[13px] text-ink-2">{{ l.label }}</span>
            <span class="flex items-center gap-1.5">
              <span class="num text-[1.25rem] font-light leading-none" :class="l.value > 0 && l.tone ? toneText[l.tone] : 'text-ink'">{{ l.value.toLocaleString('zh-CN') }}</span>
              <ChevronRight v-if="l.to" :size="14" :stroke-width="1.5" class="text-ink-4 transition-colors group-hover:text-ink" />
              <span v-else class="w-3.5" aria-hidden="true" />
            </span>
          </span>
          <span v-if="shown.length > 1" class="mt-2 block h-1 overflow-hidden rounded-full bg-ink-hair" aria-hidden="true">
            <span class="block h-full rounded-full" :class="l.value > 0 && l.tone ? toneBar[l.tone] : 'bg-ink-3'" :style="{ width: `${max ? Math.max(l.value ? 2 : 0, (l.value / max) * 100) : 0}%` }" />
          </span>
        </component>
      </li>
    </ul>
    <template v-if="note" #foot><span>{{ note }}</span></template>
    <slot />
  </Panel>
</template>
