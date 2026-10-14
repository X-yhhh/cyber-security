<script setup lang="ts">
/**
 * 工作台卡片：一个标题、若干计数行，可点击跳到对应列表并带上状态筛选。
 * 数值为 null 表示汇总接口未返回该字段（调用者无对应权限），该行不显示；
 * 卡片自身是否渲染由工作台按 anyOf 决定，这里不重复判断权限。
 */
import { RouterLink, type RouteLocationRaw } from 'vue-router'
import { ArrowRight } from 'lucide-vue-next'

export interface SummaryLine { label: string; value: number | null | undefined; to?: RouteLocationRaw; tone?: 'threat' | 'signal' }

defineProps<{ title: string; en?: string; lines: SummaryLine[]; note?: string }>()
/** 完整类名写出，避免 Tailwind 扫描不到拼接出的类。 */
const toneText = { threat: 'text-threat', signal: 'text-signal' } as const
</script>

<template>
  <section class="border-t border-ink pt-5" :aria-label="title">
    <p v-if="en" class="label mb-2">{{ en }}</p>
    <h2 class="text-[1.125rem] font-light">{{ title }}</h2>
    <ul class="mt-5">
      <template v-for="l in lines" :key="l.label">
        <li v-if="l.value !== null && l.value !== undefined" class="border-b border-ink-hair">
          <component
            :is="l.to ? RouterLink : 'div'"
            v-bind="l.to ? { to: l.to } : {}"
            class="group flex items-baseline justify-between gap-6 py-3"
            :class="l.to ? 'transition-colors hover:bg-paper-soft' : ''"
          >
            <span class="text-[13px] text-ink-2">{{ l.label }}</span>
            <span class="flex items-center gap-2">
              <span class="num text-[1.5rem] font-light leading-none" :class="l.value > 0 && l.tone ? toneText[l.tone] : 'text-ink'">{{ l.value }}</span>
              <ArrowRight v-if="l.to" :size="13" :stroke-width="1.5" class="text-ink-4 transition-colors group-hover:text-ink" />
            </span>
          </component>
        </li>
      </template>
    </ul>
    <p v-if="note" class="mt-3 text-[12px] leading-relaxed text-ink-4">{{ note }}</p>
    <slot />
  </section>
</template>
