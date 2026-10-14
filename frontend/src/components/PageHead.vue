<script setup lang="ts">
/**
 * 页头（视觉基线 v2）：图标方块 + 标题（1.5rem）+ 一句说明，右侧 slot 放该页的操作（主操作唯一）。
 *
 * - 图标默认取当前路由对应菜单项的图标（nav.ts），也可用 `icon` 显式指定；没有路由上下文时不显示。
 * - `no` 为可选页面编号，11px 常规字体，与标题同一行。
 */
import { computed, type Component } from 'vue'
import { useRoute } from 'vue-router'
import { itemOf } from '@/router/nav'

const props = defineProps<{ no?: string; title: string; desc?: string; icon?: Component }>()
const route = useRoute() as ReturnType<typeof useRoute> | undefined
const glyph = computed(() => props.icon ?? itemOf(route?.meta?.group, route?.meta?.item)?.icon)
</script>

<template>
  <div class="mb-6 flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
    <div class="flex min-w-0 items-start gap-4">
      <span v-if="glyph" class="relative mt-0.5 inline-flex h-11 w-11 shrink-0 items-center justify-center rounded border border-ink-line bg-paper text-ink" aria-hidden="true">
        <component :is="glyph" :size="20" :stroke-width="1.5" />
      </span>
      <div class="min-w-0">
        <div class="flex items-baseline gap-2.5">
          <span v-if="no" class="text-[11px] text-ink-4">{{ no }}</span>
          <h1 class="text-[1.5rem] font-medium leading-tight tracking-[-0.01em] text-ink">{{ title }}</h1>
          <span v-if="$slots.kicker" class="text-[12px] text-ink-4"><slot name="kicker" /></span>
        </div>
        <p v-if="desc" class="mt-1.5 max-w-3xl text-[13px] leading-relaxed text-ink-3">{{ desc }}</p>
      </div>
    </div>
    <div v-if="$slots.default" class="flex shrink-0 flex-wrap items-center gap-2.5"><slot /></div>
  </div>
</template>
