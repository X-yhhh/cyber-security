<script setup lang="ts" generic="T extends string">
/**
 * 因果链导航（视觉基线 v2）：把一条有先后的证据链（如 批次 → 观察 → 推理 → 证据迹）画成相连的节点，
 * 每个节点是一个分段选项（role="tab"），显示图标、名称、当前页条数与一句说明。键盘约定同 Segmented。
 */
import type { Component } from 'vue'
import { ChevronRight } from 'lucide-vue-next'
import { tabKeydown } from '@/composables/tabs'

const props = defineProps<{ options: { value: T; label: string; icon: Component; count?: number; note?: string }[]; label?: string }>()
const model = defineModel<T>({ required: true })
const onKey = (e: KeyboardEvent) => tabKeydown(e, props.options.map((o) => o.value), model.value, (v) => { model.value = v })
</script>

<template>
  <div class="grid gap-2 sm:grid-cols-2 lg:grid-cols-[repeat(var(--n),minmax(0,1fr))]" :style="{ '--n': options.length }" role="tablist" :aria-label="label">
    <div v-for="(o, i) in options" :key="o.value" class="relative">
      <button
        type="button"
        role="tab"
        :aria-selected="model === o.value"
        :tabindex="model === o.value ? 0 : -1"
        class="flex h-full w-full items-start gap-3 rounded-panel border px-4 py-3.5 text-left transition-colors duration-200"
        :class="model === o.value ? 'border-ink bg-ink text-paper' : 'border-ink-line bg-paper hover:border-ink-4'"
        @click="model = o.value"
        @keydown="onKey"
      >
        <span class="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded border" :class="model === o.value ? 'border-paper/25' : 'border-ink-line text-ink-2'">
          <component :is="o.icon" :size="16" :stroke-width="1.5" aria-hidden="true" />
        </span>
        <span class="min-w-0 flex-1">
          <span class="flex items-baseline justify-between gap-2">
            <span class="text-[13.5px] font-medium">{{ o.label }}</span>
            <span v-if="o.count !== undefined" class="num text-[13px]" :class="model === o.value ? 'text-paper/80' : 'text-ink-3'">{{ o.count }}</span>
          </span>
          <span v-if="o.note" class="mt-0.5 block text-[12px] leading-snug" :class="model === o.value ? 'text-paper/70' : 'text-ink-3'">{{ o.note }}</span>
        </span>
      </button>
      <span v-if="i < options.length - 1" class="absolute -right-[13px] top-1/2 z-10 hidden h-5 w-5 -translate-y-1/2 items-center justify-center rounded-full border border-ink-line bg-paper text-ink-3 lg:inline-flex" aria-hidden="true">
        <ChevronRight :size="12" :stroke-width="1.5" />
      </span>
    </div>
  </div>
</template>
