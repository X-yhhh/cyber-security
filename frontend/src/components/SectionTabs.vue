<script setup lang="ts" generic="T extends string">
/**
 * 详情页分段（前端设计文档第 4.3、5 节，任务单 U0.5）：概况 / 授权 / 接入设备 … 这类同一对象的不同视图。
 *
 * - 选项按 `anyOf` 与会话权限过滤，无权限的分段不渲染；当前值不可见时自动切到第一个可见分段；
 *   一个分段都不可见时不渲染任何内容，页面用 `visibleTabs()` 自行决定是否隐藏整页。
 * - 无障碍约定与 Segmented 相同（composables/tabs.ts）：tablist/tab、aria-selected、漫游 tabindex 与方向键。
 * - 前端过滤只用于隐藏入口，授权以后端为准。
 */
import { computed, watch } from 'vue'
import { session } from '@/api/session'
import { tabKeydown, visibleTabs, type TabOption } from '@/composables/tabs'

const props = defineProps<{ options: readonly TabOption<T>[]; label?: string }>()
const model = defineModel<T>({ required: true })

const shown = computed(() => visibleTabs(props.options, session.user?.permissions))
watch(shown, (list) => {
  if (list.length && !list.some((o) => o.value === model.value)) model.value = list[0].value
}, { immediate: true })

const onKey = (e: KeyboardEvent) => tabKeydown(e, shown.value.map((o) => o.value), model.value, (v) => { model.value = v })
</script>

<template>
  <div v-if="shown.length" class="inline-flex max-w-full gap-0.5 overflow-x-auto rounded bg-paper-soft p-0.5" role="tablist" :aria-label="label">
    <button
      v-for="o in shown"
      :key="o.value"
      type="button"
      role="tab"
      :aria-selected="model === o.value"
      :tabindex="model === o.value ? 0 : -1"
      class="inline-flex h-7 items-center gap-1.5 whitespace-nowrap rounded-sm px-3 text-[13px] transition-colors duration-200"
      :class="model === o.value ? 'bg-paper font-medium text-ink shadow-[0_0_0_1px_#E2E0DA]' : 'text-ink-3 hover:text-ink'"
      @click="model = o.value"
      @keydown="onKey"
    >
      {{ o.label }}<span v-if="o.count !== undefined" class="num text-[11px]" :class="model === o.value ? 'text-ink-3' : 'text-ink-4'">{{ o.count }}</span>
    </button>
  </div>
</template>
