<script lang="ts">
import type { InjectionKey } from 'vue'

/** 面板嵌套检测键：外层 Panel 提供，内层 Panel 注入到即视为嵌套。 */
export const panelKey: InjectionKey<true> = Symbol('panel')
</script>

<script setup lang="ts">
/**
 * 面板（前端设计文档第 3.2、5 节，任务单 U0.3）：一级区块容器，标题 + 右上角操作 + 内容。
 *
 * - 白底、1px 边框、8px 圆角、无阴影；每页 2—4 块，面板内的分组用标题与间距表达。
 * - **不允许嵌套**：放进另一个 Panel 时在根元素标 `data-nested="true"`，并打印控制台警告，
 *   单测据此断言；样式不做任何兼容，避免嵌套被当成可用写法。
 * - `flush`：内容区去掉左右内边距，供表格贴边显示（表格首尾列由 `.panel-flush` 补齐内边距，并裁掉表头底色超出圆角的部分）。
 * - `icon`：标题左侧的线性图标（lucide），可选。
 * - 插槽：`actions` 放右上角操作（文字链接或 `.act-ghost`），`toolbar` 放标题下方一行的筛选条，默认插槽为内容。
 */
import { inject, provide, useSlots, type Component } from 'vue'

const props = defineProps<{ title?: string; desc?: string; flush?: boolean; tag?: 'section' | 'div'; icon?: Component }>()
const slots = useSlots()

const nested = inject(panelKey, false)
provide(panelKey, true)
if (nested) console.warn(`[Panel] 面板不允许嵌套${props.title ? `：「${props.title}」` : ''}，请改用标题与间距分组。`)

const hasHead = () => Boolean(props.title || props.desc || slots.actions)
</script>

<template>
  <component
    :is="tag ?? 'section'"
    class="panel min-w-0"
    :class="flush ? 'panel-flush overflow-hidden' : ''"
    :data-nested="nested ? 'true' : undefined"
    :aria-label="title"
  >
    <header v-if="hasHead()" class="flex items-start justify-between gap-4 px-5 pt-4" :class="$slots.toolbar ? 'pb-3' : 'pb-4'">
      <div class="min-w-0">
        <h2 v-if="title" class="flex items-center gap-2 text-[15px] font-medium leading-6 text-ink">
          <component :is="icon" v-if="icon" :size="16" :stroke-width="1.5" class="shrink-0 text-ink-3" aria-hidden="true" />{{ title }}
        </h2>
        <p v-if="desc" class="mt-0.5 text-[12px] leading-relaxed text-ink-3">{{ desc }}</p>
      </div>
      <div v-if="$slots.actions" class="flex shrink-0 items-center gap-3"><slot name="actions" /></div>
    </header>
    <div v-if="$slots.toolbar" class="flex flex-wrap items-center gap-3 px-5 pb-3.5" :class="hasHead() ? '' : 'pt-3.5'"><slot name="toolbar" /></div>
    <div :class="flush ? 'overflow-x-auto' : ['px-5 pb-5', hasHead() || $slots.toolbar ? '' : 'pt-5']">
      <slot />
    </div>
    <footer v-if="$slots.foot" class="flex items-center justify-between gap-4 border-t border-ink-hair px-5 py-3 text-[12.5px] text-ink-3"><slot name="foot" /></footer>
  </component>
</template>
