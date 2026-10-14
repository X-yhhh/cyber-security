<script setup lang="ts" generic="T extends string">
/** 页内分段：文字 + 下划指示线，替代标签页面板。指示线在选项间滑动；键盘约定见 composables/tabs.ts。 */
import { nextTick, onMounted, ref, watch } from 'vue'
import { tabKeydown } from '@/composables/tabs'

const props = defineProps<{ options: { value: T; label: string; count?: number }[] }>()
const model = defineModel<T>({ required: true })
const wrap = ref<HTMLElement>()
const bar = ref({ left: 0, width: 0 })

function measure() {
  const el = wrap.value?.querySelector<HTMLElement>(`[data-v="${model.value}"]`)
  if (el) bar.value = { left: el.offsetLeft, width: el.offsetWidth }
}
onMounted(() => nextTick(measure))
watch(() => [model.value, props.options.length], () => nextTick(measure))
const onKey = (e: KeyboardEvent) => tabKeydown(e, props.options.map((o) => o.value), model.value, (v) => { model.value = v })
</script>

<template>
  <div ref="wrap" class="relative flex gap-7 overflow-x-auto border-b border-ink-hair" role="tablist">
    <button
      v-for="o in options"
      :key="o.value"
      :data-v="o.value"
      type="button"
      role="tab"
      :aria-selected="model === o.value"
      :tabindex="model === o.value ? 0 : -1"
      class="whitespace-nowrap pb-2.5 text-[13.5px] transition-colors duration-300"
      :class="model === o.value ? 'font-medium text-ink' : 'text-ink-3 hover:text-ink'"
      @click="model = o.value"
      @keydown="onKey"
    >
      {{ o.label }}<span v-if="o.count !== undefined" class="num ml-1.5 text-[11px] text-ink-4">{{ o.count }}</span>
    </button>
    <span class="absolute bottom-0 h-0.5 rounded-full bg-ink transition-all duration-500 ease-out" :style="{ left: bar.left + 'px', width: bar.width + 'px' }" />
  </div>
</template>
