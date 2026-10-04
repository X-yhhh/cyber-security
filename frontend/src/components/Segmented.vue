<script setup lang="ts" generic="T extends string">
/** 页内分段：文字 + 下划指示线，替代标签页面板。指示线在选项间滑动。 */
import { nextTick, onMounted, ref, watch } from 'vue'

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
</script>

<template>
  <div ref="wrap" class="relative flex gap-8 border-b border-ink-hair" role="tablist">
    <button
      v-for="o in options"
      :key="o.value"
      :data-v="o.value"
      role="tab"
      :aria-selected="model === o.value"
      class="pb-3 text-[13.5px] transition-colors duration-300"
      :class="model === o.value ? 'text-ink' : 'text-ink-3 hover:text-ink'"
      @click="model = o.value"
    >
      {{ o.label }}<span v-if="o.count !== undefined" class="num ml-2 text-[11px] text-ink-4">{{ o.count }}</span>
    </button>
    <span class="absolute -bottom-px h-px bg-ink transition-all duration-500 ease-out" :style="{ left: bar.left + 'px', width: bar.width + 'px' }" />
  </div>
</template>
