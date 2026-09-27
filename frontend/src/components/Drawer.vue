<script setup lang="ts">
/** 右侧详情抽屉。Esc 关闭，打开时锁定焦点起点到标题。 */
import { nextTick, onBeforeUnmount, ref, watch } from 'vue'
import { X } from 'lucide-vue-next'

const props = defineProps<{ open: boolean; title: string; kicker?: string }>()
const emit = defineEmits<{ close: [] }>()
const head = ref<HTMLElement>()

const onKey = (e: KeyboardEvent) => e.key === 'Escape' && emit('close')
watch(
  () => props.open,
  (v) => {
    if (v) {
      document.addEventListener('keydown', onKey)
      nextTick(() => head.value?.focus())
    } else document.removeEventListener('keydown', onKey)
  },
)
onBeforeUnmount(() => document.removeEventListener('keydown', onKey))
</script>

<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="open" class="fixed inset-0 z-40 bg-ink/10" @click="emit('close')" />
    </Transition>
    <Transition name="drawer">
      <aside v-if="open" class="fixed inset-y-0 right-0 z-50 flex w-full max-w-[520px] flex-col border-l border-ink-line bg-paper" role="dialog" aria-modal="true" :aria-label="title">
        <div class="flex items-start justify-between px-10 pb-8 pt-10">
          <div>
            <p v-if="kicker" class="label mb-3">{{ kicker }}</p>
            <h2 ref="head" tabindex="-1" class="text-[1.5rem] font-light leading-snug tracking-[-0.01em] outline-none">{{ title }}</h2>
          </div>
          <button class="p-1 text-ink-3 transition-colors hover:text-ink" aria-label="关闭" @click="emit('close')"><X :size="18" :stroke-width="1.5" /></button>
        </div>
        <div class="flex-1 overflow-y-auto px-10 pb-10"><slot /></div>
        <div v-if="$slots.foot" class="flex items-center justify-end gap-6 border-t border-ink-hair px-10 py-5"><slot name="foot" /></div>
      </aside>
    </Transition>
  </Teleport>
</template>
