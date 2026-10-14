<script setup lang="ts">
/**
 * 右侧详情抽屉。初次挂载即打开时也绑定键盘；焦点留在模态内，关闭后归还触发元素。
 * 视觉基线 v2：抽屉是页面中唯一允许带阴影（shadow-panel）的容器。
 */
import { nextTick, onBeforeUnmount, ref, watch } from 'vue'
import { X } from 'lucide-vue-next'

const props = defineProps<{ open: boolean; title: string; kicker?: string }>()
const emit = defineEmits<{ close: [] }>()
const head = ref<HTMLElement>()
const panel = ref<HTMLElement>()
let trigger: HTMLElement | null = null

function restoreFocus() {
  if (trigger?.isConnected) trigger.focus()
  trigger = null
}
function onKey(e: KeyboardEvent) {
  if (e.key === 'Escape') {
    e.preventDefault()
    emit('close')
  } else if (e.key === 'Tab') {
    const controls = Array.from(panel.value?.querySelectorAll<HTMLElement>(
      'button:not([disabled]), a[href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex="0"]',
    ) ?? []).filter((el) => el.getClientRects().length > 0)
    const first = controls[0], last = controls[controls.length - 1]
    if (!first) { e.preventDefault(); head.value?.focus() }
    else if (e.shiftKey && (document.activeElement === first || document.activeElement === head.value)) {
      e.preventDefault(); last?.focus()
    } else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus() }
  }
}
watch(
  () => props.open,
  (v) => {
    if (v) {
      trigger = document.activeElement instanceof HTMLElement ? document.activeElement : null
      document.addEventListener('keydown', onKey)
      nextTick(() => head.value?.focus())
    } else {
      document.removeEventListener('keydown', onKey)
      restoreFocus()
    }
  },
  { immediate: true },
)
onBeforeUnmount(() => { document.removeEventListener('keydown', onKey); restoreFocus() })
</script>

<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="open" class="fixed inset-0 z-40 bg-ink/10" @click="emit('close')" />
    </Transition>
    <Transition name="drawer">
      <aside ref="panel" v-if="open" class="fixed inset-y-0 right-0 z-50 flex w-full max-w-[520px] flex-col border-l border-ink-line bg-paper shadow-panel" role="dialog" aria-modal="true" :aria-label="title">
        <div class="flex items-start justify-between gap-4 border-b border-ink-hair px-6 pb-4 pt-5">
          <div class="min-w-0">
            <p v-if="kicker" class="mb-1 truncate text-[12px] text-ink-3">{{ kicker }}</p>
            <h2 ref="head" tabindex="-1" class="break-words text-[1.125rem] font-medium leading-snug outline-none">{{ title }}</h2>
          </div>
          <button class="-mr-1 shrink-0 rounded p-1 text-ink-3 transition-colors hover:bg-paper-soft hover:text-ink" aria-label="关闭" @click="emit('close')"><X :size="18" :stroke-width="1.5" /></button>
        </div>
        <div class="flex-1 overflow-y-auto px-6 py-5"><slot /></div>
        <div v-if="$slots.foot" class="flex items-center justify-end gap-4 border-t border-ink-hair px-6 py-3"><slot name="foot" /></div>
      </aside>
    </Transition>
  </Teleport>
</template>
