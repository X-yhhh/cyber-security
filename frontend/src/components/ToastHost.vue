<script setup lang="ts">
/**
 * 全局系统反馈：错误/警告使用原生 dialog 顶层，覆盖抽屉与遮罩且不自动消失。
 * 浏览器负责模态焦点隔离；关闭后恢复操作位置。多条提示按序确认，点击背景不关闭。
 */
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { CircleAlert, TriangleAlert, X } from 'lucide-vue-next'
import { alerts, dismissToast, toasts } from '@/composables/toast'

const dialog = ref<HTMLDialogElement>()
const confirm = ref<HTMLButtonElement>()
const message = ref<HTMLElement>()
const active = computed(() => alerts[0])
let trigger: HTMLElement | null = null
let lastFocused: HTMLElement | null = null

// 提交按钮在请求期间会禁用并失焦，保存最后一次真实操作位置供确认后恢复。
function rememberFocus(e: FocusEvent) {
  const el = e.target
  if (el instanceof HTMLElement && el !== document.body && el !== document.documentElement && !dialog.value?.contains(el)) lastFocused = el
}
onMounted(() => document.addEventListener('focusin', rememberFocus))

function onKey(e: KeyboardEvent) {
  e.stopPropagation()
  // 长文案可切到内容区用方向键滚动；短提示的 Tab/Shift+Tab 留在确认按钮。
  if (e.key === 'Tab') {
    e.preventDefault()
    const content = message.value
    if (content && content.scrollHeight > content.clientHeight && document.activeElement === confirm.value) content.focus()
    else confirm.value?.focus()
  }
}

function acknowledge() {
  if (active.value) dismissToast(active.value.id)
}
function closeDialog() {
  dialog.value?.close()
  if (trigger?.isConnected) trigger.focus()
  trigger = null
}
function syncDialog() {
  if (active.value && dialog.value) {
    if (!dialog.value.open) {
      trigger = document.activeElement instanceof HTMLElement && document.activeElement !== document.body ? document.activeElement : lastFocused
      dialog.value.showModal()
    }
    confirm.value?.focus()
  } else if (dialog.value?.open) closeDialog()
}
// 同时观察节点与队首，涵盖挂载前已入队及确认后切到下一条。
watch([dialog, () => active.value?.id], syncDialog, { flush: 'post' })
onBeforeUnmount(() => {
  document.removeEventListener('focusin', rememberFocus)
  if (dialog.value?.open) closeDialog()
})
</script>

<template>
  <Teleport to="body">
    <div class="pointer-events-none fixed bottom-4 right-4 z-[60] flex max-h-[50dvh] w-[360px] max-w-[calc(100vw-2rem)] flex-col gap-2 overflow-y-auto" aria-live="polite" aria-relevant="additions">
      <div v-for="t in toasts" :key="t.id" class="pointer-events-auto flex items-start gap-3 rounded border border-ink-line bg-paper px-4 py-3 shadow-panel" role="status">
        <span class="dot mt-[7px] shrink-0 bg-ink" aria-hidden="true" />
        <p class="min-w-0 flex-1 break-words text-[13px] leading-relaxed text-ink">{{ t.text }}</p>
        <button type="button" aria-label="关闭提示" class="shrink-0 rounded p-1 text-ink-3 hover:bg-paper-soft" @click="dismissToast(t.id)"><X :size="16" aria-hidden="true" /></button>
      </div>
    </div>
    <dialog ref="dialog" data-system-alert role="alertdialog" aria-modal="true" aria-labelledby="system-alert-title" aria-describedby="system-alert-message" class="system-alert m-auto max-h-[calc(100dvh-2rem)] w-[480px] max-w-[calc(100vw-2rem)] overflow-y-auto rounded-panel border border-ink-line bg-paper p-0 text-ink shadow-panel" @cancel.prevent="acknowledge" @keydown="onKey">
      <div v-if="active" class="flex max-h-[calc(100dvh-2rem-2px)] flex-col">
        <div class="flex shrink-0 items-center gap-3 border-b px-6 py-5" :class="active.tone === 'threat' ? 'border-threat/30 bg-threat-soft text-threat' : 'border-warn/30 bg-warn-soft text-warn'">
          <component :is="active.tone === 'threat' ? CircleAlert : TriangleAlert" :size="26" class="shrink-0" aria-hidden="true" />
          <h2 id="system-alert-title" class="text-lg font-medium">{{ active.tone === 'threat' ? '操作未完成' : '请注意' }}</h2>
        </div>
        <p ref="message" :key="active.id" id="system-alert-message" tabindex="-1" class="min-h-0 overflow-y-auto whitespace-pre-wrap break-words px-6 py-6 text-[15px] leading-relaxed">{{ active.text }}</p>
        <div class="flex shrink-0 items-center justify-between gap-4 border-t border-ink-hair px-6 py-4">
          <span class="text-[12px] text-ink-3">{{ alerts.length > 1 ? `还有 ${alerts.length - 1} 条提示待确认` : '请确认后继续操作' }}</span>
          <button ref="confirm" type="button" class="act shrink-0" autofocus @click="acknowledge">我知道了</button>
        </div>
      </div>
    </dialog>
  </Teleport>
</template>

<style scoped>
.system-alert::backdrop { background: rgb(15 23 42 / 38%); }
</style>
