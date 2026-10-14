<script setup lang="ts">
/**
 * 标识符显示（前端设计文档第 3.5 节，任务单 U0.4）：UUID 等长标识符默认只显示前 8 位，
 * 后跟复制按钮；悬停（title）与读屏（aria-label）给出完整值。不超过显示长度的值原样显示。
 *
 * - 空值显示 `—`，不显示复制按钮；
 * - 复制只写剪贴板，不写本地存储；剪贴板不可用（非安全上下文或被拒绝）时提示手动复制，不抛错。
 */
import { computed, onBeforeUnmount, ref } from 'vue'
import { Check, Copy } from 'lucide-vue-next'
import { toast } from '@/composables/toast'

const props = withDefaults(defineProps<{ value: string | number | null | undefined; length?: number; copy?: boolean }>(), { length: 8, copy: true })

const full = computed(() => (props.value === null || props.value === undefined || props.value === '' ? '' : String(props.value)))
const short = computed(() => (full.value.length > props.length ? `${full.value.slice(0, props.length)}…` : full.value))

const copied = ref(false)
let timer: ReturnType<typeof setTimeout> | undefined
async function doCopy() {
  try {
    if (!navigator.clipboard) throw new Error('clipboard unavailable')
    await navigator.clipboard.writeText(full.value)
    copied.value = true
    clearTimeout(timer)
    timer = setTimeout(() => { copied.value = false }, 1500)
  } catch {
    toast('无法访问剪贴板，请悬停查看完整值后手动复制。', 'warn')
  }
}
onBeforeUnmount(() => clearTimeout(timer))
</script>

<template>
  <span v-if="!full" class="text-ink-4">—</span>
  <span v-else class="inline-flex max-w-full items-center gap-1 align-middle">
    <span class="num truncate text-[12.5px]" :title="full" :aria-label="full" data-id-text>{{ short }}</span>
    <button
      v-if="copy"
      type="button"
      class="inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-sm text-ink-4 transition-colors hover:bg-paper-soft hover:text-ink"
      :aria-label="copied ? '已复制' : `复制 ${full}`"
      :title="copied ? '已复制' : '复制完整值'"
      @click.stop="doCopy"
      @keydown.enter.stop
    >
      <Check v-if="copied" :size="12" :stroke-width="1.5" class="text-ok" />
      <Copy v-else :size="12" :stroke-width="1.5" />
    </button>
  </span>
</template>
