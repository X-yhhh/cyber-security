<script setup lang="ts">
/**
 * 列表区块的四态：加载 → 失败 → 空 → 内容。数据为空时如实说明范围内暂无记录，不补演示值。
 * 失败带 role="alert" 并显示后端脱敏错误（含 request-id）；空态文案由父组件按范围给出。
 */
import { CircleAlert, Inbox } from 'lucide-vue-next'

defineProps<{ loading: boolean; error: string; empty?: boolean; emptyText?: string }>()
</script>

<template>
  <p v-if="loading" class="flex items-center justify-center gap-2 py-12 text-[13px] text-ink-3" aria-busy="true">
    <span class="dot animate-pulse bg-ink-4" />正在从数据库读取…
  </p>
  <div v-else-if="error" class="note note-threat my-2 flex items-start gap-3 text-threat" role="alert">
    <CircleAlert :size="20" class="mt-0.5 shrink-0" aria-hidden="true" />
    <div class="min-w-0"><p class="font-medium">数据加载失败</p><p class="mt-1 break-words">{{ error }}</p></div>
  </div>
  <div v-else-if="empty" class="flex flex-col items-center gap-3 py-12 text-center">
    <span class="inline-flex h-10 w-10 items-center justify-center rounded-full bg-paper-soft text-ink-4" aria-hidden="true"><Inbox :size="18" :stroke-width="1.5" /></span>
    <p class="text-[13px] text-ink-3">{{ emptyText ?? '数据库中暂无记录。' }}</p>
  </div>
  <slot v-else />
</template>
