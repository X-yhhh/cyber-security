<script setup lang="ts">
/**
 * 游标分页条：v2 列表按 `(createdAt,id)` 稳定倒序，用 `nextCursor` 而非页码。
 *
 * 与 Pager 的差异：后端不返回总数，因此只显示「本页 N 条」与「继续 / 返回上一页」。
 * 游标栈由父组件维护（本组件只发出意图），「返回上一页」在栈为空时禁用。
 */
defineProps<{ count: number; hasNext: boolean; hasPrev: boolean; busy?: boolean; label: string }>()
const emit = defineEmits<{ next: []; prev: [] }>()
</script>

<template>
  <nav class="mt-6 flex items-center justify-between text-[12.5px] text-ink-3" :aria-label="`${label}分页`">
    <span class="num" aria-live="polite">本页 {{ count }} 条{{ hasNext ? ' · 还有更多' : ' · 已到末尾' }}</span>
    <span class="flex gap-6">
      <button type="button" class="link" :disabled="busy || !hasPrev" @click="emit('prev')">上一页</button>
      <button type="button" class="link" :disabled="busy || !hasNext" @click="emit('next')">下一页</button>
    </span>
  </nav>
</template>
