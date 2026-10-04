<script setup lang="ts">
/** 列表区块的加载 / 失败 / 空状态。数据为空时如实说明数据库中暂无记录，不补演示值。 */
defineProps<{ loading: boolean; error: string; empty?: boolean; emptyText?: string }>()
</script>

<template>
  <p v-if="loading" class="py-10 text-[13px] text-ink-3">正在从数据库读取…</p>
  <p v-else-if="error" class="border-l-2 border-threat py-2 pl-4 text-[13px] text-threat" role="alert">{{ error }}</p>
  <p v-else-if="empty" class="py-10 text-[13px] text-ink-3">{{ emptyText ?? '数据库中暂无记录。' }}</p>
  <slot v-else />
</template>
