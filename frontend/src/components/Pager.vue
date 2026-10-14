<script setup lang="ts">
/**
 * 服务端分页条：沿用审计页“共 N 条 · 第 x / y 页 + 上一页 / 下一页”的文字型样式。
 * 只展示与发出翻页意图（page 从 0 开始），数据读取由父组件调用后端分页接口完成；
 * 只有一页时整条隐藏，busy 时禁用按钮避免重复请求。
 */
import { computed } from 'vue'

const props = defineProps<{ total: number; page: number; size: number; busy?: boolean; label: string }>()
const emit = defineEmits<{ change: [page: number] }>()
const pages = computed(() => Math.max(1, Math.ceil(props.total / props.size)))
</script>

<template>
  <nav v-if="pages > 1" class="mt-4 flex w-full items-center justify-between gap-4 text-[12.5px] text-ink-3" :aria-label="`${label}分页`">
    <span class="num" aria-live="polite">共 {{ total }} 条 · 第 {{ page + 1 }} / {{ pages }} 页</span>
    <span class="flex gap-2">
      <button type="button" class="act-ghost act-sm" :disabled="busy || page === 0" @click="emit('change', page - 1)">上一页</button>
      <button type="button" class="act-ghost act-sm" :disabled="busy || page + 1 >= pages" @click="emit('change', page + 1)">下一页</button>
    </span>
  </nav>
</template>
