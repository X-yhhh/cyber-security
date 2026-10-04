<script setup lang="ts">
/** 状态标记：圆点 + 文字，不用色块徽章。tone 仅映射到有限的语义色。 */
defineProps<{ tone?: 'threat' | 'warn' | 'ok' | 'signal' | 'mute'; label: string }>()
const dot = { threat: 'bg-threat', warn: 'bg-warn', ok: 'bg-ok', signal: 'bg-signal', mute: 'bg-ink-4' }
const text = { threat: 'text-threat', warn: 'text-warn', ok: 'text-ok', signal: 'text-signal', mute: 'text-ink-3' }
</script>

<template>
  <span class="inline-flex items-center gap-2 whitespace-nowrap text-[12.5px]" :class="text[tone ?? 'mute']">
    <span class="dot" :class="dot[tone ?? 'mute']" />{{ label }}
  </span>
</template>
