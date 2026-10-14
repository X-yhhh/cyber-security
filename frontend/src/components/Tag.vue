<script setup lang="ts">
/**
 * 状态标记：圆点 + 文字，不用彩色底徽章。tone 只映射到有限的语义色（集合登记在 data/tones.ts）。
 * `pill` 为浅底色胶囊变体（视觉基线 v2），只用于表格的状态列。
 */
defineProps<{ tone?: 'threat' | 'warn' | 'ok' | 'signal' | 'mute'; label: string; pill?: boolean }>()
const dot = { threat: 'bg-threat', warn: 'bg-warn', ok: 'bg-ok', signal: 'bg-signal', mute: 'bg-ink-4' }
const text = { threat: 'text-threat', warn: 'text-warn', ok: 'text-ok', signal: 'text-signal', mute: 'text-ink-3' }
const soft = { threat: 'bg-threat-soft', warn: 'bg-warn-soft', ok: 'bg-ok-soft', signal: 'bg-signal-soft', mute: 'bg-paper-soft' }
</script>

<template>
  <span v-if="pill" class="pill" :class="[text[tone ?? 'mute'], soft[tone ?? 'mute']]">
    <span class="dot" :class="dot[tone ?? 'mute']" />{{ label }}
  </span>
  <span v-else class="inline-flex items-center gap-2 whitespace-nowrap text-[12.5px]" :class="text[tone ?? 'mute']">
    <span class="dot" :class="dot[tone ?? 'mute']" />{{ label }}
  </span>
</template>
