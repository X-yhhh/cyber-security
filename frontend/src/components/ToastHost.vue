<script setup lang="ts">
import { toasts } from '@/composables/toast'
const bar = { info: 'bg-ink', warn: 'bg-warn', threat: 'bg-threat' }
</script>

<!-- 提示层高于抽屉（z-50，Teleport 到 body 末尾），否则抽屉内操作的校验与错误提示会被抽屉盖住。 -->
<template>
  <div class="pointer-events-none fixed bottom-6 right-6 z-[60] flex w-[360px] flex-col gap-2" aria-live="polite">
    <TransitionGroup name="drawer">
      <div v-for="t in toasts" :key="t.id" class="pointer-events-auto flex items-start gap-3 rounded border border-ink-line bg-paper px-4 py-3 shadow-panel">
        <span class="dot mt-[7px] shrink-0" :class="bar[t.tone]" />
        <p class="text-[13px] leading-snug text-ink">{{ t.text }}</p>
      </div>
    </TransitionGroup>
  </div>
</template>
