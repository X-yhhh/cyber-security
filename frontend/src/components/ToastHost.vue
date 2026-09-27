<script setup lang="ts">
import { toasts } from '@/composables/toast'
const bar = { info: 'bg-signal', warn: 'bg-warn', threat: 'bg-threat' }
</script>

<template>
  <div class="pointer-events-none fixed bottom-6 right-6 z-50 flex w-[360px] flex-col gap-2" aria-live="polite">
    <TransitionGroup name="drawer">
      <div v-for="t in toasts" :key="t.id" class="pointer-events-auto flex items-stretch bg-ink text-paper">
        <span class="w-[3px]" :class="bar[t.tone]" />
        <p class="px-4 py-3 text-[13px] leading-snug">{{ t.text }}</p>
      </div>
    </TransitionGroup>
  </div>
</template>
