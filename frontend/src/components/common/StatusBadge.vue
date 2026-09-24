<template>
  <span
    class="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium border"
    :class="badgeClass"
  >
    <span v-if="dot" class="w-1.5 h-1.5 rounded-full" :class="dotClass" />
    <slot>{{ text }}</slot>
  </span>
</template>

<script setup lang="ts">
import { computed } from 'vue';

const props = withDefaults(
  defineProps<{
    type?: 'critical' | 'high' | 'medium' | 'low' | 'safe' | 'pending' | 'neutral';
    text?: string;
    dot?: boolean;
  }>(),
  {
    type: 'neutral',
    dot: true
  }
);

const badgeClass = computed(() => {
  switch (props.type) {
    case 'critical':
      return 'bg-red-50 text-red-700 border-red-200';
    case 'high':
      return 'bg-amber-50 text-orange-700 border-orange-200';
    case 'medium':
      return 'bg-yellow-50 text-amber-700 border-yellow-200';
    case 'low':
      return 'bg-teal-50 text-teal-700 border-teal-200';
    case 'safe':
      return 'bg-emerald-50 text-emerald-700 border-emerald-200';
    case 'pending':
      return 'bg-purple-50 text-purple-700 border-purple-200';
    default:
      return 'bg-slate-100 text-slate-700 border-slate-200';
  }
});

const dotClass = computed(() => {
  switch (props.type) {
    case 'critical':
      return 'bg-red-500 animate-pulse';
    case 'high':
      return 'bg-orange-500';
    case 'medium':
      return 'bg-amber-500';
    case 'low':
      return 'bg-teal-500';
    case 'safe':
      return 'bg-emerald-500';
    case 'pending':
      return 'bg-purple-500';
    default:
      return 'bg-slate-400';
  }
});
</script>
