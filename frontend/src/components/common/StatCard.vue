<template>
  <div class="sec-card p-5 relative overflow-hidden group">
    <!-- 装饰性微光角标 -->
    <div
      class="absolute top-0 right-0 w-24 h-24 bg-gradient-to-br from-transparent to-slate-50/80 rounded-bl-full pointer-events-none"
    />

    <div class="flex items-start justify-between">
      <div class="space-y-1">
        <span class="text-xs font-medium text-slate-500 tracking-wider uppercase">
          {{ title }}
        </span>
        <div class="flex items-baseline gap-2 pt-1">
          <span class="text-2xl font-bold font-network text-slate-900 tracking-tight">
            {{ value }}
          </span>
          <span v-if="unit" class="text-xs text-slate-500 font-medium">{{ unit }}</span>
        </div>
      </div>

      <div
        class="w-10 h-10 rounded-xl flex items-center justify-center transition-transform group-hover:scale-110"
        :class="iconBgClass"
      >
        <slot name="icon" />
      </div>
    </div>

    <!-- 底部描述或对比趋势 -->
    <div v-if="subtext || $slots.footer" class="mt-4 pt-3 border-t border-slate-100 flex items-center justify-between text-xs">
      <span class="text-slate-500">{{ subtext }}</span>
      <slot name="footer" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';

const props = withDefaults(
  defineProps<{
    title: string;
    value: string | number;
    unit?: string;
    subtext?: string;
    theme?: 'cyber' | 'critical' | 'warning' | 'safe' | 'purple';
  }>(),
  {
    theme: 'cyber'
  }
);

const iconBgClass = computed(() => {
  switch (props.theme) {
    case 'critical':
      return 'bg-red-50 text-red-600 border border-red-100';
    case 'warning':
      return 'bg-amber-50 text-amber-600 border border-amber-100';
    case 'safe':
      return 'bg-emerald-50 text-emerald-600 border border-emerald-100';
    case 'purple':
      return 'bg-purple-50 text-purple-600 border border-purple-100';
    default:
      return 'bg-sky-50 text-sky-600 border border-sky-100';
  }
});
</script>
