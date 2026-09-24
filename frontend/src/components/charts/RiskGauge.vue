<template>
  <div class="flex flex-col items-center justify-center relative">
    <div class="relative w-44 h-28 overflow-hidden flex items-end justify-center">
      <svg class="w-44 h-44 -rotate-180 transform" viewBox="0 0 100 100">
        <!-- 底弧线 -->
        <circle
          cx="50"
          cy="50"
          r="40"
          fill="none"
          stroke="#f1f5f9"
          stroke-width="10"
          stroke-dasharray="125.6 125.6"
          stroke-linecap="round"
        />
        <!-- 进度弧线 -->
        <circle
          cx="50"
          cy="50"
          r="40"
          fill="none"
          :stroke="gaugeColor"
          stroke-width="10"
          :stroke-dasharray="`${progressStroke} 125.6`"
          stroke-linecap="round"
          class="transition-all duration-700 ease-out"
        />
      </svg>

      <!-- 读数展示 -->
      <div class="absolute bottom-2 flex flex-col items-center">
        <span class="text-3xl font-extrabold font-network text-slate-800 tracking-tight">
          {{ score }}
        </span>
        <span class="text-[11px] font-semibold tracking-wider uppercase" :class="labelColor">
          {{ riskLevelText }}
        </span>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';

const props = withDefaults(
  defineProps<{
    score: number; // 0 - 100
  }>(),
  {
    score: 85
  }
);

// 半圆周长 PI * R = 3.14159 * 40 ≈ 125.66
const halfCircumference = 125.66;

const progressStroke = computed(() => {
  const clamped = Math.max(0, Math.min(100, props.score));
  return (clamped / 100) * halfCircumference;
});

const riskLevelText = computed(() => {
  if (props.score >= 80) return '极高风险 (Critical)';
  if (props.score >= 60) return '高风险 (High)';
  if (props.score >= 40) return '中风险 (Medium)';
  return '低风险 (Low)';
});

const gaugeColor = computed(() => {
  if (props.score >= 80) return '#dc2626'; // red
  if (props.score >= 60) return '#ea580c'; // orange
  if (props.score >= 40) return '#ca8a04'; // yellow
  return '#16a34a'; // green
});

const labelColor = computed(() => {
  if (props.score >= 80) return 'text-red-600';
  if (props.score >= 60) return 'text-orange-600';
  if (props.score >= 40) return 'text-amber-600';
  return 'text-emerald-600';
});
</script>
