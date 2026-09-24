<template>
  <div class="flex items-center justify-between gap-4">
    <!-- SVG 环形图 -->
    <div class="relative w-36 h-36 flex-shrink-0 flex items-center justify-center">
      <svg class="w-full h-full -rotate-90 transform" viewBox="0 0 100 100">
        <!-- 底圈 -->
        <circle
          cx="50"
          cy="50"
          r="38"
          fill="none"
          stroke="#f1f5f9"
          stroke-width="12"
        />
        <!-- 环形段 -->
        <circle
          v-for="(seg, idx) in segments"
          :key="idx"
          cx="50"
          cy="50"
          r="38"
          fill="none"
          :stroke="seg.color"
          stroke-width="12"
          :stroke-dasharray="`${seg.dash} ${100 - seg.dash}`"
          :stroke-dashoffset="-seg.offset"
          class="transition-all duration-500 ease-out"
        />
      </svg>
      <!-- 中心总计 -->
      <div class="absolute inset-0 flex flex-col items-center justify-center text-center">
        <span class="text-xl font-bold font-network text-slate-800">{{ total }}</span>
        <span class="text-[10px] text-slate-400 font-medium">总告警</span>
      </div>
    </div>

    <!-- 图例 -->
    <div class="flex-1 space-y-2">
      <div
        v-for="(item, idx) in items"
        :key="idx"
        class="flex items-center justify-between text-xs"
      >
        <div class="flex items-center gap-2">
          <span class="w-2.5 h-2.5 rounded-full" :style="{ backgroundColor: item.color }" />
          <span class="text-slate-600">{{ item.label }}</span>
        </div>
        <div class="flex items-center gap-2 font-mono">
          <span class="font-semibold text-slate-800">{{ item.value }}</span>
          <span class="text-slate-400 text-[10px]">
            ({{ total > 0 ? Math.round((item.value / total) * 100) : 0 }}%)
          </span>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';

export interface DonutItem {
  label: string;
  value: number;
  color: string;
}

const props = withDefaults(
  defineProps<{
    items?: DonutItem[];
  }>(),
  {
    items: () => [
      { label: '危急 (Critical)', value: 14, color: '#dc2626' },
      { label: '高危 (High)', value: 5, color: '#ea580c' },
      { label: '中危 (Medium)', value: 8, color: '#ca8a04' },
      { label: '低危 (Low)', value: 3, color: '#0d9488' }
    ]
  }
);

const total = computed(() => {
  return props.items.reduce((acc, curr) => acc + curr.value, 0);
});

// 计算 2*PI*R 的周长约为 238.76，归一化到百分比
const circumference = 2 * Math.PI * 38;

const segments = computed(() => {
  const sum = total.value || 1;
  let accumulated = 0;

  return props.items.map(item => {
    const ratio = item.value / sum;
    const dash = ratio * circumference;
    const offset = accumulated;
    accumulated += dash;
    return {
      dash,
      offset,
      color: item.color
    };
  });
});
</script>
