<template>
  <div class="w-full h-full flex flex-col justify-end relative">
    <svg class="w-full h-full overflow-visible" viewBox="0 0 500 160" preserveAspectRatio="none">
      <defs>
        <!-- 渐变填充 -->
        <linearGradient id="cyberWaveGrad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="#0284c7" stop-opacity="0.25" />
          <stop offset="100%" stop-color="#0284c7" stop-opacity="0.0" />
        </linearGradient>
      </defs>

      <!-- 水平参考背景虚线 -->
      <line x1="0" y1="40" x2="500" y2="40" stroke="#f1f5f9" stroke-dasharray="4 4" stroke-width="1" />
      <line x1="0" y1="80" x2="500" y2="80" stroke="#f1f5f9" stroke-dasharray="4 4" stroke-width="1" />
      <line x1="0" y1="120" x2="500" y2="120" stroke="#f1f5f9" stroke-dasharray="4 4" stroke-width="1" />

      <!-- 面积图 -->
      <polygon :points="areaPoints" fill="url(#cyberWaveGrad)" />

      <!-- 折线 -->
      <polyline
        :points="linePoints"
        fill="none"
        stroke="#0284c7"
        stroke-width="2.5"
        stroke-linecap="round"
        stroke-linejoin="round"
      />

      <!-- 数据点圆点 -->
      <circle
        v-for="(pt, idx) in coords"
        :key="idx"
        :cx="pt.x"
        :cy="pt.y"
        r="3.5"
        fill="#ffffff"
        stroke="#0284c7"
        stroke-width="2"
        class="transition-all hover:r-5 cursor-pointer"
      />
    </svg>

    <!-- X 轴刻度文本 -->
    <div class="flex justify-between items-center text-[10px] text-slate-400 mt-2 font-mono">
      <span v-for="(lbl, idx) in labels" :key="idx">{{ lbl }}</span>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';

const props = withDefaults(
  defineProps<{
    data?: number[];
    labels?: string[];
  }>(),
  {
    data: () => [24, 45, 32, 68, 85, 120, 94, 60, 75, 110, 142, 98],
    labels: () => ['08:00', '08:15', '08:30', '08:45', '09:00', '09:15', '09:30']
  }
);

const coords = computed(() => {
  const points = props.data;
  if (!points || points.length === 0) return [];
  const max = Math.max(...points, 10);
  const min = 0;
  const range = max - min;
  const stepX = 500 / (points.length - 1);

  return points.map((val, idx) => {
    const x = idx * stepX;
    // 映射到高度 140 (留白 20px)
    const y = 140 - ((val - min) / range) * 110;
    return { x, y, val };
  });
});

const linePoints = computed(() => {
  return coords.value.map(p => `${p.x},${p.y}`).join(' ');
});

const areaPoints = computed(() => {
  if (coords.value.length === 0) return '';
  const first = coords.value[0];
  const last = coords.value[coords.value.length - 1];
  return `${first.x},160 ${linePoints.value} ${last.x},160`;
});
</script>
