<template>
  <div class="space-y-6">
    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
      <div>
        <h1 class="text-xl font-bold text-slate-900 tracking-tight flex items-center gap-2">
          <span>隔离靶场演练与流量回放</span>
          <span class="text-xs px-2.5 py-0.5 rounded-full bg-sky-50 text-sky-700 border border-sky-200 font-mono">
            靶场外联已物理隔离
          </span>
        </h1>
        <p class="text-xs text-slate-500 mt-1">
          使用公开基准数据或预制 PCAP 重放流量驱动检测闭环，回放事件带有明确演练标记，与授权实网事件严格隔离
        </p>
      </div>

      <div class="flex items-center gap-2">
        <button
          class="sec-btn-primary text-xs"
          :class="isPlaying ? 'bg-amber-600 hover:bg-amber-700' : ''"
          @click="togglePlayback"
        >
          <svg v-if="!isPlaying" class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <svg v-else class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 9v6m4-6v6m7-3a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          {{ isPlaying ? '暂停回放' : '启动场景回放' }}
        </button>
      </div>
    </div>

    <!-- 演练控制器卡片 -->
    <div class="sec-card p-5 space-y-4">
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-100 pb-3">
        <div>
          <h3 class="text-sm font-bold text-slate-800">当前激活演练场景: UNSW-NB15 典型 DoS 样本重放</h3>
          <p class="text-xs text-slate-400">数据源: sample_unsw_dos_50k.pcap · 目标: 隔离靶场 10.0.99.15</p>
        </div>

        <!-- 倍速选择 -->
        <div class="flex items-center gap-2">
          <span class="text-xs text-slate-400 font-medium">重放速率:</span>
          <button
            v-for="s in [1, 2, 5, 10]"
            :key="s"
            class="px-2.5 py-1 rounded-lg text-xs font-mono font-medium transition-colors"
            :class="speed === s ? 'bg-cyber-600 text-white' : 'bg-slate-100 text-slate-700 hover:bg-slate-200'"
            @click="speed = s"
          >
            {{ s }}x
          </button>
        </div>
      </div>

      <!-- 进度条 -->
      <div class="space-y-1.5">
        <div class="flex justify-between text-xs font-mono text-slate-500">
          <span>回放进度: {{ progress }}% (24,150 / 50,000 流记录)</span>
          <span class="text-cyber-600 font-semibold">{{ isPlaying ? '回放中...' : '已就绪' }}</span>
        </div>
        <div class="w-full bg-slate-100 h-2.5 rounded-full overflow-hidden">
          <div
            class="bg-cyber-600 h-full rounded-full transition-all duration-300"
            :style="{ width: `${progress}%` }"
          />
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import { useAlertStore } from '@/stores/alert';

const alertStore = useAlertStore();
const isPlaying = ref(false);
const speed = ref(1);
const progress = ref(48.3);

function togglePlayback() {
  isPlaying.value = !isPlaying.value;
  if (isPlaying.value) {
    alertStore.info('演练流量回放已启动', `回放速率: ${speed.value}x，演练产生事件已标记隔离标签`);
  } else {
    alertStore.info('回放已暂停', '流量发生器已挂起');
  }
}
</script>
