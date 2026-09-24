<template>
  <div class="space-y-6">
    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
      <div>
        <h1 class="text-xl font-bold text-slate-900 tracking-tight flex items-center gap-2">
          <span>Windows CUDA 离线训练任务</span>
          <span class="text-xs px-2.5 py-0.5 rounded-full bg-slate-100 text-slate-700 font-mono">
            {{ jobs.length }} 个任务记录
          </span>
        </h1>
        <p class="text-xs text-slate-500 mt-1">
          离线任务在独立 Windows CUDA 训练站运行，训练输出为不可变候选制品，绝不直接污染生产推理
        </p>
      </div>

      <router-link to="/models" class="sec-btn-secondary text-xs">
        ← 返回模型中心
      </router-link>
    </div>

    <!-- 任务列表 -->
    <div class="space-y-4">
      <div
        v-for="job in jobs"
        :key="job.id"
        class="sec-card p-5 space-y-4"
      >
        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-100 pb-3">
          <div class="flex items-center gap-3">
            <h3 class="text-sm font-bold text-slate-900 font-mono">{{ job.jobKey }}</h3>
            <StatusBadge type="safe" text="已完成 (COMPLETED)" />
            <span class="text-xs font-mono text-slate-500">数据集: {{ job.datasetVersion }}</span>
          </div>

          <div class="text-xs font-mono text-slate-400">
            算力节点: {{ job.trainHostRef }}
          </div>
        </div>

        <div class="grid grid-cols-1 sm:grid-cols-3 gap-3 p-3.5 rounded-xl bg-slate-50 border border-slate-100 text-xs font-network text-slate-600">
          <div>
            <span class="text-slate-400 block text-[10px] font-sans">候选算法:</span>
            <span class="font-bold text-slate-800">{{ job.algorithm }}</span>
          </div>
          <div>
            <span class="text-slate-400 block text-[10px] font-sans">训练发起人:</span>
            <span class="font-bold text-cyber-700">{{ job.requestedBy }}</span>
          </div>
          <div>
            <span class="text-slate-400 block text-[10px] font-sans">产出 Manifest 引用:</span>
            <span class="text-slate-700 truncate block">{{ job.resultManifestRef }}</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import StatusBadge from '@/components/common/StatusBadge.vue';
import { mockService } from '@/mock/mockService';

const jobs = ref(mockService.getTrainingJobs().data || []);
</script>
