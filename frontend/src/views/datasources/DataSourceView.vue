<template>
  <div class="space-y-6">
    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
      <div>
        <h1 class="text-xl font-bold text-slate-900 tracking-tight flex items-center gap-2">
          <span>数据源管理与接入管道</span>
          <span class="text-xs px-2.5 py-0.5 rounded-full bg-slate-100 text-slate-700 font-mono">
            {{ dataSources.length }} 个活跃管道
          </span>
        </h1>
        <p class="text-xs text-slate-500 mt-1">
          管理公开基准数据集源、预制回放源与主机遥测连接器，严格按显式配对校验接入合法性
        </p>
      </div>

      <router-link to="/datasources/mappings" class="sec-btn-secondary text-xs">
        查看字段映射与质量门禁 →
      </router-link>
    </div>

    <!-- 数据源列表 -->
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <div
        v-for="ds in dataSources"
        :key="ds.id"
        class="sec-card p-5 space-y-4"
      >
        <div class="flex items-start justify-between">
          <div class="space-y-1">
            <h3 class="text-sm font-bold text-slate-900">{{ ds.name }}</h3>
            <span class="text-xs font-mono text-slate-400">{{ ds.sourceKey }}</span>
          </div>

          <StatusBadge :type="ds.environment === 'authorized' ? 'safe' : 'low'" :text="ds.environment === 'authorized' ? '实网遥测' : '离线基准'" />
        </div>

        <p class="text-xs text-slate-600 leading-relaxed">
          {{ ds.description }}
        </p>

        <div class="grid grid-cols-2 gap-3 p-3 rounded-xl bg-slate-50 border border-slate-100 text-xs font-network text-slate-600">
          <div>
            <span class="text-slate-400 block text-[10px] font-sans">接入总记录数:</span>
            <span class="font-bold text-slate-800">{{ ds.recordCount.toLocaleString() }} 笔</span>
          </div>
          <div>
            <span class="text-slate-400 block text-[10px] font-sans">模式规范版本:</span>
            <span class="text-cyber-700 font-bold">{{ ds.schemaVersion }}</span>
          </div>
        </div>

        <div class="pt-3 border-t border-slate-100 flex items-center justify-between text-xs text-slate-400">
          <span>最近成功同步: {{ ds.lastSuccessAt.replace('T', ' ').slice(0, 19) }} UTC</span>
          <span class="text-emerald-600 font-medium">健康</span>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import StatusBadge from '@/components/common/StatusBadge.vue';
import { mockService } from '@/mock/mockService';

const dataSources = ref(mockService.getDataSources().data || []);
</script>
