<template>
  <div class="space-y-6">
    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
      <div>
        <h1 class="text-xl font-bold text-slate-900 tracking-tight flex items-center gap-2">
          <span>主机软件传感器与采集健康监控</span>
          <span class="text-xs px-2.5 py-0.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200 font-mono">
            全部节点健康
          </span>
        </h1>
        <p class="text-xs text-slate-500 mt-1">
          管理部署于 Mac 与 Windows 主机上的轻量软件传感器，实时监控心跳、采集队列与丢包指标
        </p>
      </div>

      <router-link to="/assets" class="sec-btn-secondary text-xs">
        ← 返回资产台账
      </router-link>
    </div>

    <!-- 传感器监控卡片 -->
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <div
        v-for="snr in sensors"
        :key="snr.id"
        class="sec-card p-5 space-y-4"
      >
        <div class="flex items-center justify-between border-b border-slate-100 pb-3">
          <div class="flex items-center gap-2.5">
            <span class="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse" />
            <div>
              <h3 class="text-sm font-bold text-slate-900">{{ snr.assetName }}</h3>
              <span class="text-xs font-mono text-slate-400">{{ snr.agentKey }}</span>
            </div>
          </div>
          <StatusBadge type="safe" text="在线监测中" />
        </div>

        <!-- 4 格核心遥测 -->
        <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
          <div class="p-3 rounded-xl bg-slate-50 border border-slate-100">
            <span class="text-slate-400 block text-[10px]">滑动时间窗</span>
            <span class="font-bold text-slate-800 font-mono">{{ snr.flowWindowSeconds }} 秒</span>
          </div>
          <div class="p-3 rounded-xl bg-slate-50 border border-slate-100">
            <span class="text-slate-400 block text-[10px]">处理流总量</span>
            <span class="font-bold text-cyber-700 font-mono">{{ (snr.flowsSeen / 1000).toFixed(1) }}k</span>
          </div>
          <div class="p-3 rounded-xl bg-slate-50 border border-slate-100">
            <span class="text-slate-400 block text-[10px]">丢帧计数</span>
            <span class="font-bold text-red-600 font-mono">{{ snr.flowsDropped }} 帧</span>
          </div>
          <div class="p-3 rounded-xl bg-slate-50 border border-slate-100">
            <span class="text-slate-400 block text-[10px]">队列深度</span>
            <span class="font-bold text-slate-800 font-mono">{{ snr.queueDepth }}</span>
          </div>
        </div>

        <!-- 详细运行环境参数 -->
        <div class="space-y-2 p-3.5 rounded-xl bg-slate-50/70 border border-slate-100 text-xs font-network text-slate-600">
          <div class="flex justify-between">
            <span class="text-slate-400 font-sans">平台版本:</span>
            <span>{{ snr.agentVersion }}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-slate-400 font-sans">抓包网卡范围:</span>
            <span>{{ snr.interfaceScope.join(', ') }}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-slate-400 font-sans">特征契约:</span>
            <span class="text-cyber-700 font-bold">{{ snr.featureContractVersion }}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-slate-400 font-sans">最近心跳:</span>
            <span>{{ snr.lastHeartbeatAt.replace('T', ' ').slice(0, 19) }} UTC</span>
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

const sensors = ref(mockService.getSensors().data || []);
</script>
