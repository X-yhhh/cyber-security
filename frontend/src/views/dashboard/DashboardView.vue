<template>
  <div class="space-y-6">
    <!-- 顶部标题与快速概览 -->
    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
      <div>
        <h1 class="text-xl font-bold text-slate-900 tracking-tight flex items-center gap-2">
          <span>安全态势感知大屏</span>
          <span class="text-xs px-2.5 py-0.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200 font-mono">
            实时流量检测中
          </span>
        </h1>
        <p class="text-xs text-slate-500 mt-1">
          面向两台授权主机软件传感器及隔离靶场的流量威胁检测、AI分类与分级防御总览
        </p>
      </div>

      <div class="flex items-center gap-3">
        <router-link to="/incidents" class="sec-btn-secondary text-xs">
          <svg class="w-3.5 h-3.5 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
          </svg>
          研判工作台
        </router-link>
        <router-link to="/response" class="sec-btn-primary text-xs">
          <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
          防御审批 (1 待办)
        </router-link>
      </div>
    </div>

    <!-- 4 个核心态势指标卡 -->
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      <StatCard
        title="软件传感器在线率"
        value="100%"
        unit="2/2 节点"
        subtext="Mac (en0) · Win (Ethernet0)"
        theme="safe"
      >
        <template #icon>
          <svg class="w-5 h-5 text-emerald-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
        </template>
      </StatCard>

      <StatCard
        title="流记录检测吞吐"
        value="279.9"
        unit="k 条"
        subtext="滑动窗口 15s · 丢弃 7 帧"
        theme="cyber"
      >
        <template #icon>
          <svg class="w-5 h-5 text-sky-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
          </svg>
        </template>
      </StatCard>

      <StatCard
        title="待处置威胁事件"
        value="2"
        unit="件"
        subtext="DoS SYN Flood 待阻断"
        theme="critical"
      >
        <template #icon>
          <svg class="w-5 h-5 text-red-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
        </template>
      </StatCard>

      <StatCard
        title="主机防火墙生效阻断"
        value="1"
        unit="条规则"
        subtext="TTL 剩余 12 分钟 (pfctl)"
        theme="purple"
      >
        <template #icon>
          <svg class="w-5 h-5 text-purple-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
          </svg>
        </template>
      </StatCard>
    </div>

    <!-- 中部图表区：流量波形 与 威胁环形占比 -->
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
      <!-- 流量与分类检测流速曲线 -->
      <div class="sec-card p-5 lg:col-span-2 flex flex-col justify-between">
        <div class="flex items-center justify-between pb-3 border-b border-slate-100">
          <div>
            <h3 class="text-sm font-bold text-slate-800 flex items-center gap-2">
              <span>流量流速与分类检测时间窗 (Flows/s)</span>
              <span class="text-[10px] text-slate-400 font-mono">15s WINDOW</span>
            </h3>
            <p class="text-xs text-slate-400">UNSW-NB15 规范特征抽取 · 冻结模型推理速率</p>
          </div>
          <div class="flex items-center gap-2 text-xs">
            <span class="inline-flex items-center gap-1.5 text-sky-600 font-medium">
              <span class="w-2.5 h-2.5 rounded-full bg-sky-500" />
              流速峰值 142 flows/s
            </span>
          </div>
        </div>

        <div class="h-48 pt-4">
          <WaveChart :data="flowRateData" :labels="timeLabels" />
        </div>
      </div>

      <!-- 威胁分类占比环形图 -->
      <div class="sec-card p-5 flex flex-col justify-between">
        <div class="pb-3 border-b border-slate-100">
          <h3 class="text-sm font-bold text-slate-800">当前告警严重度分布</h3>
          <p class="text-xs text-slate-400">基于模型多分类与确定性速率规则</p>
        </div>

        <div class="py-4">
          <DonutChart />
        </div>

        <div class="pt-3 border-t border-slate-100 text-xs text-slate-500 flex items-center justify-between">
          <span>活动分类器: v1.2.0 (LightGBM)</span>
          <span class="text-cyber-600 font-mono font-medium">F1: 0.942</span>
        </div>
      </div>
    </div>

    <!-- 底部区域：软件传感器采集监控 与 实时告警流水线 -->
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
      <!-- 软件传感器运行健康 -->
      <div class="sec-card p-5 flex flex-col justify-between">
        <div class="flex items-center justify-between pb-3 border-b border-slate-100">
          <h3 class="text-sm font-bold text-slate-800">软件传感器节点状态</h3>
          <router-link to="/assets" class="text-xs text-cyber-600 hover:underline">管理节点 →</router-link>
        </div>

        <div class="space-y-3.5 my-3">
          <div
            v-for="sensor in sensors"
            :key="sensor.id"
            class="p-3.5 rounded-xl border border-slate-100 bg-slate-50/50 hover:bg-slate-50 transition-colors space-y-2"
          >
            <div class="flex items-center justify-between">
              <div class="flex items-center gap-2">
                <span class="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                <span class="text-xs font-bold text-slate-800">{{ sensor.assetName }}</span>
              </div>
              <StatusBadge type="safe" text="正常采集" />
            </div>

            <div class="grid grid-cols-3 gap-2 text-[11px] text-slate-500 font-mono pt-1">
              <div>
                <span class="text-slate-400 block text-[10px]">接口</span>
                <span>{{ sensor.interfaceScope.join(',') }}</span>
              </div>
              <div>
                <span class="text-slate-400 block text-[10px]">CPU</span>
                <span>{{ sensor.cpuPercent }}%</span>
              </div>
              <div>
                <span class="text-slate-400 block text-[10px]">内存</span>
                <span>{{ sensor.memoryMb }}MB</span>
              </div>
            </div>
          </div>
        </div>

        <div class="text-[11px] text-slate-400 bg-slate-50 p-2.5 rounded-lg border border-slate-100">
          ⚠️ 说明：传感器仅采集主机本机可见授权流量，全网覆盖需交换机镜像配置配合。
        </div>
      </div>

      <!-- 实时告警流水线 -->
      <div class="sec-card p-5 lg:col-span-2">
        <div class="flex items-center justify-between pb-3 border-b border-slate-100">
          <div>
            <h3 class="text-sm font-bold text-slate-800">最新威胁告警流水 (Detection Alerts)</h3>
            <p class="text-xs text-slate-400">UNSW-NB15 流分类模型与速率规则命中记录</p>
          </div>
          <router-link to="/incidents" class="text-xs text-cyber-600 hover:underline">查看全部告警 →</router-link>
        </div>

        <div class="divide-y divide-slate-100 mt-2">
          <div
            v-for="alert in alerts"
            :key="alert.id"
            class="py-3 flex items-center justify-between gap-4 hover:bg-slate-50/50 px-2 rounded-lg transition-colors"
          >
            <div class="flex items-center gap-3 min-w-0">
              <StatusBadge :type="alert.severity" :text="alert.severity.toUpperCase()" />
              <div class="space-y-0.5 min-w-0">
                <div class="flex items-center gap-2">
                  <span class="text-xs font-bold text-slate-800 font-mono">{{ alert.alertKey }}</span>
                  <span class="text-xs text-slate-600 font-medium truncate">{{ alert.attackCategory || 'Traffic Anomaly' }}</span>
                </div>
                <div class="text-[11px] font-network text-slate-500 truncate">
                  {{ alert.sourceIp }}:{{ alert.sourcePort }} → {{ alert.destIp }}:{{ alert.destPort }} ({{ alert.protocol }})
                </div>
              </div>
            </div>

            <div class="flex items-center gap-4 flex-shrink-0">
              <div class="text-right">
                <div class="text-xs font-bold text-red-600 font-mono">{{ (alert.score * 100).toFixed(1) }}%</div>
                <div class="text-[10px] text-slate-400 font-mono">模型置信度</div>
              </div>

              <router-link
                :to="`/incidents/1`"
                class="sec-btn-secondary text-xs px-2.5 py-1"
              >
                研判
              </router-link>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import StatCard from '@/components/common/StatCard.vue';
import StatusBadge from '@/components/common/StatusBadge.vue';
import WaveChart from '@/components/charts/WaveChart.vue';
import DonutChart from '@/components/charts/DonutChart.vue';
import { mockService } from '@/mock/mockService';

const sensors = ref(mockService.getSensors().data || []);
const alerts = ref(mockService.getAlerts().data || []);

const flowRateData = [34, 52, 45, 78, 92, 142, 110, 85, 96, 128, 135, 118];
const timeLabels = ['09:00', '09:05', '09:10', '09:15', '09:20', '09:25', '09:30'];
</script>
