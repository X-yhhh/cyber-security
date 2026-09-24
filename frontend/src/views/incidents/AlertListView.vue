<template>
  <div class="space-y-6">
    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
      <div>
        <h1 class="text-xl font-bold text-slate-900 tracking-tight flex items-center gap-2">
          <span>原始流量告警池 (Detection Alerts)</span>
          <span class="text-xs px-2.5 py-0.5 rounded-full bg-slate-100 text-slate-700 font-mono">
            {{ alerts.length }} 笔告警记录
          </span>
        </h1>
        <p class="text-xs text-slate-500 mt-1">
          由主机传感器抽取并经质量门禁校验的流级告警，包含五元组、模型评分与特征摘要
        </p>
      </div>

      <router-link to="/incidents" class="sec-btn-secondary text-xs">
        ← 返回安全事件看板
      </router-link>
    </div>

    <!-- 告警数据表格 -->
    <div class="sec-card overflow-hidden">
      <div class="overflow-x-auto">
        <table class="w-full text-left text-xs">
          <thead class="bg-slate-50/70 border-b border-slate-100 text-slate-500 font-medium">
            <tr>
              <th class="py-3 px-4">告警标识 (Alert Key)</th>
              <th class="py-3 px-4">严重级别</th>
              <th class="py-3 px-4">五元组方向 (Source → Dest)</th>
              <th class="py-3 px-4">协议</th>
              <th class="py-3 px-4">模型置信度 / 类别</th>
              <th class="py-3 px-4">流时长 / 字节</th>
              <th class="py-3 px-4">检测时间 (UTC)</th>
              <th class="py-3 px-4 text-right">操作</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-100 font-network">
            <tr v-for="alt in alerts" :key="alt.id" class="hover:bg-slate-50/50">
              <td class="py-3 px-4 font-bold text-slate-800">{{ alt.alertKey }}</td>
              <td class="py-3 px-4">
                <StatusBadge :type="alt.severity" :text="alt.severity.toUpperCase()" />
              </td>
              <td class="py-3 px-4 font-semibold">
                <span class="text-red-600">{{ alt.sourceIp }}:{{ alt.sourcePort }}</span>
                <span class="text-slate-400 mx-1.5">→</span>
                <span class="text-slate-700">{{ alt.destIp }}:{{ alt.destPort }}</span>
              </td>
              <td class="py-3 px-4 uppercase font-sans font-medium text-slate-600">{{ alt.protocol }}</td>
              <td class="py-3 px-4">
                <div class="flex items-center gap-1.5">
                  <span class="font-bold text-red-600">{{ (alt.score * 100).toFixed(1) }}%</span>
                  <span class="text-slate-400">·</span>
                  <span class="font-sans text-slate-700 font-medium">{{ alt.attackCategory || 'DoS' }}</span>
                </div>
              </td>
              <td class="py-3 px-4 text-slate-600">
                {{ alt.flowDuration }}s / {{ alt.flowBytes.toLocaleString() }} B
              </td>
              <td class="py-3 px-4 text-slate-400">{{ alt.detectedAt.replace('T', ' ').slice(0, 19) }}</td>
              <td class="py-3 px-4 text-right">
                <router-link to="/incidents/1" class="text-cyber-600 hover:underline font-sans font-medium">
                  查看研判 →
                </router-link>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import StatusBadge from '@/components/common/StatusBadge.vue';
import { mockService } from '@/mock/mockService';

const alerts = ref(mockService.getAlerts().data || []);
</script>
