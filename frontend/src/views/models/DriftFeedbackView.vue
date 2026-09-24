<template>
  <div class="space-y-6">
    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
      <div>
        <h1 class="text-xl font-bold text-slate-900 tracking-tight flex items-center gap-2">
          <span>特征分布漂移监测与人工反馈集</span>
          <span class="text-xs px-2.5 py-0.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200 font-mono">
            分布平稳 (NORMAL)
          </span>
        </h1>
        <p class="text-xs text-slate-500 mt-1">
          在线仅进行滑动时间窗特征统计观察并生成漂移告警，严禁伪标签在线自学习；人工核验反馈用于离线再训练
        </p>
      </div>

      <router-link to="/models" class="sec-btn-secondary text-xs">
        ← 返回模型中心
      </router-link>
    </div>

    <!-- 漂移监测时间窗状态 -->
    <div class="sec-card p-5 space-y-4">
      <div class="flex items-center justify-between border-b border-slate-100 pb-3">
        <div>
          <h3 class="text-sm font-bold text-slate-800">滑动时间窗特征分布统计 (Drift Metric Window)</h3>
          <p class="text-xs text-slate-400">时间窗: 2026-09-24 00:00 - 08:00 UTC · Kolmogorov-Smirnov 检验</p>
        </div>
        <StatusBadge type="safe" text="无显著漂移" />
      </div>

      <div class="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
        <div class="p-3 rounded-xl bg-slate-50 border border-slate-100">
          <span class="text-slate-400 block text-[10px]">契约质量拒绝率 (Reject Rate)</span>
          <span class="font-bold text-slate-800 font-mono text-sm">0.20% (低于 1% 阈值)</span>
        </div>
        <div class="p-3 rounded-xl bg-slate-50 border border-slate-100">
          <span class="text-slate-400 block text-[10px]">模型输出分数均值 (Score Mean)</span>
          <span class="font-bold text-slate-800 font-mono text-sm">0.12 ± 0.18</span>
        </div>
        <div class="p-3 rounded-xl bg-slate-50 border border-slate-100">
          <span class="text-slate-400 block text-[10px]">活动基准特征契约</span>
          <span class="font-bold text-cyber-700 font-mono text-sm">unsw-flow-v1 (15 特征)</span>
        </div>
      </div>
    </div>

    <!-- 分析师人工反馈真值样本库 -->
    <div class="sec-card p-5 space-y-4">
      <div class="flex items-center justify-between border-b border-slate-100 pb-3">
        <div>
          <h3 class="text-sm font-bold text-slate-800">人工确认反馈样本库 (Feedback Samples)</h3>
          <p class="text-xs text-slate-400">仅经分析员 PCAP 抓包交叉核实的真实标签可进入离线训练候选集</p>
        </div>
        <span class="text-xs font-mono text-slate-500">{{ feedbackSamples.length }} 笔合格样本</span>
      </div>

      <div class="overflow-x-auto">
        <table class="w-full text-left text-xs">
          <thead class="bg-slate-50/70 border-b border-slate-100 text-slate-500 font-medium">
            <tr>
              <th class="py-2.5 px-3">原始流记录 Key</th>
              <th class="py-2.5 px-3">人工确认真值 (Label)</th>
              <th class="py-2.5 px-3">验证依据来源 (Source)</th>
              <th class="py-2.5 px-3">PCAP / 证据引用</th>
              <th class="py-2.5 px-3">核准分析员</th>
              <th class="py-2.5 px-3">训练集资格</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-100 font-network">
            <tr v-for="fb in feedbackSamples" :key="fb.id" class="hover:bg-slate-50/50">
              <td class="py-2.5 px-3 font-bold text-slate-800">{{ fb.sourceRecordKey }}</td>
              <td class="py-2.5 px-3">
                <StatusBadge type="critical" :text="fb.groundTruthLabel" />
              </td>
              <td class="py-2.5 px-3 font-sans text-slate-600">{{ fb.labelSource }}</td>
              <td class="py-2.5 px-3 text-slate-500 truncate max-w-xs" :title="fb.evidenceRef">{{ fb.evidenceRef }}</td>
              <td class="py-2.5 px-3 font-sans font-medium text-cyber-700">{{ fb.reviewedBy }}</td>
              <td class="py-2.5 px-3 font-sans">
                <span class="text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded text-[10px] font-bold">ELIGIBLE</span>
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

const feedbackSamples = ref(mockService.getFeedbackSamples().data || []);
</script>
