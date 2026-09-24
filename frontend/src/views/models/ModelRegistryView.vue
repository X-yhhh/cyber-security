<template>
  <div class="space-y-6">
    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
      <div>
        <h1 class="text-xl font-bold text-slate-900 tracking-tight flex items-center gap-2">
          <span>模型注册与不可变 Manifest 治理</span>
        </h1>
        <p class="text-xs text-slate-500 mt-1">
          生产推理模型严格保持冻结状态，每个模型版本均绑定唯一不可变 Manifest、数据集指纹与 SHA-256 校验和
        </p>
      </div>

      <div class="flex items-center gap-3">
        <router-link to="/models/release-reviews" class="sec-btn-primary text-xs">
          查看独立发布审查台账 (1 待办) →
        </router-link>
      </div>
    </div>

    <!-- 模型版本卡片列表 -->
    <div class="space-y-6">
      <div
        v-for="model in models"
        :key="model.id"
        class="sec-card p-5 space-y-4"
        :class="model.approvalStatus === 'active' ? 'border-cyber-200 ring-1 ring-cyber-100' : ''"
      >
        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-100 pb-3">
          <div class="flex items-center gap-3">
            <h3 class="text-sm font-bold text-slate-900 font-mono">{{ model.modelKey }}:{{ model.version }}</h3>
            <StatusBadge
              :type="model.approvalStatus === 'active' ? 'safe' : model.approvalStatus === 'candidate' ? 'pending' : 'neutral'"
              :text="model.approvalStatus === 'active' ? '生产活动模型 (ACTIVE)' : '离线候选版本 (CANDIDATE)'"
            />
            <span class="text-xs text-slate-500 font-mono">部署: {{ model.deploymentMode.toUpperCase() }}</span>
          </div>

          <div class="text-xs font-mono text-slate-400">
            登记时间: {{ model.createdAt.slice(0, 10) }}
          </div>
        </div>

        <!-- 关键评估指标 -->
        <div class="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3 text-xs">
          <div class="p-3 rounded-xl bg-slate-50 border border-slate-100">
            <span class="text-slate-400 block text-[10px]">综合 F1-Score</span>
            <span class="font-bold text-cyber-700 font-mono text-sm">{{ model.manifest.metrics.f1Score.toFixed(3) }}</span>
          </div>
          <div class="p-3 rounded-xl bg-slate-50 border border-slate-100">
            <span class="text-slate-400 block text-[10px]">准确率 (Accuracy)</span>
            <span class="font-bold text-slate-800 font-mono text-sm">{{ (model.manifest.metrics.accuracy * 100).toFixed(1) }}%</span>
          </div>
          <div class="p-3 rounded-xl bg-slate-50 border border-slate-100">
            <span class="text-slate-400 block text-[10px]">DoS 检出召回率</span>
            <span class="font-bold text-red-600 font-mono text-sm">{{ (model.manifest.metrics.dosRecall * 100).toFixed(1) }}%</span>
          </div>
          <div class="p-3 rounded-xl bg-slate-50 border border-slate-100">
            <span class="text-slate-400 block text-[10px]">正常流误报率 (FAR)</span>
            <span class="font-bold text-emerald-600 font-mono text-sm">{{ (model.manifest.metrics.falseAlarmRate * 100).toFixed(1) }}%</span>
          </div>
          <div class="p-3 rounded-xl bg-slate-50 border border-slate-100">
            <span class="text-slate-400 block text-[10px]">AUC-ROC</span>
            <span class="font-bold text-slate-800 font-mono text-sm">{{ model.manifest.metrics.aucRoc.toFixed(3) }}</span>
          </div>
          <div class="p-3 rounded-xl bg-slate-50 border border-slate-100">
            <span class="text-slate-400 block text-[10px]">决策阈值策略</span>
            <span class="font-semibold text-slate-700 font-mono text-[11px] truncate block" :title="model.manifest.thresholdStrategy.strategy">
              {{ model.manifest.thresholdStrategy.optimalThreshold }}
            </span>
          </div>
        </div>

        <!-- 不可变 Manifest 详细元数据摘要 -->
        <div class="p-3.5 rounded-xl bg-slate-50/70 border border-slate-100 text-xs space-y-1.5 font-network text-slate-600">
          <div class="flex flex-col sm:flex-row justify-between gap-1">
            <span class="text-slate-400 font-sans">模型算法与框架:</span>
            <span class="font-semibold text-slate-800">{{ model.manifest.algorithm }} ({{ model.manifest.runtime.framework }})</span>
          </div>
          <div class="flex flex-col sm:flex-row justify-between gap-1">
            <span class="text-slate-400 font-sans">数据集与切分指纹:</span>
            <span class="text-slate-600 truncate max-w-lg">{{ model.manifest.datasetSplitFingerprint }}</span>
          </div>
          <div class="flex flex-col sm:flex-row justify-between gap-1">
            <span class="text-slate-400 font-sans">制品 SHA-256 校验和:</span>
            <span class="text-slate-700 font-bold truncate max-w-lg">{{ model.artifactSha256 }}</span>
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

const models = ref(mockService.getModels().data || []);
</script>
