<template>
  <div class="space-y-6">
    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
      <div>
        <h1 class="text-xl font-bold text-slate-900 tracking-tight flex items-center gap-2">
          <span>独立模型发布审查台账</span>
          <span class="text-xs px-2.5 py-0.5 rounded-full bg-amber-50 text-amber-700 border border-amber-200 font-mono">
            {{ pendingReviews.length }} 项待审查
          </span>
        </h1>
        <p class="text-xs text-slate-500 mt-1">
          模型操作员提交候选版本发布申请后，由独立发布审批员核查 Manifest 指标与门禁测试，严禁在线自训练或自动换权重
        </p>
      </div>

      <router-link to="/models" class="sec-btn-secondary text-xs">
        ← 返回模型版本库
      </router-link>
    </div>

    <!-- 审查卡片列表 -->
    <div class="space-y-4">
      <div
        v-for="review in reviews"
        :key="review.id"
        class="sec-card p-5 space-y-4"
      >
        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-100 pb-3">
          <div class="flex items-center gap-3">
            <h3 class="text-sm font-bold text-slate-900 font-mono">{{ review.modelKey }}:{{ review.version }}</h3>
            <StatusBadge
              :type="review.releaseStatus === 'pending_review' ? 'pending' : review.releaseStatus === 'approved' ? 'safe' : 'critical'"
              :text="review.releaseStatus === 'pending_review' ? '待独立审查 (PENDING)' : review.releaseStatus === 'approved' ? '已核准发布' : '已驳回'"
            />
          </div>

          <div class="text-xs font-mono text-slate-400">
            申请提交时间: {{ review.requestedAt.replace('T', ' ').slice(0, 19) }} UTC
          </div>
        </div>

        <div class="p-3.5 rounded-xl bg-slate-50 border border-slate-100 text-xs space-y-2">
          <div class="flex justify-between">
            <span class="text-slate-400">模型开发申请人:</span>
            <span class="font-mono font-bold text-cyber-700">{{ review.requestedBy }}</span>
          </div>
          <div>
            <span class="text-slate-400 block mb-1">发布申请理由与门禁验证总结:</span>
            <p class="text-slate-700 leading-relaxed font-sans">{{ review.requestReason }}</p>
          </div>
        </div>

        <div class="pt-3 border-t border-slate-100 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
          <div v-if="review.approvedBy" class="text-slate-600">
            独立审查人: <strong class="font-mono text-slate-800">{{ review.approvedBy }}</strong> · 决策说明: {{ review.decisionReason }}
          </div>
          <div v-else class="text-slate-400">
            等待独立模型发布审批员裁决（不可由申请人本人审批）
          </div>

          <div v-if="review.releaseStatus === 'pending_review'" class="flex items-center gap-2">
            <button
              class="sec-btn-secondary text-xs text-red-600"
              @click="handleReview(review.id, 'rejected')"
            >
              驳回申请
            </button>
            <button
              class="sec-btn-primary text-xs"
              @click="handleReview(review.id, 'approved')"
            >
              批准模型发布
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue';
import StatusBadge from '@/components/common/StatusBadge.vue';
import { mockService } from '@/mock/mockService';
import { useAlertStore } from '@/stores/alert';

const alertStore = useAlertStore();
const reviews = ref(mockService.getReleaseReviews().data || []);

const pendingReviews = computed(() => {
  return reviews.value.filter(r => r.releaseStatus === 'pending_review');
});

function handleReview(reviewId: number, decision: 'approved' | 'rejected') {
  const res = mockService.decideReleaseReview(reviewId, decision);
  if (res.success) {
    reviews.value = mockService.getReleaseReviews().data || [];
    alertStore.success('审查已决策', decision === 'approved' ? '候选模型版本已批准激活' : '申请已驳回');
  } else {
    alertStore.error('操作被安全合规拦截', res.error?.message);
  }
}
</script>
