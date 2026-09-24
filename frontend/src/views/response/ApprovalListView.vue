<template>
  <div class="space-y-6">
    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
      <div>
        <h1 class="text-xl font-bold text-slate-900 tracking-tight flex items-center gap-2">
          <span>受控响应与防御审批工单</span>
          <span class="text-xs px-2.5 py-0.5 rounded-full bg-purple-50 text-purple-700 border border-purple-200 font-mono">
            {{ pendingCount }} 单待处理
          </span>
        </h1>
        <p class="text-xs text-slate-500 mt-1">
          严禁自动执行未经授权的高影响防御动作；依据安全合规规则严格实行【申请人与审批人职责分离】
        </p>
      </div>

      <div class="flex items-center gap-3">
        <router-link to="/response/ledger" class="sec-btn-secondary text-xs">
          查看执行台账与安全回滚 →
        </router-link>
      </div>
    </div>

    <!-- 安全合规规则横幅提示 -->
    <div class="p-4 rounded-xl bg-purple-50/60 border border-purple-200 flex items-start gap-3">
      <div class="p-1 rounded-lg bg-purple-100 text-purple-700 mt-0.5">
        <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        </svg>
      </div>
      <div class="text-xs text-purple-900 space-y-1">
        <div class="font-bold">职责分离与受控回滚原则 (Separation of Duties):</div>
        <p class="text-purple-700 leading-relaxed">
          安全分析员提交处置申请后，系统生成带防篡改摘要的不可变工单。申请人本人无权自我审批；必须由具备独立审批权限的角色（如
          <span class="font-bold underline cursor-pointer" @click="authStore.switchRole('response_approver')">王主管 response_approver</span>）审核确认后方可向主机防火墙适配器下发带 TTL 的窄范围阻断规则。
        </p>
      </div>
    </div>

    <!-- 工单列表 -->
    <div class="space-y-4">
      <div
        v-for="task in tasks"
        :key="task.id"
        class="sec-card p-5 space-y-4 transition-all"
        :class="task.status === 'pending' ? 'border-purple-200 shadow-sm' : ''"
      >
        <div class="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-slate-100 pb-3">
          <div class="flex items-center gap-3">
            <span class="font-mono text-xs font-bold text-slate-800">{{ task.taskKey }}</span>
            <StatusBadge :type="task.status === 'pending' ? 'pending' : task.status === 'approved' ? 'safe' : 'neutral'" :text="task.status.toUpperCase()" />
            <span class="text-xs text-slate-500 font-medium">关联事件: {{ task.eventTitle }}</span>
          </div>

          <div class="flex items-center gap-2">
            <span class="text-xs text-slate-400 font-mono">工单时效至: {{ task.expiresAt.slice(11, 19) }} UTC</span>
          </div>
        </div>

        <!-- 工单核心参数 -->
        <div class="grid grid-cols-1 md:grid-cols-4 gap-4 p-3.5 rounded-xl bg-slate-50/60 border border-slate-100 text-xs">
          <div>
            <span class="text-slate-400 block text-[11px]">目标资产</span>
            <span class="font-semibold text-slate-800">{{ task.assetName }}</span>
          </div>
          <div>
            <span class="text-slate-400 block text-[11px]">动作目标 IP</span>
            <span class="font-mono font-bold text-red-600">{{ task.targetIp }}</span>
          </div>
          <div>
            <span class="text-slate-400 block text-[11px]">动作类型 / 时限 (TTL)</span>
            <span class="font-semibold text-slate-800">窄范围阻断 / {{ task.durationSeconds }}秒</span>
          </div>
          <div>
            <span class="text-slate-400 block text-[11px]">申请人 (Applicant)</span>
            <span class="font-mono font-bold text-cyber-700">{{ task.requestedBy }}</span>
          </div>
        </div>

        <!-- 申请理由与摘要 -->
        <div class="text-xs text-slate-600 leading-relaxed">
          <span class="font-semibold text-slate-700">申请理由:</span> {{ task.reason }}
        </div>

        <div class="text-[11px] font-mono text-slate-400 truncate">
          请求防篡改摘要: {{ task.requestDigest }}
        </div>

        <!-- 审批结果与操作 -->
        <div class="pt-3 border-t border-slate-100 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
          <div v-if="task.reviewedBy" class="flex items-center gap-2 text-slate-600">
            <span>独立审批人: <strong class="font-mono text-slate-800">{{ task.reviewedBy }}</strong></span>
            <span>· 决策说明: {{ task.decisionReason }}</span>
          </div>
          <div v-else class="text-slate-400">
            等待独立审批员审定裁决...
          </div>

          <div v-if="task.status === 'pending'" class="flex items-center gap-2">
            <button
              class="sec-btn-secondary text-xs text-red-600 hover:text-red-700"
              @click="handleDecision(task.id, 'reject')"
            >
              驳回阻断
            </button>
            <button
              class="sec-btn-primary text-xs bg-purple-600 hover:bg-purple-700"
              @click="handleDecision(task.id, 'approve')"
            >
              核准并下发阻断
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
import { useAuthStore } from '@/stores/auth';
import { useAlertStore } from '@/stores/alert';

const authStore = useAuthStore();
const alertStore = useAlertStore();
const tasks = ref(mockService.getApprovalTasks().data || []);

const pendingCount = computed(() => {
  return tasks.value.filter(t => t.status === 'pending').length;
});

function handleDecision(taskId: number, decision: 'approve' | 'reject') {
  const res = mockService.decideApproval(taskId, decision);
  if (res.success) {
    tasks.value = mockService.getApprovalTasks().data || [];
    alertStore.success('决策已记录', decision === 'approve' ? '阻断动作已核准并下发至主机适配器执行' : '动作申请已被驳回');
  } else {
    // 触发职责分离警告
    alertStore.error('操作被安全合规拦截', res.error?.message);
  }
}
</script>
