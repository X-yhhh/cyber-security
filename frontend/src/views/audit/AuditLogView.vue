<template>
  <div class="space-y-6">
    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
      <div>
        <h1 class="text-xl font-bold text-slate-900 tracking-tight flex items-center gap-2">
          <span>安全审计日志与合规追踪</span>
          <span class="text-xs px-2.5 py-0.5 rounded-full bg-slate-100 text-slate-700 font-mono">
            只读不可篡改 (Append-Only)
          </span>
        </h1>
        <p class="text-xs text-slate-500 mt-1">
          完整记录用户登录、角色切换、资产授权、事件研判、阻断审批、模型审查与规则回滚的完整证据链
        </p>
      </div>

      <div class="flex items-center gap-2">
        <button class="sec-btn-secondary text-xs" @click="handleExportReport">
          <svg class="w-3.5 h-3.5 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
          </svg>
          导出合规脱敏审计报告
        </button>
      </div>
    </div>

    <!-- 审计日志表格 -->
    <div class="sec-card overflow-hidden">
      <div class="overflow-x-auto">
        <table class="w-full text-left text-xs">
          <thead class="bg-slate-50/70 border-b border-slate-100 text-slate-500 font-medium">
            <tr>
              <th class="py-3 px-4">发生时间 (UTC)</th>
              <th class="py-3 px-4">操作主体 (Actor)</th>
              <th class="py-3 px-4">安全动作 (Action)</th>
              <th class="py-3 px-4">资源类别 / 标识</th>
              <th class="py-3 px-4">请求链路 (Request ID)</th>
              <th class="py-3 px-4">执行结果</th>
              <th class="py-3 px-4">审计原因与说明</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-100 font-network">
            <tr v-for="log in auditLogs" :key="log.id" class="hover:bg-slate-50/50">
              <td class="py-3 px-4 text-slate-400">{{ log.occurredAt.replace('T', ' ').slice(0, 19) }}</td>
              <td class="py-3 px-4 font-bold text-cyber-700 font-sans">{{ log.actorName }}</td>
              <td class="py-3 px-4 font-semibold text-slate-800">{{ log.action }}</td>
              <td class="py-3 px-4 text-slate-600">
                <span class="text-slate-400 font-sans text-[11px] block">{{ log.resourceType }}</span>
                <span>{{ log.resourceId }}</span>
              </td>
              <td class="py-3 px-4 text-slate-400 font-mono text-[11px] truncate max-w-xs">{{ log.requestId }}</td>
              <td class="py-3 px-4">
                <StatusBadge
                  :type="log.outcome === 'success' ? 'safe' : log.outcome === 'denied' ? 'critical' : 'neutral'"
                  :text="log.outcome.toUpperCase()"
                />
              </td>
              <td class="py-3 px-4 text-slate-600 font-sans text-xs max-w-md truncate" :title="log.reason">
                {{ log.reason || '-' }}
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
import { useAlertStore } from '@/stores/alert';

const alertStore = useAlertStore();
const auditLogs = ref(mockService.getAuditLogs().data || []);

function handleExportReport() {
  alertStore.success('审计报告生成任务已派发', '已按 UTC 语义脱敏生成 PDF/JSON 合规归档制品');
}
</script>
