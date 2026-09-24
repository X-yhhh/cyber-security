<template>
  <div class="space-y-6">
    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
      <div>
        <h1 class="text-xl font-bold text-slate-900 tracking-tight flex items-center gap-2">
          <span>主机防火墙防御执行台账与安全回滚</span>
        </h1>
        <p class="text-xs text-slate-500 mt-1">
          记录所有经核准并在 Mac (pfctl) / Windows (netsh) 适配器生效的动作，支持 TTL 倒计时与可审计的主动回滚
        </p>
      </div>

      <router-link to="/response" class="sec-btn-secondary text-xs">
        ← 返回审批工单中心
      </router-link>
    </div>

    <!-- 列表表格 -->
    <div class="sec-card overflow-hidden">
      <div class="overflow-x-auto">
        <table class="w-full text-left text-xs">
          <thead class="bg-slate-50/70 border-b border-slate-100 text-slate-500 font-medium">
            <tr>
              <th class="py-3 px-4">执行流水号 (Key)</th>
              <th class="py-3 px-4">目标资产</th>
              <th class="py-3 px-4">阻断目标 IP</th>
              <th class="py-3 px-4">适配器类型</th>
              <th class="py-3 px-4">生效状态</th>
              <th class="py-3 px-4">TTL 时限 / 到期时间</th>
              <th class="py-3 px-4">适配器执行回执</th>
              <th class="py-3 px-4 text-right">操作</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-100 font-network">
            <tr v-for="exec in executions" :key="exec.id" class="hover:bg-slate-50/50">
              <td class="py-3 px-4 font-bold text-slate-800">{{ exec.executionKey }}</td>
              <td class="py-3 px-4 font-sans font-medium text-slate-700">{{ exec.assetName }}</td>
              <td class="py-3 px-4 font-bold text-red-600">{{ exec.targetIp }}</td>
              <td class="py-3 px-4 text-slate-600 font-mono">{{ exec.adapterKey }}</td>
              <td class="py-3 px-4">
                <StatusBadge
                  :type="exec.status === 'succeeded' ? 'safe' : exec.status === 'rolled_back' ? 'neutral' : 'critical'"
                  :text="exec.status === 'succeeded' ? '生效阻断中' : exec.status === 'rolled_back' ? '已安全回滚' : exec.status"
                />
              </td>
              <td class="py-3 px-4 text-slate-600">
                {{ exec.durationSeconds }}s ({{ exec.expiresAt.slice(11, 19) }} UTC)
              </td>
              <td class="py-3 px-4 max-w-xs truncate text-slate-500 font-mono text-[11px]" :title="exec.resultReceipt">
                {{ exec.resultReceipt || 'OK' }}
              </td>
              <td class="py-3 px-4 text-right">
                <button
                  v-if="exec.status === 'succeeded' && exec.canRollback"
                  class="sec-btn-secondary text-xs px-2.5 py-1 text-amber-700 hover:text-amber-800 hover:bg-amber-50"
                  @click="handleRollback(exec.id)"
                >
                  安全回滚
                </button>
                <span v-else class="text-slate-400 font-sans text-[11px]">已归档</span>
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
const executions = ref(mockService.getExecutions().data || []);

function handleRollback(id: number) {
  const res = mockService.rollbackExecution(id);
  if (res.success) {
    executions.value = mockService.getExecutions().data || [];
    alertStore.success('规则已安全回滚', '已调用主机适配器撤销临时阻断表项，审计记录已写入');
  }
}
</script>
