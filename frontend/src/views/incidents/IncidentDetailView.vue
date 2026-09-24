<template>
  <div v-if="event" class="space-y-6">
    <!-- 顶部导航与操作栏 -->
    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
      <div class="flex items-center gap-3">
        <router-link
          to="/incidents"
          class="p-2 rounded-xl bg-white border border-slate-200 text-slate-500 hover:text-slate-800 hover:bg-slate-50 transition-colors"
          title="返回事件列表"
        >
          <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18" />
          </svg>
        </router-link>
        <div>
          <div class="flex items-center gap-2">
            <span class="font-mono text-xs font-semibold text-slate-500">{{ event.eventKey }}</span>
            <StatusBadge :type="event.severity" :text="event.severity.toUpperCase()" />
            <span class="text-xs px-2 py-0.5 rounded bg-slate-100 font-mono text-slate-700 uppercase font-semibold">
              状态: {{ event.status }}
            </span>
          </div>
          <h1 class="text-lg font-bold text-slate-900 tracking-tight mt-1">{{ event.title }}</h1>
        </div>
      </div>

      <!-- 分析员动作操作区 -->
      <div class="flex items-center gap-3">
        <button class="sec-btn-secondary text-xs" @click="showNoteModal = true">
          <svg class="w-3.5 h-3.5 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
          </svg>
          追加研判结论
        </button>

        <button class="sec-btn-danger text-xs" @click="showActionModal = true">
          <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
          </svg>
          发起临时阻断申请
        </button>
      </div>
    </div>

    <!-- 上部卡片：风险指标与影响资产 -->
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
      <!-- 风险仪表与研判结论 -->
      <div class="sec-card p-5 flex flex-col justify-between">
        <div class="pb-3 border-b border-slate-100 flex items-center justify-between">
          <h3 class="text-sm font-bold text-slate-800">事件风险评级</h3>
          <span class="text-[11px] font-mono text-slate-400">规则: {{ event.riskRuleVersion }}</span>
        </div>

        <div class="py-2">
          <RiskGauge :score="event.riskScore" />
        </div>

        <div class="pt-3 border-t border-slate-100 text-xs text-slate-500 space-y-1">
          <div class="flex justify-between">
            <span>流特征异常置信度:</span>
            <span class="font-mono font-bold text-red-600">98.4% (DoS)</span>
          </div>
          <div class="flex justify-between">
            <span>速率规则命中:</span>
            <span class="font-mono text-slate-800">SYN包速 > 6000 pps</span>
          </div>
        </div>
      </div>

      <!-- 核心资产上下文 -->
      <div class="sec-card p-5 lg:col-span-2 space-y-4">
        <div class="pb-3 border-b border-slate-100 flex items-center justify-between">
          <h3 class="text-sm font-bold text-slate-800">受影响资产与防护边界</h3>
          <span class="text-xs text-emerald-600 font-medium">授权防护生效中</span>
        </div>

        <div
          v-for="ast in event.impactedAssets"
          :key="ast.assetId"
          class="p-4 rounded-xl border border-slate-200/80 bg-slate-50/50 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4"
        >
          <div class="space-y-1">
            <div class="flex items-center gap-2">
              <span class="text-sm font-bold text-slate-900">{{ ast.assetName }}</span>
              <StatusBadge type="critical" text="关键资产" />
            </div>
            <div class="text-xs font-network text-slate-500">
              IP: {{ ast.ipAddress }} · 资产唯一键: {{ ast.assetKey }}
            </div>
          </div>

          <div class="text-xs text-right space-y-1 font-mono">
            <div class="text-slate-400">授权有效期至</div>
            <div class="font-semibold text-slate-700">2026-12-31 UTC</div>
          </div>
        </div>

        <!-- 研判摘要 -->
        <div class="p-3.5 rounded-xl bg-sky-50/50 border border-sky-100 text-xs text-slate-700 leading-relaxed">
          <span class="font-bold text-cyber-700 mr-1.5">[研判摘要]</span>
          {{ event.summary }}
        </div>
      </div>
    </div>

    <!-- 中部：关联告警五元组与特征明细 -->
    <div class="sec-card p-5 space-y-4">
      <div class="pb-3 border-b border-slate-100 flex items-center justify-between">
        <div>
          <h3 class="text-sm font-bold text-slate-800">关联流量特征与五元组明细</h3>
          <p class="text-xs text-slate-400">由软件传感器抽取的滑动时间窗 UNSW-NB15 规范流记录</p>
        </div>
        <span class="text-xs font-mono text-slate-500">特征契约: unsw-flow-v1</span>
      </div>

      <div class="overflow-x-auto">
        <table class="w-full text-left text-xs">
          <thead>
            <tr class="border-b border-slate-100 text-slate-400 font-mono">
              <th class="pb-2">告警 Key</th>
              <th class="pb-2">源 IP : 端口</th>
              <th class="pb-2">目标 IP : 端口</th>
              <th class="pb-2">协议</th>
              <th class="pb-2">流时长 (s)</th>
              <th class="pb-2">吞吐字节</th>
              <th class="pb-2">分类评分</th>
              <th class="pb-2">判定类别</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-100 font-network">
            <tr v-for="alt in alerts" :key="alt.id" class="hover:bg-slate-50/50">
              <td class="py-2.5 font-bold text-slate-700">{{ alt.alertKey }}</td>
              <td class="py-2.5 text-red-600 font-semibold">{{ alt.sourceIp }}:{{ alt.sourcePort }}</td>
              <td class="py-2.5 text-slate-800">{{ alt.destIp }}:{{ alt.destPort }}</td>
              <td class="py-2.5 uppercase font-sans">{{ alt.protocol }}</td>
              <td class="py-2.5">{{ alt.flowDuration }}</td>
              <td class="py-2.5">{{ alt.flowBytes.toLocaleString() }} B</td>
              <td class="py-2.5 font-bold text-red-600">{{ (alt.score * 100).toFixed(1) }}%</td>
              <td class="py-2.5">
                <StatusBadge type="critical" :text="alt.attackCategory || 'DoS'" />
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- 底部：证据与研判时间线 (Timeline) -->
    <div class="sec-card p-5 space-y-4">
      <div class="pb-3 border-b border-slate-100 flex items-center justify-between">
        <div>
          <h3 class="text-sm font-bold text-slate-800">事件证据与研判生命周期时间线</h3>
          <p class="text-xs text-slate-400">记录系统告警、研判结论、状态流转与处置审批完整链条</p>
        </div>

        <!-- 状态流转快捷按钮 -->
        <div class="flex items-center gap-2">
          <span class="text-xs text-slate-400 mr-1">迁移状态:</span>
          <button
            class="px-2.5 py-1 rounded-lg border text-xs font-medium hover:bg-slate-50 transition-colors"
            :class="event.status === 'contained' ? 'bg-sky-50 border-sky-200 text-cyber-700' : 'border-slate-200 text-slate-700'"
            @click="handleTransition('contained')"
          >
            已遏制
          </button>
          <button
            class="px-2.5 py-1 rounded-lg border text-xs font-medium hover:bg-slate-50 transition-colors"
            :class="event.status === 'resolved' ? 'bg-emerald-50 border-emerald-200 text-emerald-700' : 'border-slate-200 text-slate-700'"
            @click="handleTransition('resolved')"
          >
            结案解决
          </button>
        </div>
      </div>

      <!-- 时间线节点 -->
      <div class="relative pl-6 space-y-6 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-200">
        <div
          v-for="item in timeline"
          :key="item.id"
          class="relative flex items-start gap-3 group"
        >
          <!-- 时间线圆点 -->
          <span
            class="absolute -left-6 top-1 w-4 h-4 rounded-full border-2 border-white flex items-center justify-center shadow-xs"
            :class="item.entryType === 'action_requested' ? 'bg-purple-600' : item.entryType === 'status_change' ? 'bg-sky-500' : 'bg-slate-400'"
          />

          <div class="flex-1 p-3.5 rounded-xl border border-slate-100 bg-slate-50/50 hover:bg-slate-50 transition-colors space-y-1">
            <div class="flex items-center justify-between text-xs">
              <span class="font-bold text-slate-800">{{ item.actorName }}</span>
              <span class="font-mono text-slate-400 text-[11px]">{{ item.occurredAt.slice(11, 19) }} UTC</span>
            </div>
            <p class="text-xs text-slate-600 leading-relaxed">{{ item.summary }}</p>
          </div>
        </div>
      </div>
    </div>

    <!-- 弹窗 1：追加研判笔记 -->
    <SecModal v-model="showNoteModal" title="追加分析员研判分析记录">
      <div class="space-y-4">
        <div>
          <label class="block text-xs font-semibold text-slate-700 mb-1">研判分析结论与依据</label>
          <textarea
            v-model="newNoteContent"
            rows="3"
            placeholder="说明流特征比对结果、协议畸形情况或误报研判依据..."
            class="sec-input w-full"
          />
        </div>
      </div>
      <template #footer>
        <button class="sec-btn-secondary text-xs" @click="showNoteModal = false">取消</button>
        <button class="sec-btn-primary text-xs" @click="submitNote">提交研判记录</button>
      </template>
    </SecModal>

    <!-- 弹窗 2：发起受控阻断申请 -->
    <SecModal v-model="showActionModal" title="发起主机防火墙窄范围限时阻断申请">
      <div class="space-y-4">
        <div class="p-3 rounded-lg bg-amber-50 border border-amber-200 text-xs text-amber-800">
          ⚠️ 遵循受控安全原则：系统仅追加针对单一攻击 IP 的窄范围临时阻断，不覆盖主机默认放行策略，且保护管理连接与网关。
        </div>

        <div>
          <label class="block text-xs font-semibold text-slate-700 mb-1">目标阻断 IP</label>
          <input
            v-model="actionForm.targetIp"
            type="text"
            class="sec-input w-full font-network"
            readonly
          />
        </div>

        <div class="grid grid-cols-2 gap-3">
          <div>
            <label class="block text-xs font-semibold text-slate-700 mb-1">动作时效 (TTL)</label>
            <select v-model="actionForm.durationSeconds" class="sec-input w-full">
              <option :value="600">10 分钟 (600s)</option>
              <option :value="1800">30 分钟 (1800s)</option>
              <option :value="3600">1 小时 (3600s)</option>
              <option :value="7200">2 小时 (7200s)</option>
            </select>
          </div>
          <div>
            <label class="block text-xs font-semibold text-slate-700 mb-1">执行策略版本</label>
            <input
              type="text"
              value="pol_narrow_block_ipv4 (v1.2.0)"
              class="sec-input w-full bg-slate-50 text-slate-500"
              disabled
            />
          </div>
        </div>

        <div>
          <label class="block text-xs font-semibold text-slate-700 mb-1">申请理由</label>
          <input
            v-model="actionForm.reason"
            type="text"
            placeholder="例如：缓解对 80 端口的高频 SYN Flood"
            class="sec-input w-full"
          />
        </div>
      </div>
      <template #footer>
        <button class="sec-btn-secondary text-xs" @click="showActionModal = false">取消</button>
        <button class="sec-btn-danger text-xs" @click="submitActionRequest">提交至审批队列</button>
      </template>
    </SecModal>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import { useRoute } from 'vue-router';
import StatusBadge from '@/components/common/StatusBadge.vue';
import RiskGauge from '@/components/charts/RiskGauge.vue';
import SecModal from '@/components/common/SecModal.vue';
import { mockService } from '@/mock/mockService';
import { useAlertStore } from '@/stores/alert';
import { EventStatus } from '@/types/incident';

const route = useRoute();
const alertStore = useAlertStore();

const eventId = Number(route.params.id) || 1;
const event = ref(mockService.getEventById(eventId).data);
const alerts = ref(mockService.getAlerts().data || []);
const timeline = ref(mockService.getTimelineByEventId(eventId).data || []);

// 弹窗状态
const showNoteModal = ref(false);
const newNoteContent = ref('');

const showActionModal = ref(false);
const actionForm = ref({
  targetIp: '203.0.113.88',
  durationSeconds: 1800,
  reason: '缓解对 80 端口的持续畸形 SYN Flood 攻击，依据特征与速率阈值申请临时阻断'
});

function handleTransition(newStatus: EventStatus) {
  const res = mockService.updateEventStatus(eventId, newStatus);
  if (res.success && res.data) {
    event.value = res.data;
    timeline.value = mockService.getTimelineByEventId(eventId).data || [];
    alertStore.success('状态已迁移', `事件状态已更新为 [${newStatus}]`);
  }
}

function submitNote() {
  if (!newNoteContent.value) return;
  mockService.addEventInvestigationNote(eventId, newNoteContent.value);
  timeline.value = mockService.getTimelineByEventId(eventId).data || [];
  newNoteContent.value = '';
  showNoteModal.value = false;
  alertStore.success('研判记录已追加', '已录入时间线并计入证据链统计');
}

function submitActionRequest() {
  const res = mockService.requestAction({
    eventId,
    assetId: event.value?.impactedAssets[0]?.assetId || 1,
    targetIp: actionForm.value.targetIp,
    durationSeconds: actionForm.value.durationSeconds,
    reason: actionForm.value.reason
  });
  if (res.success) {
    timeline.value = mockService.getTimelineByEventId(eventId).data || [];
    showActionModal.value = false;
    alertStore.success('阻断申请已生成', '工单已提交至审批队列，等待独立审批人裁决');
  }
}
</script>
