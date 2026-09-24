<template>
  <div class="space-y-6">
    <!-- 头部操作区 -->
    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
      <div>
        <h1 class="text-xl font-bold text-slate-900 tracking-tight flex items-center gap-2">
          <span>威胁告警与事件研判中心</span>
          <span class="text-xs px-2.5 py-0.5 rounded-full bg-slate-100 text-slate-700 font-mono">
            共 {{ events.length }} 起事件
          </span>
        </h1>
        <p class="text-xs text-slate-500 mt-1">
          将流量告警、终端证据与资产上下文在时间窗内归并为安全事件，支撑分析员状态机流转与受控处置
        </p>
      </div>

      <div class="flex items-center gap-3">
        <router-link to="/incidents/alerts" class="sec-btn-secondary text-xs">
          <svg class="w-3.5 h-3.5 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 10h16M4 14h16M4 18h16" />
          </svg>
          查看原始告警池
        </router-link>
      </div>
    </div>

    <!-- 筛选过滤栏 -->
    <div class="sec-card p-4 flex flex-wrap items-center justify-between gap-4">
      <div class="flex flex-wrap items-center gap-3">
        <!-- 搜索输入框 -->
        <div class="relative w-64">
          <input
            v-model="searchQuery"
            type="text"
            placeholder="搜索事件标题、Key、摘要..."
            class="sec-input w-full pl-8"
            @input="filterEvents"
          />
          <svg class="w-4 h-4 text-slate-400 absolute left-2.5 top-2.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
        </div>

        <!-- 状态选择 -->
        <select v-model="selectedStatus" class="sec-input" @change="filterEvents">
          <option value="">全部状态 (All Status)</option>
          <option value="open">待研判 (Open)</option>
          <option value="investigating">研判中 (Investigating)</option>
          <option value="contained">已遏制 (Contained)</option>
          <option value="resolved">已解决 (Resolved)</option>
        </select>

        <!-- 严重度选择 -->
        <select v-model="selectedSeverity" class="sec-input" @change="filterEvents">
          <option value="">全部严重度 (All Severity)</option>
          <option value="critical">危急 (Critical)</option>
          <option value="high">高危 (High)</option>
          <option value="medium">中危 (Medium)</option>
          <option value="low">低危 (Low)</option>
        </select>
      </div>

      <div class="text-xs text-slate-400">
        显示 {{ filteredEvents.length }} / {{ events.length }} 条记录
      </div>
    </div>

    <!-- 事件卡片列表 -->
    <div class="space-y-4">
      <div
        v-for="evt in filteredEvents"
        :key="evt.id"
        class="sec-card p-5 hover:border-slate-300 transition-all space-y-4"
      >
        <div class="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-slate-100 pb-3">
          <div class="flex items-center gap-3">
            <StatusBadge :type="evt.severity" :text="evt.severity.toUpperCase()" />
            <span class="font-mono text-xs font-semibold text-slate-500">{{ evt.eventKey }}</span>
            <h3 class="text-sm font-bold text-slate-900">{{ evt.title }}</h3>
          </div>

          <div class="flex items-center gap-3">
            <span class="text-xs text-slate-500">
              研判状态:
              <span class="font-semibold text-slate-800 uppercase font-mono">{{ evt.status }}</span>
            </span>
            <router-link
              :to="`/incidents/${evt.id}`"
              class="sec-btn-primary text-xs"
            >
              进入研判工作台 →
            </router-link>
          </div>
        </div>

        <!-- 摘要说明 -->
        <p class="text-xs text-slate-600 leading-relaxed">
          {{ evt.summary }}
        </p>

        <!-- 底部元数据栏 -->
        <div class="flex flex-wrap items-center justify-between gap-4 pt-2 text-xs text-slate-500">
          <div class="flex flex-wrap items-center gap-4">
            <!-- 风险分 -->
            <div class="flex items-center gap-1.5">
              <span class="text-slate-400">风险指数:</span>
              <span class="font-mono font-bold" :class="evt.riskScore >= 80 ? 'text-red-600' : 'text-orange-600'">
                {{ evt.riskScore }} / 100
              </span>
            </div>

            <!-- 受影响资产 -->
            <div class="flex items-center gap-1.5">
              <span class="text-slate-400">目标资产:</span>
              <span
                v-for="ast in evt.impactedAssets"
                :key="ast.assetId"
                class="px-2 py-0.5 rounded bg-slate-100 font-mono text-[11px] text-slate-700 font-medium"
              >
                {{ ast.assetName }} ({{ ast.ipAddress }})
              </span>
            </div>

            <!-- 关联告警与证据数 -->
            <div class="flex items-center gap-1.5 text-[11px] font-mono">
              <span class="text-slate-400">关联告警:</span>
              <span class="font-semibold text-slate-700">{{ evt.alertCount }} 笔</span>
              <span class="text-slate-300">|</span>
              <span class="text-slate-400">研判证据:</span>
              <span class="font-semibold text-slate-700">{{ evt.evidenceCount }} 项</span>
            </div>
          </div>

          <div class="flex items-center gap-3 text-[11px] text-slate-400 font-mono">
            <span>首现: {{ evt.firstSeenAt.slice(11, 19) }}</span>
            <span>更新: {{ evt.lastSeenAt.slice(11, 19) }}</span>
            <span v-if="evt.assigneeName" class="text-cyber-700 font-sans font-medium">
              负责人: {{ evt.assigneeName }}
            </span>
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
import { SecurityEvent } from '@/types/incident';

const events = ref<SecurityEvent[]>(mockService.getEvents().data || []);
const searchQuery = ref('');
const selectedStatus = ref('');
const selectedSeverity = ref('');

const filteredEvents = computed(() => {
  return events.value.filter(e => {
    const matchQuery = !searchQuery.value ||
      e.title.toLowerCase().includes(searchQuery.value.toLowerCase()) ||
      e.eventKey.toLowerCase().includes(searchQuery.value.toLowerCase()) ||
      e.summary.toLowerCase().includes(searchQuery.value.toLowerCase());
    const matchStatus = !selectedStatus.value || e.status === selectedStatus.value;
    const matchSeverity = !selectedSeverity.value || e.severity === selectedSeverity.value;
    return matchQuery && matchStatus && matchSeverity;
  });
});

function filterEvents() {
  // 响应 computed
}
</script>
