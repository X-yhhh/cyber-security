<template>
  <div class="space-y-6">
    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
      <div>
        <h1 class="text-xl font-bold text-slate-900 tracking-tight flex items-center gap-2">
          <span>资产台账与授权生命周期管理</span>
          <span class="text-xs px-2.5 py-0.5 rounded-full bg-slate-100 text-slate-700 font-mono">
            {{ assets.length }} 台已登记资产
          </span>
        </h1>
        <p class="text-xs text-slate-500 mt-1">
          明确区分实网授权主机与隔离靶场边界，任何防御动作必须以有效资产授权为前置条件
        </p>
      </div>

      <router-link to="/assets/sensors" class="sec-btn-secondary text-xs">
        查看软件传感器健康监控 →
      </router-link>
    </div>

    <!-- 资产卡片网格 -->
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
      <div
        v-for="asset in assets"
        :key="asset.id"
        class="sec-card p-5 space-y-4 flex flex-col justify-between"
      >
        <div class="space-y-3">
          <div class="flex items-start justify-between gap-2">
            <div class="space-y-1">
              <div class="flex items-center gap-2">
                <span class="text-sm font-bold text-slate-900">{{ asset.name }}</span>
              </div>
              <div class="text-xs font-mono text-slate-500">{{ asset.assetKey }}</div>
            </div>

            <StatusBadge
              :type="asset.environment === 'authorized' ? 'safe' : 'low'"
              :text="asset.environment === 'authorized' ? '授权实网' : '隔离靶场'"
            />
          </div>

          <div class="space-y-1.5 p-3 rounded-xl bg-slate-50 border border-slate-100 text-xs font-network text-slate-600">
            <div class="flex justify-between">
              <span class="text-slate-400">IP 地址:</span>
              <span class="font-bold text-slate-800">{{ asset.ipAddress }}</span>
            </div>
            <div class="flex justify-between">
              <span class="text-slate-400">MAC 地址:</span>
              <span>{{ asset.macAddress }}</span>
            </div>
            <div class="flex justify-between font-sans">
              <span class="text-slate-400">操作系统:</span>
              <span class="truncate max-w-[160px]">{{ asset.osVersion }}</span>
            </div>
            <div class="flex justify-between font-sans">
              <span class="text-slate-400">资产关键度:</span>
              <span class="font-semibold uppercase" :class="asset.criticality === 'critical' ? 'text-red-600' : 'text-orange-600'">
                {{ asset.criticality }}
              </span>
            </div>
          </div>

          <!-- 授权凭证状态 -->
          <div v-if="asset.activeAuthorization" class="p-3 rounded-xl bg-sky-50/50 border border-sky-100 text-xs space-y-1.5">
            <div class="flex items-center justify-between">
              <span class="font-bold text-cyber-800">安全授权状态</span>
              <StatusBadge type="safe" text="授权有效" />
            </div>
            <div class="text-[11px] font-mono text-slate-600">
              证明编号: {{ asset.activeAuthorization.authorizationRef }}
            </div>
            <div class="text-[11px] text-slate-500 font-mono">
              有效期: {{ asset.activeAuthorization.validFrom.slice(0, 10) }} 至 {{ asset.activeAuthorization.validUntil.slice(0, 10) }}
            </div>
          </div>
        </div>

        <div class="pt-3 border-t border-slate-100 flex items-center justify-between text-xs text-slate-400">
          <span>责任单位: {{ asset.owner }}</span>
          <span class="text-emerald-600 font-medium">状态正常</span>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import StatusBadge from '@/components/common/StatusBadge.vue';
import { mockService } from '@/mock/mockService';

const assets = ref(mockService.getAssets().data || []);
</script>
