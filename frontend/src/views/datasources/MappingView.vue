<template>
  <div class="space-y-6">
    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
      <div>
        <h1 class="text-xl font-bold text-slate-900 tracking-tight flex items-center gap-2">
          <span>字段映射版本与质量门禁</span>
          <span class="text-xs px-2.5 py-0.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200 font-mono">
            通过率 99.8%
          </span>
        </h1>
        <p class="text-xs text-slate-500 mt-1">
          将来源流记录映射为模型输入契约所必需的统一特征，不符合契约字段或单位异常的记录严禁直接送入模型
        </p>
      </div>

      <router-link to="/datasources" class="sec-btn-secondary text-xs">
        ← 返回数据源列表
      </router-link>
    </div>

    <!-- 映射规则详情卡片 -->
    <div class="sec-card p-5 space-y-4">
      <div class="flex items-center justify-between border-b border-slate-100 pb-3">
        <div>
          <h3 class="text-sm font-bold text-slate-800">UNSW-NB15 规范映射表 (unsw-flow-v1)</h3>
          <p class="text-xs text-slate-400">经批准生效的规范流转换定义 · 字段数 15</p>
        </div>
        <StatusBadge type="safe" text="已批准生效" />
      </div>

      <div class="overflow-x-auto">
        <table class="w-full text-left text-xs">
          <thead class="bg-slate-50/70 border-b border-slate-100 text-slate-500 font-medium">
            <tr>
              <th class="py-2.5 px-3">原始来源字段 (Source Field)</th>
              <th class="py-2.5 px-3">目标模型特征 (Target Feature)</th>
              <th class="py-2.5 px-3">数据类型</th>
              <th class="py-2.5 px-3">单位/转换</th>
              <th class="py-2.5 px-3">是否必填</th>
              <th class="py-2.5 px-3">门禁校验规则</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-100 font-network">
            <tr v-for="(rule, idx) in mappingRules" :key="idx" class="hover:bg-slate-50/50">
              <td class="py-2.5 px-3 text-slate-600">{{ rule.src }}</td>
              <td class="py-2.5 px-3 font-bold text-cyber-700">{{ rule.target }}</td>
              <td class="py-2.5 px-3 font-sans text-slate-600">{{ rule.type }}</td>
              <td class="py-2.5 px-3 text-slate-500 font-sans">{{ rule.unit }}</td>
              <td class="py-2.5 px-3 font-sans">
                <span class="text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded text-[10px] font-bold">YES</span>
              </td>
              <td class="py-2.5 px-3 text-slate-500 font-sans text-[11px]">{{ rule.gate }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
const mappingRules = [
  { src: 'dur / flow_duration', target: 'dur', type: 'Float', unit: '秒 (Seconds)', gate: '值 >= 0.0 且非 NaN' },
  { src: 'proto / protocol', target: 'proto', type: 'Categorical', unit: '小写字符', gate: '枚举白名单 (tcp/udp/icmp)' },
  { src: 'service', target: 'service', type: 'Categorical', unit: '服务标识', gate: '有效端口/服务名' },
  { src: 'sbytes / src_bytes', target: 'sbytes', type: 'Integer', unit: '字节 (Bytes)', gate: '整型 >= 0' },
  { src: 'dbytes / dst_bytes', target: 'dbytes', type: 'Integer', unit: '字节 (Bytes)', gate: '整型 >= 0' },
  { src: 'rate / flow_rate', target: 'rate', type: 'Float', unit: '包/秒 (pkts/s)', gate: '有限浮点数' },
  { src: 'sttl', target: 'sttl', type: 'Integer', unit: '跳数 (TTL)', gate: '0 <= sttl <= 255' },
  { src: 'sload', target: 'sload', type: 'Float', unit: '比特/秒 (bps)', gate: '浮点数 >= 0' }
];
</script>
