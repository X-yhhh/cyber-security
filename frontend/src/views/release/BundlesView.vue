<script setup lang="ts">
/**
 * F3 的最终路由入口：分段与 URL 接线，内容沿用已有 v2 页面，不引入新版页面设计。
 * 正式组合/策略/能力表单、验证记录整合与交互验收由后续页面工作替换本桥接层。
 */
import { ref } from 'vue'
import { useRoute } from 'vue-router'
import { can } from '@/api/session'
import { useQueryState } from '@/composables/query'
import { releaseSelection, type ReleaseTab, type ValidationRecord } from '@/router/release'
import SectionTabs from '@/components/SectionTabs.vue'
import ReleaseView from '@/views/console/ReleaseView.vue'
import LabView from '@/views/console/LabView.vue'

const route = useRoute()
const initial = releaseSelection(route.query, 'bundles', 'lab')
const tab = ref<ReleaseTab>(initial.tab)
const record = ref<ValidationRecord>(initial.record)
useQueryState({
  tab: { state: tab, default: 'bundles' as ReleaseTab, parse: (_, query) => releaseSelection(query, 'bundles', 'lab').tab },
  record: { state: record, default: 'lab' as ValidationRecord, parse: (_, query) => releaseSelection(query, 'bundles', 'lab').record },
})
</script>

<template>
  <div>
    <SectionTabs v-model="tab" class="mb-4" label="发布管理分段" :options="[
      { value: 'bundles', label: '发布组合', anyOf: ['resource.read'] },
      { value: 'policies', label: '决策策略', anyOf: ['resource.read'] },
      { value: 'capabilities', label: '能力', anyOf: ['resource.read'] },
      { value: 'validation', label: '验证记录', anyOf: ['evaluation.read'] },
    ]" />
    <template v-if="tab === 'validation' && can('evaluation.read')">
      <SectionTabs v-model="record" class="mb-4" label="验证记录类型" :options="[{ value: 'lab', label: 'lab 会话' }, { value: 'evaluations', label: '评价运行' }]" />
      <LabView v-if="record === 'lab'" />
      <ReleaseView v-else key="evaluations" segment="evaluations" :show-tabs="false" />
    </template>
    <ReleaseView v-else-if="tab !== 'validation' && can('resource.read')" :key="tab" :segment="tab" :show-tabs="false" />
    <p v-else class="panel p-5 text-[13px] text-ink-3">当前身份没有读取此分段的权限。</p>
  </div>
</template>
