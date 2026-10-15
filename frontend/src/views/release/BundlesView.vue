<script setup lang="ts">
/**
 * 发布管理（模型与发布 / Bundles，前端设计文档第 10.3、10.10 节，任务单 F3）。
 *
 * 分段「发布组合 · 决策策略 · 能力 · 验证记录」按读权限展开；分段、验证记录类型（record）、`q`、状态与打开的对象（`id`）
 * 同步到 URL。待办中心的组合审批（`?tab=bundles&id=`）、策略审核（`?tab=policies&id=`）与 lab 资格（`?tab=validation&id=`）
 * 直接打开对应抽屉。只读取当前分段需要的集合：组合分段不读取策略与评价集合，只有评价读取权限时不读取资源目录。
 * 页头主操作随分段变化，由当前分段组件提供表单（defineExpose 的 create）。
 */
import { computed, ref } from 'vue'
import { Plus } from 'lucide-vue-next'
import PageHead from '@/components/PageHead.vue'
import PipelineSteps from '@/components/PipelineSteps.vue'
import SectionTabs from '@/components/SectionTabs.vue'
import { useQueryState } from '@/composables/query'
import { useSummary } from '@/composables/summary'
import { can } from '@/api/session'
import { isUuid } from '@/api/v2/detect'
import { releaseSelection, type ReleaseTab, type ValidationRecord } from '@/router/release'
import BundlesPanel from './BundlesPanel.vue'
import PoliciesPanel from './PoliciesPanel.vue'
import CapabilitiesPanel from './CapabilitiesPanel.vue'
import ValidationPanel from './ValidationPanel.vue'

const STATUS: Record<string, readonly string[]> = {
  bundles: ['candidate', 'evaluated', 'approved', 'active', 'suspended', 'retired'],
  policies: ['draft', 'reviewed', 'retired'],
  lab: ['registered', 'running', 'interrupted', 'completed', 'failed', 'cancelled'],
  evaluations: ['pending', 'running', 'completed', 'failed'],
  replays: ['queued', 'running', 'completed', 'failed'],
}
const statusKey = (tab: ReleaseTab, record: ValidationRecord) => (tab === 'validation' ? record : tab)

const tab = ref<ReleaseTab>('bundles')
const record = ref<ValidationRecord>('lab')
const q = ref('')
const status = ref('')
const openId = ref('')
const str = (v: unknown) => (typeof v === 'string' ? v : '')
useQueryState({
  tab: { state: tab, default: 'bundles' as ReleaseTab, parse: (_, query) => releaseSelection(query, 'bundles', 'lab').tab },
  record: { state: record, default: 'lab' as ValidationRecord, parse: (_, query) => releaseSelection(query, 'bundles', 'lab').record },
  q: { state: q, default: '', parse: (v) => str(v).trim().slice(0, 128) },
  status: {
    state: status, default: '', parse: (v, query) => {
      const { tab: t, record: r } = releaseSelection(query, 'bundles', 'lab')
      return STATUS[statusKey(t, r)]?.includes(str(v)) ? str(v) : ''
    },
  },
  id: { state: openId, default: '', parse: (v) => (isUuid(str(v)) ? str(v).trim() : '') },
})

/** 用户切换分段或记录类型时清空筛选与打开的对象；外部链接带来的参数由 useQueryState 一次回填，不经过这里。 */
const clear = () => { q.value = ''; status.value = ''; openId.value = '' }
const tabModel = computed({ get: () => tab.value, set: (v: ReleaseTab) => { if (v !== tab.value) { tab.value = v; clear() } } })
const recordModel = computed({ get: () => record.value, set: (v: ValidationRecord) => { if (v !== record.value) { record.value = v; clear() } } })

const resources = can('resource.read')
const evaluations = can('evaluation.read')

/* 发布流水线：数量来自汇总接口（全量、按权限裁剪），没有该字段时不显示；点击阶段按状态筛选组合。 */
const summary = useSummary()
const pipeline = computed(() => {
  const p = summary.data.releasePipeline
  if (!p) return null
  return [
    { key: 'candidate', label: '候选', value: p.candidate, note: '导入评价报告后封存', tone: 'mute' as const },
    { key: 'evaluated', label: '已封存待批', value: p.evaluated, note: '由申请人以外的人批准', tone: 'signal' as const },
    { key: 'approved', label: '已批准', value: p.approved, note: '批准不等于激活', tone: 'ok' as const },
    { key: 'active', label: '已激活', value: p.active, note: '按资产与有效授权激活', tone: 'ok' as const },
  ]
})
function pickStage(k: string) {
  if (tab.value !== 'bundles') { tab.value = 'bundles'; clear() }
  status.value = status.value === k ? '' : k
  openId.value = ''
}

/* 页头主操作：随分段变化，表单由当前分段组件打开。 */
const panel = ref<{ create: () => void } | null>(null)
const primary = computed(() => {
  if (tab.value === 'bundles') return can('bundle.request') ? '申请发布组合' : ''
  if (tab.value === 'policies') return can('policy.draft') ? '起草策略' : ''
  if (tab.value === 'capabilities') return can('bundle.request') ? '登记能力' : ''
  if (record.value === 'plans') return can('evaluation.run') ? '建立冻结计划' : ''
  if (record.value === 'replays') return can('evaluation.run') ? '新建研究回放' : ''
  return ''
})
</script>

<template>
  <div>
    <PageHead title="发布管理" desc="发布组合、决策策略、能力与验证记录。审核、批准与激活分开进行。">
      <button v-if="primary" type="button" class="act" @click="panel?.create()"><Plus :size="15" :stroke-width="1.5" />{{ primary }}</button>
    </PageHead>

    <PipelineSteps v-if="pipeline && tab === 'bundles'" class="mb-5" title="发布流水线" :steps="pipeline" :current="status || undefined" @select="pickStage" />

    <SectionTabs v-model="tabModel" class="mb-4" label="发布管理分段" :options="[
      { value: 'bundles', label: '发布组合', anyOf: ['resource.read'] },
      { value: 'policies', label: '决策策略', anyOf: ['resource.read'] },
      { value: 'capabilities', label: '能力', anyOf: ['resource.read'] },
      { value: 'validation', label: '验证记录', anyOf: ['evaluation.read'] },
    ]" />

    <template v-if="tab === 'validation'">
      <ValidationPanel v-if="evaluations" ref="panel" v-model:record="recordModel" v-model:q="q" v-model:status="status" v-model:id="openId" />
      <p v-else class="panel px-5 py-10 text-center text-[13px] text-ink-3">当前身份没有评价读取权限（evaluation.read），不显示验证记录。</p>
    </template>
    <template v-else-if="resources">
      <BundlesPanel v-if="tab === 'bundles'" ref="panel" v-model:q="q" v-model:status="status" v-model:id="openId" />
      <PoliciesPanel v-else-if="tab === 'policies'" ref="panel" v-model:q="q" v-model:status="status" v-model:id="openId" />
      <CapabilitiesPanel v-else ref="panel" v-model:q="q" v-model:id="openId" />
    </template>
    <p v-else class="panel px-5 py-10 text-center text-[13px] text-ink-3">当前身份没有读取此分段的权限。</p>
  </div>
</template>
