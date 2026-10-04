<script setup lang="ts">
/**
 * 告警与事件：事件为主视图，告警为次视图；筛选只保留严重度与状态。
 * 数据来自 /events 与 /alerts（后端 SQL 已按资产与数据源范围过滤），前端只做本页筛选。
 * 「规则」页签为确定性检测规则台账与登记/审批（DetectionRulesPanel），仅对有 detection.rule.read 的身份显示；
 * 「检测策略」页签为分级/关联/风险策略版本（DetectionPoliciesPanel），仅对有 detection.policy.read 的身份显示。
 * 告警分两层：alert 进入人工队列（默认）；signal 为低等级模型命中，经 ?layer=signal 单独读取，不进事件与计数。
 */
import { computed, ref } from 'vue'
import { useRouter } from 'vue-router'
import PageHead from '@/components/PageHead.vue'
import Segmented from '@/components/Segmented.vue'
import Tag from '@/components/Tag.vue'
import Drawer from '@/components/Drawer.vue'
import LoadState from '@/components/LoadState.vue'
import DetectionRulesPanel from './DetectionRulesPanel.vue'
import DetectionPoliciesPanel from './DetectionPoliciesPanel.vue'
import { api, type Page } from '@/api/client'
import { can } from '@/api/session'
import { alertLayerLabel, alertSource, alertTypeLabel, basisEntries, eventStatusLabel, fmtTime, severityLabel, type AlertView, type EventView, type Severity } from '@/api/types'
import { eventTone, severityTone, statusTone } from '@/data/tones'
import { errText, useLoad } from '@/composables/load'

const router = useRouter()
const view = ref<'events' | 'alerts' | 'rules' | 'policies'>('events')
const sev = ref<Severity | 'all'>('all')
const onlyOpen = ref(true)
const q = ref('')

const { data, loading, error } = useLoad(async () => {
  const [events, alerts] = await Promise.all([
    can('event.read') ? api.get<Page<EventView>>('/events?size=100') : null,
    can('alert.read') ? api.get<Page<AlertView>>('/alerts?size=100') : null,
  ])
  return { events: events?.items ?? [], alerts: alerts?.items ?? [], eventTotal: events?.totalElements ?? 0, alertTotal: alerts?.totalElements ?? 0 }
}, { events: [] as EventView[], alerts: [] as AlertView[], eventTotal: 0, alertTotal: 0 })

const shownEvents = computed(() =>
  data.value.events.filter(
    (e) =>
      (sev.value === 'all' || e.severity === sev.value) &&
      (!onlyOpen.value || ['open', 'investigating', 'contained'].includes(e.status)) &&
      (!q.value || (e.eventKey + e.title + e.category).toLowerCase().includes(q.value.toLowerCase())),
  ),
)
// 模型信号层：首次切到 signal 时才请求，失败只在本区块提示
const layer = ref<'alert' | 'signal'>('alert')
const signals = ref<{ items: AlertView[]; total: number; loading: boolean; error: string; loaded: boolean }>({ items: [], total: 0, loading: false, error: '', loaded: false })
async function loadSignals() {
  signals.value.loading = true
  signals.value.error = ''
  try {
    const p = await api.get<Page<AlertView>>('/alerts?layer=signal&size=100')
    signals.value = { items: p.items, total: p.totalElements, loading: false, error: '', loaded: true }
  } catch (e) {
    signals.value = { ...signals.value, loading: false, error: errText(e) }
  }
}
function pickLayer(l: 'alert' | 'signal') {
  layer.value = l
  if (l === 'signal' && !signals.value.loaded && !signals.value.loading) loadSignals()
}
const layerAlerts = computed(() => (layer.value === 'signal' ? signals.value.items : data.value.alerts))
const shownAlerts = computed(() =>
  layerAlerts.value.filter((a) => (sev.value === 'all' || a.severity === sev.value) && (!q.value || (a.alertKey + a.alertType + alertSource(a)).toLowerCase().includes(q.value.toLowerCase()))),
)
const picked = ref<AlertView | null>(null)
const pickedBasis = computed(() => basisEntries(picked.value?.basisJson ?? null))
const sevs: (Severity | 'all')[] = ['all', 'critical', 'high', 'medium', 'low']
const views = computed(() => [
  { value: 'events' as const, label: '事件', count: data.value.eventTotal },
  { value: 'alerts' as const, label: '告警', count: data.value.alertTotal },
  ...(can('detection.rule.read') ? [{ value: 'rules' as const, label: '规则' }] : []),
  ...(can('detection.policy.read') ? [{ value: 'policies' as const, label: '检测策略' }] : []),
])
</script>

<template>
  <div>
    <PageHead no="02" title="告警与事件" desc="告警由冻结模型与确定性规则产生，按资产与时间窗归并为事件。只显示全部关联资源都在你授权范围内的事件。">
      <template #kicker>Detection</template>
    </PageHead>

    <Segmented v-model="view" :options="views" />

    <div v-if="view === 'rules'" class="mt-10"><DetectionRulesPanel /></div>
    <div v-else-if="view === 'policies'" class="mt-10"><DetectionPoliciesPanel /></div>

    <template v-else>
    <div class="mt-8 flex flex-wrap items-center justify-between gap-6">
      <div class="flex items-center gap-5 text-[13px]">
        <button v-for="s in sevs" :key="s" class="transition-colors" :class="sev === s ? 'text-ink underline decoration-1 underline-offset-[6px]' : 'text-ink-3 hover:text-ink'" @click="sev = s">
          {{ s === 'all' ? '全部' : severityLabel[s] }}
        </button>
        <label v-if="view === 'events'" class="ml-4 flex items-center gap-2 text-ink-3">
          <input v-model="onlyOpen" type="checkbox" class="h-3.5 w-3.5 accent-ink" /> 仅未结案
        </label>
        <span v-if="view === 'alerts'" class="ml-4 flex items-center gap-4 border-l border-ink-hair pl-5" role="group" aria-label="告警层级">
          <button v-for="l in (['alert', 'signal'] as const)" :key="l" class="transition-colors" :aria-pressed="layer === l" :class="layer === l ? 'text-ink underline decoration-1 underline-offset-[6px]' : 'text-ink-3 hover:text-ink'" @click="pickLayer(l)">
            {{ alertLayerLabel[l] }}<span v-if="l === 'signal' && signals.loaded" class="num ml-1.5 text-[11px] text-ink-4">{{ signals.total }}</span>
          </button>
        </span>
      </div>
      <input v-model="q" class="field w-64" placeholder="搜索编号、类型或标题" aria-label="搜索" />
    </div>

    <div class="mt-10"><LoadState :loading="loading" :error="error">
    <Transition name="fade" mode="out-in">
      <table v-if="view === 'events'" key="e" class="table">
        <thead>
          <tr><th>风险</th><th>事件</th><th>类别</th><th>严重度</th><th>状态</th><th>资产</th><th class="text-right">最近</th></tr>
        </thead>
        <tbody>
          <tr v-for="e in shownEvents" :key="e.id" class="row-link" tabindex="0" @click="router.push({ name: 'event-detail', params: { id: e.id } })" @keydown.enter="router.push({ name: 'event-detail', params: { id: e.id } })">
            <td class="num w-16 text-[1.25rem] font-light" :class="(e.riskScore ?? 0) > 0.7 ? 'text-threat' : ''">{{ e.riskScore == null ? '—' : Math.round(e.riskScore * 100) }}</td>
            <td><span class="block">{{ e.title }}</span><span class="num text-[12px] text-ink-3">{{ e.eventKey }} · {{ e.alertCount }} 条告警</span></td>
            <td class="text-ink-2">{{ e.category }}</td>
            <td><Tag :tone="severityTone[e.severity]" :label="severityLabel[e.severity] ?? e.severity" /></td>
            <td><Tag :tone="eventTone[e.status]" :label="eventStatusLabel[e.status] ?? e.status" /></td>
            <td class="num text-ink-2">{{ e.assetCount }}</td>
            <td class="num text-right text-ink-3">{{ fmtTime(e.lastSeenAt) }}</td>
          </tr>
          <tr v-if="!shownEvents.length"><td colspan="7" class="py-16 text-center text-ink-3">{{ data.events.length ? '没有符合条件的事件。' : '数据库中暂无可见事件。' }}</td></tr>
        </tbody>
      </table>

      <div v-else key="a">
      <p v-if="layer === 'signal'" class="mb-6 border-l-2 border-signal py-1 pl-4 text-[12.5px] leading-relaxed text-ink-2">模型信号，未进人工队列：低于高分阈值的模型命中，不计入事件和态势告警数；同一资产在关联窗口内累计达到策略计数时提升为告警。</p>
      <LoadState :loading="layer === 'signal' && signals.loading" :error="layer === 'signal' ? signals.error : ''">
      <table class="table">
        <thead>
          <tr><th>时间</th><th>告警</th><th>类型</th><th>分数</th><th>状态</th><th>严重度</th></tr>
        </thead>
        <tbody>
          <tr v-for="a in shownAlerts" :key="a.id" class="row-link" tabindex="0" @click="picked = a" @keydown.enter="picked = a">
            <td class="num text-ink-3">{{ fmtTime(a.detectedAt) }}</td>
            <td><span class="num block">{{ a.alertKey }}</span><span class="num text-[12px] text-ink-3">资产 #{{ a.assetId ?? '—' }} · 数据源 #{{ a.dataSourceId }}</span></td>
            <td><span class="block text-ink-2">{{ alertTypeLabel[a.alertType] ?? a.alertType }}<template v-if="a.alertLayer === 'signal'"> · 模型信号</template><template v-else-if="a.promotedAt"> · 信号提升</template></span><span class="num text-[12px] text-ink-3">{{ alertSource(a) }}</span></td>
            <td class="num">{{ a.score == null ? '—' : Number(a.score).toFixed(3) }}</td>
            <td><Tag :tone="statusTone[a.status]" :label="a.status" /></td>
            <td><Tag :tone="severityTone[a.severity]" :label="severityLabel[a.severity] ?? a.severity" /></td>
          </tr>
          <tr v-if="!shownAlerts.length"><td colspan="6" class="py-16 text-center text-ink-3">{{ layerAlerts.length ? '没有符合条件的告警。' : layer === 'signal' ? '数据库中暂无可见模型信号。' : '数据库中暂无可见告警。' }}</td></tr>
        </tbody>
      </table>
      </LoadState>
      </div>
    </Transition>
    </LoadState></div>
    </template>

    <Drawer :open="!!picked" :title="picked?.alertKey ?? ''" :kicker="picked ? `ALERT #${picked.id}` : ''" @close="picked = null">
      <template v-if="picked">
        <dl class="border-t border-ink">
          <div v-for="[k, v] in [
            ['时间', fmtTime(picked.detectedAt)],
            ['类型', alertTypeLabel[picked.alertType] ?? picked.alertType],
            ['来源', alertSource(picked)],
            ['特征契约', picked.contractVersion ?? '—'],
            ['层级', picked.alertLayer === 'signal' ? '模型信号，未进人工队列' : alertLayerLabel[picked.alertLayer ?? 'alert'] ?? picked.alertLayer],
            ['分级策略', picked.severityPolicyVersion ?? '—'],
            ['关联策略', picked.correlationPolicyVersion ?? '—'],
            ['提升时间', fmtTime(picked.promotedAt)],
            ['阈值策略', picked.thresholdVersion ?? '—'],
            ['资产', picked.assetId == null ? '—' : `#${picked.assetId}`],
            ['数据源', `#${picked.dataSourceId}`],
            ['分数', picked.score == null ? '—' : Number(picked.score).toFixed(4)],
            ['状态', picked.status],
            ['严重度', severityLabel[picked.severity] ?? picked.severity],
          ]" :key="k" class="grid grid-cols-[8rem_1fr] border-b border-ink-hair py-3 text-[13px]">
            <dt class="text-ink-3">{{ k }}</dt><dd class="num break-all">{{ v }}</dd>
          </div>
        </dl>
        <h3 class="label mb-4 mt-10">评分依据</h3>
        <dl class="border-t border-ink">
          <div v-for="[k, v] in pickedBasis" :key="k" class="grid grid-cols-[10rem_1fr] border-b border-ink-hair py-2.5 text-[12.5px]">
            <dt class="text-ink-3">{{ k }}</dt><dd class="num break-all">{{ v }}</dd>
          </div>
          <p v-if="!pickedBasis.length" class="py-3 text-[12.5px] text-ink-3">该告警未保存评分依据。</p>
        </dl>
        <p class="mt-6 text-[12.5px] leading-relaxed text-ink-3">评分依据为告警生成时的快照，不随后续策略修改而变化。模型分数不单独决定放行或隔离；归属事件请在事件视图中查看。</p>
      </template>
    </Drawer>
  </div>
</template>
