<script setup lang="ts">
/**
 * 检测记录（威胁检测 / Records，任务单 F1R，前端设计文档第 10.2 节）：原「观测与推理」「判定与来源」合并为一页四段。
 *
 * 分段按因果链排列（接入批次 → 观察 → 推理 → 判定），默认打开判定段；只有打开的分段才读取数据。
 * - 资产与时间范围由后端筛选（`assetId`、`from`），换筛选后各分段重新从第一页读取；四个集合没有搜索列，不提供 `q`。
 * - 判定段每次读取 200 条、可追加；「来源 × 类别」矩阵与判定 / 类别 / 来源筛选只作用于已加载样本，页面写明条数与时间范围。
 * - 推理段的类别筛选只作用于当前页；不成功的推理不带分数，显示「—」而不是 0。
 * - 观察、推理详情可提交样本标注（`feedback.label`）。证据组只在事件详情中展开，本页不单独成段。
 * - 分段与筛选同步到 URL 查询参数（tab、assetId、range、view、decision、family、source）。
 */
import { computed, ref, watch } from 'vue'
import { RouterLink, useRoute, useRouter } from 'vue-router'
import { Brain, ChevronRight, Eye, FileStack, Grid3x3, History, List, Radio, Scale, ShieldX, Siren, X } from 'lucide-vue-next'
import PageHead from '@/components/PageHead.vue'
import ChainNav from '@/components/ChainNav.vue'
import SectionTabs from '@/components/SectionTabs.vue'
import Panel from '@/components/Panel.vue'
import Tag from '@/components/Tag.vue'
import IdText from '@/components/IdText.vue'
import Drawer from '@/components/Drawer.vue'
import LoadState from '@/components/LoadState.vue'
import CursorPager from '@/components/CursorPager.vue'
import FamilyScores from '@/components/FamilyScores.vue'
import { countIf } from '@/components/viz'
import { useCursor } from '@/composables/cursor'
import { errText } from '@/composables/load'
import { can } from '@/api/session'
import { detectApi, isRange, RANGES, rangeFrom, type RangeKey } from '@/api/v2/detect'
import {
  fmtTime, GUARD_FAMILIES, guardDecisionLabel, guardFamilyLabel, guardInferenceStatusLabel, guardReasonLabel,
  guardSourceKey, guardSourceLabel,
  type GuardDecision, type GuardDecisionEvidence, type GuardDetection, type GuardObservation, type GuardObservationBatch,
} from '@/api/types'
import { decisionTone, inferenceTone } from '@/data/tones'
import { useAssetNames } from './assets'
import LabelForm from './LabelForm.vue'

type Seg = 'batches' | 'observations' | 'detections' | 'decisions'
type DecisionKind = 'all' | 'alert' | 'block_candidate' | 'observe'
type DecisionView = 'matrix' | 'list'
const SEGS: readonly Seg[] = ['batches', 'observations', 'detections', 'decisions']
const KINDS: readonly DecisionKind[] = ['all', 'alert', 'block_candidate', 'observe']
const PAGE = 200

const route = useRoute()
const router = useRouter()
const str = (v: unknown) => (typeof v === 'string' ? v : '')
const pick = <T extends string>(v: unknown, list: readonly T[], fallback: T): T => (list.includes(v as T) ? (v as T) : fallback)

const seg = ref<Seg>(pick(route.query.tab, SEGS, 'decisions'))
const assetFilter = ref(str(route.query.assetId))
const range = ref<RangeKey | ''>(isRange(route.query.range) ? route.query.range : '')
const decisionView = ref<DecisionView>(pick(route.query.view, ['matrix', 'list'] as const, 'matrix'))
const decisionFilter = ref<DecisionKind>(pick(route.query.decision, KINDS, 'all'))
const familyFilter = ref(str(route.query.family))
const sourceFilter = ref(str(route.query.source))

const { assets, label: assetLabel } = useAssetNames()
const canLabel = computed(() => can('feedback.label'))

/* ---------- 读取：后端筛选（资产、时间） ---------- */

/** 时间下界在筛选变化时计算一次，翻页沿用同一值（游标与筛选绑定，变化会被后端拒绝）。 */
let from = rangeFrom(range.value)
const query = (cursor?: string, limit = 50) => ({ assetId: assetFilter.value || undefined, from, cursor, limit })

const batches = useCursor<GuardObservationBatch>((c) => detectApi.records('observation-batches', query(c)), false)
const observations = useCursor<GuardObservation>((c) => detectApi.records('observations', query(c)), false)
const detections = useCursor<GuardDetection>((c) => detectApi.records('detections', query(c)), false)
const paged = { batches, observations, detections }

/** 判定按 200 条追加读取，矩阵与列表随样本扩大同步更新；请求序号作废过期响应。 */
const decisions = ref<GuardDecision[]>([])
const decNext = ref<string | null>(null)
const decLoading = ref(false)
const decMore = ref(false)
const decError = ref('')
let decSeq = 0
async function loadDecisions(cursor?: string) {
  const mine = ++decSeq
  if (cursor) decMore.value = true
  else { decLoading.value = true; decisions.value = []; decNext.value = null }
  decError.value = ''
  try {
    const page = await detectApi.records<GuardDecision>('decisions', query(cursor, PAGE))
    if (mine !== decSeq) return
    decisions.value = cursor ? [...decisions.value, ...page.items] : page.items
    decNext.value = page.nextCursor
  } catch (e) {
    if (mine !== decSeq) return
    decError.value = errText(e)
  } finally {
    if (mine === decSeq) { decLoading.value = false; decMore.value = false }
  }
}
function loadMore() {
  if (decNext.value && !decMore.value) void loadDecisions(decNext.value)
}

/** 只读取打开过的分段；筛选变化后全部标记为过期，当前分段立即重读，其余在打开时重读。 */
const fresh = new Set<Seg>()
function ensure(s: Seg) {
  if (fresh.has(s)) return
  fresh.add(s)
  if (s === 'decisions') void loadDecisions()
  else paged[s].reset()
}
watch(seg, ensure, { immediate: true })
watch([assetFilter, range], () => {
  from = rangeFrom(range.value)
  fresh.clear()
  ensure(seg.value)
})

watch([seg, assetFilter, range, decisionView, decisionFilter, familyFilter, sourceFilter], () => {
  const q: Record<string, string> = { tab: seg.value }
  if (assetFilter.value) q.assetId = assetFilter.value
  if (range.value) q.range = range.value
  if (seg.value === 'decisions' && decisionView.value === 'list') q.view = 'list'
  if (seg.value === 'decisions' && decisionFilter.value !== 'all') q.decision = decisionFilter.value
  if ((seg.value === 'decisions' || seg.value === 'detections') && familyFilter.value) q.family = familyFilter.value
  if (seg.value === 'decisions' && sourceFilter.value) q.source = sourceFilter.value
  void router.replace({ query: q })
})

/* ---------- 分段导航 ---------- */

const loaded = (s: Seg) => (s === 'decisions' ? (fresh.has(s) && !decLoading.value ? decisions.value.length : undefined)
  : (fresh.has(s) && !paged[s].loading.value ? paged[s].items.value.length : undefined))
const segs = computed(() => [
  { value: 'batches' as const, label: '接入批次', icon: FileStack, count: loaded('batches'), note: '受理不等于已完成检测' },
  { value: 'observations' as const, label: '观察', icon: Radio, count: loaded('observations'), note: '单条快照，只含 asOf 之前的报文' },
  { value: 'detections' as const, label: '推理', icon: Brain, count: loaded('detections'), note: '模型输出，失败不带分数' },
  { value: 'decisions' as const, label: '判定', icon: Scale, count: loaded('decisions'), note: '模型与每条规则分别判定' },
])
const current = computed(() => segs.value.find((s) => s.value === seg.value)!)
const pager = computed(() => (seg.value === 'decisions' ? null : paged[seg.value]))

const filtered = computed(() => Boolean(assetFilter.value || range.value || familyFilter.value || sourceFilter.value || decisionFilter.value !== 'all'))
function clearFilters() {
  assetFilter.value = ''
  range.value = ''
  familyFilter.value = ''
  sourceFilter.value = ''
  decisionFilter.value = 'all'
}

/* ---------- 判定：来源 × 类别（只统计已加载样本） ---------- */

const ev = (d: GuardDecision) => (d.evidence && typeof d.evidence === 'object' ? d.evidence : {}) as GuardDecisionEvidence
const familyOf = (d: GuardDecision) => ev(d).family ?? ''
const sourceOf = (d: GuardDecision) => guardSourceKey(ev(d).source, ev(d).ruleId)
const reasonText = (code: string | null | undefined) => (code ? (guardReasonLabel[code] ?? code) : '—')

/** 矩阵列：模型在前，规则按编号排序；只列样本中出现过的来源。 */
const sources = computed(() => {
  const keys = new Set(decisions.value.map(sourceOf))
  keys.add('model')
  return [...keys].sort((a, b) => (a === 'model' ? -1 : b === 'model' ? 1 : a.localeCompare(b)))
})
interface Cell { total: number; alert: number; candidate: number; reasons: [string, number][] }
const matrix = computed(() => {
  const m = new Map<string, Cell>()
  for (const d of decisions.value) {
    const key = `${familyOf(d)}|${sourceOf(d)}`
    const c = m.get(key) ?? { total: 0, alert: 0, candidate: 0, reasons: [] }
    c.total++
    if (d.decision === 'alert') c.alert++
    if (d.decision === 'block_candidate') c.candidate++
    if (d.reasonCode && d.decision !== 'observe') {
      const hit = c.reasons.find((r) => r[0] === d.reasonCode)
      if (hit) hit[1]++
      else c.reasons.push([d.reasonCode, 1])
    }
    m.set(key, c)
  }
  for (const c of m.values()) c.reasons.sort((a, b) => b[1] - a[1])
  return m
})
const cell = (family: string, source: string) => matrix.value.get(`${family}|${source}`)
/** 单元格底色：有阻断候选为浅红，只有告警为浅黄，其余为浅灰。 */
const heat = (c: Cell) => (c.candidate ? 'bg-threat-soft hover:bg-threat/15' : c.alert ? 'bg-warn-soft hover:bg-warn/15' : 'bg-paper-soft hover:bg-ink-hair')
const span = computed(() => {
  const times = decisions.value.map((d) => d.decidedAt ?? d.createdAt).filter(Boolean).sort()
  return times.length ? { from: times[0], to: times[times.length - 1] } : null
})

const shownDecisions = computed(() => decisions.value.filter((d) =>
  (decisionFilter.value === 'all' || d.decision === decisionFilter.value)
  && (!familyFilter.value || familyOf(d) === familyFilter.value)
  && (!sourceFilter.value || sourceOf(d) === sourceFilter.value)))
function drill(family: string, source: string) {
  familyFilter.value = family
  sourceFilter.value = source
  decisionFilter.value = 'all'
  decisionView.value = 'list'
}

const legend = computed(() => [
  { key: 'alert', label: '告警', value: countIf(decisions.value, (d) => d.decision === 'alert'), icon: Siren, cls: 'bg-warn-soft text-warn' },
  { key: 'candidate', label: '阻断候选', value: countIf(decisions.value, (d) => d.decision === 'block_candidate'), icon: ShieldX, cls: 'bg-threat-soft text-threat' },
  { key: 'observe', label: '仅观察', value: countIf(decisions.value, (d) => d.decision === 'observe'), icon: Eye, cls: 'bg-paper-soft text-ink-3' },
])
const decisionViews = computed(() => [
  { value: 'matrix' as const, label: '来源 × 类别' },
  { value: 'list' as const, label: '判定列表', count: shownDecisions.value.length },
])

/* ---------- 推理：类别筛选只作用于当前页 ---------- */

const shownDetections = computed(() => detections.items.value.filter((d) => !familyFilter.value || d.family === familyFilter.value))
const familyText = (f: string | null | undefined) => (f ? (guardFamilyLabel[f] ?? f) : '—')

/* ---------- 批次：受理结果三态并存 ---------- */

const resultCount = (b: GuardObservationBatch, key: 'acceptedCount' | 'rejectedCount' | 'duplicateCount') => {
  const r = b.result
  if (!r || typeof r !== 'object') return null
  const v = (r as Record<string, unknown>)[key]
  return typeof v === 'number' ? v : null
}
const entries = (v: unknown): [string, string][] => {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return []
  return Object.entries(v as Record<string, unknown>).map(([k, x]) => [k, typeof x === 'object' && x !== null ? JSON.stringify(x) : String(x)])
}

/* ---------- 详情 ---------- */

const pickedBatch = ref<GuardObservationBatch | null>(null)
const pickedObservation = ref<GuardObservation | null>(null)
const pickedDetection = ref<GuardDetection | null>(null)
const pickedDecision = ref<GuardDecision | null>(null)
const pickedEv = computed(() => (pickedDecision.value ? ev(pickedDecision.value) : null))
const open = {
  batch: (b: GuardObservationBatch) => { pickedBatch.value = b },
  observation: (o: GuardObservation) => { pickedObservation.value = o },
  detection: (d: GuardDetection) => { pickedDetection.value = d },
  decision: (d: GuardDecision) => { pickedDecision.value = d },
}
const scoreText = (s: number | null | undefined, digits = 3) => (s == null ? '—' : Number(s).toFixed(digits))
</script>

<template>
  <div>
    <PageHead title="检测记录" desc="沿接入批次、观察、推理到判定查看检测链路，只显示你授权范围内的记录。" />

    <ChainNav v-model="seg" :options="segs" label="检测链路" />

    <!-- 判定构成：三类判定的计数与占比，兼作矩阵图例（只统计已加载样本） -->
    <div v-if="seg === 'decisions'" class="mt-4 grid gap-3 sm:grid-cols-3">
      <div v-for="st in legend" :key="st.key" class="panel flex items-center gap-4 px-5 py-4">
        <span class="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded" :class="st.cls" aria-hidden="true"><component :is="st.icon" :size="18" :stroke-width="1.5" /></span>
        <div class="min-w-0">
          <p class="whitespace-nowrap text-[12.5px] text-ink-3">{{ st.label }}</p>
          <p class="mt-0.5 flex items-baseline gap-2"><span class="num text-[1.5rem] font-light leading-none text-ink">{{ st.value }}</span><span class="num text-[12px] text-ink-4">{{ decisions.length ? Math.round((st.value / decisions.length) * 100) : 0 }}%</span></p>
        </div>
      </div>
    </div>

    <Panel class="mt-4" :title="seg === 'decisions' ? (decisionView === 'matrix' ? '来源 × 类别' : '判定列表') : current.label"
      :icon="seg === 'decisions' ? (decisionView === 'matrix' ? Grid3x3 : List) : current.icon" flush>
      <template v-if="seg === 'decisions'" #actions><SectionTabs v-model="decisionView" :options="decisionViews" label="判定视图" /></template>

      <template #toolbar>
        <div class="toolbar w-full">
          <label v-if="assets.length" class="toolbar-field"><span>资产</span>
            <select v-model="assetFilter" aria-label="资产筛选" class="field">
              <option value="">全部授权资产</option>
              <option v-for="a in assets" :key="a.id" :value="a.id">{{ a.displayName || a.assetKey }}</option>
            </select>
          </label>
          <label class="toolbar-field"><span>时间</span>
            <select v-model="range" aria-label="时间范围" class="field">
              <option value="">全部时间</option>
              <option v-for="r in RANGES" :key="r.value" :value="r.value">{{ r.label }}</option>
            </select>
          </label>
          <template v-if="seg === 'decisions' && decisionView === 'list'">
            <label class="toolbar-field"><span>判定</span>
              <select v-model="decisionFilter" aria-label="判定筛选" class="field">
                <option value="all">全部</option><option value="alert">告警</option><option value="block_candidate">阻断候选</option><option value="observe">仅观察</option>
              </select>
            </label>
            <label class="toolbar-field"><span>来源</span>
              <select v-model="sourceFilter" aria-label="来源筛选" class="field">
                <option value="">全部</option><option v-for="s in sources" :key="s" :value="s">{{ guardSourceLabel(s) }}</option>
              </select>
            </label>
          </template>
          <label v-if="(seg === 'decisions' && decisionView === 'list') || seg === 'detections'" class="toolbar-field" :title="seg === 'detections' ? '只筛选当前页' : '只筛选已加载样本'"><span>类别</span>
            <select v-model="familyFilter" aria-label="类别筛选" class="field">
              <option value="">全部</option><option v-for="f in GUARD_FAMILIES" :key="f" :value="f">{{ guardFamilyLabel[f] }}</option>
            </select>
          </label>
          <button v-if="filtered" type="button" class="act-ghost act-sm" @click="clearFilters"><X :size="13" :stroke-width="1.5" />清除筛选</button>
          <span v-if="seg === 'decisions'" class="toolbar-end text-[12.5px] text-ink-3">
            已加载 <span class="num text-ink">{{ decisions.length }}</span> 条<template v-if="span">（<span class="num">{{ fmtTime(span.from) }} — {{ fmtTime(span.to) }}</span>）</template>，统计只覆盖这部分
          </span>
          <span v-else-if="seg === 'detections' && familyFilter" class="toolbar-end text-[12.5px] text-ink-3">类别只筛选当前页</span>
        </div>
      </template>

      <!-- 判定 -->
      <LoadState v-if="seg === 'decisions'" :loading="decLoading" :error="decError" :empty="!decisions.length" empty-text="你可见范围内暂无判定记录。">
        <Transition name="fade" mode="out-in">
          <div v-if="decisionView === 'matrix'" key="m">
            <div class="overflow-x-auto">
              <table class="table min-w-[640px]">
                <thead><tr><th class="w-28">类别</th><th v-for="s in sources" :key="s" class="whitespace-nowrap">{{ guardSourceLabel(s) }}</th></tr></thead>
                <tbody>
                  <tr v-for="f in GUARD_FAMILIES" :key="f">
                    <td class="whitespace-nowrap text-ink">{{ guardFamilyLabel[f] }}</td>
                    <td v-for="s in sources" :key="s" class="!py-1.5">
                      <button v-if="cell(f, s)" type="button" class="group block w-full rounded px-2.5 py-2 text-left transition-colors" :class="heat(cell(f, s)!)"
                        :aria-label="`查看${guardFamilyLabel[f]}·${guardSourceLabel(s)}的判定`" @click="drill(f, s)">
                        <span class="num block whitespace-nowrap text-[13px]">
                          <span :class="cell(f, s)!.alert ? 'text-warn' : 'text-ink-4'">告警 {{ cell(f, s)!.alert }}</span>
                          <span class="mx-1.5 text-ink-4">·</span>
                          <span :class="cell(f, s)!.candidate ? 'text-threat' : 'text-ink-4'">候选 {{ cell(f, s)!.candidate }}</span>
                        </span>
                        <span class="block text-[11.5px] text-ink-3">共 <span class="num">{{ cell(f, s)!.total }}</span> 条<template v-if="cell(f, s)!.reasons.length"> · 主要原因 {{ reasonText(cell(f, s)!.reasons[0][0]) }}</template></span>
                        <span class="mt-0.5 inline-flex items-center gap-0.5 text-[11.5px] text-ink-4 group-hover:text-ink">查看<ChevronRight :size="12" :stroke-width="1.5" /></span>
                      </button>
                      <span v-else class="num block px-2.5 text-ink-4">—</span>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
            <p class="border-t border-ink-hair px-5 py-3 text-[12.5px] leading-relaxed text-ink-3">
              「候选」通过了全部自动门，是否执行以处置记录为准；带原因码的「告警」在该门被拒绝。本页不推断来源能否自动，
              <RouterLink v-if="can('evaluation.read')" to="/console/release/lab" class="link">来源等级以验证记录为准</RouterLink><template v-else>来源等级以发布管理的验证记录为准</template>。
            </p>
          </div>

          <div v-else key="l">
            <p v-if="!shownDecisions.length" class="py-12 text-center text-[13px] text-ink-3">已加载的判定中没有符合条件的记录。</p>
            <div v-else class="overflow-x-auto">
              <table class="table min-w-[760px]">
                <thead><tr><th>判定</th><th>类别</th><th>来源</th><th>原因</th><th>资产</th><th class="text-right">判定时间</th></tr></thead>
                <tbody>
                  <tr v-for="d in shownDecisions" :key="d.id" class="row-link" tabindex="0" @click="open.decision(d)" @keydown.enter="open.decision(d)">
                    <td><Tag :tone="decisionTone[d.decision]" :label="guardDecisionLabel[d.decision] ?? d.decision" /></td>
                    <td class="text-ink-2">{{ familyText(familyOf(d)) }}</td>
                    <td class="text-ink-2">{{ guardSourceLabel(ev(d).source, ev(d).ruleId) }}</td>
                    <td class="text-ink-2">{{ reasonText(d.reasonCode) }}</td>
                    <td class="text-ink-2">{{ assetLabel(d.assetId) }}</td>
                    <td class="num text-right text-ink-3">{{ fmtTime(d.decidedAt ?? d.createdAt) }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </Transition>
      </LoadState>

      <!-- 推理 -->
      <LoadState v-else-if="seg === 'detections'" :loading="detections.loading.value" :error="detections.error.value" :empty="!shownDetections.length"
        :empty-text="familyFilter ? '当前页没有该类别的推理记录。' : '你可见范围内暂无推理记录。'">
        <div class="overflow-x-auto">
          <table class="table min-w-[760px]">
            <thead><tr><th>分数</th><th>结论</th><th>类别</th><th>四类分数</th><th>资产</th><th class="text-right">完成时间</th></tr></thead>
            <tbody>
              <tr v-for="d in shownDetections" :key="d.id" class="row-link" tabindex="0" @click="open.detection(d)" @keydown.enter="open.detection(d)">
                <td class="w-28">
                  <span class="num block text-[15px]" :class="(d.score ?? 0) >= 0.9 ? 'text-threat' : 'text-ink'">{{ scoreText(d.score) }}</span>
                  <span v-if="d.score != null" class="mt-1 block h-1 w-20 overflow-hidden rounded-full bg-ink-hair"><span class="block h-full rounded-full" :class="d.score >= 0.9 ? 'bg-threat' : 'bg-ink-3'" :style="{ width: `${Math.min(1, Math.max(0, d.score)) * 100}%` }" /></span>
                </td>
                <td><Tag :tone="inferenceTone[d.status]" :label="guardInferenceStatusLabel[d.status] ?? d.status" /><span v-if="d.errorCode" class="num ml-2 text-[12px] text-threat">{{ d.errorCode }}</span></td>
                <td class="text-ink-2">{{ familyText(d.family) }}</td>
                <td><FamilyScores :scores="d.familyScores" compact /></td>
                <td class="text-ink-2">{{ assetLabel(d.assetId) }}</td>
                <td class="num text-right text-ink-3">{{ fmtTime(d.completedAt) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </LoadState>

      <!-- 观察 -->
      <LoadState v-else-if="seg === 'observations'" :loading="observations.loading.value" :error="observations.error.value" :empty="!observations.items.value.length" empty-text="你可见范围内暂无观察记录。">
        <div class="overflow-x-auto">
          <table class="table min-w-[720px]">
            <thead><tr><th>对端</th><th>资产</th><th>方向 / 端口</th><th>快照</th><th>特征格式</th><th class="text-right">快照时刻</th></tr></thead>
            <tbody>
              <tr v-for="o in observations.items.value" :key="o.id" class="row-link" tabindex="0" @click="open.observation(o)" @keydown.enter="open.observation(o)">
                <td><IdText :value="o.peerKey" :length="12" :copy="false" /></td>
                <td class="text-ink-2">{{ assetLabel(o.assetId) }}</td>
                <td class="num text-ink-2">{{ o.direction ?? '—' }} / {{ o.servicePort ?? '—' }}</td>
                <td class="num text-ink-3">#{{ o.snapshotIndex ?? '—' }}</td>
                <td class="num text-ink-3">{{ o.profile ?? '—' }}</td>
                <td class="num text-right text-ink-3">{{ fmtTime(o.asOf) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </LoadState>

      <!-- 接入批次 -->
      <LoadState v-else :loading="batches.loading.value" :error="batches.error.value" :empty="!batches.items.value.length" empty-text="你可见范围内暂无接入批次。">
        <div class="overflow-x-auto">
          <table class="table min-w-[640px]">
            <thead><tr><th>批次</th><th>资产</th><th>序号</th><th>接受 / 拒绝 / 重复</th><th class="text-right">接收时间</th></tr></thead>
            <tbody>
              <tr v-for="b in batches.items.value" :key="b.id" class="row-link" tabindex="0" @click="open.batch(b)" @keydown.enter="open.batch(b)">
                <td><IdText :value="b.id" :copy="false" /></td>
                <td class="text-ink-2">{{ assetLabel(b.assetId) }}</td>
                <td class="num text-ink-2">{{ b.sequenceNo }}</td>
                <td class="num">
                  <span class="text-ink">{{ resultCount(b, 'acceptedCount') ?? '—' }}</span>
                  <span class="mx-1 text-ink-4">/</span><span :class="resultCount(b, 'rejectedCount') ? 'text-threat' : 'text-ink-3'">{{ resultCount(b, 'rejectedCount') ?? '—' }}</span>
                  <span class="mx-1 text-ink-4">/</span><span class="text-ink-3">{{ resultCount(b, 'duplicateCount') ?? '—' }}</span>
                </td>
                <td class="num text-right text-ink-3">{{ fmtTime(b.createdAt) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </LoadState>

      <template #foot>
        <div v-if="seg === 'decisions'" class="flex items-center justify-between gap-3 px-5 py-3 text-[12.5px] text-ink-3">
          <span>{{ decNext ? '还有更早的判定' : (decisions.length ? '已到最早一条' : '') }}</span>
          <button type="button" class="act-ghost act-sm" :disabled="!decNext || decMore || decLoading" @click="loadMore"><History :size="14" :stroke-width="1.5" />{{ decMore ? '读取中…' : `再加载 ${PAGE} 条` }}</button>
        </div>
        <CursorPager v-else-if="pager" :count="pager.items.value.length" :has-next="!!pager.next.value" :has-prev="!!pager.stack.value.length"
          :busy="pager.turning.value" :label="current.label" @next="pager.forward()" @prev="pager.back()" />
      </template>
    </Panel>

    <!-- 判定详情 -->
    <Drawer :open="!!pickedDecision" :title="pickedDecision ? `${guardDecisionLabel[pickedDecision.decision] ?? pickedDecision.decision} · ${familyText(familyOf(pickedDecision))}` : ''" kicker="判定" @close="pickedDecision = null">
      <template v-if="pickedDecision && pickedEv">
        <p class="note mb-5" :class="pickedDecision.decision === 'block_candidate' ? 'note-threat' : pickedDecision.decision === 'alert' ? 'note-warn' : ''">
          <template v-if="pickedDecision.decision === 'block_candidate'">通过全部自动门的阻断候选；是否下发与生效以处置记录中的动作和回执为准。</template>
          <template v-else-if="pickedDecision.decision === 'alert'">已告警。{{ pickedDecision.reasonCode ? `自动门在「${reasonText(pickedDecision.reasonCode)}」处拒绝，因此不会自动封禁。` : '' }}</template>
          <template v-else>未达告警阈值，只作观察记录。</template>
        </p>
        <dl class="kv">
          <div v-for="[k, v] in [
            ['类别', familyText(pickedEv.family)],
            ['来源', guardSourceLabel(pickedEv.source, pickedEv.ruleId)],
            ['原因', pickedDecision.reasonCode ? reasonText(pickedDecision.reasonCode) : '—'],
            ['资产', assetLabel(pickedDecision.assetId)],
            ['作用域', pickedEv.scope ?? '—'],
            ['环境', pickedEv.environment ?? '—'],
            ['执行能力', pickedEv.capabilityId ? '已匹配' : '该环境没有匹配的执行能力'],
            ['判定时间', fmtTime(pickedDecision.decidedAt ?? pickedDecision.createdAt)],
          ]" :key="k" class="grid-cols-[7rem_minmax(0,1fr)] text-[13px]">
            <dt class="text-ink-3">{{ k }}</dt><dd class="break-all">{{ v }}</dd>
          </div>
        </dl>
        <h3 class="section-title mt-8">选用证据（{{ pickedEv.selectedObservations?.length ?? 0 }}）</h3>
        <ul>
          <li v-for="o in pickedEv.selectedObservations ?? []" :key="o.observationId" class="grid grid-cols-[1fr_auto] gap-3 border-b border-ink-hair py-2.5 text-[12.5px]">
            <span><span class="flex items-center gap-1.5">观察 <IdText :value="o.observationId" /><span v-if="o.observationId === pickedEv.triggerObservationId" class="text-ink-3">· 触发观察</span></span>
              <span class="text-[11.5px] text-ink-4">{{ familyText(o.family) }} · {{ guardSourceLabel(o.source, o.ruleId) }}</span></span>
            <span class="num text-ink-3">{{ fmtTime(o.asOf) }}</span>
          </li>
          <li v-if="!pickedEv.selectedObservations?.length" class="py-3 text-[12.5px] text-ink-3">该判定未选用证据。</li>
        </ul>
        <p class="mt-4 text-[12px] leading-relaxed text-ink-3">证据为判定时冻结的摘要；目标只显示引用，不返回真实地址。</p>
        <details class="tech-details mt-6">
          <summary>技术细节</summary>
          <dl class="kv text-[12px]">
            <div v-for="[k, v] in [
              ['判定 ID', pickedDecision.id],
              ['原因码', pickedDecision.reasonCode || '—'],
              ['细分原因码', pickedEv.detailCode ?? '—'],
              ['证据组', pickedDecision.episodeId],
              ['发布组合', pickedEv.bundleId ?? '—'],
              ['执行能力', pickedEv.capabilityId ?? '—'],
              ['授权', pickedEv.authorizationId ? `${pickedEv.authorizationId} · 修订 ${pickedEv.authorizationRevision ?? '—'}` : '—'],
              ['预算目标', pickedEv.budgetTargetId ?? '—'],
              ['证据摘要', pickedDecision.evidenceSha256 ?? '—'],
              ['判定协议', pickedDecision.decisionContractVersion ?? '—'],
            ]" :key="k" class="grid-cols-[6rem_minmax(0,1fr)]">
              <dt>{{ k }}</dt><dd class="num break-all">{{ v }}</dd>
            </div>
          </dl>
        </details>
      </template>
    </Drawer>

    <!-- 推理详情 -->
    <Drawer :open="!!pickedDetection" :title="pickedDetection ? `推理 · ${familyText(pickedDetection.family)}` : ''" kicker="推理" @close="pickedDetection = null">
      <template v-if="pickedDetection">
        <p class="note mb-5" :class="pickedDetection.status === 'succeeded' ? '' : 'note-threat'">
          {{ pickedDetection.status === 'succeeded' ? '分数为模型输出，本身不决定放行或封禁；判定由策略与发布组合完成。' : '推理未成功，不带攻击概率；缺失数据不当作低风险。' }}
        </p>
        <dl class="kv">
          <div v-for="[k, v] in [
            ['结论', guardInferenceStatusLabel[pickedDetection.status] ?? pickedDetection.status],
            ['分数', scoreText(pickedDetection.score, 4)],
            ['类别', familyText(pickedDetection.family)],
            ['适用性', pickedDetection.applicability ?? '—'],
            ['错误码', pickedDetection.errorCode ?? '—'],
            ['资产', assetLabel(pickedDetection.assetId)],
            ['完成时间', fmtTime(pickedDetection.completedAt)],
          ]" :key="k" class="grid-cols-[7rem_minmax(0,1fr)] text-[13px]">
            <dt class="text-ink-3">{{ k }}</dt><dd class="break-all">{{ v }}</dd>
          </div>
        </dl>
        <h3 class="section-title mt-8">四类分数</h3>
        <FamilyScores :scores="pickedDetection.familyScores" />
        <LabelForm v-if="canLabel && pickedDetection.observationId" :observation-id="pickedDetection.observationId"
          :evidence-ref="`det:${pickedDetection.id.slice(0, 8)}`" title="标注关联观察" />
        <details class="tech-details mt-6">
          <summary>技术细节</summary>
          <dl class="kv text-[12px]">
            <div v-for="[k, v] in [
              ['推理 ID', pickedDetection.id],
              ['观察', pickedDetection.observationId],
              ['模型', pickedDetection.modelId ?? '—'],
              ['模型清单摘要', pickedDetection.manifestSha256 ?? '—'],
              ['写入时间', fmtTime(pickedDetection.createdAt)],
            ]" :key="k" class="grid-cols-[6rem_minmax(0,1fr)]">
              <dt>{{ k }}</dt><dd class="num break-all">{{ v }}</dd>
            </div>
          </dl>
        </details>
      </template>
    </Drawer>

    <!-- 观察详情 -->
    <Drawer :open="!!pickedObservation" :title="pickedObservation ? `观察 · ${assetLabel(pickedObservation.assetId)} · ${pickedObservation.direction ?? '—'} / ${pickedObservation.servicePort ?? '—'}` : ''" kicker="观察" @close="pickedObservation = null">
      <template v-if="pickedObservation">
        <dl class="kv">
          <div v-for="[k, v] in [
            ['资产', assetLabel(pickedObservation.assetId)],
            ['方向 / 传输', `${pickedObservation.direction ?? '—'} / ${pickedObservation.transport ?? '—'}`],
            ['服务端口', pickedObservation.servicePort == null ? '—' : String(pickedObservation.servicePort)],
            ['环境', pickedObservation.environment ?? '—'],
            ['快照序号', pickedObservation.snapshotIndex == null ? '—' : String(pickedObservation.snapshotIndex)],
            ['快照时刻', fmtTime(pickedObservation.asOf)],
            ['最后报文', fmtTime(pickedObservation.lastPacketAt)],
          ]" :key="k" class="grid-cols-[7rem_minmax(0,1fr)] text-[13px]">
            <dt class="text-ink-3">{{ k }}</dt><dd class="break-all">{{ v }}</dd>
          </div>
        </dl>
        <p class="mt-2 text-[12px] leading-relaxed text-ink-3">快照只含快照时刻之前的报文；同一父流的续段不重复计数。</p>
        <h3 class="section-title mt-8">特征</h3>
        <dl class="kv">
          <div v-for="[k, v] in entries(pickedObservation.payload)" :key="k" class="grid-cols-[10rem_minmax(0,1fr)] text-[12.5px]">
            <dt class="num text-ink-3">{{ k }}</dt><dd class="num break-all">{{ v }}</dd>
          </div>
          <p v-if="!entries(pickedObservation.payload).length" class="py-3 text-[12.5px] text-ink-3">该记录未保存特征。</p>
        </dl>
        <LabelForm v-if="canLabel" :observation-id="pickedObservation.id" :evidence-ref="`sha256:${pickedObservation.contentSha256.slice(0, 16)}`"
          @submitted="observations.reset()" />
        <details class="tech-details mt-6">
          <summary>技术细节</summary>
          <dl class="kv text-[12px]">
            <div v-for="[k, v] in [
              ['观察 ID', pickedObservation.id],
              ['对端', pickedObservation.peerKey ?? '—'],
              ['批次', pickedObservation.batchId],
              ['传感器', pickedObservation.sensorId],
              ['启动标识', pickedObservation.bootId],
              ['捕获范围', pickedObservation.captureScopeId ?? '—'],
              ['流标识', pickedObservation.flowId],
              ['父流', pickedObservation.parentConnectionId ?? '—'],
              ['对端密钥轮次', pickedObservation.keyEpoch ?? '—'],
              ['特征格式', pickedObservation.profile ?? '—'],
              ['内容摘要', pickedObservation.contentSha256],
              ['写入时间', fmtTime(pickedObservation.createdAt)],
            ]" :key="k" class="grid-cols-[6rem_minmax(0,1fr)]">
              <dt>{{ k }}</dt><dd class="num break-all">{{ v }}</dd>
            </div>
          </dl>
        </details>
      </template>
    </Drawer>

    <!-- 批次详情 -->
    <Drawer :open="!!pickedBatch" :title="pickedBatch ? `批次 · 序号 ${pickedBatch.sequenceNo}` : ''" kicker="接入批次" @close="pickedBatch = null">
      <template v-if="pickedBatch">
        <p class="note mb-5">受理表示批次已持久化，检测与处置尚未完成；允许部分接收，拒绝明细按观察逐条返回。</p>
        <dl class="kv">
          <div v-for="[k, v] in [
            ['资产', assetLabel(pickedBatch.assetId)],
            ['序号', String(pickedBatch.sequenceNo)],
            ['接收时间', fmtTime(pickedBatch.createdAt)],
          ]" :key="k" class="grid-cols-[7rem_minmax(0,1fr)] text-[13px]">
            <dt class="text-ink-3">{{ k }}</dt><dd class="break-all">{{ v }}</dd>
          </div>
        </dl>
        <h3 class="section-title mt-8">受理结果</h3>
        <dl class="kv">
          <div v-for="[k, v] in entries(pickedBatch.result)" :key="k" class="grid-cols-[9rem_minmax(0,1fr)] text-[12.5px]">
            <dt class="num text-ink-3">{{ k }}</dt><dd class="num break-all">{{ v }}</dd>
          </div>
          <p v-if="!entries(pickedBatch.result).length" class="py-3 text-[12.5px] text-ink-3">未保存受理明细。</p>
        </dl>
        <details class="tech-details mt-6">
          <summary>技术细节</summary>
          <dl class="kv text-[12px]">
            <div v-for="[k, v] in [
              ['批次 ID', pickedBatch.id],
              ['传感器', pickedBatch.sensorId],
              ['启动标识', pickedBatch.bootId],
              ['采集配置', pickedBatch.configId ?? '—'],
              ['请求摘要', pickedBatch.requestSha256],
            ]" :key="k" class="grid-cols-[6rem_minmax(0,1fr)]">
              <dt>{{ k }}</dt><dd class="num break-all">{{ v }}</dd>
            </div>
          </dl>
        </details>
      </template>
    </Drawer>
  </div>
</template>
