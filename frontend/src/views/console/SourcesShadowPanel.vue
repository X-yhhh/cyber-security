<script setup lang="ts">
/**
 * 数据源页「影子验证」页签（路线 B 阶段 7 §13）。
 *
 * - 汇总：GET /data-sources/{id}/shadow-report?from&to&zone，点击后生成，不在挂载时自动请求。
 *   起止按浏览器本地时间输入，提交时转为 ISO UTC 瞬时；31 天上限与参数合法性由后端校验（400）。
 * - 人工抽检：展示后端给出的抽检规则、计数与样本（样本仅在有 alert.read 时返回，已按可见性过滤），
 *   每行可打开告警标注抽屉，标注后按同一参数重新生成汇总。
 * - 待我复核：GET /feedback-reviews 分页（后端已排除本人标注），复核 POST /feedback-samples/{id}/review。
 * 本页只读汇总并承载人工标注 / 复核，不修改阈值、不换模型、不触发处置；权限只用于隐藏入口，授权以后端为准。
 */
import { computed, reactive, ref, watch } from 'vue'
import Tag from '@/components/Tag.vue'
import Drawer from '@/components/Drawer.vue'
import LoadState from '@/components/LoadState.vue'
import Pager from '@/components/Pager.vue'
import AlertFeedbackDrawer from '@/components/AlertFeedbackDrawer.vue'
import { api, type Page } from '@/api/client'
import { can } from '@/api/session'
import {
  alertTypeLabel, criterionLabel, driftStatusLabel, feedbackLabel, feedbackReviewLabel, fmtTime, severityLabel, verdictLabel,
  type AlertFeedbackView, type DataSourceView, type ShadowReport, type ShadowReviewItem,
} from '@/api/types'
import { criterionTone, driftTone, feedbackReviewTone, feedbackTone, severityTone, verdictTone } from '@/data/tones'
import { toast } from '@/composables/toast'
import { errText, useLoad } from '@/composables/load'

const props = defineProps<{ sources: DataSourceView[] }>()

// ---------------------------------------------------------------- 查询表单

/** Date → datetime-local 输入值（浏览器本地时间，精确到分钟）。 */
function localInput(d: Date) {
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`
}
const now = new Date()
const form = reactive({ sourceId: 0, from: localInput(new Date(now.getTime() - 7 * 86_400_000)), to: localInput(now), zone: 'Asia/Shanghai' })
watch(() => props.sources, (l) => { if (!l.some((s) => s.id === form.sourceId)) form.sourceId = l[0]?.id ?? 0 }, { immediate: true })

const report = ref<ShadowReport | null>(null)
const generating = ref(false)
const reportError = ref('')
/** 最近一次成功生成的请求路径；标注或复核后按同一参数重新生成，不采用表单中尚未提交的修改。 */
let lastPath = ''
let seq = 0
/** 按表单构造请求路径；本地时间转 ISO UTC，缺失或起止倒置时提示并返回 null。 */
function buildPath(): string | null {
  const from = new Date(form.from)
  const to = new Date(form.to)
  const problem = !form.sourceId ? '请先选择数据源。'
    : Number.isNaN(from.getTime()) || Number.isNaN(to.getTime()) ? '请填写完整的起止时间。'
      : from >= to ? '开始时间必须早于结束时间。' : ''
  if (problem) {
    toast(problem, 'warn')
    return null
  }
  const q = new URLSearchParams({ from: from.toISOString(), to: to.toISOString() })
  if (form.zone.trim()) q.set('zone', form.zone.trim())
  return `/data-sources/${form.sourceId}/shadow-report?${q.toString()}`
}

/** 请求汇总；以请求序号丢弃过期响应。失败时清空旧结果，避免把旧参数的结论当作新结论。 */
async function fetchReport(path: string) {
  const mine = ++seq
  generating.value = true
  reportError.value = ''
  try {
    const r = await api.get<ShadowReport>(path)
    if (mine !== seq) return
    report.value = r
    lastPath = path
  } catch (e) {
    if (mine !== seq) return
    report.value = null
    reportError.value = errText(e)
  } finally {
    if (mine === seq) generating.value = false
  }
}
function generate() {
  const path = buildPath()
  if (path) fetchReport(path)
}
const refreshReport = () => { if (lastPath) fetchReport(lastPath) }

// ---------------------------------------------------------------- 显示格式（缺失值显示 —，不补值）

const pct = (v: number | null | undefined, digits = 2) => (v == null ? '—' : (Number(v) * 100).toFixed(digits) + '%')
const int = (v: number | null | undefined) => (v == null ? '—' : Number(v).toLocaleString('zh-CN'))
const hrs = (v: number | null | undefined) => (v == null ? '—' : Number(v).toFixed(1) + ' h')
const ms = (v: number | null | undefined) => (v == null ? '—' : Number(v).toLocaleString('zh-CN') + ' ms')
const fix = (v: number | null | undefined, digits = 3) => (v == null ? '—' : Number(v).toFixed(digits))
/** 计数映射 → 「键 n · 键 n」，空映射返回 —。 */
const counts = (m: Record<string, number> | null | undefined) => {
  const e = Object.entries(m ?? {})
  return e.length ? e.map(([k, n]) => `${k} ${Number(n).toLocaleString('zh-CN')}`).join(' · ') : '—'
}
const ratios = (m: Record<string, number | null> | null | undefined) => {
  const e = Object.entries(m ?? {})
  return e.length ? e.map(([k, v]) => `${k} ${pct(v)}`).join(' · ') : '—'
}
const coverageRows = computed(() => {
  const c = report.value?.coverage
  if (!c) return []
  return [
    ['覆盖率', `${pct(c.coverageRatio, 1)}（${hrs(c.coveredHours)} / ${hrs(c.rangeHours)} · 传感器 ${c.sensors}）`],
    ['观测日', `${c.observedDays} 天 · 工作日 ${c.observedWeekdays} · 非工作日 ${c.observedWeekendDays}`],
    ['停机段', `${int(c.gapCount)} 段 · ${hrs(c.gapHours)}`],
    ['流 seen / emitted / dropped', `${int(c.flowsSeen)} / ${int(c.flowsEmitted)} / ${int(c.flowsDropped)}`],
    ['队列峰值', int(c.queueDepthMax)],
    ['健康窗口', int(c.healthWindows)],
  ]
})
const recordRows = computed(() => {
  const r = report.value?.records
  const a = report.value?.alerts
  if (!r || !a) return []
  return [
    ['记录总数', int(r.total)],
    ['接入拒绝', `${int(r.ingestRejected)}${Object.keys(r.ingestIssueCodes ?? {}).length ? '（' + counts(r.ingestIssueCodes) + '）' : ''}`],
    ['转人工', int(r.manualReview)],
    ['契约拒绝', `${int(r.contractRejected)} · 契约拒绝率 ${pct(r.contractRejectRate)}`],
    ['推理拒绝原因', counts(r.rejectReasons)],
    ['运行故障', `${int(r.operationalFailed)}（不计入契约拒绝率）`],
    ['未送推理', int(r.notInferred)],
    ['模型范围外', int(r.notInModelScope)],
    ['推理成功', int(r.scored)],
    ['判为攻击', `${int(r.scoredAttack)} · 占推理成功 ${pct(r.scopeAttackRatio)}`],
    ['词表外比例', ratios(r.outOfVocabularyRatio)],
    ['推理状态', counts(r.inferenceStatus)],
    ['模型告警', `${int(a.modelAlerts)} · 涉及资产 ${int(a.assetsWithAlerts)}`],
    ['每资产每日告警', `均值 ${fix(a.meanPerAssetDay)} · 最大 ${int(a.maxPerAssetDay)}${a.maxDay ? '（' + a.maxDay + '）' : ''}`],
  ]
})
const perfRows = computed(() => {
  const p = report.value?.performance
  if (!p) return []
  return [
    ['批次', int(p.batches)],
    ['P50 / P95', `${ms(p.p50Ms)} / ${ms(p.p95Ms)}`],
    ['P99 / 最大', `${ms(p.p99Ms)} / ${ms(p.maxMs)}`],
    ['死信', int(p.deadLetters)],
    ['消费重试中', int(p.consumerRetrying)],
    ['Outbox 积压', `${int(p.outboxPending)}${p.oldestPendingSeconds == null ? '' : ' · 最老 ' + Number(p.oldestPendingSeconds).toFixed(0) + ' s'}`],
  ]
})
const driftRows = computed(() => {
  const d = report.value?.drift
  if (!d) return []
  const keys = [...new Set([...Object.keys(d.psi ?? {}), ...Object.keys(d.otherRatio ?? {}), ...Object.keys(d.invalid ?? {})])]
  return keys.map((field) => ({ field, psi: d.psi?.[field] ?? null, other: d.otherRatio?.[field] ?? null, invalid: d.invalid?.[field] ?? 0 }))
})
/** PSI 口径与后端一致：> 0.3 为漂移告警，> 0.2 为预警；null 表示无法计算，不当作无漂移。 */
const psiTag = (v: number | null) =>
  v == null ? { tone: 'mute' as const, label: '无法计算' }
    : v > 0.3 ? { tone: 'threat' as const, label: '> 0.3' }
      : v > 0.2 ? { tone: 'warn' as const, label: '> 0.2' } : { tone: 'ok' as const, label: '正常' }
// ---------------------------------------------------------------- 人工抽检样本标注

const sampling = ref<ShadowReviewItem | null>(null)

// ---------------------------------------------------------------- 待我复核

const reviewPage = ref(0)
const { data: reviewList, loading: reviewLoading, error: reviewError, reload: reloadReviews } = useLoad(
  () => (can('feedback.review')
    ? api.get<Page<AlertFeedbackView>>(`/feedback-reviews?page=${reviewPage.value}&size=20`)
    : Promise.resolve({ totalElements: 0, page: 0, size: 20, items: [] } as Page<AlertFeedbackView>)),
  { totalElements: 0, page: 0, size: 20, items: [] } as Page<AlertFeedbackView>,
)
function turnReviews(page: number) {
  reviewPage.value = page
  reloadReviews()
}

const reviewing = ref<AlertFeedbackView | null>(null)
const reviewReason = ref('')
const reviewBusy = ref(false)
function openReview(f: AlertFeedbackView) {
  reviewing.value = f
  reviewReason.value = ''
}
/** 第二人复核；职责分离（403 REVIEW_SEPARATION_REQUIRED）与重复复核（409）由后端判定。 */
async function decide(decision: 'approve' | 'reject') {
  if (!reviewing.value || !reviewReason.value.trim()) return
  reviewBusy.value = true
  try {
    await api.post<AlertFeedbackView>(`/feedback-samples/${reviewing.value.id}/review`, { decision, reason: reviewReason.value.trim() })
    toast(decision === 'approve' ? '已批准：该标注进入离线训练候选，未改动模型或阈值。' : '已驳回：该标注失效，告警可重新标注。')
    reviewing.value = null
    reviewReason.value = ''
    // 本页最后一条被复核后回到上一页，避免停在空页
    if (reviewList.value.items.length === 1 && reviewPage.value > 0) reviewPage.value--
    await reloadReviews()
    refreshReport()
  } catch (e) {
    toast(errText(e), 'threat')
  } finally {
    reviewBusy.value = false
  }
}
</script>

<template>
  <div class="mt-10">
    <form class="grid items-end gap-6 md:grid-cols-[1.4fr_1fr_1fr_0.9fr_auto]" @submit.prevent="generate">
      <label class="block"><span class="label">数据源</span>
        <select v-model.number="form.sourceId" class="field mt-2">
          <option v-if="!sources.length" :value="0">无可见数据源</option>
          <option v-for="s in sources" :key="s.id" :value="s.id">{{ s.sourceKey }} · #{{ s.id }} · {{ s.environment }}</option>
        </select>
      </label>
      <label class="block"><span class="label">开始（本地时间）</span><input v-model="form.from" type="datetime-local" class="field num mt-2" required /></label>
      <label class="block"><span class="label">结束（本地时间）</span><input v-model="form.to" type="datetime-local" class="field num mt-2" required /></label>
      <label class="block"><span class="label">时区（划分自然日）</span><input v-model="form.zone" class="field num mt-2" maxlength="64" placeholder="Asia/Shanghai" /></label>
      <button type="submit" class="act" :disabled="generating || !form.sourceId">生成汇总</button>
    </form>
    <p class="mt-3 text-[12px] text-ink-3">起止按浏览器本地时间输入，提交时转为 UTC；范围不超过 31 天。时区只决定按日与工作日的划分。</p>

    <LoadState :loading="generating" :error="reportError" :empty="!report" empty-text="选择数据源与时间范围后生成汇总。">
      <div v-if="report" class="mt-14">
        <section>
          <p class="label">结论</p>
          <p class="mt-4 flex flex-wrap items-baseline gap-x-6 gap-y-2">
            <Tag :tone="verdictTone[report.verdict]" :label="verdictLabel[report.verdict] ?? report.verdict" />
            <span class="num text-[12.5px] text-ink-3">阈值 {{ report.thresholdsVersion }} · {{ report.reportVersion }} · 生成于 {{ fmtTime(report.generatedAt) }}</span>
          </p>
          <p class="num mt-2 text-[12.5px] text-ink-3">范围 {{ fmtTime(report.from) }} — {{ fmtTime(report.to) }} · 时区 {{ report.timeZone }} · 数据源 #{{ report.dataSourceId }}</p>
        </section>

        <h2 class="mb-6 mt-14 text-[15px]">G3 逐项判定</h2>
        <table class="table">
          <thead><tr><th>项目</th><th>阈值</th><th>当前值</th><th>状态</th><th>备注</th></tr></thead>
          <tbody>
            <tr v-for="c in report.criteria" :key="c.key">
              <td><span class="block">{{ c.title }}</span><span class="num text-[12px] text-ink-3">{{ c.key }}</span></td>
              <td class="num text-ink-2">{{ c.threshold }}</td>
              <td class="num">{{ c.value }}</td>
              <td><Tag :tone="criterionTone[c.status]" :label="criterionLabel[c.status] ?? c.status" /></td>
              <td class="text-[12.5px] text-ink-3">{{ c.note ?? '—' }}</td>
            </tr>
            <tr v-if="!report.criteria.length"><td colspan="5" class="py-8 text-center text-ink-3">后端未返回判定项。</td></tr>
          </tbody>
        </table>

        <h2 class="mb-4 mt-14 text-[15px]">局限性</h2>
        <ul class="border-t border-ink">
          <li v-for="(l, i) in report.limitations" :key="i" class="border-b border-ink-hair py-3 text-[13px] leading-relaxed">{{ l }}</li>
          <li v-if="!report.limitations.length" class="py-3 text-[13px] text-ink-3">后端未列出局限性。</li>
        </ul>
        <div class="mt-14 grid gap-14 xl:grid-cols-2">
          <div>
            <h3 class="label mb-4">覆盖</h3>
            <dl class="border-t border-ink">
              <div v-for="[k, v] in coverageRows" :key="k" class="grid grid-cols-[10rem_1fr] border-b border-ink-hair py-3 text-[13px]">
                <dt class="text-ink-3">{{ k }}</dt><dd class="num break-all">{{ v }}</dd>
              </div>
            </dl>
          </div>
          <div>
            <h3 class="label mb-4">记录与契约</h3>
            <dl class="border-t border-ink">
              <div v-for="[k, v] in recordRows" :key="k" class="grid grid-cols-[10rem_1fr] border-b border-ink-hair py-3 text-[13px]">
                <dt class="text-ink-3">{{ k }}</dt><dd class="num break-all">{{ v }}</dd>
              </div>
            </dl>
          </div>
        </div>

        <h2 class="mb-6 mt-14 text-[15px]">按日覆盖</h2>
        <table class="table">
          <thead><tr><th>日期</th><th>周末</th><th>覆盖小时</th><th>观测日</th><th class="text-right">模型告警</th></tr></thead>
          <tbody>
            <tr v-for="d in report.coverage.days" :key="d.date">
              <td class="num">{{ d.date }}</td>
              <td class="text-ink-2">{{ d.weekend ? '是' : '否' }}</td>
              <td class="num">{{ hrs(d.coveredHours) }}</td>
              <td><Tag :tone="d.observed ? 'ok' : 'mute'" :label="d.observed ? '是' : '否（< 12 h）'" /></td>
              <td class="num text-right">{{ int(d.modelAlerts) }}</td>
            </tr>
            <tr v-if="!report.coverage.days.length"><td colspan="5" class="py-8 text-center text-ink-3">范围内无按日数据。</td></tr>
          </tbody>
        </table>

        <h2 class="mb-6 mt-14 flex flex-wrap items-center gap-x-6 gap-y-2 text-[15px]">
          <span>特征漂移</span><Tag :tone="driftTone[report.drift.status]" :label="driftStatusLabel[report.drift.status] ?? report.drift.status" />
        </h2>
        <p class="num text-[12.5px] text-ink-3">
          基线 {{ report.drift.baselineVersion ?? '—' }} · 样本 {{ int(report.drift.samples) }} / 最小 {{ int(report.drift.minSamples) }} · 最大 PSI {{ fix(report.drift.maxPsi) }}
          · 超预警字段 {{ report.drift.fieldsAboveWarning.length ? report.drift.fieldsAboveWarning.join('、') : '无' }}
        </p>
        <p v-for="mu in report.drift.models" :key="mu.modelVersionId" class="num mt-1 break-all text-[12px] text-ink-3">模型 {{ mu.version }} · 推理 {{ int(mu.scored) }} · SHA-256 {{ mu.artifactSha256 }}</p>
        <table class="table mt-6">
          <thead><tr><th>字段</th><th>PSI</th><th>判定</th><th>其他类占比</th><th class="text-right">无效值</th></tr></thead>
          <tbody>
            <tr v-for="r in driftRows" :key="r.field">
              <td class="num">{{ r.field }}</td>
              <td class="num">{{ fix(r.psi, 4) }}</td>
              <td><Tag :tone="psiTag(r.psi).tone" :label="psiTag(r.psi).label" /></td>
              <td class="num">{{ pct(r.other) }}</td>
              <td class="num text-right">{{ int(r.invalid) }}</td>
            </tr>
            <tr v-if="!driftRows.length"><td colspan="5" class="py-8 text-center text-ink-3">未计算字段 PSI（{{ driftStatusLabel[report.drift.status] ?? report.drift.status }}）。</td></tr>
          </tbody>
        </table>
        <p class="mt-4 text-[12px] text-ink-3">PSI &gt; 0.2 为预警、&gt; 0.3 为漂移告警；PSI 只提示分布变化，需人工判断是否由采集降级导致，不会自动调整阈值或权重。</p>

        <h3 class="label mb-4 mt-14">端到端性能</h3>
        <dl class="border-t border-ink xl:w-1/2">
          <div v-for="[k, v] in perfRows" :key="k" class="grid grid-cols-[10rem_1fr] border-b border-ink-hair py-3 text-[13px]">
            <dt class="text-ink-3">{{ k }}</dt><dd class="num">{{ v }}</dd>
          </div>
        </dl>
        <h2 class="mb-6 mt-20 text-[15px]">人工抽检</h2>
        <p class="text-[13px] text-ink-2">{{ report.review.rule }}</p>
        <p class="num mt-2 flex flex-wrap gap-x-8 gap-y-1 text-[12.5px] text-ink-3">
          <span>总体 {{ int(report.review.population) }}</span><span>样本 {{ int(report.review.sampleSize) }}</span>
          <span>已标注 {{ int(report.review.labeled) }}</span><span>误报 {{ int(report.review.falsePositive) }} · 真报 {{ int(report.review.truePositive) }}</span>
          <span>误报率 {{ pct(report.review.falsePositiveRate) }}</span>
        </p>
        <table v-if="can('alert.read')" class="table mt-6">
          <thead><tr><th>告警</th><th>检测时间</th><th>严重级</th><th>分数</th><th>标注</th><th>复核状态</th><th><span class="sr-only">操作</span></th></tr></thead>
          <tbody>
            <tr v-for="s in report.review.sample" :key="s.alertId">
              <td class="num">{{ s.alertKey }}</td>
              <td class="num text-ink-3">{{ fmtTime(s.detectedAt) }}</td>
              <td><Tag :tone="severityTone[s.severity]" :label="severityLabel[s.severity] ?? s.severity" /></td>
              <td class="num">{{ fix(s.score) }}</td>
              <td><Tag v-if="s.label" :tone="feedbackTone[s.label]" :label="feedbackLabel[s.label] ?? s.label" /><span v-else class="text-ink-3">未标注</span></td>
              <td><Tag v-if="s.reviewStatus" :tone="feedbackReviewTone[s.reviewStatus]" :label="feedbackReviewLabel[s.reviewStatus] ?? s.reviewStatus" /><span v-else class="text-ink-3">—</span></td>
              <td class="text-right"><button type="button" class="link text-[13px]" :aria-label="`${s.label ? '查看标注' : '标注'} ${s.alertKey}`" @click="sampling = s">{{ s.label ? '查看标注' : '标注' }}</button></td>
            </tr>
            <tr v-if="!report.review.sample.length"><td colspan="7" class="py-8 text-center text-ink-3">{{ report.review.sampleSize ? '样本中没有你可见的告警。' : '范围内没有模型告警。' }}</td></tr>
          </tbody>
        </table>
        <p v-else class="mt-6 text-[12.5px] text-ink-3">当前身份没有告警读取权限（alert.read），只显示抽检计数。</p>
        <p class="mt-4 text-[12px] leading-relaxed text-ink-3">样本明细最多列出 500 条，且只含你按资产与数据源范围可见的告警；计数不受可见性过滤影响。</p>
      </div>
    </LoadState>
    <section v-if="can('feedback.review')" class="mt-20">
      <h2 class="mb-4 text-[15px]">待我复核<span class="num ml-2 text-[11px] text-ink-4">{{ reviewList.totalElements }}</span></h2>
      <p class="mb-6 text-[12.5px] text-ink-3">复核人不能是标注人；批准只表示该标注可进入离线训练候选，不会改动模型或阈值。</p>
      <LoadState :loading="reviewLoading" :error="reviewError">
        <table class="table">
          <thead><tr><th>告警</th><th>标注</th><th>说明</th><th>标注人</th><th>时间</th><th><span class="sr-only">操作</span></th></tr></thead>
          <tbody>
            <tr v-for="f in reviewList.items" :key="f.id">
              <td><span class="num block">{{ f.alertKey }}</span><span class="text-[12px] text-ink-3">{{ alertTypeLabel[f.alertType] ?? f.alertType }}</span></td>
              <td><Tag :tone="feedbackTone[f.label]" :label="feedbackLabel[f.label] ?? f.label" /></td>
              <td class="max-w-[22rem] text-[12.5px] text-ink-2">{{ f.note }}</td>
              <td class="text-ink-2">{{ f.reviewerName }}</td>
              <td class="num text-ink-3">{{ fmtTime(f.reviewedAt) }}</td>
              <td class="text-right"><button type="button" class="link text-[13px]" :aria-label="`复核 ${f.alertKey}`" @click="openReview(f)">复核</button></td>
            </tr>
            <tr v-if="!reviewList.items.length"><td colspan="6" class="py-8 text-center text-ink-3">没有待你复核的标注。</td></tr>
          </tbody>
        </table>
        <Pager label="待我复核" :total="reviewList.totalElements" :page="reviewList.page" :size="reviewList.size" :busy="reviewLoading" @change="turnReviews" />
      </LoadState>
    </section>

    <p class="mt-16 max-w-2xl text-[12.5px] leading-relaxed text-ink-3">影子验证只读汇总，不修改阈值、不换模型、不触发处置。正常流量上的误报率不代表对攻击的检出率。</p>

    <AlertFeedbackDrawer
      :open="!!sampling" :alert-id="sampling?.alertId ?? null" :alert-key="sampling?.alertKey ?? ''" alert-type="model"
      @close="sampling = null" @changed="refreshReport"
    />

    <Drawer :open="!!reviewing" :title="`复核标注 · ${reviewing?.alertKey ?? ''}`" kicker="第二人复核" @close="reviewing = null">
      <template v-if="reviewing">
        <dl class="border-t border-ink">
          <div v-for="[k, v] in [['告警', `${reviewing.alertKey} · ${alertTypeLabel[reviewing.alertType] ?? reviewing.alertType}`], ['标注人', reviewing.reviewerName], ['标注时间', fmtTime(reviewing.reviewedAt)], ['数据源 / 资产', `#${reviewing.dataSourceId} / #${reviewing.assetId}`]]" :key="k" class="grid grid-cols-[6.5rem_1fr] border-b border-ink-hair py-3 text-[13px]">
            <dt class="text-ink-3">{{ k }}</dt><dd class="num break-all">{{ v }}</dd>
          </div>
          <div class="grid grid-cols-[6.5rem_1fr] border-b border-ink-hair py-3 text-[13px]">
            <dt class="text-ink-3">标注</dt><dd><Tag :tone="feedbackTone[reviewing.label]" :label="feedbackLabel[reviewing.label] ?? reviewing.label" /></dd>
          </div>
        </dl>
        <h3 class="label mb-3 mt-8">研判说明</h3>
        <p class="whitespace-pre-line text-[13.5px] leading-relaxed">{{ reviewing.note }}</p>
        <label class="mt-10 block"><span class="label">复核理由</span><textarea v-model="reviewReason" rows="3" maxlength="1000" required class="field mt-2 h-auto resize-none py-2" /></label>
        <p class="mt-6 text-[12px] leading-relaxed text-ink-3">复核人不能是标注人；批准只表示该标注可进入离线训练候选，不会改动模型或阈值。驳回后标注失效，误报告警退回 acknowledged，可重新标注。</p>
      </template>
      <template #foot>
        <button type="button" class="link text-[13px]" :disabled="reviewBusy || !reviewReason.trim()" @click="decide('reject')">驳回</button>
        <button type="button" class="act" :disabled="reviewBusy || !reviewReason.trim()" @click="decide('approve')">批准用于训练</button>
      </template>
    </Drawer>
  </div>
</template>
