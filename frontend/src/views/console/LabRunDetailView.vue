<script setup lang="ts">
/**
 * lab 会话详情：会话状态、签名 G3 报告的逐类与逐场景结论、已登记的来源等级、会话事实时间线。
 *
 * 数据来源（全部只读）：
 * - GET /lab-validation-runs/{id} 与 /qualifications：会话状态与已登记的来源等级；
 * - G3 报告原文存于评价运行（GET /evaluations/{evaluationId} 的 payload）：先取等级记录里的
 *   evaluationId，没有登记等级时（报告未通过或未导入）再在评价列表中按 sessionId 查找；
 * - GET /lab-validation-runs/{id}/events?after=：事实按追加序号翻页，不一次载入全部。
 *
 * 时延只报告不设门槛（latencyIsReportOnly）；报告的 limitations 原样列出，不改写措辞。
 */
import { computed, ref } from 'vue'
import { RouterLink, useRoute } from 'vue-router'
import { ArrowLeft } from 'lucide-vue-next'
import Tag from '@/components/Tag.vue'
import LoadState from '@/components/LoadState.vue'
import { errText } from '@/composables/load'
import { guard, type Cursor } from '@/api/client'
import {
  fmtTime, GUARD_FAMILIES, guardFamilyLabel, guardLabEligibilityLabel, guardLabEventKindLabel, guardLabRunStatusLabel,
  guardReasonLabel, guardSourceLabel,
  type GuardEvaluation, type GuardG3Report, type GuardG3Scenario, type GuardLabEvent, type GuardLabEventPage,
  type GuardLabQualifications, type GuardLabRun,
} from '@/api/types'
import { labEligibilityTone, labRunTone, qualificationTone, scenarioTone } from '@/data/tones'

const route = useRoute()
const id = String(route.params.id)

const run = ref<GuardLabRun | null>(null)
const quals = ref<GuardLabQualifications | null>(null)
const report = ref<GuardG3Report | null>(null)
const evaluation = ref<GuardEvaluation | null>(null)
const loading = ref(true)
const error = ref('')
const reportError = ref('')

async function load() {
  try {
    const [r, q] = await Promise.all([
      guard.read<GuardLabRun>(`lab-validation-runs/${encodeURIComponent(id)}`),
      guard.read<GuardLabQualifications>(`lab-validation-runs/${encodeURIComponent(id)}/qualifications`),
    ])
    run.value = r
    quals.value = q
  } catch (e) {
    error.value = errText(e)
    loading.value = false
    return
  }
  loading.value = false
  try {
    const evaluationId = quals.value?.sources[0]?.evaluationId
    let found: GuardEvaluation | null = evaluationId ? await guard.get<GuardEvaluation>('evaluations', evaluationId) : null
    if (!found) {
      const page: Cursor<GuardEvaluation> = await guard.list<GuardEvaluation>('evaluations', { limit: 200 })
      found = page.items.filter((x) => (x.payload as { sessionId?: string } | null)?.sessionId === id)
        .sort((a, b) => b.createdAt.localeCompare(a.createdAt))[0] ?? null
    }
    evaluation.value = found
    report.value = found ? (found.payload as GuardG3Report) : null
  } catch (e) {
    reportError.value = errText(e)
  }
}
void load()

/** 来源等级按 类别/来源 索引；只有登记过的组合显示为 lab 自动，其余一律只告警。 */
const level = (family: string, source: string) => quals.value?.sources.find((s) => s.family === family && s.source === source)?.level ?? null
const classes = computed(() => {
  const list = report.value?.classes ?? []
  return [...list].sort((a, b) => GUARD_FAMILIES.indexOf(a.family as never) - GUARD_FAMILIES.indexOf(b.family as never))
})
const scenarios = computed(() => {
  const order = (s: GuardG3Scenario) => (s.family === 'normal' ? 99 : GUARD_FAMILIES.indexOf(s.family as never))
  return [...(report.value?.scenarios ?? [])].sort((a, b) => order(a) - order(b) || a.scenarioId.localeCompare(b.scenarioId))
})
const passedScenarios = computed(() => scenarios.value.filter((s) => s.status === 'passed').length)
const commandCount = computed(() => scenarios.value.reduce((n, s) => n + s.commands.length, 0))
const verifiedCleanup = computed(() => scenarios.value.reduce((n, s) => n + s.commands.filter((c) => c.cleanup === 'verified').length, 0))

const sec = (ms: number | null | undefined) => (ms === null || ms === undefined ? '—' : `${(ms / 1000).toFixed(ms < 10000 ? 2 : 1)} 秒`)
const minutes = (ms: number | null | undefined) => (ms === null || ms === undefined ? '—' : `${(ms / 60000).toFixed(1)} 分钟`)
const pct = (v: number | null | undefined) => (v === null || v === undefined ? '—' : `${(v * 100).toFixed(1)}%`)

/* ---------------- 事实时间线：按追加序号向后翻页 ---------------- */
const events = ref<GuardLabEvent[]>([])
const nextAfter = ref<number | null>(null)
const eventsLoading = ref(false)
const eventsError = ref('')
const startAt = ref(0)
const kindFilter = ref('')
let eventSeq = 0
async function loadEvents(after: number, append: boolean) {
  const mine = ++eventSeq
  eventsLoading.value = true
  eventsError.value = ''
  try {
    const page = await guard.read<GuardLabEventPage>(`lab-validation-runs/${encodeURIComponent(id)}/events`, { after, limit: 200 })
    if (mine !== eventSeq) return
    events.value = append ? [...events.value, ...page.items] : page.items
    nextAfter.value = page.nextAfter
  } catch (e) {
    if (mine !== eventSeq) return
    eventsError.value = errText(e)
  } finally {
    if (mine === eventSeq) eventsLoading.value = false
  }
}
void loadEvents(0, false)
function jump() {
  const n = Math.max(0, Math.floor(Number(startAt.value) || 0))
  void loadEvents(n, false)
}
const str = (v: unknown) => (typeof v === 'string' ? v : v === null || v === undefined ? '' : String(v))
/** 报告导入事实是后端生成的结果对象，本身不带 kind 字段，按 evaluationId 识别。 */
const kindOf = (e: GuardLabEvent) => str(e.fact.kind) || (e.fact.evaluationId ? 'report' : 'unknown')
const kinds = computed(() => {
  const m = new Map<string, number>()
  for (const e of events.value) m.set(kindOf(e), (m.get(kindOf(e)) ?? 0) + 1)
  return [...m.entries()]
})
const visibleEvents = computed(() => (kindFilter.value ? events.value.filter((e) => kindOf(e) === kindFilter.value) : events.value))
/** 每类事实只摘最能说明问题的字段，其余在展开中原样显示。 */
function summary(e: GuardLabEvent) {
  const f = e.fact
  switch (kindOf(e)) {
    case 'lifecycle': return `${str(f.operation)}${f.reason ? ` · ${str(f.reason)}` : ''}`
    case 'decision': return `${str(f.decision)}${f.reasonCode ? ` · ${guardReasonLabel[str(f.reasonCode)] ?? str(f.reasonCode)}` : ''}${f.detectedFamily && f.detectedFamily !== f.family ? ` · 检出 ${guardFamilyLabel[str(f.detectedFamily)] ?? str(f.detectedFamily)}` : ''}`
    case 'report': return `报告 ${str(f.status)} · 来源等级${f.qualificationEffect === 'registered' ? '已登记' : '未登记'} · 验签${f.signatureVerified ? '通过' : '未通过'}`
    case 'scenario_result': return f.completed ? '场景完成' : '场景未完成'
    default: return [f.verification ? `核验 ${str(f.verification)}` : '', f.status ? str(f.status) : ''].filter(Boolean).join(' · ')
  }
}
const expanded = ref<string | null>(null)
</script>

<template>
  <div>
    <RouterLink :to="{ name: 'lab' }" class="link mb-10 text-[13px] text-ink-3"><ArrowLeft :size="14" :stroke-width="1.5" /> lab 验证与 G3</RouterLink>
    <LoadState :loading="loading" :error="error">
      <div v-if="run">
        <header class="mb-14">
          <p class="label mb-5 flex flex-wrap items-center gap-4">
            <span class="num">会话 {{ run.id }}</span>
            <Tag :tone="labRunTone[run.runStatus]" :label="guardLabRunStatusLabel[run.runStatus] ?? run.runStatus" />
            <Tag :tone="labEligibilityTone[run.effectiveEligibility]" :label="`资格${guardLabEligibilityLabel[run.effectiveEligibility] ?? run.effectiveEligibility}`" />
          </p>
          <h1 class="text-[2rem] font-light leading-snug tracking-[-0.02em]">
            G3 联合闭环 · {{ report ? (report.passed ? '通过' : '未通过') : '报告未导入' }}
          </h1>
          <p class="num mt-5 flex flex-wrap gap-x-8 gap-y-1 text-[12.5px] text-ink-3">
            <span>证据类别 {{ run.evidenceKind }}</span><span>发布组合 {{ run.bundleId ?? '—' }}</span>
            <span>开始 {{ fmtTime(run.startedAt) }}</span><span>结束 {{ fmtTime(run.endedAt) }}</span><span>有效期至 {{ fmtTime(run.validUntil) }}</span>
          </p>
          <p class="mt-6 max-w-3xl border-l-2 border-warn py-1 pl-4 text-[12.5px] leading-relaxed text-ink-2">
            本会话在网络隔离的 lab 资产上以 1 倍速回放冻结 PCAP；会话不授予执行权限。登记的 lab_auto 等级只对 lab 资产有效，不适用于真实主机——真实主机按当前决定只告警。
          </p>
        </header>

        <p v-if="reportError" class="mb-10 border-l-2 border-threat py-2 pl-4 text-[13px] text-threat" role="alert">G3 报告读取失败：{{ reportError }}</p>
        <p v-else-if="!report" class="mb-10 text-[13px] text-ink-3">该会话尚无已导入的 G3 报告，以下只显示会话事实。</p>

        <template v-if="report">
          <!-- 总览：场景、正常场景误封与命令清理 -->
          <section class="mb-16 grid gap-10 sm:grid-cols-2 lg:grid-cols-4">
            <div class="border-t border-ink pt-5"><p class="label">场景通过</p><p class="num mt-4 text-[2.25rem] font-light leading-none">{{ passedScenarios }}<span class="text-[14px] text-ink-3"> / {{ scenarios.length }}</span></p></div>
            <div class="border-t border-ink pt-5"><p class="label">正常场景累计</p><p class="num mt-4 text-[2.25rem] font-light leading-none">{{ (report.normal.cumulativeMs / 60000).toFixed(1) }}<span class="text-[14px] text-ink-3"> 分钟</span></p><p class="mt-3 text-[12.5px] text-ink-3">门槛 ≥ 30 分钟</p></div>
            <div class="border-t border-ink pt-5"><p class="label">误封 / 小时</p><p class="num mt-4 text-[2.25rem] font-light leading-none" :class="report.normal.perHour > 1 ? 'text-threat' : ''">{{ report.normal.perHour }}</p><p class="mt-3 text-[12.5px] text-ink-3">已核验误封 {{ report.normal.verifiedFalseBlocks }} 次 · 门槛 ≤ 1</p></div>
            <div class="border-t border-ink pt-5"><p class="label">真实规则清理</p><p class="num mt-4 text-[2.25rem] font-light leading-none">{{ verifiedCleanup }}<span class="text-[14px] text-ink-3"> / {{ commandCount }}</span></p><p class="mt-3 text-[12.5px] text-ink-3">执行器核验清理 / 下发命令</p></div>
          </section>

          <!-- 逐类结论：等级来自已登记来源，未登记的一律只告警 -->
          <section class="mb-16">
            <h2 class="label mb-6">逐类结论</h2>
            <table class="table">
              <thead><tr><th>类别</th><th>结论</th><th>来源与等级</th><th>首次告警时延</th><th>首次生效时延</th><th class="text-right">场景</th></tr></thead>
              <tbody>
                <tr v-for="c in classes" :key="c.family">
                  <td class="text-ink">{{ guardFamilyLabel[c.family] ?? c.family }}</td>
                  <td><Tag :tone="scenarioTone[c.status]" :label="c.status === 'passed' ? '通过' : c.status" /></td>
                  <td>
                    <span v-for="s in c.sources" :key="s" class="mr-4 inline-flex items-center gap-2">
                      <span class="text-ink-2">{{ guardSourceLabel(s) }}</span>
                      <Tag v-if="level(c.family, s)" :tone="qualificationTone[level(c.family, s)!]" :label="level(c.family, s) === 'lab_auto' ? 'lab 自动（仅 lab）' : level(c.family, s)!" />
                      <Tag v-else tone="mute" label="只告警" />
                    </span>
                  </td>
                  <td class="num text-ink-2">{{ sec(c.firstAlertLatencyMs) }}</td>
                  <td class="num text-ink-2">{{ c.firstApplicationLatencyMs === null ? '不封禁' : sec(c.firstApplicationLatencyMs) }}</td>
                  <td class="num text-right text-ink-3">{{ c.scenarioIds.length }}</td>
                </tr>
              </tbody>
            </table>
            <p class="mt-5 max-w-3xl text-[12.5px] leading-relaxed text-ink-3">
              时延只报告、不设门槛：从冻结场景在 lab 中的起点计算，「生效」为该类命令首次进入 applied 的时间。
              只告警的类别不下发命令，也不出现生效时延。
            </p>
          </section>

          <!-- 逐场景 -->
          <section class="mb-16">
            <h2 class="label mb-6">逐场景（{{ scenarios.length }}）</h2>
            <div class="overflow-x-auto">
              <table class="table min-w-[860px]">
                <thead><tr><th>场景</th><th>结论</th><th>告警</th><th>签发</th><th>生效</th><th>清理</th><th>命令 / 已清理</th><th class="text-right">质量合格</th></tr></thead>
                <tbody>
                  <tr v-for="s in scenarios" :key="s.scenarioId">
                    <td><span class="num block">{{ s.scenarioId }}</span><span class="text-[11.5px] text-ink-4">{{ guardFamilyLabel[s.family] ?? s.family }} · {{ guardSourceLabel(s.source, s.ruleId) }}</span></td>
                    <td><Tag :tone="scenarioTone[s.status]" :label="s.status === 'passed' ? '通过' : s.status" /><span v-if="s.missing.length" class="num ml-2 text-[11.5px] text-threat">缺 {{ s.missing.join('、') }}</span></td>
                    <td class="num text-ink-2">{{ sec(s.alertLatencyMs) }}</td>
                    <td class="num text-ink-2">{{ sec(s.issueLatencyMs) }}</td>
                    <td class="num text-ink-2">{{ sec(s.applicationLatencyMs) }}</td>
                    <td class="num text-ink-2">{{ sec(s.cleanupLatencyMs) }}</td>
                    <td class="num text-ink-2">{{ s.commands.length }} / {{ s.commands.filter((c) => c.cleanup === 'verified').length }}</td>
                    <td class="num text-right text-ink-3">{{ pct(s.qualifiedCoverage) }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>

          <section class="mb-16 grid gap-12 lg:grid-cols-2">
            <div>
              <h2 class="label mb-6">报告完整性</h2>
              <dl class="border-t border-ink">
                <div v-for="[k, v] in [
                  ['报告状态', `${report.status} · ${report.passed ? 'passed' : 'not passed'}`],
                  ['缺失类别', report.missingClasses.length ? report.missingClasses.join('、') : '无'],
                  ['未关联命令', String(report.unlinkedCommandIds.length)],
                  ['未关联判定', String(report.unlinkedDecisionIds.length)],
                  ['未核验项', String(report.unverifiedItems.length)],
                  ['评分窗口外判定', String(report.outsideScoringDecisionIds?.length ?? 0)],
                  ['正常场景单资产并集', minutes(report.normal.singleAssetUnionMs)],
                  ['误封按 TTL 恢复', report.normal.falseBlocksTtlRestored ? '是' : '否'],
                  ['评价运行', evaluation ? `${evaluation.id} · ${evaluation.runnerIdentity}` : '—'],
                ]" :key="k" class="grid grid-cols-[9rem_1fr] border-b border-ink-hair py-2.5 text-[13px]">
                  <dt class="text-ink-3">{{ k }}</dt><dd class="num break-all">{{ v }}</dd>
                </div>
              </dl>
            </div>
            <div>
              <h2 class="label mb-6">报告声明的局限（原文）</h2>
              <ul class="border-t border-ink">
                <li v-for="l in report.limitations" :key="l" class="border-b border-ink-hair py-2.5 text-[12.5px] leading-relaxed text-ink-2">{{ l }}</li>
              </ul>
            </div>
          </section>

          <section class="mb-16">
            <h2 class="label mb-6">已登记的来源等级</h2>
            <p v-if="!quals?.sources.length" class="text-[13px] text-ink-3">本会话未登记任何来源等级。</p>
            <table v-else class="table">
              <thead><tr><th>类别</th><th>来源</th><th>等级</th><th>评价运行</th><th class="text-right">组合可用</th></tr></thead>
              <tbody>
                <tr v-for="s in quals.sources" :key="`${s.family}/${s.source}`">
                  <td class="text-ink">{{ guardFamilyLabel[s.family] ?? s.family }}</td>
                  <td class="text-ink-2">{{ guardSourceLabel(s.source) }}</td>
                  <td><Tag :tone="qualificationTone[s.level]" :label="s.level === 'lab_auto' ? 'lab 自动（仅 lab）' : s.level" /></td>
                  <td class="num text-ink-3">{{ s.evaluationId.slice(0, 8) }}</td>
                  <td class="text-right text-ink-3">{{ quals.bundleUsable ? '是' : '否' }}</td>
                </tr>
              </tbody>
            </table>
          </section>
        </template>

        <!-- 会话事实时间线 -->
        <section class="mb-16">
          <h2 class="label mb-6">会话事实</h2>
          <form class="mb-6 flex flex-wrap items-end gap-6 text-[13px]" @submit.prevent="jump">
            <label class="w-36"><span class="label">从序号之后</span><input v-model="startAt" type="number" min="0" class="field mt-1" /></label>
            <button type="submit" class="link text-[12.5px]">跳转</button>
            <span class="flex flex-wrap gap-4 text-[12.5px]">
              <button type="button" class="link" :class="kindFilter ? 'text-ink-3' : ''" @click="kindFilter = ''">全部 {{ events.length }}</button>
              <button v-for="[k, n] in kinds" :key="k" type="button" class="link" :class="kindFilter === k ? '' : 'text-ink-3'" @click="kindFilter = k">{{ guardLabEventKindLabel[k] ?? k }} {{ n }}</button>
            </span>
          </form>
          <LoadState :loading="eventsLoading && !events.length" :error="eventsError" :empty="!events.length" empty-text="该序号之后没有会话事实。">
            <ul class="border-t border-ink">
              <li v-for="e in visibleEvents" :key="e.eventId" class="border-b border-ink-hair py-2.5 text-[12.5px]">
                <button type="button" class="grid w-full grid-cols-[4.5rem_6rem_8rem_1fr_auto] items-baseline gap-3 text-left" :aria-expanded="expanded === e.eventId" @click="expanded = expanded === e.eventId ? null : e.eventId">
                  <span class="num text-ink-4">#{{ e.sequence }}</span>
                  <span class="text-ink-2">{{ guardLabEventKindLabel[kindOf(e)] ?? kindOf(e) }}</span>
                  <span class="num truncate text-ink-3">{{ str(e.fact.scenarioId) || '—' }}</span>
                  <span class="truncate text-ink-2">{{ summary(e) }}</span>
                  <span class="num text-ink-4">{{ fmtTime(str(e.fact.occurredAt)) }}</span>
                </button>
                <dl v-if="expanded === e.eventId" class="mt-3 border-t border-ink-hair">
                  <div v-for="[k, v] in Object.entries(e.fact)" :key="k" class="grid grid-cols-[10rem_1fr] border-b border-ink-hair py-1.5 text-[12px]">
                    <dt class="num text-ink-3">{{ k }}</dt><dd class="num break-all">{{ typeof v === 'object' && v !== null ? JSON.stringify(v) : String(v) }}</dd>
                  </div>
                  <div class="grid grid-cols-[10rem_1fr] py-1.5 text-[12px]"><dt class="num text-ink-3">sha256</dt><dd class="num break-all">{{ e.sha256 }}</dd></div>
                </dl>
              </li>
            </ul>
          </LoadState>
          <nav class="mt-6 flex items-center justify-between text-[12.5px] text-ink-3" aria-label="会话事实分页">
            <span class="num">已加载 {{ events.length }} 条{{ nextAfter ? ' · 还有更多' : ' · 已到末尾' }}</span>
            <button type="button" class="link" :disabled="eventsLoading || !nextAfter" @click="nextAfter && loadEvents(nextAfter, true)">继续加载 200 条</button>
          </nav>
        </section>

        <section>
          <h2 class="label mb-6">绑定摘要</h2>
          <dl class="border-t border-ink">
            <div v-for="[k, v] in [
              ['会话摘要', run.sessionSha256],
              ['清单摘要', run.manifestSha256],
              ['组合 subject', report?.subjectSha256 ?? '—'],
              ['评价计划', report?.evaluationPlanSha256 ?? '—'],
              ['报告输入', report?.inputSha256 ?? '—'],
              ...Object.entries(report?.provenance ?? {}).map(([pk, pv]) => [pk, String(pv)]),
            ]" :key="k" class="grid grid-cols-[10rem_1fr] border-b border-ink-hair py-2.5 text-[12.5px]">
              <dt class="num text-ink-3">{{ k }}</dt><dd class="num break-all">{{ v }}</dd>
            </div>
          </dl>
        </section>
      </div>
    </LoadState>
  </div>
</template>
