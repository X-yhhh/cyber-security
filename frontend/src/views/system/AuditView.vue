<script setup lang="ts">
/**
 * 审计日志（系统管理 / Audit，前端设计文档第 10.8、10.10 节，任务单 F5）。只读，需 audit.read。
 *
 * 数据：GET /api/v2/audit（action 精确匹配、assetId 为资产公开 UUID、requestId、from；游标分页，新在前）。
 * - 筛选同步到 URL；点击某条的动作或请求编号即按其筛选，便于沿一次请求追溯。
 * - 版式：按日期分组的日志流（左侧时间轴，非成功结果标红），页头为最近 24 小时总数（来自 summary）。
 * - resourceId 按后端返回原样展示（外部 UUID 或不可逆引用），页面不解释、不改写。
 */
import { computed, ref, watch } from 'vue'
import { BarChart3, Filter, ScrollText, Search, ShieldX, X } from 'lucide-vue-next'
import PageHead from '@/components/PageHead.vue'
import Panel from '@/components/Panel.vue'
import IdText from '@/components/IdText.vue'
import DistBar from '@/components/DistBar.vue'
import LoadState from '@/components/LoadState.vue'
import CursorPager from '@/components/CursorPager.vue'
import { countIf, tally } from '@/components/viz'
import { useCursor } from '@/composables/cursor'
import { queryString, useQueryState } from '@/composables/query'
import { useSummary } from '@/composables/summary'
import { can } from '@/api/session'
import { fmtTime } from '@/api/types'
import { isUuid } from '@/api/v2/detect'
import { iamApi, type AuditEntry } from '@/api/v2/iam'
import { assetsApi, assetTitle, type Asset } from '@/api/v2/assets'
import { auditOutcomeTone, type Tone } from '@/data/tones'
import { auditActorLabel, auditOutcomeLabel } from './shared'

const RANGES = { '1h': 36e5, '24h': 864e5, '7d': 7 * 864e5, '30d': 30 * 864e5 } as const
type Range = keyof typeof RANGES | ''
const rangeLabel: Record<string, string> = { '': '不限', '1h': '1 小时', '24h': '24 小时', '7d': '7 天', '30d': '30 天' }
const action = ref('')
const assetId = ref('')
const requestId = ref('')
const range = ref<Range>('')
const ACTION_RE = /^[a-z0-9_.:-]{1,128}$/i
/** 动作与请求编号先写入草稿，提交后才成为筛选条件；外部导航回填时同步草稿。 */
const draft = ref({ action: '', requestId: '' })
useQueryState({
  action: { state: action, default: '', parse: (v) => (ACTION_RE.test(queryString(v)) ? queryString(v) : '') },
  assetId: { state: assetId, default: '', parse: (v) => (isUuid(queryString(v)) ? queryString(v).toLowerCase() : '') },
  requestId: { state: requestId, default: '', parse: (v) => queryString(v).trim().slice(0, 128) },
  range: { state: range, default: '', parse: (v) => (queryString(v) in RANGES ? queryString(v) as Range : '') },
}, () => { draft.value = { action: action.value, requestId: requestId.value } })

const draftError = ref('')
function apply() {
  const a = draft.value.action.trim(), r = draft.value.requestId.trim()
  if (a && !ACTION_RE.test(a)) { draftError.value = '动作只含字母、数字与 . _ : -，如 iam.user.create。'; return }
  draftError.value = ''
  action.value = a
  requestId.value = r.slice(0, 128)
}

const audit = useCursor<AuditEntry>((cursor) => iamApi.listAudit({
  action: action.value || undefined, assetId: assetId.value || undefined, requestId: requestId.value || undefined,
  from: range.value ? new Date(Date.now() - RANGES[range.value]).toISOString() : undefined, cursor,
}))
watch([action, assetId, requestId, range], () => audit.reset())

/* 资产筛选：有 resource.read 时从资产列表选取（公开 UUID），否则不提供该筛选。 */
const assets = ref<Asset[]>([])
if (can('resource.read')) assetsApi.listAssets({ limit: 200 }).then((p) => { assets.value = p.items }).catch(() => { /* 资产下拉降级为不可选，审计列表不受影响 */ })
const assetName = (id: string) => { const a = assets.value.find((x) => x.id === id); return a ? assetTitle(a) : `${id.slice(0, 8)}…` }

const filters = computed(() => [
  action.value && { key: 'action', label: `动作 ${action.value}`, clear: () => { action.value = ''; draft.value.action = '' } },
  assetId.value && { key: 'asset', label: `资产 ${assetName(assetId.value)}`, clear: () => { assetId.value = '' } },
  requestId.value && { key: 'req', label: `请求 ${requestId.value.length > 12 ? `${requestId.value.slice(0, 12)}…` : requestId.value}`, clear: () => { requestId.value = ''; draft.value.requestId = '' } },
].filter(Boolean) as { key: string; label: string; clear: () => void }[])
function clearAll() { action.value = ''; assetId.value = ''; requestId.value = ''; range.value = ''; draft.value = { action: '', requestId: '' } }
const filtered = computed(() => !!(filters.value.length || range.value))

/** 按本地日期分组，组内保持后端顺序（新在前）。 */
const days = computed(() => {
  const out: { day: string; items: AuditEntry[] }[] = []
  for (const a of audit.items.value) {
    const day = fmtTime(a.occurredAt).slice(0, 10)
    const last = out[out.length - 1]
    if (last?.day === day) last.items.push(a)
    else out.push({ day, items: [a] })
  }
  return out
})
const outcomeLabel = (o: string) => auditOutcomeLabel[o] ?? o
const actorLabel = (a: string) => auditActorLabel[a] ?? a
const failed = computed(() => countIf(audit.items.value, (a) => a.outcome !== 'success'))
const pageHint = computed(() => `按当前页 ${audit.items.value.length} 条统计`)
const outcomes = computed(() => tally(audit.items.value, (a) => a.outcome, outcomeLabel, (k) => auditOutcomeTone[k]))
const actorTone: Record<string, Tone> = { human: 'signal', machine: 'warn', system: 'mute' }
const actors = computed(() => tally(audit.items.value, (a) => a.actorType, actorLabel, (k) => actorTone[k] ?? 'mute'))
/** 动作类别：取动作键的前两段（如 iam.user、guard.lab），按当前页计数排行。 */
const families = computed(() => {
  const rows = tally(audit.items.value, (a) => a.action.split('.').slice(0, 2).join('.'), (k) => k, () => 'mute').slice(0, 6)
  const max = Math.max(1, ...rows.map((r) => r.value))
  return rows.map((r) => ({ ...r, pct: Math.round((r.value / max) * 100) }))
})
const dotBg: Record<string, string> = { ok: 'bg-ok', threat: 'bg-threat', warn: 'bg-warn', signal: 'bg-signal', mute: 'bg-ink-4' }

const summary = useSummary()
const emptyText = computed(() => (filtered.value ? '当前筛选条件下你的审计范围内没有记录。' : '你的审计范围内还没有记录。'))
</script>

<template>
  <div>
    <PageHead title="审计日志" desc="追加式记录：登录、授权、审批、发布与执行都会写入，不可改写。">
      <span v-if="summary.data.recentAuditCount24h !== undefined" class="flex items-baseline gap-2 text-[12.5px] text-ink-3">最近 24 小时<span class="num text-[1.5rem] font-light text-ink">{{ summary.data.recentAuditCount24h.toLocaleString('zh-CN') }}</span>条</span>
    </PageHead>

    <div class="grid items-start gap-5 xl:grid-cols-[minmax(0,1fr)_18rem]">
      <Panel title="审计记录" :icon="ScrollText">
        <template #actions>
          <span class="flex items-center gap-1.5 text-[12.5px] text-ink-3"><ShieldX :size="14" :stroke-width="1.5" :class="failed ? 'text-threat' : ''" aria-hidden="true" />当前页非成功<span class="num" :class="failed ? 'text-threat' : 'text-ink'">{{ failed }}</span></span>
        </template>
        <template #toolbar>
          <form class="toolbar w-full" role="search" @submit.prevent="apply">
            <label class="toolbar-field"><Search :size="14" :stroke-width="1.5" aria-hidden="true" />
              <input v-model="draft.action" class="field num !w-56" maxlength="128" placeholder="动作，精确匹配" aria-label="动作（精确匹配）" />
            </label>
            <label class="toolbar-field"><span>请求</span>
              <input v-model="draft.requestId" class="field num !w-44" maxlength="128" placeholder="requestId" aria-label="请求编号" />
            </label>
            <label v-if="assets.length" class="toolbar-field"><span>资产</span>
              <select v-model="assetId" class="field !w-44" aria-label="资产">
                <option value="">全部资产</option>
                <option v-for="a in assets" :key="a.id" :value="a.id">{{ assetTitle(a) }}</option>
              </select>
            </label>
            <button type="submit" class="act-ghost act-sm"><Filter :size="13" :stroke-width="1.5" />筛选</button>
            <div class="chips" role="group" aria-label="时间范围">
              <button v-for="(label, k) in rangeLabel" :key="k" type="button" class="chip" :aria-pressed="range === k" @click="range = k as Range">{{ k ? `近 ${label}` : label }}</button>
            </div>
          </form>
          <p v-if="draftError" class="w-full text-[12px] text-threat" role="alert">{{ draftError }}</p>
          <div v-if="filters.length" class="flex w-full flex-wrap items-center gap-2">
            <span v-for="f in filters" :key="f.key" class="inline-flex items-center gap-1 rounded-full bg-paper-soft py-0.5 pl-2.5 pr-1 text-[12px] text-ink-2">
              <span class="num">{{ f.label }}</span>
              <button type="button" class="inline-flex h-4 w-4 items-center justify-center rounded-full text-ink-4 hover:bg-ink-hair hover:text-ink" :aria-label="`移除筛选 ${f.label}`" @click="f.clear()"><X :size="11" :stroke-width="1.5" /></button>
            </span>
            <button type="button" class="link text-[12px]" @click="clearAll">全部清除</button>
          </div>
        </template>

        <LoadState :loading="audit.loading.value" :error="audit.error.value" :empty="!audit.items.value.length" :empty-text="emptyText">
          <div class="space-y-6">
            <section v-for="d in days" :key="d.day" :aria-label="d.day">
              <h3 class="num sticky top-14 z-[1] mb-2 bg-paper py-1 text-[12.5px] text-ink-3">{{ d.day }}<span class="ml-2 text-ink-4">{{ d.items.length }} 条</span></h3>
              <ol class="relative ml-1.5 border-l border-ink-hair">
                <li v-for="a in d.items" :key="a.id" class="relative grid grid-cols-[3.25rem_minmax(0,1fr)] gap-x-3 rounded-r py-2 pl-5 transition-colors hover:bg-paper-soft md:grid-cols-[3.25rem_minmax(0,1fr)_auto]">
                  <span class="absolute -left-[4.5px] top-[14px] h-2 w-2 rounded-full ring-2 ring-paper" :class="dotBg[auditOutcomeTone[a.outcome]]" :title="outcomeLabel(a.outcome)" />
                  <span class="num pt-px text-[12px] text-ink-3">{{ fmtTime(a.occurredAt, false) }}</span>
                  <div class="min-w-0">
                    <p class="flex flex-wrap items-center gap-x-2 gap-y-1">
                      <button type="button" class="num break-all text-left text-[13px] text-ink hover:underline" :title="`只看动作 ${a.action}`" @click="action = a.action; draft.action = a.action">{{ a.action }}</button>
                      <span v-if="a.outcome !== 'success'" class="pill bg-threat-soft text-threat">{{ outcomeLabel(a.outcome) }}</span>
                    </p>
                    <p class="mt-0.5 flex flex-wrap items-center gap-x-2 text-[12px] text-ink-3">
                      {{ actorLabel(a.actorType) }}<span class="text-ink-line">|</span>{{ a.resourceType || '—' }}<IdText v-if="a.resourceId" :value="a.resourceId" />
                    </p>
                  </div>
                  <span class="col-start-2 flex items-center gap-1 text-[12px] text-ink-4 md:col-start-auto">
                    请求
                    <button v-if="a.requestId" type="button" class="num hover:text-ink hover:underline" :title="`只看请求 ${a.requestId}`" @click="requestId = a.requestId!; draft.requestId = a.requestId!">{{ a.requestId.length > 10 ? `${a.requestId.slice(0, 10)}…` : a.requestId }}</button>
                    <span v-else>—</span>
                  </span>
                </li>
              </ol>
            </section>
          </div>
        </LoadState>
        <template #foot>
          <CursorPager :count="audit.items.value.length" :has-next="!!audit.next.value" :has-prev="!!audit.stack.value.length"
            :busy="audit.turning.value" label="审计" @next="audit.forward()" @prev="audit.back()" />
        </template>
      </Panel>

      <aside class="space-y-4 xl:sticky xl:top-20">
        <Panel title="结果与主体" :icon="ShieldX" :desc="pageHint">
          <p class="mb-2 text-[12px] text-ink-3">结果</p>
          <DistBar :segments="outcomes" empty-text="当前页没有记录" />
          <p class="mb-2 mt-5 text-[12px] text-ink-3">主体类型</p>
          <DistBar :segments="actors" empty-text="当前页没有记录" />
        </Panel>
        <Panel title="动作类别" :icon="BarChart3" :desc="pageHint">
          <p v-if="!families.length" class="text-[12.5px] text-ink-4">当前页没有记录。</p>
          <ul v-else class="space-y-2.5">
            <li v-for="f in families" :key="f.key">
              <button type="button" class="group block w-full text-left" :title="`动作前缀 ${f.key}`" @click="draft.action = f.key + '.'">
                <span class="flex items-baseline justify-between gap-2 text-[12.5px]"><span class="num truncate text-ink-2 group-hover:text-ink">{{ f.key }}</span><span class="num text-ink">{{ f.value }}</span></span>
                <span class="mt-1 block h-1.5 overflow-hidden rounded-full bg-paper-soft"><span class="block h-full rounded-full bg-ink-3" :style="{ width: `${f.pct}%` }" /></span>
              </button>
            </li>
          </ul>
          <p class="mt-3 text-[11.5px] leading-relaxed text-ink-4">动作筛选为精确匹配；点击类别会把前缀填入动作框，补全后再筛选。</p>
        </Panel>
      </aside>
    </div>
  </div>
</template>
