<script setup lang="ts">
/**
 * 事件研判（威胁检测 / Events）：v2 单资产安全事件列表（GET /api/v2/events）。
 *
 * 口径（docs/接口设计.md、权限设计 §7.2）：
 * - 事件由后端按 15 分钟同资产与同攻击家族窗口自动归并，不再混合 v1 告警/规则/检测策略旧表；
 * - 支持按状态（status）、资产（assetId）、时间（range → from）筛选与标题搜索（q，前缀匹配），均同步到 URL；
 *   游标分页每次切换筛选即重新请求；
 * - 工作台「未结事件」带 `?status=open` 进入本页时，自动同步为初始状态筛选；
 * - 点击行进入整页详情 `/console/detect/events/:id`。
 */
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { Flame, ListOrdered, Search, Shapes, UserX } from 'lucide-vue-next'
import PageHead from '@/components/PageHead.vue'
import DistBar from '@/components/DistBar.vue'
import TrendChart from '@/components/TrendChart.vue'
import { countIf, tally, toneBg } from '@/components/viz'
import { useSummary } from '@/composables/summary'
import Panel from '@/components/Panel.vue'
import IdText from '@/components/IdText.vue'
import Tag from '@/components/Tag.vue'
import LoadState from '@/components/LoadState.vue'
import CursorPager from '@/components/CursorPager.vue'
import { useCursor } from '@/composables/cursor'
import { detectApi, isRange, RANGES, rangeFrom, type RangeKey } from '@/api/v2/detect'
import {
  eventStatusLabel, fmtTime, guardFamilyLabel, severityLabel,
  type EventStatus, type GuardGuardEvent,
} from '@/api/types'
import { useAssetNames } from './assets'
import { eventTone, severityTone } from '@/data/tones'

const STATUSES: EventStatus[] = ['open', 'investigating', 'contained', 'resolved', 'false_positive', 'closed']
const isStatus = (v: unknown): v is EventStatus => typeof v === 'string' && (STATUSES as string[]).includes(v)

const route = useRoute()
const router = useRouter()

const statusFilter = ref<EventStatus | ''>(isStatus(route.query.status) ? route.query.status : '')
const assetFilter = ref(typeof route.query.assetId === 'string' ? route.query.assetId : '')
const range = ref<RangeKey | ''>(isRange(route.query.range) ? route.query.range : '')
/** 搜索框输入与生效的查询分开：回车或失焦才提交，避免逐字请求。 */
const search = ref(typeof route.query.q === 'string' ? route.query.q : '')
const q = ref(search.value.trim())

const { assets, label: assetLabel } = useAssetNames()

/** 时间下界在筛选变化时计算一次，翻页沿用同一值（游标与筛选绑定）。 */
let from = rangeFrom(range.value)
const events = useCursor<GuardGuardEvent>((cursor) =>
  detectApi.listEvents({
    status: statusFilter.value || undefined,
    assetId: assetFilter.value || undefined,
    q: q.value || undefined,
    from,
    cursor,
    limit: 50,
  }),
)
function submitSearch() { q.value = search.value.trim() }

watch(() => route.query.status, (q) => {
  const next = isStatus(q) ? q : ''
  if (next !== statusFilter.value) statusFilter.value = next
})

watch([statusFilter, assetFilter, range, q], ([s, a, r, text]) => {
  const query: Record<string, string> = {}
  if (s) query.status = s
  if (a) query.assetId = a
  if (r) query.range = r
  if (text) query.q = text
  void router.replace({ query })
  from = rangeFrom(r)
  events.reset()
})

function setStatus(s: EventStatus | '') {
  statusFilter.value = statusFilter.value === s ? '' : s
}

/*
 * 版式（视觉基线 v2，事件研判）：主栏为研判队列，行首色条按严重度着色；顶部状态条按事件生命周期排列
 * （待处理 → 研判中 → 已遏制 → 已解决，误报与已关闭为旁路终态），点选即筛选。右侧栏给出当前页的严重度与类别构成。
 * 未结事件总数来自汇总接口（全量），其余计数只按当前页统计并写明范围。
 */
const summary = useSummary()
const pageItems = computed(() => events.items.value)
const pageHint = computed(() => `按当前页 ${pageItems.value.length} 条统计`)
const FLOW: EventStatus[] = ['open', 'investigating', 'contained', 'resolved']
const SIDE: EventStatus[] = ['false_positive', 'closed']
const pageCount = (st: EventStatus) => countIf(pageItems.value, (e) => e.status === st)
const SEVERITIES = ['critical', 'high', 'medium', 'low']
const bySeverity = computed(() => SEVERITIES.map((k) => ({ key: k, label: severityLabel[k], value: countIf(pageItems.value, (e) => e.severity === k), tone: severityTone[k] })).filter((x) => x.value))
const byCategory = computed(() => tally(pageItems.value, (e) => e.category, (k) => guardFamilyLabel[k] ?? k, () => 'mute'))
const unassigned = computed(() => countIf(pageItems.value, (e) => !e.assigneeId))
const stripe: Record<string, string> = { critical: 'bg-threat', high: 'bg-threat', medium: 'bg-warn', low: 'bg-ink-line' }

function goDetail(id: string) {
  void router.push(`/console/detect/events/${encodeURIComponent(id)}`)
}
</script>

<template>
  <div>
    <PageHead title="事件研判" desc="同一资产、同一类别 15 分钟内的告警归并为一个事件，点开处理。" />

    <!-- 生命周期状态条：主流程四段 + 旁路终态；点选即筛选，再次点选取消 -->
    <div class="mb-5 flex flex-wrap items-stretch gap-3" role="group" aria-label="事件状态筛选">
      <button type="button" class="chip self-center" :aria-pressed="statusFilter === ''" @click="statusFilter = ''">全部</button>
      <ol class="flex min-w-0 flex-1 overflow-hidden rounded border border-ink-line">
        <li v-for="(st, i) in FLOW" :key="st" class="min-w-0 flex-1" :class="i ? 'border-l border-ink-hair' : ''">
          <button type="button" class="flex h-full w-full items-center justify-between gap-3 px-4 py-2.5 text-left transition-colors"
            :class="statusFilter === st ? 'bg-ink text-paper' : 'hover:bg-paper-soft'" :aria-pressed="statusFilter === st" @click="setStatus(st)">
            <span class="flex items-center gap-2 whitespace-nowrap text-[13px]"><span class="dot" :class="statusFilter === st ? 'bg-paper' : toneBg[eventTone[st]]" />{{ eventStatusLabel[st] }}</span>
            <span v-if="st === 'open' && summary.data.openEvents !== undefined" class="num text-[15px]" :title="'全部可见资产的未结事件'">{{ summary.data.openEvents }}</span>
            <span v-else-if="!statusFilter" class="num text-[13px] text-ink-3">{{ pageCount(st) }}</span>
          </button>
        </li>
      </ol>
      <div class="flex items-center gap-1">
        <button v-for="st in SIDE" :key="st" type="button" class="chip" :aria-pressed="statusFilter === st" @click="setStatus(st)">{{ eventStatusLabel[st] }}</button>
      </div>
    </div>

    <div class="grid items-start gap-5 xl:grid-cols-[minmax(0,1fr)_18rem]">
      <Panel title="研判队列" :icon="ListOrdered" flush>
        <template #actions><span class="text-[12px] text-ink-3">最近发现在前</span></template>
        <template #toolbar>
          <form class="toolbar w-full" role="search" @submit.prevent="submitSearch">
            <label class="toolbar-field"><Search :size="14" :stroke-width="1.5" aria-hidden="true" />
              <input v-model="search" type="search" aria-label="搜索事件标题" class="field" maxlength="128" placeholder="按标题开头搜索" @blur="submitSearch" />
            </label>
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
          </form>
        </template>
        <LoadState :loading="events.loading.value" :error="events.error.value" :empty="!events.items.value.length" empty-text="当前筛选条件下没有可见的安全事件。">
          <table class="table min-w-[720px]">
            <thead>
              <tr>
                <th class="w-1 !px-0"><span class="sr-only">严重度色条</span></th>
                <th>事件</th>
                <th>严重度</th>
                <th>状态</th>
                <th>处理人</th>
                <th>资产</th>
                <th class="text-right">最近发现</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="e in events.items.value" :key="e.id" class="row-link" tabindex="0"
                @click="goDetail(e.id)" @keydown.enter="goDetail(e.id)">
                <td class="relative w-1 !p-0"><span class="absolute inset-y-2 left-0 w-[3px] rounded-r-full" :class="stripe[e.severity] ?? 'bg-ink-line'" /></td>
                <td>
                  <span class="block text-ink">{{ e.title }}</span>
                  <span class="flex items-center gap-2 whitespace-nowrap text-[12px] text-ink-3">{{ guardFamilyLabel[e.category] ?? e.category }}<span class="text-ink-line">|</span><IdText :value="e.eventKey" :length="14" /></span>
                </td>
                <td class="whitespace-nowrap"><Tag :tone="severityTone[e.severity]" :label="severityLabel[e.severity] ?? e.severity" /></td>
                <td><Tag pill :tone="eventTone[e.status]" :label="eventStatusLabel[e.status as EventStatus] ?? e.status" /></td>
                <td class="whitespace-nowrap text-ink-2"><IdText v-if="e.assigneeId" :value="e.assigneeId" :copy="false" /><span v-else class="text-ink-4">未指派</span></td>
                <td class="num whitespace-nowrap text-ink-2">{{ assetLabel(e.guardAssetId) }}</td>
                <td class="num whitespace-nowrap text-right text-ink-3">{{ fmtTime(e.lastSeenAt ?? e.createdAt) }}</td>
              </tr>
            </tbody>
          </table>
        </LoadState>
        <template #foot>
          <CursorPager :count="events.items.value.length" :has-next="!!events.next.value" :has-prev="!!events.stack.value.length"
            :busy="events.turning.value" label="安全事件" @next="events.forward()" @prev="events.back()" />
        </template>
      </Panel>

      <aside class="space-y-4 xl:sticky xl:top-20">
        <Panel title="严重度" :icon="Flame" :desc="pageHint">
          <DistBar :segments="bySeverity" empty-text="当前页没有事件" />
        </Panel>
        <Panel title="类别" :icon="Shapes" :desc="pageHint">
          <TrendChart kind="rank" title="类别" :items="byCategory.map((c) => ({ key: c.key, name: c.label, value: c.value, tone: 'mute' as const }))" empty-text="当前页没有事件" />
        </Panel>
        <div class="panel flex items-center gap-3 px-5 py-4">
          <UserX :size="18" :stroke-width="1.5" class="text-ink-3" aria-hidden="true" />
          <span class="text-[13px] text-ink-2">当前页未指派</span>
          <span class="num ml-auto text-[1.25rem] font-light" :class="unassigned ? 'text-warn' : 'text-ink'">{{ unassigned }}</span>
        </div>
      </aside>
    </div>
  </div>
</template>
