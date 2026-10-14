<script setup lang="ts">
/**
 * 工作台（权限设计第 7.4 节）：登录后的统一入口，按卡片配置（cards.ts）渲染。
 *
 * - 卡片 anyOf 与会话权限无交集即不渲染；没有任何可见卡片时不请求汇总。
 * - 数字取自 GET /api/v2/summary（B2.5 契约）：没有权限的字段后端不返回，前端不补 0。
 * - 卡片行可点击，跳到对应列表并带上状态筛选；目标页尚未上线或无权访问时只显示数字。
 * F2 负责接入 GET /todos 的逐条待办与 30 秒定时刷新；版式见下方说明。
 */
import { computed, ref } from 'vue'
import { RouterLink } from 'vue-router'
import { ArrowRight, CalendarDays, ChevronRight, CircleCheck, Gauge, Inbox, LayoutGrid } from 'lucide-vue-next'
import DistBar from '@/components/DistBar.vue'
import type { SummaryLine } from '@/components/SummaryCard.vue'
import type { Tone } from '@/data/tones'
import LoadState from '@/components/LoadState.vue'
import SummaryCard from '@/components/SummaryCard.vue'
import { session } from '@/api/session'
import { fetchSummary, type WorkbenchSummary } from '@/api/v2/summary'
import { errText } from '@/composables/load'
import { allowed, nav, routeName, visibleMenu } from '@/router/nav'
import { cards, linker, type CardDef } from './cards'

const permissions = computed(() => session.user?.permissions ?? [])
const visible = computed(() => cards.filter((c) => allowed(c.anyOf, permissions.value)))
const link = computed(() => linker(permissions.value))

const summary = ref<WorkbenchSummary>({})
const loading = ref(visible.value.length > 0)
const error = ref('')
async function reload() {
  if (!visible.value.length) return
  loading.value = true
  error.value = ''
  try { summary.value = await fetchSummary() } catch (e) { error.value = errText(e) } finally { loading.value = false }
}
reload()

/*
 * 版式（视觉基线 v2，待办中心）自上而下：
 * 1. 页头：问候语与日期；右侧为待处理合计，下方构成条说明合计由哪几类组成；
 * 2. 优先处理：数量最多且可进入的一项待办，给出唯一主按钮；没有待办时写明“当前没有需要你处理的事项”；
 * 3. 分项卡片：主栏“需要你处理”（事件、审批、复核、发布），侧栏“运行与审计”（只读状态）；
 * 4. 常用入口：当前身份能进入的页面（按菜单与权限过滤）。
 * 全部计数只来自 GET /summary，合计只加总待处理字段，不含运行健康与审计计数；不额外请求数据。
 */
const ACTION_KEYS = new Set(['events', 'approvals', 'feedback', 'release'])
const actionCards = computed(() => visible.value.filter((c) => ACTION_KEYS.has(c.key)))
const statusCards = computed(() => visible.value.filter((c) => !ACTION_KEYS.has(c.key)))
const num = (v: unknown) => (typeof v === 'number' ? v : 0)
const cardTotals = computed(() => actionCards.value.map((c) => ({ card: c, lines: c.lines(summary.value, link.value) }))
  .map(({ card, lines }) => ({ card, lines, total: lines.reduce((n, l) => n + num(l.value), 0) })))
const pendingTotal = computed(() => cardTotals.value.reduce((n, c) => n + c.total, 0))
const SEG_TONE: Record<string, Tone> = { events: 'threat', approvals: 'warn', feedback: 'signal', release: 'mute' }
const composition = computed(() => cardTotals.value.filter((c) => c.total > 0)
  .map((c) => ({ key: c.card.key, label: c.card.title, value: c.total, tone: SEG_TONE[c.card.key] ?? 'mute' })))
/** 优先处理：可进入的行中数量最多的一行。 */
const priority = computed(() => {
  let best: { card: CardDef; line: SummaryLine; value: number } | null = null
  for (const { card, lines } of cardTotals.value) {
    for (const l of lines) if (l.to && num(l.value) > 0 && (!best || num(l.value) > best.value)) best = { card, line: l, value: num(l.value) }
  }
  return best
})
const priorityTarget = computed(() => {
  const to = priority.value?.line.to as { name?: string } | undefined
  return nav.find((i) => routeName(i) === to?.name)?.title
})
/** 常用入口：可见菜单中除待办中心以外的页面。 */
const shortcuts = computed(() => visibleMenu(permissions.value).flatMap((g) => g.items.filter((i) => i.key !== 'workbench').map((i) => ({ ...i, groupTitle: g.title }))))

const greeting = (() => {
  const h = new Date().getHours()
  return h < 6 ? '夜深了' : h < 11 ? '早上好' : h < 14 ? '中午好' : h < 18 ? '下午好' : '晚上好'
})()
const today = new Date().toLocaleDateString('zh-CN', { year: 'numeric', month: 'long', day: 'numeric', weekday: 'long' })
</script>

<template>
  <div class="space-y-6">
    <header class="flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
      <div class="min-w-0">
        <p class="flex items-center gap-2 text-[13px] text-ink-3"><CalendarDays :size="14" :stroke-width="1.5" aria-hidden="true" />{{ today }}</p>
        <h1 class="mt-2 text-[1.75rem] font-light leading-tight tracking-[-0.01em] text-ink">{{ greeting }}，{{ session.user?.displayName ?? session.user?.username }}</h1>
        <p class="mt-2 text-[13px] text-ink-3">这里汇总你权限范围内需要关注的事项，计数只覆盖你可见的资产范围。</p>
      </div>
      <div v-if="actionCards.length && !loading && !error" class="w-full shrink-0 lg:w-[22rem]">
        <p class="flex items-baseline justify-between gap-3">
          <span class="text-[13px] text-ink-3">待处理合计</span>
          <span class="num text-[2.25rem] font-light leading-none tracking-[-0.03em] text-ink">{{ pendingTotal.toLocaleString('zh-CN') }}</span>
        </p>
        <DistBar class="mt-3" :segments="composition" empty-text="各类待处理都已清零" />
      </div>
    </header>

    <p v-if="!visible.length" class="panel px-5 py-10 text-center text-[13px] text-ink-3">当前身份没有可显示的工作台卡片，可从左侧菜单进入有权限的页面。</p>
    <LoadState v-else :loading="loading" :error="error">
      <div class="space-y-6">
        <!-- 优先处理 -->
        <div v-if="actionCards.length" class="panel flex flex-col gap-4 border-ink p-5 md:flex-row md:items-center">
          <template v-if="priority">
            <span class="inline-flex h-12 w-12 shrink-0 items-center justify-center rounded" :class="priority.line.tone === 'threat' ? 'bg-threat-soft text-threat' : 'bg-paper-soft text-ink'" aria-hidden="true">
              <component :is="priority.card.icon" :size="22" :stroke-width="1.5" />
            </span>
            <div class="min-w-0 flex-1">
              <p class="text-[12.5px] text-ink-3">优先处理 · {{ priority.card.title }}</p>
              <p class="mt-1 text-[1.125rem] text-ink"><span class="num font-medium">{{ priority.value.toLocaleString('zh-CN') }}</span> 项{{ priority.line.label }}等待处理</p>
            </div>
            <RouterLink :to="priority.line.to!" class="act">进入{{ priorityTarget ?? '处理' }}<ArrowRight :size="14" :stroke-width="1.5" /></RouterLink>
          </template>
          <template v-else>
            <span class="inline-flex h-12 w-12 shrink-0 items-center justify-center rounded bg-ok-soft text-ok" aria-hidden="true"><CircleCheck :size="22" :stroke-width="1.5" /></span>
            <div>
              <p class="text-[1.125rem] text-ink">当前没有需要你处理的事项</p>
              <p class="mt-1 text-[12.5px] text-ink-3">新的待办出现后会在这里置顶显示。</p>
            </div>
          </template>
        </div>

        <div class="grid items-start gap-6" :class="actionCards.length && statusCards.length ? 'xl:grid-cols-[minmax(0,1fr)_22rem]' : ''">
          <div v-if="actionCards.length">
            <h2 class="section-title flex items-center gap-2"><Inbox :size="15" :stroke-width="1.5" class="text-ink-3" aria-hidden="true" />需要你处理</h2>
            <div class="grid gap-4 md:grid-cols-2">
              <SummaryCard v-for="c in actionCards" :key="c.key" class="h-full" :title="c.title" :icon="c.icon" :lines="c.lines(summary, link)" :note="c.note?.(summary)" :badge="c.badge?.(summary)" />
            </div>
          </div>
          <aside v-if="statusCards.length">
            <h2 class="section-title flex items-center gap-2"><Gauge :size="15" :stroke-width="1.5" class="text-ink-3" aria-hidden="true" />运行与审计</h2>
            <div class="grid gap-4" :class="actionCards.length ? '' : 'md:grid-cols-2'">
              <SummaryCard v-for="c in statusCards" :key="c.key" :title="c.title" :icon="c.icon" :lines="c.lines(summary, link)" :note="c.note?.(summary)" :badge="c.badge?.(summary)" />
            </div>
          </aside>
        </div>
      </div>
    </LoadState>

    <!-- 常用入口：按菜单与权限过滤，不发请求 -->
    <nav v-if="shortcuts.length" aria-label="常用入口">
      <h2 class="section-title flex items-center gap-2"><LayoutGrid :size="15" :stroke-width="1.5" class="text-ink-3" aria-hidden="true" />常用入口</h2>
      <ul class="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-4">
        <li v-for="i in shortcuts" :key="i.path">
          <RouterLink :to="{ name: routeName(i) }" class="group flex items-center gap-3 rounded-panel border border-ink-line px-4 py-3 transition-colors hover:border-ink-4 hover:bg-paper-soft">
            <span class="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded border border-ink-line bg-paper text-ink-2 transition-colors group-hover:border-ink group-hover:bg-ink group-hover:text-paper" aria-hidden="true">
              <component :is="i.icon" :size="17" :stroke-width="1.5" />
            </span>
            <span class="min-w-0">
              <span class="block truncate text-[13.5px] text-ink">{{ i.title }}</span>
              <span class="block text-[12px] text-ink-4">{{ i.groupTitle }}</span>
            </span>
            <ChevronRight :size="14" :stroke-width="1.5" class="ml-auto text-ink-4 transition-colors group-hover:text-ink" aria-hidden="true" />
          </RouterLink>
        </li>
      </ul>
    </nav>
  </div>
</template>
