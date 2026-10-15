<script setup lang="ts">
/**
 * 待办中心（权限设计第 7.4 节、前端设计文档第 10.1 节，任务单 F2）：登录即可进入，只列需要当前用户本人处理的事项。
 *
 * - 逐条待办来自 GET /api/v2/todos：按「需要批准 → 需要研判 → 其他」分组（TodoList），组计数以后端为准，
 *   超过 100 条写明「仅显示最近 100 条」；本人发起的待批对象由后端排除。
 * - 顶部计数来自 GET /api/v2/summary，按权限显示 4—6 个；后端未返回的字段不显示、不补 0。
 * - 两个接口由 useTodos 每 30 秒刷新，页面不可见时暂停；分别显示错误（含 request-id）。
 * - 条目的 route 只是处理入口：目标页未上线或当前身份无权访问时不显示进入按钮，目标页仍独立鉴权。
 */
import { computed, ref, watch } from 'vue'
import { RouterLink, useRouter, type RouteLocationRaw } from 'vue-router'
import {
  CalendarDays, ChevronRight, ClipboardCheck, HeartPulse, Inbox, LayoutGrid, MessageSquareWarning, RefreshCw, ScrollText, ShieldAlert, FlaskConical,
} from 'lucide-vue-next'
import DistBar from '@/components/DistBar.vue'
import LoadState from '@/components/LoadState.vue'
import Panel from '@/components/Panel.vue'
import StatBand, { type Stat } from '@/components/StatBand.vue'
import TodoList, { type TodoGroup } from '@/components/TodoList.vue'
import { session } from '@/api/session'
import type { TodoGroupKind } from '@/api/v2/todos'
import { useTodos } from '@/composables/todos'
import { allowed, itemOf, routeName, visibleMenu, type GroupKey } from '@/router/nav'
import { useAssetNames } from '@/views/detect/assets'

const router = useRouter()
const permissions = computed(() => session.user?.permissions ?? [])
const { todos, summary, loading, error, summaryError, refresh } = useTodos()
const { label: assetLabel } = useAssetNames()

const updatedAt = ref<number | null>(null)
watch([todos, summary], ([t, s]) => { if (t || s) updatedAt.value = Date.now() })

/** 菜单项已上线且有权访问时给出跳转目标，否则只显示数字。 */
function link(group: GroupKey, key: string, query?: Record<string, string>): RouteLocationRaw | undefined {
  const item = itemOf(group, key)
  return item?.ready && allowed(item.anyOf, permissions.value) ? { name: routeName(item), query } : undefined
}
/** 待办 route 解析到已注册且有权访问的页面才可进入；未上线页面会落到 404 记录。 */
function reachable(path: string): RouteLocationRaw | undefined {
  try {
    const r = router.resolve(path)
    const last = r.matched[r.matched.length - 1]
    if (!last || String(last.name ?? '').startsWith('console-') || last.name === 'not-found') return undefined
    return allowed(r.meta.anyOf, permissions.value) ? path : undefined
  } catch { return undefined }
}

const sum = (o: Record<string, number | undefined> | undefined) =>
  (o ? Object.values(o).reduce<number>((n, v) => n + (typeof v === 'number' ? v : 0), 0) : undefined)

const stats = computed<Stat[]>(() => {
  const s = summary.value
  if (!s) return []
  const ops = s.ops ? s.ops.sensorsUnhealthy + s.ops.executorsUnhealthy : undefined
  return [
    { key: 'events', label: '未结事件', icon: ShieldAlert, value: s.openEvents, tone: 'threat', to: link('detect', 'events', { status: 'open' }) },
    { key: 'approvals', label: '待我审批', icon: ClipboardCheck, value: sum(s.pendingApprovals), tone: 'signal', hint: '不含本人发起的对象' },
    { key: 'feedback', label: '待复核标注', icon: MessageSquareWarning, value: s.pendingFeedbackReviews, tone: 'signal', to: link('detect', 'feedback', { tab: 'pending' }) },
    { key: 'models', label: '待校验模型', icon: FlaskConical, value: s.modelsPendingValidation, tone: 'signal', to: link('release', 'models') },
    { key: 'ops', label: '设备异常', icon: HeartPulse, value: ops, tone: 'threat', hint: s.ops ? `采集 ${s.ops.sensorsUnhealthy} · 执行 ${s.ops.executorsUnhealthy}` : undefined, to: link('assets', 'agents') ?? link('assets', 'health') },
    { key: 'audit', label: '近 24 小时审计', icon: ScrollText, value: s.recentAuditCount24h, to: link('system', 'audit') },
  ]
})

const ACTION_TEXT: Record<TodoGroupKind, string> = { approve: '去审批', triage: '去研判', other: '查看' }
const groups = computed<TodoGroup[]>(() => (todos.value?.groups ?? []).map((g) => ({
  key: g.kind,
  count: g.count,
  items: g.items.map((t) => ({
    id: `${t.kind}:${t.id}`,
    title: t.title,
    asset: t.assetId ? assetLabel(t.assetId) : null,
    at: t.createdAt,
    to: reachable(t.route),
    action: ACTION_TEXT[g.kind],
  })),
})))
const total = computed(() => groups.value.reduce((n, g) => n + (g.count ?? 0), 0))
const GROUP_META: Record<TodoGroupKind, { label: string; tone: 'warn' | 'threat' | 'mute' }> = {
  approve: { label: '需要批准', tone: 'warn' },
  triage: { label: '需要研判', tone: 'threat' },
  other: { label: '其他', tone: 'mute' },
}
const composition = computed(() => groups.value.filter((g) => (g.count ?? 0) > 0)
  .map((g) => ({ key: g.key, label: GROUP_META[g.key].label, value: g.count ?? 0, tone: GROUP_META[g.key].tone })))

/** 常用入口：可见菜单中除待办中心以外的页面，不发请求。 */
const shortcuts = computed(() => visibleMenu(permissions.value).flatMap((g) => g.items.filter((i) => i.key !== 'workbench').map((i) => ({ ...i, groupTitle: g.title }))))

const greeting = (() => {
  const h = new Date().getHours()
  return h < 6 ? '夜深了' : h < 11 ? '早上好' : h < 14 ? '中午好' : h < 18 ? '下午好' : '晚上好'
})()
const today = new Date().toLocaleDateString('zh-CN', { year: 'numeric', month: 'long', day: 'numeric', weekday: 'long' })
const timeText = (t: number) => new Date(t).toLocaleTimeString('zh-CN', { hour12: false })
</script>

<template>
  <div class="space-y-6">
    <header class="flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
      <div class="min-w-0">
        <p class="flex items-center gap-2 text-[13px] text-ink-3"><CalendarDays :size="14" :stroke-width="1.5" aria-hidden="true" />{{ today }}</p>
        <h1 class="mt-2 text-[1.75rem] font-light leading-tight tracking-[-0.01em] text-ink">{{ greeting }}，{{ session.user?.displayName ?? session.user?.username }}</h1>
        <p class="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-[13px] text-ink-3">
          <span>这里只列需要你本人处理的事项，范围限于你可见的资产。</span>
          <span class="flex items-center gap-1.5 text-[12px] text-ink-4">
            每 30 秒刷新<template v-if="updatedAt"> · 更新于 <span class="num">{{ timeText(updatedAt) }}</span></template>
            <button type="button" class="link ml-1 inline-flex items-center gap-1 text-[12px]" :disabled="loading" @click="refresh()">
              <RefreshCw :size="12" :stroke-width="1.5" :class="loading ? 'animate-spin' : ''" aria-hidden="true" />刷新
            </button>
          </span>
        </p>
      </div>
      <div v-if="todos && total > 0" class="w-full shrink-0 lg:w-[22rem]">
        <p class="flex items-baseline justify-between gap-3">
          <span class="text-[13px] text-ink-3">待办合计</span>
          <span class="num text-[2.25rem] font-light leading-none tracking-[-0.03em] text-ink">{{ total.toLocaleString('zh-CN') }}</span>
        </p>
        <DistBar class="mt-3" :segments="composition" />
      </div>
    </header>

    <p v-if="summaryError" class="note note-threat text-threat" role="alert">计数读取失败：{{ summaryError }}</p>
    <StatBand v-else label="计数" :stats="stats" />

    <div class="grid items-start gap-6" :class="shortcuts.length ? 'xl:grid-cols-[minmax(0,1fr)_20rem]' : ''">
      <Panel title="我的待办" :icon="Inbox">
        <template v-if="todos" #actions><span class="text-[12px] text-ink-3">同组按创建时间倒序</span></template>
        <LoadState :loading="!todos && !error" :error="error">
          <TodoList :groups="groups" :truncated="todos?.truncated" :limit="100" />
        </LoadState>
      </Panel>

      <!-- 常用入口：按菜单与权限过滤，不发请求 -->
      <nav v-if="shortcuts.length" aria-label="常用入口">
        <h2 class="section-title flex items-center gap-2"><LayoutGrid :size="15" :stroke-width="1.5" class="text-ink-3" aria-hidden="true" />常用入口</h2>
        <ul class="grid gap-2 sm:grid-cols-2 xl:grid-cols-1">
          <li v-for="i in shortcuts" :key="i.path">
            <RouterLink :to="{ name: routeName(i) }" class="group flex items-center gap-3 rounded-panel border border-ink-line px-3.5 py-2.5 transition-colors hover:border-ink-4 hover:bg-paper-soft">
              <span class="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded border border-ink-line bg-paper text-ink-2 transition-colors group-hover:border-ink group-hover:bg-ink group-hover:text-paper" aria-hidden="true">
                <component :is="i.icon" :size="16" :stroke-width="1.5" />
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
  </div>
</template>
