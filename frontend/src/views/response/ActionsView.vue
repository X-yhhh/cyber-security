<script setup lang="ts">
/**
 * 处置记录（响应处置 / Actions，前端设计文档第 10.4 节，任务单 F2）。
 *
 * 数据：GET /api/v2/actions（`active=true` 为当前封禁）、actions/{id}、actions/{id}/receipts、budget-targets/{id}。
 * - 分段「当前封禁 · 全部动作」，分段、状态（观测状态）、资产、时间与打开的动作（`id`）同步到 URL；
 *   待办中心的处置申请跳转 `?id=` 直接打开该动作详情。
 * - 期望状态与观测状态分两列：期望是意图，观测以执行器回执为准；没有回执时写「命令未下发」，不写执行成功。
 * - 详情显示该目标的预算占用、最近清零时刻与恢复条件，全部只读；界面不提供任何预算清零入口。
 * - 写操作：立即解除/撤销（action.revoke）、批准/驳回（authorization.approve，本人申请的不显示）、
 *   页头停用自动化（automation.stop，202 只表示受理）。均带幂等键，审批与撤销带 If-Match，写后重新读取。
 * 前端只按权限隐藏入口；职责分离、状态迁移与硬约束以后端判定为准。
 */
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { ArrowRight, Ban, Gauge, ListOrdered, OctagonPause, PieChart, ShieldCheck, Timer } from 'lucide-vue-next'
import PageHead from '@/components/PageHead.vue'
import Panel from '@/components/Panel.vue'
import Segmented from '@/components/Segmented.vue'
import Tag from '@/components/Tag.vue'
import IdText from '@/components/IdText.vue'
import Drawer from '@/components/Drawer.vue'
import DistBar from '@/components/DistBar.vue'
import LoadState from '@/components/LoadState.vue'
import CursorPager from '@/components/CursorPager.vue'
import { tally } from '@/components/viz'
import { useCursor } from '@/composables/cursor'
import { errText } from '@/composables/load'
import { queryString, useQueryState } from '@/composables/query'
import { toast } from '@/composables/toast'
import { can, session } from '@/api/session'
import { isRange, isUuid, RANGES, rangeFrom, type RangeKey } from '@/api/v2/detect'
import { responseApi, type ActionState } from '@/api/v2/response'
import { fmtTime, guardActionModeLabel, guardAssetEnvLabel, guardActionStateLabel, type GuardAction, type GuardActionReceipt, type GuardBudgetLedger } from '@/api/types'
import { actionStateTone } from '@/data/tones'
import { useAssetNames } from '@/views/detect/assets'

type Tab = 'active' | 'all'
const STATES: readonly ActionState[] = ['pending', 'dispatched', 'applied', 'uncertain', 'recovery_failed', 'revoked', 'expired', 'rejected']
const TERMINAL = ['revoked', 'expired', 'rejected']
const isState = (v: unknown): v is ActionState => typeof v === 'string' && (STATES as readonly string[]).includes(v)
const stateLabel = (k: string) => guardActionStateLabel[k] ?? k
/** 连续阻断上限与恢复冷却（检测与处置契约 T7）；只用于说明与只读估算，额度恢复由后端事务判定。 */
const MAX_BLOCK_MS = 120_000
const COOLDOWN_MS = 120_000

const tab = ref<Tab>('active')
const statusFilter = ref<ActionState | ''>('')
const assetFilter = ref('')
const range = ref<RangeKey | ''>('')
const openId = ref('')
useQueryState({
  tab: { state: tab, default: 'active', parse: (v) => (v === 'all' ? 'all' : 'active') },
  status: { state: statusFilter, default: '', parse: (v) => (isState(v) ? v : '') },
  assetId: { state: assetFilter, default: '', parse: (v) => queryString(v).trim() },
  range: { state: range, default: '', parse: (v) => (isRange(v) ? v : '') },
  id: { state: openId, default: '', parse: (v) => (isUuid(queryString(v)) ? queryString(v).trim() : '') },
})

const { assets, label: assetLabel } = useAssetNames()

/** 时间下界在筛选变化时计算一次，翻页沿用同一值（游标与筛选绑定）。状态筛选只作用于全部动作。 */
let from = rangeFrom(range.value)
const actions = useCursor<GuardAction>((cursor) => responseApi.listActions({
  active: tab.value === 'active' ? true : undefined,
  status: tab.value === 'all' ? statusFilter.value || undefined : undefined,
  assetId: assetFilter.value || undefined,
  from,
  cursor,
}))
watch([tab, statusFilter, assetFilter, range], ([, , , r]) => { from = rangeFrom(r); actions.reset() })

const now = ref(Date.now())
const clock = setInterval(() => { now.value = Date.now() }, 15_000)
onBeforeUnmount(() => clearInterval(clock))

/** 剩余时长只按 blockUntil 与本机时间估算；到期解除仍以执行器回执为准。 */
function remaining(until: string | null) {
  if (!until) return '未设置到期时间'
  const ms = Date.parse(until) - now.value
  if (Number.isNaN(ms)) return '—'
  if (ms <= 0) return '已到期，等待清理回执'
  const s = Math.round(ms / 1000)
  if (s < 60) return `剩余 ${s} 秒`
  if (s < 600) return `剩余 ${Math.floor(s / 60)} 分 ${s % 60} 秒`
  const m = Math.round(s / 60)
  return m >= 60 ? `剩余约 ${Math.floor(m / 60)} 小时 ${m % 60} 分` : `剩余约 ${m} 分钟`
}
/** 已过去的阻断时长占比（登记 → 到期），用于封禁卡片的进度条。 */
function elapsed(a: GuardAction) {
  const start = Date.parse(a.createdAt), end = Date.parse(a.blockUntil ?? '')
  if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start) return 0
  return Math.min(100, Math.max(0, ((now.value - start) / (end - start)) * 100))
}

const activeSorted = computed(() => [...actions.items.value].sort((x, y) => (x.blockUntil ?? '').localeCompare(y.blockUntil ?? '')))
const pageHint = computed(() => `按当前页 ${actions.items.value.length} 条统计`)
const composition = computed(() => tally(actions.items.value, (a) => a.observedState, stateLabel, (k) => actionStateTone[k]))
const tabs = computed(() => [
  { value: 'active' as const, label: '当前封禁', count: tab.value === 'active' && !actions.loading.value ? actions.items.value.length : undefined },
  { value: 'all' as const, label: '全部动作', count: tab.value === 'all' && !actions.loading.value ? actions.items.value.length : undefined },
])
const filtered = computed(() => !!(assetFilter.value || range.value || (tab.value === 'all' && statusFilter.value)))
const emptyText = computed(() => tab.value === 'active'
  ? (filtered.value ? '当前筛选条件下没有生效的封禁。' : '当前没有生效的封禁。')
  : '当前筛选条件下没有处置动作。')
function clearFilters() { statusFilter.value = ''; assetFilter.value = ''; range.value = '' }

/* ---------------- 动作详情（?id=） ---------------- */
interface Detail {
  loading: boolean; error: string; action: GuardAction | null
  receipts: { loading: boolean; error: string; items: GuardActionReceipt[] }
  ledger: { loading: boolean; error: string; data: GuardBudgetLedger | null }
}
const blank = (): Detail => ({ loading: false, error: '', action: null, receipts: { loading: false, error: '', items: [] }, ledger: { loading: false, error: '', data: null } })
const detail = ref<Detail>(blank())
let detailSeq = 0
const busy = ref(false)
const reason = ref('')

async function loadDetail(id: string) {
  const mine = ++detailSeq
  const cached = actions.items.value.find((a) => a.id === id) ?? null
  detail.value = { ...blank(), loading: !cached, action: cached, receipts: { loading: true, error: '', items: [] } }
  let action: GuardAction
  try {
    action = await responseApi.getAction(id)
  } catch (e) {
    if (mine === detailSeq) detail.value = { ...blank(), error: errText(e) }
    return
  }
  if (mine !== detailSeq) return
  detail.value.action = action
  detail.value.loading = false
  detail.value.ledger.loading = !!action.budgetTargetId
  const receipts = responseApi.listReceipts(id).then(
    (r) => { if (mine === detailSeq) detail.value.receipts = { loading: false, error: '', items: [...r.items].sort((x, y) => x.observedAt.localeCompare(y.observedAt)) } },
    (e: unknown) => { if (mine === detailSeq) detail.value.receipts = { loading: false, error: errText(e), items: [] } },
  )
  const ledger = action.budgetTargetId
    ? responseApi.getBudgetLedger(action.budgetTargetId).then(
      (d) => { if (mine === detailSeq) detail.value.ledger = { loading: false, error: '', data: d } },
      (e: unknown) => { if (mine === detailSeq) detail.value.ledger = { loading: false, error: errText(e), data: null } },
    )
    : Promise.resolve()
  await Promise.all([receipts, ledger])
}
watch(openId, (id) => {
  reason.value = ''
  if (id) void loadDetail(id)
  else { detailSeq++; detail.value = blank() }
}, { immediate: true })
const open = (a: GuardAction) => { openId.value = a.id }
const close = () => { openId.value = '' }
const picked = computed(() => detail.value.action)

/** 后端暂不返回申请人时为 undefined，按钮照常显示，自批由后端 403 拒绝。 */
const ownRequest = computed(() => {
  const by = (picked.value as (GuardAction & { createdBy?: number | string | null }) | null)?.createdBy
  return by !== undefined && by !== null && session.user != null && String(by) === String(session.user.id)
})
const revocable = (a: GuardAction) => a.desiredState === 'active' && !TERMINAL.includes(a.observedState)
const canRevoke = computed(() => can('action.revoke') && !!picked.value && revocable(picked.value))
const canDecide = computed(() => can('authorization.approve') && picked.value?.mode === 'manual' && picked.value.observedState === 'pending' && !ownRequest.value)
const revokeLabel = (a: GuardAction) => (a.observedState === 'applied' ? '立即解除' : '撤销')

const stateNote = computed(() => {
  const a = picked.value
  if (!a) return { text: '', tone: '' }
  if (a.observedState === 'applied') return { text: '执行器已回执规则生效。到期解除不代表攻击已解决。', tone: 'border-ok/40' }
  if (a.observedState === 'uncertain') return { text: '命令已领取但没有终结证明：保留额度并核对实态，不按时间推断已清理。', tone: 'note-warn' }
  if (a.observedState === 'recovery_failed') return { text: '清理未能证明完成，须人工核对主机规则实态。', tone: 'note-threat' }
  if (a.desiredState === 'revoked' && !TERMINAL.includes(a.observedState)) return { text: '已请求撤销，规则是否清理以后续回执为准。', tone: 'note-warn' }
  return { text: '期望状态是意图，不是执行结果；终态只由执行器回执推进。', tone: '' }
})

/** 回执时间线：按观测时间正序；没有回执表示命令未下发或执行器未回报。 */
const receiptTone = (s: string) => actionStateTone[s]

/* ---------------- 预算（只读） ---------------- */
const budget = computed(() => {
  const d = detail.value.ledger.data
  if (!d) return null
  const charged = d.chargedMs ?? 0
  const endAt = d.lastBlockEndAt ? Date.parse(d.lastBlockEndAt) : NaN
  const cooldownLeft = Number.isFinite(endAt) ? Math.max(0, endAt + COOLDOWN_MS - now.value) : null
  return {
    pct: Math.min(100, (charged / MAX_BLOCK_MS) * 100),
    used: d.chargedMs == null ? '—' : `${(charged / 1000).toLocaleString('zh-CN', { maximumFractionDigits: 1 })} 秒`,
    cooldown: cooldownLeft === null ? '尚无阻断结束记录' : cooldownLeft === 0 ? '已过 120 秒冷却' : `冷却中，还需约 ${Math.ceil(cooldownLeft / 1000)} 秒`,
    cooldownOk: cooldownLeft === 0,
  }
})

/* ---------------- 写操作 ---------------- */
async function run(fn: () => Promise<unknown>, done: string, after: () => void) {
  busy.value = true
  try {
    await fn()
    toast(done)
    after()
  } catch (e) { toast(errText(e), 'threat') } finally { busy.value = false }
}
function revoke() {
  const a = picked.value
  if (!a) return
  if (!reason.value.trim()) return toast('请填写理由，理由会写入审计。', 'warn')
  const label = revokeLabel(a)
  void run(() => responseApi.revokeAction(a.id, a.revision, reason.value.trim()),
    `已受理${label}，规则清理请看回执。`, () => { reason.value = ''; actions.reset(); void loadDetail(a.id) })
}
function decide(decision: 'approve' | 'reject') {
  const a = picked.value
  if (!a) return
  if (!reason.value.trim()) return toast('请填写审批理由，理由会写入审计。', 'warn')
  void run(() => responseApi.decideAction(a.id, a.revision, decision, reason.value.trim()),
    decision === 'approve' ? '已批准；仍须满足全部硬约束才会下发命令。' : '已驳回。', () => { reason.value = ''; actions.reset(); void loadDetail(a.id) })
}

/** 卡片上的「立即解除」：二次确认并填写理由。 */
const quick = ref<GuardAction | null>(null)
const quickReason = ref('')
function startQuick(a: GuardAction) { quick.value = a; quickReason.value = '' }
function confirmQuick() {
  const a = quick.value
  if (!a) return
  if (!quickReason.value.trim()) return toast('请填写理由，理由会写入审计。', 'warn')
  void run(() => responseApi.revokeAction(a.id, a.revision, quickReason.value.trim()),
    '已受理立即解除，规则清理请看回执。', () => { quick.value = null; actions.reset() })
}

/** 停用自动化：选资产、填原因、选择是否撤销现有规则；202 只表示受理。 */
const stopOpen = ref(false)
const stopForm = ref<{ assetIds: string[]; manual: string; reason: string; revokeExisting: boolean }>({ assetIds: [], manual: '', reason: '', revokeExisting: true })
function openStop() {
  stopForm.value = { assetIds: assetFilter.value ? [assetFilter.value] : [], manual: '', reason: '', revokeExisting: true }
  stopOpen.value = true
}
const stopIds = computed(() => (assets.value.length
  ? stopForm.value.assetIds
  : stopForm.value.manual.split(/[\s,，]+/).map((s) => s.trim()).filter(Boolean)))
function submitStop() {
  const ids = stopIds.value
  if (!ids.length) return toast('至少选择一个资产。', 'warn')
  if (ids.length > 32) return toast('单次最多选择 32 个资产。', 'warn')
  if (!assets.value.length && ids.some((id) => !isUuid(id))) return toast('资产 ID 格式不正确。', 'warn')
  if (!stopForm.value.reason.trim()) return toast('请填写停用原因。', 'warn')
  void run(() => responseApi.stopAutomation({ assetIds: ids, reason: stopForm.value.reason.trim(), revokeExisting: stopForm.value.revokeExisting }),
    '已受理，清理状态请看回执。', () => { stopOpen.value = false; actions.reset() })
}

const snapshot = computed(() => {
  const v = picked.value?.targetSnapshot
  if (!v || typeof v !== 'object' || Array.isArray(v)) return []
  return Object.entries(v as Record<string, unknown>).map(([k, val]) => [k, typeof val === 'object' && val !== null ? JSON.stringify(val) : String(val)] as const)
})
</script>

<template>
  <div>
    <PageHead title="处置记录" desc="当前生效的封禁与全部处置动作。期望状态是意图，观测状态以执行器回执为准；只显示你权限范围内的资产。">
      <button v-if="can('automation.stop')" type="button" class="act-ghost" @click="openStop"><OctagonPause :size="15" :stroke-width="1.5" />停用自动化</button>
    </PageHead>

    <Segmented v-model="tab" :options="tabs" />

    <div class="mt-4 grid items-start gap-5 xl:grid-cols-[minmax(0,1fr)_18rem]">
      <Panel :title="tab === 'active' ? '生效中的封禁' : '动作台账'" :icon="tab === 'active' ? ShieldCheck : ListOrdered" flush>
        <template #actions><span class="text-[12px] text-ink-3">{{ tab === 'active' ? '按到期时间排序' : '最近登记在前' }}</span></template>
        <template #toolbar>
          <div class="toolbar w-full" role="search">
            <label v-if="tab === 'all'" class="toolbar-field"><span>状态</span>
              <select v-model="statusFilter" aria-label="观测状态筛选" class="field">
                <option value="">全部状态</option>
                <option v-for="s in STATES" :key="s" :value="s">{{ stateLabel(s) }}</option>
              </select>
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
            <button v-if="filtered" type="button" class="link text-[12.5px]" @click="clearFilters">清除筛选</button>
          </div>
        </template>

        <LoadState :loading="actions.loading.value" :error="actions.error.value" :empty="!actions.items.value.length" :empty-text="emptyText">
          <!-- 当前封禁：卡片，按到期时间排序，显示剩余时长与已过去的比例 -->
          <ul v-if="tab === 'active'" class="grid gap-3 p-4 sm:grid-cols-2 2xl:grid-cols-3" aria-label="生效中的封禁">
            <li v-for="a in activeSorted" :key="a.id" class="flex flex-col rounded border border-ink-line bg-paper transition-colors hover:border-ink-4">
              <button type="button" class="flex flex-1 flex-col gap-3 px-4 pb-3 pt-4 text-left" @click="open(a)">
                <span class="flex items-start justify-between gap-3">
                  <span class="min-w-0">
                    <span class="block truncate text-[14px] font-medium text-ink">{{ assetLabel(a.assetId) }}</span>
                    <span class="mt-0.5 block text-[12px] text-ink-3">{{ guardActionModeLabel[a.mode] ?? a.mode }}处置 · 登记于 <span class="num">{{ fmtTime(a.createdAt) }}</span></span>
                  </span>
                  <Tag pill :tone="actionStateTone[a.observedState]" :label="stateLabel(a.observedState)" />
                </span>
                <span class="block">
                  <span class="flex items-center justify-between gap-2 text-[12.5px]">
                    <span class="flex items-center gap-1.5 text-ink-2"><Timer :size="13" :stroke-width="1.5" aria-hidden="true" />{{ remaining(a.blockUntil) }}</span>
                    <span class="num text-ink-4">至 {{ fmtTime(a.blockUntil) }}</span>
                  </span>
                  <span class="mt-2 block h-1 overflow-hidden rounded-full bg-ink-hair" aria-hidden="true">
                    <span class="block h-full rounded-full" :class="a.observedState === 'applied' ? 'bg-ok' : 'bg-signal'" :style="{ width: `${elapsed(a)}%` }" />
                  </span>
                </span>
              </button>
              <span class="flex items-center justify-between gap-2 border-t border-ink-hair px-4 py-2">
                <span class="min-w-0 truncate text-[12px] text-ink-3">期望：{{ stateLabel(a.desiredState) }}</span>
                <span class="flex shrink-0 items-center gap-2">
                  <button v-if="can('action.revoke') && revocable(a)" type="button" class="act-danger act-sm" @click="startQuick(a)"><Ban :size="13" :stroke-width="1.5" />{{ revokeLabel(a) }}</button>
                  <button type="button" class="act-ghost act-sm" @click="open(a)">详情<ArrowRight :size="13" :stroke-width="1.5" /></button>
                </span>
              </span>
            </li>
          </ul>

          <!-- 全部动作：期望与观测分两列 -->
          <table v-else class="table min-w-[760px]">
            <thead>
              <tr><th>资产</th><th>模式</th><th>期望状态</th><th>观测状态</th><th>阻断至</th><th class="text-right">登记</th></tr>
            </thead>
            <tbody>
              <tr v-for="a in actions.items.value" :key="a.id" class="row-link" tabindex="0" :aria-current="openId === a.id ? 'true' : undefined" @click="open(a)" @keydown.enter="open(a)">
                <td class="text-ink">{{ assetLabel(a.assetId) }}</td>
                <td class="whitespace-nowrap text-ink-2">{{ guardActionModeLabel[a.mode] ?? a.mode }}</td>
                <td class="whitespace-nowrap"><Tag :tone="a.desiredState === 'active' ? 'signal' : 'mute'" :label="stateLabel(a.desiredState)" /><span class="num ml-1.5 text-[11px] text-ink-4">r{{ a.desiredRevision }}</span></td>
                <td class="whitespace-nowrap"><Tag pill :tone="actionStateTone[a.observedState]" :label="stateLabel(a.observedState)" /></td>
                <td class="num whitespace-nowrap text-ink-3">{{ fmtTime(a.blockUntil) }}</td>
                <td class="num whitespace-nowrap text-right text-ink-3">{{ fmtTime(a.createdAt) }}</td>
              </tr>
            </tbody>
          </table>
        </LoadState>
        <template #foot>
          <CursorPager :count="actions.items.value.length" :has-next="!!actions.next.value" :has-prev="!!actions.stack.value.length"
            :busy="actions.turning.value" :label="tab === 'active' ? '当前封禁' : '处置动作'" @next="actions.forward()" @prev="actions.back()" />
        </template>
      </Panel>

      <aside class="space-y-4 xl:sticky xl:top-20">
        <Panel title="观测状态" :icon="PieChart" :desc="pageHint">
          <DistBar :segments="composition" empty-text="当前页没有动作" />
        </Panel>
        <Panel title="预算与恢复" :icon="Gauge">
          <ul class="space-y-2.5 text-[12.5px] leading-relaxed text-ink-2">
            <li class="flex gap-2"><span class="dot mt-[7px] bg-ink-4" />同一目标连续阻断上限 120 秒，跨策略与重启累计。</li>
            <li class="flex gap-2"><span class="dot mt-[7px] bg-ink-4" />额度恢复须同时满足：规则实际清零、连续健康、120 秒冷却，由后端判定。</li>
            <li class="flex gap-2"><span class="dot mt-[7px] bg-ink-4" />各目标的占用在动作详情中只读显示，页面不提供清零入口。</li>
          </ul>
        </Panel>
      </aside>
    </div>

    <!-- 动作详情：由 ?id= 打开，待办中心可直达 -->
    <Drawer :open="!!openId" :title="picked ? `${assetLabel(picked.assetId)} · ${guardActionModeLabel[picked.mode] ?? picked.mode}处置` : '动作详情'" kicker="处置动作" @close="close">
      <LoadState :loading="detail.loading" :error="detail.error">
        <template v-if="picked">
          <p class="note mb-5" :class="stateNote.tone">{{ stateNote.text }}</p>

          <div class="grid grid-cols-2 overflow-hidden rounded border border-ink-line" aria-label="期望与观测状态">
            <div class="px-4 py-3">
              <p class="text-[12px] text-ink-3">期望状态</p>
              <p class="mt-1.5 flex items-center gap-2"><Tag :tone="picked.desiredState === 'active' ? 'signal' : 'mute'" :label="stateLabel(picked.desiredState)" /><span class="num text-[11.5px] text-ink-4">r{{ picked.desiredRevision }}</span></p>
            </div>
            <div class="border-l border-ink-hair px-4 py-3">
              <p class="text-[12px] text-ink-3">观测状态</p>
              <p class="mt-1.5"><Tag pill :tone="actionStateTone[picked.observedState]" :label="stateLabel(picked.observedState)" /></p>
            </div>
          </div>

          <dl class="kv mt-4">
            <div><dt>资产</dt><dd>{{ assetLabel(picked.assetId) }}</dd></div>
            <div><dt>模式</dt><dd>{{ guardActionModeLabel[picked.mode] ?? picked.mode }}</dd></div>
            <div><dt>阻断至</dt><dd><span class="num">{{ fmtTime(picked.blockUntil) }}</span><span v-if="picked.desiredState === 'active'" class="ml-2 text-[12px] text-ink-3">{{ remaining(picked.blockUntil) }}</span></dd></div>
            <div><dt>登记</dt><dd class="num">{{ fmtTime(picked.createdAt) }}</dd></div>
          </dl>

          <h3 class="section-title mt-7">执行回执</h3>
          <LoadState :loading="detail.receipts.loading" :error="detail.receipts.error">
            <div v-if="!detail.receipts.items.length" class="rounded border border-dashed border-ink-line px-4 py-5 text-center">
              <p class="text-[13.5px] text-ink">命令未下发</p>
              <p class="mt-1 text-[12px] text-ink-3">还没有执行器回执，不代表执行成功。</p>
            </div>
            <ol v-else class="relative ml-1.5 border-l border-ink-line" aria-label="回执时间线">
              <li v-for="r in detail.receipts.items" :key="r.id" class="relative pb-4 pl-5 last:pb-0">
                <span class="absolute -left-[5px] top-1.5 h-2.5 w-2.5 rounded-full border-2 border-paper" :class="{ 'bg-ok': receiptTone(r.status) === 'ok', 'bg-threat': receiptTone(r.status) === 'threat', 'bg-warn': receiptTone(r.status) === 'warn', 'bg-signal': receiptTone(r.status) === 'signal', 'bg-ink-4': receiptTone(r.status) === 'mute' }" aria-hidden="true" />
                <p class="flex flex-wrap items-center gap-x-3 gap-y-1 text-[13px]">
                  <span class="text-ink">{{ r.revocationId ? '撤销' : '执行' }} · {{ stateLabel(r.status) }}</span>
                  <span class="num text-[12px] text-ink-3">{{ fmtTime(r.observedAt) }}</span>
                  <Tag v-if="!r.projected" tone="warn" label="未通过实态核对" />
                </p>
                <p class="mt-1 flex flex-wrap gap-x-3 text-[12px] text-ink-4">命令 <IdText :value="r.commandId" :copy="false" /></p>
              </li>
            </ol>
          </LoadState>

          <h3 class="section-title mt-7">目标预算（只读）</h3>
          <p v-if="!picked.budgetTargetId" class="text-[12.5px] text-ink-3">该动作没有绑定预算目标。</p>
          <LoadState v-else :loading="detail.ledger.loading" :error="detail.ledger.error">
            <template v-if="budget && detail.ledger.data">
              <div>
                <p class="flex items-baseline justify-between text-[12.5px]"><span class="text-ink-3">本周期已占用</span><span><span class="num text-[15px] text-ink">{{ budget.used }}</span><span class="text-ink-4"> / 120 秒</span></span></p>
                <span class="mt-2 block h-1.5 overflow-hidden rounded-full bg-ink-hair" aria-hidden="true">
                  <span class="block h-full rounded-full" :class="budget.pct >= 100 ? 'bg-threat' : budget.pct >= 75 ? 'bg-warn' : 'bg-ink-3'" :style="{ width: `${budget.pct}%` }" />
                </span>
              </div>
              <dl class="kv mt-3">
                <div><dt>最近清零时刻</dt><dd class="num">{{ fmtTime(detail.ledger.data.cycleStartedAt) }}</dd></div>
                <div><dt>最后阻断结束</dt><dd class="num">{{ fmtTime(detail.ledger.data.lastBlockEndAt) }}</dd></div>
                <div><dt>最后合格证据</dt><dd class="num">{{ fmtTime(detail.ledger.data.lastEvidenceAt) }}</dd></div>
              </dl>
              <p class="mt-4 text-[12.5px] text-ink-3">恢复条件（同时满足，由后端判定）</p>
              <ul class="mt-2 space-y-1.5 text-[12.5px]">
                <li class="flex items-center gap-2"><span class="dot bg-ink-4" />规则已实际清零（以执行器回执为准）</li>
                <li class="flex items-center gap-2"><span class="dot bg-ink-4" />采集与执行连续健康</li>
                <li class="flex items-center gap-2"><span class="dot" :class="budget.cooldownOk ? 'bg-ok' : 'bg-ink-4'" />阻断结束后 120 秒冷却<span class="text-ink-3">· {{ budget.cooldown }}</span></li>
              </ul>
            </template>
          </LoadState>

          <details class="mt-7 text-[12.5px]">
            <summary class="cursor-pointer text-ink-3 hover:text-ink">技术细节</summary>
            <dl class="kv mt-2">
              <div><dt>动作 ID</dt><dd><IdText :value="picked.id" /></dd></div>
              <div><dt>决策</dt><dd><IdText :value="picked.decisionId" /></dd></div>
              <div><dt>发布组合</dt><dd><IdText :value="picked.bundleId" /></dd></div>
              <div><dt>执行器</dt><dd><IdText :value="picked.executorId" /></dd></div>
              <div><dt>预算目标</dt><dd><IdText :value="picked.budgetTargetId" /><span v-if="picked.budgetRevision != null" class="num ml-2 text-ink-4">r{{ picked.budgetRevision }}</span></dd></div>
              <div><dt>授权</dt><dd><IdText :value="picked.authorizationId" /><span v-if="picked.authorizationRevision != null" class="num ml-2 text-ink-4">r{{ picked.authorizationRevision }}</span></dd></div>
              <div><dt>修订号</dt><dd class="num">{{ picked.revision }}</dd></div>
              <div v-for="[k, v] in snapshot" :key="k"><dt class="num">{{ k }}</dt><dd class="num break-all">{{ v }}</dd></div>
            </dl>
          </details>

          <label v-if="canDecide || canRevoke" class="form-field mt-7"><span class="label">理由</span>
            <textarea v-model="reason" rows="3" maxlength="1000" class="field resize-none" placeholder="写入审计" />
          </label>
          <p v-if="canDecide" class="mt-3 text-[12px] leading-relaxed text-ink-3">人工申请须由申请人之外的审批人决定；批准后仍执行全部硬约束。</p>
        </template>
      </LoadState>
      <template v-if="picked && (canDecide || canRevoke)" #foot>
        <button v-if="canRevoke" type="button" class="act-danger" :disabled="busy" @click="revoke">{{ revokeLabel(picked) }}</button>
        <template v-if="canDecide">
          <button type="button" class="act-ghost" :disabled="busy" @click="decide('reject')">驳回</button>
          <button type="button" class="act" :disabled="busy" @click="decide('approve')">批准</button>
        </template>
      </template>
    </Drawer>

    <!-- 立即解除：二次确认 -->
    <Drawer :open="!!quick" :title="quick ? `${revokeLabel(quick)} · ${assetLabel(quick.assetId)}` : ''" @close="quick = null">
      <template v-if="quick">
        <p class="note note-warn mb-5">提交后请求撤销该封禁。受理不等于规则已清理，清理结果以执行器回执为准。</p>
        <dl class="kv mb-6">
          <div><dt>资产</dt><dd>{{ assetLabel(quick.assetId) }}</dd></div>
          <div><dt>观测状态</dt><dd>{{ stateLabel(quick.observedState) }}</dd></div>
          <div><dt>阻断至</dt><dd class="num">{{ fmtTime(quick.blockUntil) }}</dd></div>
        </dl>
        <label class="form-field"><span class="label">理由</span><textarea v-model="quickReason" rows="3" maxlength="1000" class="field resize-none" placeholder="写入审计" /></label>
      </template>
      <template #foot>
        <button type="button" class="act-ghost" @click="quick = null">取消</button>
        <button type="button" class="act-danger" :disabled="busy" @click="confirmQuick">确认{{ quick ? revokeLabel(quick) : '' }}</button>
      </template>
    </Drawer>

    <!-- 停用自动化 -->
    <Drawer :open="stopOpen" title="停用自动化" @close="stopOpen = false">
      <div class="space-y-6">
        <p class="note note-threat">停用后立即停止向所选资产下发新命令。受理不等于规则已清理，清理状态请看回执。</p>
        <fieldset v-if="assets.length" class="form-field">
          <legend class="label">资产（最多 32 个）</legend>
          <ul class="max-h-64 space-y-1 overflow-y-auto rounded border border-ink-line p-2">
            <li v-for="a in assets" :key="a.id">
              <label class="flex cursor-pointer items-center gap-3 rounded px-2 py-1.5 text-[13px] hover:bg-paper-soft">
                <input v-model="stopForm.assetIds" type="checkbox" :value="a.id" class="h-4 w-4 accent-ink" />
                <span class="min-w-0 flex-1 truncate text-ink">{{ a.displayName || a.assetKey }}</span>
                <span class="text-[12px] text-ink-4">{{ guardAssetEnvLabel[a.environment] ?? a.environment }}</span>
              </label>
            </li>
          </ul>
          <span class="mt-1.5 block text-[12px] text-ink-3">已选 {{ stopForm.assetIds.length }} 个</span>
        </fieldset>
        <label v-else class="form-field"><span class="label">资产 ID（逗号或换行分隔，最多 32 个）</span>
          <textarea v-model="stopForm.manual" rows="3" class="field num resize-none text-[12px]" />
        </label>
        <label class="form-field"><span class="label">原因</span><textarea v-model="stopForm.reason" rows="3" maxlength="1000" class="field resize-none" placeholder="写入审计" /></label>
        <label class="flex cursor-pointer items-start gap-3 text-[13px]">
          <input v-model="stopForm.revokeExisting" type="checkbox" class="mt-0.5 h-4 w-4 accent-ink" />
          <span><span class="text-ink">同时撤销现有规则</span><span class="mt-0.5 block text-[12px] text-ink-3">不勾选时只停止新命令，已生效的封禁保留到期满。</span></span>
        </label>
      </div>
      <template #foot>
        <button type="button" class="act-ghost" @click="stopOpen = false">取消</button>
        <button type="button" class="act-danger" :disabled="busy" @click="submitStop">确认停用</button>
      </template>
    </Drawer>
  </div>
</template>
