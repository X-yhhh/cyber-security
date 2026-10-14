<script setup lang="ts">
/**
 * 执行与预算（11）：v5 动作台账、稳定目标预算与自动化停用。
 *
 * 读 `/api/v2` 的 actions（含 receipts 子资源）与 budget-targets，写 automation-stops、
 * actions/{id}/decisions、actions/{id}/revocations。
 *
 * 关键口径（docs/检测与处置契约.md、功能模块设计.md §3.2）：
 * - `desiredState` 与 `observedState` **分别显示**：期望状态不是执行结果，
 *   从未领取可证明未执行的记 expired，已领取但无终结证明的记 uncertain 并核对，不按时间推断已清理；
 * - 动作终态只能由执行器回执推进；迟到回执不逆转终态；
 * - 稳定预算账本跨活动、boot、keyEpoch 与策略版本；**没有客户端直接清零预算的接口**，
 *   额度恢复须同时满足实际规则清零、连续健康与 120 秒冷却，由后端事务恢复；
 * - 停用立即停新命令，但「已停用」与「规则已清理」是两件事，必须分别查询；
 * - 人工申请不得提交原始地址或命令，targetRef 必须是决策绑定的稳定预算目标。
 *
 * 前端只按权限隐藏入口；审批分离（自批 403）、状态迁移与硬约束一律以后端判定为准。
 */
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { ArrowRight, Gauge, CircleHelp, Hourglass, ListOrdered, ShieldCheck, Timer } from 'lucide-vue-next'
import PageHead from '@/components/PageHead.vue'
import IdText from '@/components/IdText.vue'
import { countIf } from '@/components/viz'
import Panel from '@/components/Panel.vue'
import Segmented from '@/components/Segmented.vue'
import Tag from '@/components/Tag.vue'
import Drawer from '@/components/Drawer.vue'
import LoadState from '@/components/LoadState.vue'
import CursorPager from '@/components/CursorPager.vue'
import { errText } from '@/composables/load'
import { usePageTitle } from '@/composables/page'
import { guard } from '@/api/client'
import { can } from '@/api/session'
import {
  fmtTime, guardActionModeLabel, guardActionStateLabel, guardDecisionLabel, guardIdentityStatusLabel, guardReasonLabel,
  type GuardAction, type GuardActionReceipt, type GuardAsset, type GuardBudgetLedger, type GuardBudgetTarget,
  type GuardDecision, type GuardEpisode,
} from '@/api/types'
import { actionStateTone, identityTone, statusTone } from '@/data/tones'
import { toast } from '@/composables/toast'

type View = 'actions' | 'budgets'
/** 两级菜单（FE-9）按二级项指定初始分段；F1—F4 拆分本页后删除。 */
const props = defineProps<{ segment?: View }>()
const view = ref<View>(props.segment ?? 'actions')

/** v2 游标分页：不返回总数，游标栈支持回退。 */
function useCursor<T>(load: (cursor?: string) => Promise<{ items: T[]; nextCursor: string | null }>) {
  const items = ref([]) as { value: T[] }
  const next = ref<string | null>(null)
  const loading = ref(true)
  const error = ref('')
  const stack = ref<string[]>([])
  const turning = ref(false)
  let seq = 0
  async function go(cursor?: string) {
    const mine = ++seq
    loading.value = true
    error.value = ''
    try {
      const page = await load(cursor)
      if (mine !== seq) return
      items.value = page.items
      next.value = page.nextCursor
    } catch (e) {
      if (mine !== seq) return
      error.value = errText(e)
      items.value = []
      next.value = null
    } finally { if (mine === seq) loading.value = false }
  }
  async function forward() {
    if (!next.value) return
    turning.value = true
    try { const c = next.value; await go(c); stack.value.push(c) } finally { turning.value = false }
  }
  async function back() {
    if (!stack.value.length) return
    turning.value = true
    try { stack.value.pop(); await go(stack.value[stack.value.length - 1]) } finally { turning.value = false }
  }
  function refresh() { seq++; stack.value = []; void go() }
  void go()
  return { items, next, loading, error, stack, turning, forward, back, refresh }
}

const actions = useCursor<GuardAction>((cursor) => guard.list<GuardAction>('actions', { cursor, limit: 50 }))
const budgets = useCursor<GuardBudgetTarget>((cursor) => guard.list<GuardBudgetTarget>('budget-targets', { cursor, limit: 50 }))

/** 资产与证据迹用于把 UUID 翻译成可读标识；无权限时保持为空，不显示占位假值。 */
const assets = ref<GuardAsset[]>([])
const episodes = ref<GuardEpisode[]>([])
void (async () => {
  try {
    if (can('resource.read')) assets.value = (await guard.list<GuardAsset>('assets', { limit: 200 })).items
    if (can('detection.read')) episodes.value = (await guard.list<GuardEpisode>('evidence-episodes', { limit: 200 })).items
  } catch { /* 翻译失败不影响主列表 */ }
})()
const assetLabel = (id: string | null) => (id ? (assets.value.find((a) => a.id === id)?.assetKey ?? id.slice(0, 8)) : '—')
const episodeLabel = (id: string | null) => (id ? (episodes.value.find((e) => e.id === id)?.peerKey ?? id.slice(0, 8)) : '—')

const active = computed(() => (view.value === 'actions' ? actions : budgets))

/*
 * 版式（视觉基线 v2，处置记录）：动作分段顶部是“生效中的封禁”卡片（观测状态为已生效、按阻断到期时间排序），
 * 右侧是待处理与待核对计数；下方台账把“期望 → 观测”放在同一列，强调制定不等于执行。只按当前页统计。
 */
const actHint = computed(() => `按当前页 ${actions.items.value.length} 条动作`)
const live = computed(() => actions.items.value
  .filter((a) => a.observedState === 'applied')
  .sort((x, y) => (x.blockUntil ?? '').localeCompare(y.blockUntil ?? '')))
const waiting = computed(() => countIf(actions.items.value, (a) => a.observedState === 'pending'))
const unsure = computed(() => countIf(actions.items.value, (a) => a.observedState === 'uncertain' || a.observedState === 'recovery_failed'))
const now = ref(Date.now())
const timer = setInterval(() => { now.value = Date.now() }, 30_000)
onBeforeUnmount(() => clearInterval(timer))
/** 剩余时长只按 blockUntil 与本机时间估算；到期解除仍以执行器回执为准。 */
function remaining(until: string | null) {
  if (!until) return '未设置到期'
  const ms = Date.parse(until) - now.value
  if (Number.isNaN(ms)) return '—'
  if (ms <= 0) return '已到期，等待清理回执'
  const m = Math.round(ms / 60000)
  return m >= 60 ? `约 ${Math.floor(m / 60)} 小时 ${m % 60} 分后到期` : `约 ${m} 分钟后到期`
}
const stateLabel = (k: string) => guardActionStateLabel[k] ?? k
const views = computed(() => [
  { value: 'actions' as const, label: '动作台账', count: actions.items.value.length },
  { value: 'budgets' as const, label: '预算目标', count: budgets.items.value.length },
])

const busy = ref(false)
const reason = ref('')
const picked = ref<GuardAction | null>(null)
const ledger = ref<{ loading: boolean; error: string; data: GuardBudgetLedger | null }>({ loading: false, error: '', data: null })

/**
 * 回执按需读取（子资源最多 200 条）。该动作没有命令时后端返回空列表，
 * 表示命令尚未下发，而不是「执行成功」。
 */
const receipts = ref<{ loading: boolean; error: string; items: GuardActionReceipt[] }>({ loading: false, error: '', items: [] })
watch(picked, async (a) => {
  reason.value = ''
  if (!a) { receipts.value = { loading: false, error: '', items: [] }; return }
  receipts.value = { loading: true, error: '', items: [] }
  try {
    const r = await guard.child<{ items: GuardActionReceipt[] }>('actions', a.id, 'receipts')
    receipts.value = { loading: false, error: '', items: r.items }
  } catch (e) {
    receipts.value = { loading: false, error: errText(e), items: [] }
  }
})

/** 人工申请：必须绑定该证据迹对应决策的稳定预算目标，不接受原始地址。 */
const manualOpen = ref(false)
const manual = ref({ episodeId: '', targetRef: '', policyId: '', reason: '' })
const decisions = ref<GuardDecision[]>([])
watch(manualOpen, async (open) => {
  if (!open || decisions.value.length || !can('detection.read')) return
  try { decisions.value = (await guard.list<GuardDecision>('decisions', { limit: 200 })).items } catch { /* 无权限时保持为空 */ }
})
/** 选中证据迹后，可从其决策中取出稳定预算目标，避免人工抄错引用。 */
const episodeDecisions = computed(() => decisions.value.filter((d) => manual.value.episodeId.trim() && d.episodeId === manual.value.episodeId.trim()))

async function act(fn: () => Promise<unknown>, done: string, after?: () => void) {
  busy.value = true
  try {
    await fn()
    toast(done)
    after?.()
  } catch (e) { toast(errText(e), 'threat') } finally { busy.value = false }
}

/** 审批分离：后端要求审批人 ≠ 申请发起人；此处只在无权限时隐藏入口。 */
const canDecide = computed(() => can('authorization.approve') && picked.value?.mode === 'manual' && picked.value?.observedState === 'pending')
const canRevoke = computed(() => can('action.revoke') && picked.value != null && ['active', 'applied'].includes(picked.value.observedState))

const decide = (decision: 'approve' | 'reject') => {
  if (!reason.value.trim()) return toast('请填写理由。', 'warn')
  void act(
    () => guard.op('actions', picked.value!.id, 'decisions', { decision, reason: reason.value.trim() }, picked.value!.revision),
    decision === 'approve' ? '已批准；仍须执行全部硬约束后才可能生成命令。' : '已驳回。',
    () => { picked.value = null; actions.refresh() },
  )
}
const revoke = () => {
  if (!reason.value.trim()) return toast('请填写撤销理由。', 'warn')
  void act(
    () => guard.op('actions', picked.value!.id, 'revocations', { reason: reason.value.trim() }, picked.value!.revision),
    '已请求撤销；不代表规则已清理，须等候执行器回执与实态核对。',
    () => { picked.value = null; actions.refresh() },
  )
}

async function openBudget(id: string) {
  ledger.value = { loading: true, error: '', data: null }
  try {
    ledger.value = { loading: false, error: '', data: await guard.get<GuardBudgetLedger>('budget-targets', id) }
  } catch (e) {
    ledger.value = { loading: false, error: errText(e), data: null }
  }
}

/** 自动化停用：202 表示已受理停新命令，实际清理状态另行查询。 */
const stopOpen = ref(false)
const stopForm = ref({ assetIds: '', reason: '' })
const stop = () => {
  const ids = stopForm.value.assetIds.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean)
  if (!ids.length) return toast('至少选择一个资产。', 'warn')
  if (ids.length > 32) return toast('单次最多停用 32 个资产。', 'warn')
  if (!stopForm.value.reason.trim()) return toast('请填写停用理由。', 'warn')
  void act(
    () => guard.create('automation-stops', { assetIds: ids, reason: stopForm.value.reason.trim(), revokeExisting: true }),
    '已受理停用：立即停新命令并请求清理现有规则；已停用与规则已清理需分别查询。',
    () => { stopOpen.value = false; stopForm.value = { assetIds: '', reason: '' }; actions.refresh() },
  )
}

const submitManual = () => {
  const m = manual.value
  if (!m.episodeId.trim() || !m.targetRef.trim() || !m.policyId.trim()) return toast('证据迹、目标引用与策略都必填。', 'warn')
  if (!m.reason.trim()) return toast('请填写申请理由。', 'warn')
  void act(
    () => guard.create('actions', { episodeId: m.episodeId.trim(), targetRef: m.targetRef.trim(), policyId: m.policyId.trim(), reason: m.reason.trim() }),
    '申请已登记，等待另一主体审批。',
    () => { manualOpen.value = false; manual.value = { episodeId: '', targetRef: '', policyId: '', reason: '' }; actions.refresh() },
  )
}

const entries = (v: unknown): [string, string][] => {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return []
  return Object.entries(v as Record<string, unknown>).map(([k, val]) => [k, typeof val === 'object' && val !== null ? JSON.stringify(val) : String(val)])
}

/** 本页由多个菜单行复用，标题跟随当前菜单项。 */
const pageTitle = usePageTitle('执行与预算')
</script>

<template>
  <div>
    <PageHead :title="pageTitle" desc="动作台账、回执、稳定目标预算与自动化停用。期望状态与观测状态分别显示：制定不等于执行，回执才能推进终态。只显示你范围内的资产与目标。">
      <button v-if="can('automation.stop')" class="act-ghost" @click="stopOpen = true">停用自动化</button>
      <button v-if="can('action.request')" class="act" @click="manualOpen = true">提交处置申请</button>
    </PageHead>

    <section v-if="view === 'actions' && !actions.loading.value && !actions.error.value" class="mb-5 grid gap-4 xl:grid-cols-[minmax(0,1fr)_16rem]" aria-label="生效中的封禁">
      <div class="panel p-4">
        <h2 class="mb-3 flex items-center gap-2 px-1 text-[15px] font-medium"><ShieldCheck :size="16" :stroke-width="1.5" class="text-ok" aria-hidden="true" />生效中的封禁<span class="num text-[13px] font-normal text-ink-3">{{ live.length }}</span></h2>
        <p v-if="!live.length" class="rounded border border-dashed border-ink-line px-4 py-6 text-center text-[13px] text-ink-3">当前页没有执行器回执为“已生效”的封禁。</p>
        <ul v-else class="grid gap-3 sm:grid-cols-2 2xl:grid-cols-3">
          <li v-for="a in live.slice(0, 6)" :key="a.id">
            <button type="button" class="flex w-full flex-col gap-2 rounded border border-ink-line bg-paper px-4 py-3 text-left transition-colors hover:border-ink-4" @click="picked = a">
              <span class="flex items-center justify-between gap-2">
                <span class="truncate text-[13.5px] font-medium text-ink">{{ assetLabel(a.assetId) }}</span>
                <Tag pill tone="ok" label="已生效" />
              </span>
              <span class="flex items-center gap-1.5 text-[12px] text-ink-3"><Timer :size="13" :stroke-width="1.5" aria-hidden="true" />{{ remaining(a.blockUntil) }}</span>
              <span class="text-[12px] text-ink-4">{{ guardActionModeLabel[a.mode] ?? a.mode }} · 证据迹 <span class="num">{{ episodeLabel(a.decisionId) }}</span></span>
            </button>
          </li>
        </ul>
        <p v-if="live.length > 6" class="mt-3 px-1 text-[12px] text-ink-3">另有 {{ live.length - 6 }} 条，见下方台账。</p>
      </div>
      <div class="grid gap-4">
        <div class="panel flex items-center gap-3 px-5 py-4">
          <Hourglass :size="18" :stroke-width="1.5" class="text-signal" aria-hidden="true" />
          <div><p class="text-[12.5px] text-ink-3">待处理</p><p class="text-[11.5px] text-ink-4">{{ actHint }}</p></div>
          <span class="num ml-auto text-[1.5rem] font-light">{{ waiting }}</span>
        </div>
        <div class="panel flex items-center gap-3 px-5 py-4">
          <CircleHelp :size="18" :stroke-width="1.5" class="text-warn" aria-hidden="true" />
          <div><p class="text-[12.5px] text-ink-3">待核对</p><p class="text-[11.5px] text-ink-4">已领取但无终结证明</p></div>
          <span class="num ml-auto text-[1.5rem] font-light" :class="unsure ? 'text-warn' : ''">{{ unsure }}</span>
        </div>
      </div>
    </section>

    <Segmented v-model="view" :options="views" />

    <Panel class="mt-4" :title="view === 'actions' ? '动作台账' : '预算目标'" :icon="view === 'actions' ? ListOrdered : Gauge" flush>
      <LoadState :loading="active.loading.value" :error="active.error.value" :empty="!active.items.value.length">
      <Transition name="fade" mode="out-in">
        <table v-if="view === 'actions'" key="a" class="table">
          <thead><tr><th>期望 → 观测</th><th>模式</th><th>资产 / 证据</th><th>预算目标</th><th class="text-right">登记</th></tr></thead>
          <tbody>
            <tr v-for="a in actions.items.value" :key="a.id" class="row-link" tabindex="0" @click="picked = a" @keydown.enter="picked = a">
              <td class="whitespace-nowrap">
                <span class="inline-flex items-center gap-2">
                  <Tag :tone="statusTone[a.desiredState]" :label="stateLabel(a.desiredState)" /><span class="num text-[11px] text-ink-4">r{{ a.desiredRevision }}</span>
                  <ArrowRight :size="13" :stroke-width="1.5" class="text-ink-4" aria-hidden="true" />
                  <Tag pill :tone="actionStateTone[a.observedState]" :label="stateLabel(a.observedState)" />
                </span>
              </td>
              <td class="whitespace-nowrap text-ink-3">{{ guardActionModeLabel[a.mode] ?? a.mode }}</td>
              <td><span class="block text-ink">{{ assetLabel(a.assetId) }}</span><span class="text-[12px] text-ink-3">证据迹 <span class="num">{{ episodeLabel(a.decisionId) }}</span><template v-if="!(a.targetSnapshot && typeof a.targetSnapshot === 'object')"> · 无目标快照</template></span></td>
              <td><IdText :value="a.budgetTargetId" /></td>
              <td class="num text-right text-ink-3">{{ fmtTime(a.createdAt) }}</td>
            </tr>
          </tbody>
        </table>

        <table v-else key="b" class="table">
          <thead><tr><th>预算目标</th><th>资产</th><th>环境</th><th>标识核验</th><th class="text-right">登记</th></tr></thead>
          <tbody>
            <tr v-for="b in budgets.items.value" :key="b.id" class="row-link" tabindex="0" @click="openBudget(b.id)" @keydown.enter="openBudget(b.id)">
              <td><IdText :value="b.id" /></td>
              <td class="num text-ink-2">{{ assetLabel(b.assetId) }}</td>
              <td class="num text-ink-3">{{ b.environment ?? '—' }}</td>
              <td><Tag :tone="identityTone[b.identityStatus ?? '']" :label="guardIdentityStatusLabel[b.identityStatus ?? ''] ?? b.identityStatus ?? '未核验'" /></td>
              <td class="num text-right text-ink-3">{{ fmtTime(b.createdAt) }}</td>
            </tr>
          </tbody>
        </table>
      </Transition>
      </LoadState>

      <template #foot>
        <CursorPager :count="active.items.value.length" :has-next="!!active.next.value" :has-prev="!!active.stack.value.length"
        :busy="active.turning.value" :label="String(view)" @next="active.forward()" @prev="active.back()" />
      </template>
    </Panel>

    <!-- 动作详情：期望与观测分开，回执推进终态 -->
    <Drawer :open="!!picked" :title="picked ? `动作 ${picked.id.slice(0, 8)}` : ''" @close="picked = null">
      <template v-if="picked">
        <p class="note mb-5" :class="picked.observedState === 'applied' ? 'border-ok/40' : picked.observedState === 'uncertain' ? 'note-warn' : ''">
          {{ picked.observedState === 'applied'
            ? '执行器已回执规则生效。到期解除不自动宣称攻击已解决。'
            : picked.observedState === 'uncertain'
              ? '已领取但无终结证明：保留额度并核对实态，不按时间推断已清理，也不以旧 ID 盲重试。'
              : '期望状态是意图，不是执行结果。从未领取可证明未执行的记为 expired。' }}
        </p>
        <dl class="kv">
          <div v-for="[k, v] in [
            ['期望状态', `${stateLabel(picked.desiredState)} · r${picked.desiredRevision}`],
            ['观测状态', stateLabel(picked.observedState)],
            ['模式', guardActionModeLabel[picked.mode] ?? picked.mode],
            ['资产', assetLabel(picked.assetId)],
            ['执行身份', picked.executorId ?? '—'],
            ['决策', picked.decisionId ?? '—'],
            ['发布组合', picked.bundleId ?? '—'],
            ['授权', picked.authorizationId ? `${picked.authorizationId.slice(0, 8)} · r${picked.authorizationRevision ?? '—'}` : '—'],
            ['预算目标', picked.budgetTargetId ?? '—'],
            ['预算修订', picked.budgetRevision == null ? '—' : String(picked.budgetRevision)],
            ['阻断至', fmtTime(picked.blockUntil)],
            ['修订', String(picked.revision)],
            ['登记', fmtTime(picked.createdAt)],
          ]" :key="k">
            <dt class="text-ink-3">{{ k }}</dt><dd class="num break-all">{{ v }}</dd>
          </div>
        </dl>

        <h3 class="section-title mt-8">目标快照</h3>
        <dl class="kv">
          <div v-for="[k, v] in entries(picked.targetSnapshot)" :key="k" class="grid-cols-[10rem_minmax(0,1fr)] text-[12.5px]">
            <dt class="num text-ink-3">{{ k }}</dt><dd class="num break-all">{{ v }}</dd>
          </div>
          <p v-if="!entries(picked.targetSnapshot).length" class="py-3 text-[12.5px] text-ink-3">该动作没有目标快照。</p>
        </dl>

        <h3 class="section-title mt-8">执行回执</h3>
        <LoadState :loading="receipts.loading" :error="receipts.error" :empty="!receipts.items.length" empty-text="尚无回执：命令未下发或执行器未回报。">
          <ul>
            <li v-for="r in receipts.items" :key="r.id" class="border-b border-ink-hair py-3 text-[12.5px]">
              <div class="flex items-center gap-3"><Tag :tone="actionStateTone[r.status]" :label="r.status" /><span class="num text-ink-3">{{ fmtTime(r.observedAt) }}</span></div>
              <p class="num mt-1 break-all text-ink-3">命令 {{ r.commandId.slice(0, 8) }}<template v-if="r.revocationId"> · 撤销 {{ r.revocationId.slice(0, 8) }}</template><template v-if="!r.projected"> · 未通过实态核对</template></p>
              <p class="num mt-1 break-all text-ink-4">stateDigest {{ r.stateDigest.slice(0, 24) }}…</p>
            </li>
          </ul>
        </LoadState>

        <label v-if="canDecide || canRevoke" class="form-field mt-8"><span class="label">理由</span><textarea v-model="reason" rows="3" maxlength="1000" class="field resize-none" placeholder="写入审计" /></label>
        <p v-if="picked.mode === 'manual' && picked.observedState === 'pending'" class="mt-6 text-[12.5px] leading-relaxed text-ink-3">人工申请须由发起人之外的审批人决定；批准后仍走同一命令服务与代理，不绕过签名、TTL、范围与恢复规则。</p>
      </template>
      <template v-if="canDecide || canRevoke" #foot>
        <button v-if="canRevoke" class="act-danger" :disabled="busy" @click="revoke">请求撤销</button>
        <template v-if="canDecide">
          <button class="act-ghost" :disabled="busy" @click="decide('reject')">驳回</button>
          <button class="act" :disabled="busy" @click="decide('approve')">批准</button>
        </template>
      </template>
    </Drawer>

    <!-- 预算账本：只读；没有客户端直接清零接口 -->
    <Drawer :open="!!ledger.data || ledger.loading || !!ledger.error" :title="ledger.data ? `预算目标 ${ledger.data.id.slice(0, 12)}` : '预算账本'" @close="ledger = { loading: false, error: '', data: null }">
      <LoadState :loading="ledger.loading" :error="ledger.error">
        <template v-if="ledger.data">
          <p class="note mb-5">
            稳定预算跨活动、boot、keyEpoch 与策略版本。没有客户端直接清零的接口：额度只在真实规则清零、连续健康与 120 秒冷却同时满足时由后端事务恢复，缺口、未知或不确定态不重置。
          </p>
          <dl class="kv">
            <div v-for="[k, v] in [
              ['已占用', ledger.data.chargedMs == null ? '—' : `${ledger.data.chargedMs} ms`],
              ['周期起点', fmtTime(ledger.data.cycleStartedAt)],
              ['最后阻断结束', fmtTime(ledger.data.lastBlockEndAt)],
              ['最后合格证据', fmtTime(ledger.data.lastEvidenceAt)],
              ['健康证明哈希', ledger.data.healthProofSha256 ?? '—'],
              ['修订', String(ledger.data.revision)],
              ['登记', fmtTime(ledger.data.createdAt)],
            ]" :key="k">
              <dt class="text-ink-3">{{ k }}</dt><dd class="num break-all">{{ v }}</dd>
            </div>
          </dl>
          <p class="mt-6 text-[12.5px] leading-relaxed text-ink-3">账本不返回稳定目标 token 与真实端点；原始地址只存在于本机。人工恢复仍须暂停自动能力、核对实态并留下批准与审计。</p>
        </template>
      </LoadState>
    </Drawer>

    <!-- 人工处置申请 -->
    <Drawer :open="manualOpen" title="提交处置申请" @close="manualOpen = false">
      <div class="space-y-6">
        <label class="form-field"><span class="label">证据迹 ID</span><input v-model="manual.episodeId" class="field num" placeholder="UUID" /></label>
        <div v-if="episodeDecisions.length" class="border-l-2 border-signal py-1 pl-4 text-[12.5px]">
          <p class="text-ink-3">该证据迹的决策；点选填入稳定预算目标。</p>
          <ul class="mt-2 space-y-1.5">
            <li v-for="d in episodeDecisions" :key="d.id">
              <button class="link text-[12.5px]" @click="manual.targetRef = d.budgetTargetId ?? ''; manual.policyId = ''">
                {{ guardDecisionLabel[d.decision] ?? d.decision }} · <span class="num">{{ guardReasonLabel[d.reasonCode] ?? d.reasonCode }}</span>
                <template v-if="d.budgetTargetId"> · <span class="num">{{ d.budgetTargetId.slice(0, 8) }}</span></template>
              </button>
            </li>
          </ul>
        </div>
        <label class="form-field"><span class="label">目标引用（targetRef）</span><input v-model="manual.targetRef" class="field num" placeholder="必须等于决策绑定的稳定预算目标" /></label>
        <label class="form-field"><span class="label">策略 ID</span><input v-model="manual.policyId" class="field num" placeholder="该证据迹所属组合的策略" /></label>
        <label class="form-field"><span class="label">申请理由</span><textarea v-model="manual.reason" rows="3" maxlength="1000" class="field resize-none" /></label>
        <p class="text-[12px] leading-relaxed text-ink-3">不得提交原始地址、命令或任意参数。目标引用必须与决策绑定的稳定预算目标一致，不一致会被拒绝；申请需由其他主体审批，批准后仍执行全部硬约束。</p>
      </div>
      <template #foot>
        <button class="act-ghost" @click="manualOpen = false">取消</button>
        <button class="act" :disabled="busy" @click="submitManual">提交申请</button>
      </template>
    </Drawer>

    <!-- 自动化停用 -->
    <Drawer :open="stopOpen" title="停用自动化" @close="stopOpen = false">
      <div class="space-y-6">
        <p class="note note-threat">停用立即阻止新命令，并请求清理该资产已有规则。受理不等于清理完成：规则实态须以执行器回执与核对结果为准。</p>
        <label class="form-field"><span class="label">资产 ID（逗号或换行分隔，最多 32 个）</span><textarea v-model="stopForm.assetIds" rows="3" class="field num resize-none text-[12px]" /></label>
        <label class="form-field"><span class="label">停用理由</span><textarea v-model="stopForm.reason" rows="3" maxlength="1000" class="field resize-none" /></label>
      </div>
      <template #foot>
        <button class="act-ghost" @click="stopOpen = false">取消</button>
        <button class="act" :disabled="busy" @click="stop">确认停用</button>
      </template>
    </Drawer>
  </div>
</template>
