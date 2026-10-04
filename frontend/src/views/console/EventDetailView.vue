<script setup lang="ts">
/**
 * 事件详情：左侧证据时间线与研判，右侧风险与处置申请。
 * 数据来自 GET /events/{id}；时间线与关联告警只内嵌第一页（按时间倒序），翻页读
 * GET /events/{id}/timeline、/events/{id}/alerts，不一次载入全部证据。
 * 状态迁移、研判笔记和处置申请分别调用后端命令接口，成功后重新读取详情（回到第一页，
 * 新写入的条目在最前），不在本地伪造时间线。状态按钮只列出状态机允许的下一步，
 * 最终合法性、资产授权与策略匹配均由后端校验（失败时展示后端脱敏原因）。
 * 关联告警每行可打开人工标注抽屉（阶段 7），标注成功后重新读取告警当前页。
 * 处理人：PUT /events/{id}/assignee（填理由，assigneeId 为 null 即取消指派）；目标用户须 active 且能研判全部证据，
 * 否则后端 400；关闭事件 409。时间线的 assignee_changed 条目展示前后处理人。
 */
import { computed, reactive, ref, watch } from 'vue'
import { RouterLink, useRoute } from 'vue-router'
import { ArrowLeft } from 'lucide-vue-next'
import Tag from '@/components/Tag.vue'
import Drawer from '@/components/Drawer.vue'
import LoadState from '@/components/LoadState.vue'
import Pager from '@/components/Pager.vue'
import AlertFeedbackDrawer from '@/components/AlertFeedbackDrawer.vue'
import { api, ApiError, type Page } from '@/api/client'
import { can, session } from '@/api/session'
import { alertSource, alertTypeLabel, basisEntries, eventStatusLabel, eventTransitions, fmtTime, severityLabel, type AlertView, type EventDetail, type EventStatus, type PolicyView, type TimelineView } from '@/api/types'
import { eventTone, severityTone, statusTone } from '@/data/tones'
import { toast } from '@/composables/toast'
import { errText, optional, useLoad } from '@/composables/load'
import { vReveal } from '@/composables/reveal'

const route = useRoute()
const id = String(route.params.id)
const { data, loading, error, reload } = useLoad(() => api.get<EventDetail>(`/events/${encodeURIComponent(id)}`), null as EventDetail | null)
const ev = computed(() => data.value?.event)
const notFound = computed(() => !loading.value && !data.value)
const busy = ref(false)

/**
 * 服务端分页状态：以详情内嵌的第一页为初值，翻页时请求子资源。
 * 以请求序号丢弃过期响应，避免快速翻页时旧页覆盖新页；失败只提示，保留当前页。
 */
function usePaged<T>(kind: 'timeline' | 'alerts', first: () => Page<T> | undefined) {
  const state = ref<Page<T> | null>(null)
  const turning = ref(false)
  let seq = 0
  watch(first, (p) => { seq++; turning.value = false; state.value = p ?? null }, { immediate: true })
  async function go(page: number) {
    const size = state.value?.size ?? 20
    const mine = ++seq
    turning.value = true
    try {
      const next = await api.get<Page<T>>(`/events/${encodeURIComponent(id)}/${kind}?page=${page}&size=${size}`)
      if (mine === seq) state.value = next
    } catch (e) {
      if (mine === seq) toast(errText(e), 'threat')
    } finally {
      if (mine === seq) turning.value = false
    }
  }
  return { state, turning, go }
}
const timeline = usePaged('timeline', () => data.value?.timeline)
const alerts = usePaged('alerts', () => data.value?.alerts)

// 告警人工标注：抽屉内读取标注历史并提交；标注会改变告警状态，成功后重新读取当前页
const labeling = ref<AlertView | null>(null)
/** 抽屉中的告警状态以刷新后的当前页为准，找不到时沿用打开时的快照。 */
const labelingStatus = computed(() => alerts.state.value?.items.find((a) => a.id === labeling.value?.id)?.status ?? labeling.value?.status ?? null)
const onFeedbackChanged = () => alerts.go(alerts.state.value?.page ?? 0)
/** 按钮文案只是入口提示：可标注状态显示「标注」，否则只读查看；是否已有有效标注在抽屉内按历史判断。 */
const feedbackAction = (a: AlertView) => (can('alert.feedback.label') && ['new', 'acknowledged'].includes(a.status) ? '标注' : '查看标注')

// 状态迁移与笔记都要求理由，写入后端追加式时间线
const pendingTo = ref<EventStatus | null>(null)
const reason = ref('')
async function transit() {
  if (!pendingTo.value || !reason.value.trim()) return
  busy.value = true
  try {
    await api.post(`/events/${id}/transitions`, { status: pendingTo.value, reason: reason.value.trim() })
    toast(`状态已更新为「${eventStatusLabel[pendingTo.value]}」`)
    pendingTo.value = null
    reason.value = ''
    await reload()
  } catch (e) { toast(errText(e), 'threat') } finally { busy.value = false }
}
const note = ref('')
async function addNote() {
  if (!note.value.trim()) return
  busy.value = true
  try {
    await api.post(`/events/${id}/notes`, { note: note.value.trim() })
    note.value = ''
    await reload()
  } catch (e) { toast(errText(e), 'threat') } finally { busy.value = false }
}

// 处理人指派：用户 ID 输入（研判员通常没有用户目录权限），可一键指派给自己
const assigning = ref(false)
const assignForm = reactive({ assigneeId: '', reason: '' })
const who = (id: number | string | null | undefined) => (id == null || id === 'unassigned' ? '未指派' : String(id) === String(session.user?.id) ? `#${id}（我）` : `#${id}`)
function openAssign() {
  assignForm.assigneeId = ev.value?.assigneeId == null ? '' : String(ev.value.assigneeId)
  assignForm.reason = ''
  assigning.value = true
}
async function assign(unassign = false) {
  const raw = assignForm.assigneeId.trim()
  const assigneeId = unassign ? null : Number(raw)
  if (!unassign && !(Number.isInteger(assigneeId) && (assigneeId as number) > 0)) return toast('请填写有效的用户 ID。', 'warn')
  if (!assignForm.reason.trim()) return toast('请填写指派理由。', 'warn')
  busy.value = true
  try {
    await api.put(`/events/${id}/assignee`, { assigneeId, reason: assignForm.reason.trim() })
    toast(unassign ? '已取消指派。' : `已指派给 ${who(assigneeId)}。`)
    assigning.value = false
    await reload()
  } catch (e) { toast(errText(e), 'threat') } finally { busy.value = false }
}
/** assignee_changed 条目的前后处理人；detailsJson 缺失或无法解析时返回 null。 */
function assigneeChange(t: TimelineView): { from: string; to: string } | null {
  if (t.entryType !== 'assignee_changed' || !t.detailsJson) return null
  try {
    const d = JSON.parse(t.detailsJson) as { from?: unknown; to?: unknown }
    return { from: who(d.from == null ? null : String(d.from)), to: who(d.to == null ? null : String(d.to)) }
  } catch { return null }
}

// 处置申请：目标资产限定为事件已关联资产，策略来自 /response-policies
const asking = ref(false)
const policies = ref<PolicyView[]>([])
const form = reactive({ assetId: 0, policyId: 0, peer: '', ttl: 30, reason: '' })
const policy = computed(() => policies.value.find((p) => p.id === form.policyId))
const maxTtlMin = computed(() => Math.floor(Math.min(policy.value?.actionParams?.maxTtlSeconds ?? 0, policy.value?.maxDurationSeconds ?? 0) / 60))
const checks = computed(() => [
  { k: '目标为事件关联资产', ok: !!data.value?.assets.some((a) => a.assetId === form.assetId) },
  { k: '策略处于 active 且已批准', ok: policy.value?.status === 'active' && policy.value.approved },
  { k: '策略动作为 temporary_block', ok: policy.value?.actionType === 'temporary_block' },
  { k: `TTL ≤ 策略上限 ${maxTtlMin.value} min`, ok: form.ttl > 0 && form.ttl <= maxTtlMin.value },
  { k: '对端为单一 IPv4 地址', ok: /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(form.peer) },
  { k: '已填写申请理由', ok: !!form.reason.trim() },
])
const allOk = computed(() => checks.value.every((c) => c.ok))
async function openAsk() {
  try {
    policies.value = (await optional(api.get<PolicyView[]>('/response-policies'), [])).filter((p) => p.status === 'active')
  } catch (e) { toast(errText(e), 'threat') }
  form.assetId = data.value?.assets[0]?.assetId ?? 0
  form.policyId = policies.value[0]?.id ?? 0
  asking.value = true
}
async function submitAction() {
  if (!allOk.value) return
  busy.value = true
  try {
    // 幂等键：同一次提交的重试不会产生重复申请
    const key = `ui-${crypto.randomUUID()}`
    await api.post(`/events/${id}/actions`, {
      assetId: form.assetId, policyId: form.policyId, actionType: 'temporary_block',
      parameters: { targetAddress: form.peer, ttlSeconds: form.ttl * 60 }, reason: form.reason.trim(),
    }, { 'Idempotency-Key': key })
    asking.value = false
    toast('已提交处置申请，等待响应审批员决定')
    await reload()
  } catch (e) {
    toast(e instanceof ApiError ? errText(e) : '提交失败', 'threat')
  } finally { busy.value = false }
}

const mark = (t: string) => (t.includes('alert') ? 'bg-threat' : t.includes('transition') || t.includes('status') ? 'bg-ink' : t.includes('action') ? 'bg-signal' : 'bg-ink-4')
const risk = computed(() => (ev.value?.riskScore == null ? null : Math.round(Number(ev.value.riskScore) * 100)))
const riskBasis = computed(() => basisEntries(ev.value?.riskBasisJson ?? null))
</script>

<template>
  <div>
    <RouterLink :to="{ name: 'events' }" class="link mb-10 text-[13px] text-ink-3"><ArrowLeft :size="14" :stroke-width="1.5" /> 告警与事件</RouterLink>
    <LoadState :loading="loading" :error="error && !notFound ? error : ''">
    <div v-if="data && ev">
    <header class="mb-16 grid gap-10 lg:grid-cols-[1fr_auto] lg:items-end">
      <div>
        <p class="label mb-5 flex items-center gap-4"><span class="num">{{ ev.eventKey }}</span><Tag :tone="severityTone[ev.severity]" :label="severityLabel[ev.severity] ?? ev.severity" /><Tag :tone="eventTone[ev.status]" :label="eventStatusLabel[ev.status] ?? ev.status" /></p>
        <h1 class="max-w-3xl text-[2rem] font-light leading-snug tracking-[-0.02em]">{{ ev.title }}</h1>
        <p class="num mt-5 flex flex-wrap gap-x-8 gap-y-1 text-[12.5px] text-ink-3">
          <span>资产 {{ data.assets.map((a) => a.assetKey).join('、') || '—' }}</span><span>类别 {{ ev.category }}</span><span>处理人 {{ who(ev.assigneeId) }}</span><span>首次 {{ fmtTime(ev.firstSeenAt) }}</span><span>最近 {{ fmtTime(ev.lastSeenAt) }}</span>
        </p>
      </div>
      <div v-if="can('event.investigate')" class="flex flex-wrap items-center gap-6">
        <button v-for="to in eventTransitions[ev.status]" :key="to" class="link text-[13px]" @click="pendingTo = to">标记为{{ eventStatusLabel[to] }}</button>
        <button v-if="ev.status !== 'closed'" class="link text-[13px]" @click="openAssign">{{ ev.assigneeId == null ? '指派' : '更换处理人' }}</button>
        <button v-if="can('action.request')" class="act" :disabled="!['open', 'investigating', 'contained'].includes(ev.status)" @click="openAsk">申请处置</button>
      </div>
    </header>

    <form v-if="pendingTo" class="mb-14 flex items-end gap-6 border-l-2 border-signal pl-6" @submit.prevent="transit">
      <label class="flex-1"><span class="label">迁移为「{{ eventStatusLabel[pendingTo] }}」的理由</span><input v-model="reason" class="field mt-2" maxlength="1000" /></label>
      <button type="button" class="link text-[13px] text-ink-3" @click="pendingTo = null">取消</button>
      <button type="submit" class="act" :disabled="busy || !reason.trim()">确认</button>
    </form>

    <div class="grid gap-20 lg:grid-cols-[1.35fr_1fr]">
      <section v-reveal>
        <h2 class="mb-8 flex items-baseline justify-between text-[15px]">
          <span>证据时间线<span class="num ml-2 text-[11px] text-ink-4">{{ timeline.state.value?.totalElements ?? 0 }}</span></span>
          <span class="label">最新在前</span>
        </h2>
        <ol class="relative ml-1 border-l border-ink-hair transition-opacity duration-300" :class="timeline.turning.value ? 'opacity-50' : ''" :aria-busy="timeline.turning.value">
          <li v-for="t in timeline.state.value?.items ?? []" :key="t.id" class="relative pb-9 pl-8">
            <span class="absolute -left-[3.5px] top-[7px] h-[6px] w-[6px]" :class="mark(t.entryType)" />
            <p class="num flex gap-4 text-[11.5px] text-ink-3"><span>{{ fmtTime(t.occurredAt) }}</span><span class="label !text-[10px]">{{ t.entryType }}</span><span>{{ t.actorType }}{{ t.actorId ? ' · ' + t.actorId : '' }}</span></p>
            <p class="mt-2 text-[14px] leading-relaxed">{{ t.summary }}</p>
            <p v-if="assigneeChange(t)" class="num mt-1 text-[12.5px] text-ink-3">处理人 {{ assigneeChange(t)!.from }} → {{ assigneeChange(t)!.to }}</p>
          </li>
          <li v-if="!timeline.state.value?.items.length" class="pb-9 pl-8 text-[13px] text-ink-3">暂无时间线记录。</li>
        </ol>
        <Pager v-if="timeline.state.value" class="!mt-0 mb-8 pl-8" label="证据时间线" :total="timeline.state.value.totalElements" :page="timeline.state.value.page" :size="timeline.state.value.size" :busy="timeline.turning.value" @change="timeline.go" />
        <form v-if="can('event.investigate')" class="mt-2 flex items-end gap-6 pl-8" @submit.prevent="addNote">
          <label class="flex-1"><span class="label">追加研判</span><input v-model="note" class="field mt-2" maxlength="1000" placeholder="写下依据，而不是结论" /></label>
          <button type="submit" class="link text-[13px]" :disabled="busy || !note.trim()">添加</button>
        </form>

        <h2 class="mb-6 mt-20 flex items-baseline justify-between text-[15px]">
          <span>关联告警<span class="num ml-2 text-[11px] text-ink-4">{{ alerts.state.value?.totalElements ?? 0 }}</span></span>
          <span class="label">最新在前</span>
        </h2>
        <table class="table transition-opacity duration-300" :class="alerts.turning.value ? 'opacity-50' : ''" :aria-busy="alerts.turning.value">
          <thead><tr><th>时间</th><th>告警</th><th>来源</th><th>分数</th><th>状态</th><th>标注</th></tr></thead>
          <tbody>
            <tr v-for="a in alerts.state.value?.items ?? []" :key="a.id">
              <td class="num text-ink-3">{{ fmtTime(a.detectedAt) }}</td>
              <td class="num">{{ a.alertKey }}</td>
              <td>
                <span class="block text-ink-2">{{ alertTypeLabel[a.alertType] ?? a.alertType }} · {{ alertSource(a) }}</span>
                <span class="num text-[12px] text-ink-3">契约 {{ a.contractVersion ?? '—' }}{{ a.severityPolicyVersion ? ' · 分级 ' + a.severityPolicyVersion : '' }}</span>
              </td>
              <td class="num">{{ a.score == null ? '—' : Number(a.score).toFixed(3) }}</td>
              <td><Tag :tone="statusTone[a.status]" :label="a.status" /></td>
              <td>
                <button v-if="can('alert.read')" type="button" class="link text-[13px]" :aria-label="`${feedbackAction(a)} ${a.alertKey}`" @click="labeling = a">{{ feedbackAction(a) }}</button>
                <span v-else class="text-ink-3">—</span>
              </td>
            </tr>
            <tr v-if="!alerts.state.value?.items.length"><td colspan="6" class="py-8 text-center text-ink-3">无可见关联告警。</td></tr>
          </tbody>
        </table>
        <Pager v-if="alerts.state.value" label="关联告警" :total="alerts.state.value.totalElements" :page="alerts.state.value.page" :size="alerts.state.value.size" :busy="alerts.turning.value" @change="alerts.go" />
      </section>

      <aside v-reveal="120">
        <h2 class="mb-8 text-[15px]">风险评分</h2>
        <p class="num text-[4.5rem] font-extralight leading-none tracking-[-0.04em]" :class="(risk ?? 0) > 70 ? 'text-threat' : ''">{{ risk ?? '—' }}<span class="ml-2 text-[14px] text-ink-3">/ 100</span></p>
        <div class="mt-8 h-1.5 w-full bg-paper-deep"><span class="block h-full bg-ink" :style="{ width: (risk ?? 0) + '%' }" /></div>
        <h3 class="label mb-4 mt-12">评分依据</h3>
        <dl class="border-t border-ink">
          <div v-for="[k, v] in riskBasis" :key="k" class="grid grid-cols-[9rem_1fr] border-b border-ink-hair py-2.5 text-[12.5px]">
            <dt class="text-ink-3">{{ k }}</dt><dd class="num break-all">{{ v }}</dd>
          </div>
          <p v-if="!riskBasis.length" class="py-3 text-[12.5px] text-ink-3">该事件未保存评分依据。</p>
        </dl>
        <p v-if="ev.correlationKey" class="num mt-4 text-[12px] text-ink-3">关联 {{ ev.correlationKey }} · {{ ev.correlationPolicyVersion ?? '—' }}</p>
        <h3 class="label mb-4 mt-12">关联资产</h3>
        <ul class="border-t border-ink">
          <li v-for="a in data.assets" :key="a.assetId" class="flex justify-between border-b border-ink-hair py-3.5 text-[13px]">
            <span class="num">{{ a.assetKey }}</span><span class="text-ink-3">{{ a.relationType }} · 证据 {{ a.evidenceCount }}</span>
          </li>
        </ul>
        <p class="mt-6 text-[12px] leading-relaxed text-ink-3">评分由后端风险规则计算并随事件保存。低质量或不完整数据不会被展示为高置信结论。</p>
      </aside>
    </div>

    <Drawer :open="asking" title="申请主机临时阻断" :kicker="ev.eventKey" @close="asking = false">
      <div class="space-y-8">
        <label class="block"><span class="label">目标资产</span>
          <select v-model.number="form.assetId" class="field mt-2">
            <option v-for="a in data.assets" :key="a.assetId" :value="a.assetId">{{ a.assetKey }}</option>
          </select>
        </label>
        <label class="block"><span class="label">策略</span>
          <select v-model.number="form.policyId" class="field mt-2">
            <option v-if="!policies.length" :value="0">无可用 active 策略</option>
            <option v-for="p in policies" :key="p.id" :value="p.id">{{ p.policyKey }} · {{ p.version }} · {{ p.environment }}</option>
          </select>
        </label>
        <div class="grid grid-cols-[1fr_8rem] gap-8">
          <label class="block"><span class="label">对端 IP</span><input v-model="form.peer" class="field num mt-2" /></label>
          <label class="block"><span class="label">TTL（分钟）</span><input v-model.number="form.ttl" type="number" min="1" class="field num mt-2" /></label>
        </div>
        <label class="block"><span class="label">申请理由</span><textarea v-model="form.reason" rows="3" maxlength="1000" class="field mt-2 h-auto resize-none py-2" /></label>
      </div>

      <h3 class="label mb-4 mt-12">提交前校验</h3>
      <ul class="border-t border-ink">
        <li v-for="c in checks" :key="c.k" class="flex items-center justify-between border-b border-ink-hair py-3 text-[13px]">
          <span :class="c.ok ? '' : 'text-ink-3'">{{ c.k }}</span>
          <Tag :tone="c.ok ? 'ok' : 'threat'" :label="c.ok ? '通过' : '不满足'" />
        </li>
      </ul>
      <p class="mt-6 text-[12px] leading-relaxed text-ink-3">以上为前端预检；资产授权有效期、策略允许目标与环境匹配由后端最终校验。申请人不能审批本人申请。</p>
      <template #foot>
        <button class="link text-[13px]" @click="asking = false">取消</button>
        <button class="act" :disabled="!allOk || busy" @click="submitAction">提交审批</button>
      </template>
    </Drawer>

    <Drawer :open="assigning" title="指派处理人" :kicker="ev.eventKey" @close="assigning = false">
      <div class="space-y-6">
        <p class="text-[13px] text-ink-2">当前处理人：{{ who(ev.assigneeId) }}</p>
        <label class="block"><span class="label">处理人用户 ID</span>
          <span class="mt-2 flex items-center gap-4">
            <input v-model="assignForm.assigneeId" inputmode="numeric" class="field num flex-1" placeholder="例如 8" />
            <button v-if="session.user" type="button" class="link whitespace-nowrap text-[13px]" @click="assignForm.assigneeId = String(session.user.id)">指派给我</button>
          </span>
        </label>
        <label class="block"><span class="label">理由</span><textarea v-model="assignForm.reason" rows="3" maxlength="1000" class="field mt-2 h-auto resize-none py-2" placeholder="写入时间线与审计" /></label>
        <p class="text-[12px] leading-relaxed text-ink-3">目标用户须为正常状态，且对该事件全部关联资产与数据源有研判权限，否则后端拒绝。关闭的事件不可指派。</p>
      </div>
      <template #foot>
        <button v-if="ev.assigneeId != null" class="link text-[13px]" :disabled="busy" @click="assign(true)">取消指派</button>
        <button class="link text-[13px]" @click="assigning = false">取消</button>
        <button class="act" :disabled="busy" @click="assign()">确认指派</button>
      </template>
    </Drawer>

    <AlertFeedbackDrawer
      :open="!!labeling" :alert-id="labeling?.id ?? null" :alert-key="labeling?.alertKey ?? ''"
      :status="labelingStatus" :alert-type="labeling?.alertType ?? null"
      @close="labeling = null" @changed="onFeedbackChanged"
    />
    </div>
    <div v-else-if="notFound" class="py-32 text-center">
      <p class="label">404</p>
      <p class="mt-4 text-ink-3">事件不存在，或不在你的授权范围内。</p>
      <RouterLink :to="{ name: 'events' }" class="link mt-8 text-[13px]">返回告警与事件</RouterLink>
    </div>
    </LoadState>
  </div>
</template>
