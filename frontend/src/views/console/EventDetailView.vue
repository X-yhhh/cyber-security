<script setup lang="ts">
/**
 * 事件详情：左侧证据时间线与研判，右侧风险与处置申请。
 * 数据来自 GET /events/{id}；状态迁移、研判笔记和处置申请分别调用后端命令接口，
 * 成功后重新读取详情，不在本地伪造时间线。状态按钮只列出状态机允许的下一步，
 * 最终合法性、资产授权与策略匹配均由后端校验（失败时展示后端脱敏原因）。
 */
import { computed, reactive, ref } from 'vue'
import { RouterLink, useRoute } from 'vue-router'
import { ArrowLeft } from 'lucide-vue-next'
import Tag from '@/components/Tag.vue'
import Drawer from '@/components/Drawer.vue'
import LoadState from '@/components/LoadState.vue'
import { api, ApiError } from '@/api/client'
import { can } from '@/api/session'
import { alertSource, alertTypeLabel, basisEntries, eventStatusLabel, eventTransitions, fmtTime, severityLabel, type EventDetail, type EventStatus, type PolicyView } from '@/api/types'
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
          <span>资产 {{ data.assets.map((a) => a.assetKey).join('、') || '—' }}</span><span>类别 {{ ev.category }}</span><span>首次 {{ fmtTime(ev.firstSeenAt) }}</span><span>最近 {{ fmtTime(ev.lastSeenAt) }}</span>
        </p>
      </div>
      <div v-if="can('event.investigate')" class="flex flex-wrap items-center gap-6">
        <button v-for="to in eventTransitions[ev.status]" :key="to" class="link text-[13px]" @click="pendingTo = to">标记为{{ eventStatusLabel[to] }}</button>
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
        <h2 class="mb-8 text-[15px]">证据时间线</h2>
        <ol class="relative ml-1 border-l border-ink-hair">
          <li v-for="t in data.timeline" :key="t.id" class="relative pb-9 pl-8">
            <span class="absolute -left-[3.5px] top-[7px] h-[6px] w-[6px]" :class="mark(t.entryType)" />
            <p class="num flex gap-4 text-[11.5px] text-ink-3"><span>{{ fmtTime(t.occurredAt) }}</span><span class="label !text-[10px]">{{ t.entryType }}</span><span>{{ t.actorType }}{{ t.actorId ? ' · ' + t.actorId : '' }}</span></p>
            <p class="mt-2 text-[14px] leading-relaxed">{{ t.summary }}</p>
          </li>
          <li v-if="!data.timeline.length" class="pb-9 pl-8 text-[13px] text-ink-3">暂无时间线记录。</li>
        </ol>
        <form v-if="can('event.investigate')" class="mt-2 flex items-end gap-6 pl-8" @submit.prevent="addNote">
          <label class="flex-1"><span class="label">追加研判</span><input v-model="note" class="field mt-2" maxlength="1000" placeholder="写下依据，而不是结论" /></label>
          <button type="submit" class="link text-[13px]" :disabled="busy || !note.trim()">添加</button>
        </form>

        <h2 class="mb-6 mt-20 text-[15px]">关联告警</h2>
        <table class="table">
          <thead><tr><th>时间</th><th>告警</th><th>来源</th><th>分数</th><th>状态</th></tr></thead>
          <tbody>
            <tr v-for="a in data.alerts" :key="a.id">
              <td class="num text-ink-3">{{ fmtTime(a.detectedAt) }}</td>
              <td class="num">{{ a.alertKey }}</td>
              <td>
                <span class="block text-ink-2">{{ alertTypeLabel[a.alertType] ?? a.alertType }} · {{ alertSource(a) }}</span>
                <span class="num text-[12px] text-ink-3">契约 {{ a.contractVersion ?? '—' }}{{ a.severityPolicyVersion ? ' · 分级 ' + a.severityPolicyVersion : '' }}</span>
              </td>
              <td class="num">{{ a.score == null ? '—' : Number(a.score).toFixed(3) }}</td>
              <td><Tag :tone="statusTone[a.status]" :label="a.status" /></td>
            </tr>
            <tr v-if="!data.alerts.length"><td colspan="5" class="py-8 text-center text-ink-3">无可见关联告警。</td></tr>
          </tbody>
        </table>
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
    </div>
    <div v-else-if="notFound" class="py-32 text-center">
      <p class="label">404</p>
      <p class="mt-4 text-ink-3">事件不存在，或不在你的授权范围内。</p>
      <RouterLink :to="{ name: 'events' }" class="link mt-8 text-[13px]">返回告警与事件</RouterLink>
    </div>
    </LoadState>
  </div>
</template>
