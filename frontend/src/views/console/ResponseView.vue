<script setup lang="ts">
/**
 * 受控响应：审批队列、审批台账、本人申请、策略版本管理（M6：起草/提交/撤回、他人批准/驳回/退役）。
 * 审批决定调用 POST /approvals/{id}/decision；申请人不能审批本人申请由后端强制，
 * 前端仅提前禁用按钮。真实执行器未开放，执行状态如实显示为“未开放”。
 * 「我的申请」中本人 pending 申请可撤回（POST /actions/{id}/withdraw，填理由）；与审批竞争时只有一方成功，
 * 失败显示后端原因并重新读取。已撤回的申请显示撤回原因与时间。
 */
import { computed, ref } from 'vue'
import { RouterLink } from 'vue-router'
import PageHead from '@/components/PageHead.vue'
import Segmented from '@/components/Segmented.vue'
import Tag from '@/components/Tag.vue'
import Drawer from '@/components/Drawer.vue'
import LoadState from '@/components/LoadState.vue'
import { api } from '@/api/client'
import { can, session } from '@/api/session'
import { approvalLabel, execLabel, fmtTime, policyStatusLabel, type LedgerView, type PolicyView } from '@/api/types'
import { approvalTone, execTone, statusTone } from '@/data/tones'
import { toast } from '@/composables/toast'
import { errText, optional, useLoad } from '@/composables/load'

const { data, loading, error, reload } = useLoad(async () => {
  const [ledger, mine, policies] = await Promise.all([
    can('approval.read') ? optional(api.get<LedgerView[]>('/api/v1/approvals/ledger'), []) : [],
    can('action.request') ? api.get<LedgerView[]>('/api/v1/actions/mine') : [],
    can('response.policy.read') ? api.get<PolicyView[]>('/api/v1/response-policies') : [],
  ])
  return { ledger, mine, policies }
}, { ledger: [] as LedgerView[], mine: [] as LedgerView[], policies: [] as PolicyView[] })

const tab = ref<'approvals' | 'ledger' | 'mine' | 'policies'>(can('approval.read') ? 'approvals' : 'mine')
const pending = computed(() => data.value.ledger.filter((a) => a.status === 'pending'))
const picked = ref<LedgerView | null>(null)
const reason = ref('')
const busy = ref(false)
const isMine = (a: LedgerView | null) => !!a && a.requester === session.user?.username

async function decide(ok: boolean) {
  const a = picked.value
  if (!a || !reason.value.trim()) return toast('请填写决定理由。', 'warn')
  busy.value = true
  try {
    await api.post(`/api/v1/approvals/${a.id}/decision`, { decision: ok ? 'approve' : 'reject', reason: reason.value.trim() })
    toast(ok ? '已批准；执行器未开放，不会触发真实阻断。' : '已驳回。')
    picked.value = null
    reason.value = ''
    await reload()
  } catch (e) { toast(errText(e), 'threat') } finally { busy.value = false }
}
// 撤回本人待审申请
const withdrawing = ref<LedgerView | null>(null)
const withdrawReason = ref('')
function openWithdraw(a: LedgerView) { withdrawing.value = a; withdrawReason.value = '' }
async function withdraw() {
  const a = withdrawing.value
  if (!a || !withdrawReason.value.trim()) return toast('请填写撤回理由。', 'warn')
  busy.value = true
  try {
    await api.post(`/api/v1/actions/${a.id}/withdraw`, { reason: withdrawReason.value.trim() })
    toast('申请已撤回，不会进入审批。')
    withdrawing.value = null
    await reload()
  } catch (e) {
    toast(errText(e), 'threat')
    await reload()
  } finally { busy.value = false }
}
const target = (a: LedgerView) => a.actionRequest.parameters?.targetAddress ?? '—'
const ttl = (a: LedgerView) => Math.round((a.actionRequest.parameters?.ttlSeconds ?? 0) / 60)
const tabs = computed(() => [
  ...(can('approval.read') ? [{ value: 'approvals' as const, label: '审批', count: pending.value.length }, { value: 'ledger' as const, label: '审批台账', count: data.value.ledger.length }] : []),
  ...(can('action.request') ? [{ value: 'mine' as const, label: '我的申请', count: data.value.mine.length }] : []),
  ...(can('response.policy.read') ? [{ value: 'policies' as const, label: '策略', count: data.value.policies.length }] : []),
])

// 策略版本管理（M6）：起草人提交/撤回本人版本，审批人批准/驳回他人版本并可退役 active 版本。
// 按钮可见性只是提示；职责分离、状态迁移与内容校验以后端为准。
const policy = ref<PolicyView | null>(null)
const policyReason = ref('')
const isAuthor = (p: PolicyView | null) => !!p && p.createdBy != null && p.createdBy === session.user?.id
const canReview = (p: PolicyView | null) => !!p && can('response.policy.approve') && p.status === 'pending' && p.createdBy != null && !isAuthor(p)
const canRetire = (p: PolicyView | null) => !!p && can('response.policy.approve') && p.status === 'active'
const canAuthorAct = (p: PolicyView | null) => !!p && can('response.policy.draft') && isAuthor(p) && ['draft', 'pending'].includes(p.status)
const canVersion = (p: PolicyView) => can('response.policy.draft') && ['active', 'rejected', 'retired'].includes(p.status)
  && !data.value.policies.some((o) => o.policyKey === p.policyKey && ['draft', 'pending'].includes(o.status))

async function policyAction(path: string, body: Record<string, unknown>, done: string, needReason = false) {
  const p = policy.value
  if (!p) return
  if (needReason && !policyReason.value.trim()) return toast('请填写理由。', 'warn')
  busy.value = true
  try {
    await api.post(`/api/v1/response-policies/${p.id}/${path}`, needReason ? { ...body, reason: policyReason.value.trim() } : body)
    toast(done)
    policy.value = null
    policyReason.value = ''
    await reload()
  } catch (e) { toast(errText(e), 'threat') } finally { busy.value = false }
}

// 起草表单：首期只有 temporary_block，自动执行恒为关闭（无经验证回滚证据时后端拒绝）。
const drafting = ref(false)
const baseId = ref<number | null>(null)
const form = ref({ policyKey: '', environment: 'lab', targets: '', maxTtlSeconds: 600, maxDurationSeconds: 600, reason: '' })
function openDraft(base: PolicyView | null) {
  baseId.value = base?.id ?? null
  form.value = base
    ? { policyKey: base.policyKey, environment: base.environment, targets: base.actionParams?.allowedTargets?.join(', ') ?? '',
        maxTtlSeconds: base.actionParams?.maxTtlSeconds ?? base.maxDurationSeconds, maxDurationSeconds: base.maxDurationSeconds, reason: '' }
    : { policyKey: '', environment: 'lab', targets: '', maxTtlSeconds: 600, maxDurationSeconds: 600, reason: '' }
  drafting.value = true
}
async function saveDraft() {
  const f = form.value
  if (!f.reason.trim()) return toast('请填写起草理由。', 'warn')
  const allowedTargets = f.targets.split(/[\s,]+/).filter(Boolean)
  const body = {
    ...(baseId.value ? {} : { policyKey: f.policyKey.trim() }),
    environment: f.environment.trim(), match: { environment: f.environment.trim() }, actionType: 'temporary_block',
    actionParams: { maxTtlSeconds: Number(f.maxTtlSeconds), allowedTargets },
    autoExecute: false, approvalRequired: true, maxDurationSeconds: Number(f.maxDurationSeconds), reason: f.reason.trim(),
  }
  busy.value = true
  try {
    await api.post(baseId.value ? `/api/v1/response-policies/${baseId.value}/versions` : '/api/v1/response-policies', body)
    toast('草稿已登记；提交后须由其他审批员批准才生效。')
    drafting.value = false
    await reload()
  } catch (e) { toast(errText(e), 'threat') } finally { busy.value = false }
}
</script>

<template>
  <div>
    <PageHead no="03" title="受控响应" desc="动作只能作用于登记且授权有效的资产，并须命中 active 策略白名单。审批只更新台账；真实防火墙执行器尚未开放。">
      <template #kicker>Response</template>
    </PageHead>

    <Segmented v-if="tabs.length" v-model="tab" :options="tabs" />
    <p v-else class="text-[13px] text-ink-3">当前身份没有响应相关权限。</p>

    <div class="mt-10"><LoadState :loading="loading" :error="error">
    <Transition v-if="tabs.length" name="fade" mode="out-in">
      <section v-if="tab === 'approvals'" key="a">
        <ul class="border-t border-ink">
          <li v-for="a in pending" :key="a.id" class="grid grid-cols-1 items-center gap-6 border-b border-ink-hair py-7 md:grid-cols-[1fr_auto]">
            <div>
              <p class="num text-[12px] text-ink-3">#{{ a.id }} · 来自 <RouterLink :to="{ name: 'event-detail', params: { id: a.eventId } }" class="link">{{ a.eventKey }}</RouterLink> · 申请人 {{ a.requester }}</p>
              <p class="mt-3 text-[1.25rem] font-light">阻断 <span class="num">{{ target(a) }}</span></p>
              <p class="num mt-2 text-[12.5px] text-ink-3">{{ a.assetKey }} · {{ a.actionRequest.actionType }} · TTL {{ ttl(a) }} min · {{ a.actionRequest.policyKey }} {{ a.actionRequest.policyVersion }}</p>
            </div>
            <div class="flex items-center gap-8">
              <span class="num text-[12px] text-ink-3">过期 {{ fmtTime(a.expiresAt) }}</span>
              <button class="act-ghost" @click="picked = a">审查</button>
            </div>
          </li>
          <li v-if="!pending.length" class="py-20 text-center text-ink-3">没有待审批的动作。</li>
        </ul>
      </section>

      <section v-else-if="tab === 'ledger' || tab === 'mine'" :key="tab">
        <table class="table">
          <thead><tr><th>申请</th><th>目标</th><th>策略</th><th>申请 / 审批人</th><th>审批</th><th>执行</th><th v-if="tab === 'mine'"></th></tr></thead>
          <tbody>
            <tr v-for="a in (tab === 'ledger' ? data.ledger : data.mine)" :key="a.id">
              <td><span class="num block">#{{ a.id }} · {{ a.eventKey }}</span><span class="text-[12px] text-ink-3">{{ fmtTime(a.createdAt) }}</span></td>
              <td><span class="num block">{{ target(a) }}</span><span class="text-[12px] text-ink-3">{{ a.assetKey }} · TTL {{ ttl(a) }}m</span></td>
              <td class="num text-ink-2">{{ a.actionRequest.policyKey }} {{ a.actionRequest.policyVersion }}</td>
              <td class="text-[12.5px] text-ink-2">{{ a.requester }}<br /><span class="text-ink-3">{{ a.reviewer ?? '—' }}</span></td>
              <td>
                <Tag :tone="approvalTone[a.status]" :label="a.withdrawnAt ? '已撤回' : approvalLabel[a.status] ?? a.status" />
                <span v-if="a.withdrawnAt" class="mt-1 block max-w-[16rem] text-[12px] text-ink-3">{{ fmtTime(a.withdrawnAt) }} · {{ a.withdrawReason ?? '—' }}</span>
              </td>
              <td><Tag :tone="a.executionStatus ? execTone[a.executionStatus] : 'mute'" :label="a.executionStatus ? execLabel[a.executionStatus] ?? a.executionStatus : '未开放'" /></td>
              <td v-if="tab === 'mine'" class="whitespace-nowrap text-right"><button v-if="a.status === 'pending' && isMine(a)" class="link text-[12.5px]" @click="openWithdraw(a)">撤回</button></td>
            </tr>
            <tr v-if="!(tab === 'ledger' ? data.ledger : data.mine).length"><td :colspan="tab === 'mine' ? 7 : 6" class="py-16 text-center text-ink-3">数据库中暂无记录。</td></tr>
          </tbody>
        </table>
        <p class="mt-6 text-[12.5px] text-ink-3">执行端点当前固定返回 <span class="num">503 ACTION_EXECUTION_UNAVAILABLE</span>，不调用适配器、不写执行记录。</p>
      </section>

      <section v-else key="p">
        <div v-if="can('response.policy.draft')" class="mb-6 flex justify-end"><button class="act-ghost" @click="openDraft(null)">新建策略</button></div>
        <table class="table">
          <thead><tr><th>策略</th><th>环境</th><th>动作</th><th>TTL 上限</th><th>允许目标</th><th>审批要求</th><th>状态</th><th></th></tr></thead>
          <tbody>
            <tr v-for="p in data.policies" :key="p.id">
              <td><span class="num block">{{ p.policyKey }}</span><span class="num text-[12px] text-ink-3">v{{ p.version }}{{ p.basedOnPolicyId ? ` · 基于 #${p.basedOnPolicyId}` : '' }}</span></td>
              <td class="text-ink-2">{{ p.environment }}</td>
              <td class="num text-ink-2">{{ p.actionType }}</td>
              <td class="num">{{ Math.floor(Math.min(p.actionParams?.maxTtlSeconds ?? p.maxDurationSeconds, p.maxDurationSeconds) / 60) }} min</td>
              <td class="num text-[12px] text-ink-2">{{ p.actionParams?.allowedTargets?.join(', ') ?? '—' }}</td>
              <td class="text-ink-2">{{ p.approvalRequired ? '人工审批' : '免审批' }}{{ p.autoExecute ? ' · 自动' : '' }}</td>
              <td><Tag :tone="statusTone[p.status]" :label="policyStatusLabel[p.status] ?? p.status" /></td>
              <td class="whitespace-nowrap text-right">
                <button class="link text-[12.5px]" @click="policy = p; policyReason = ''">详情</button>
                <button v-if="canVersion(p)" class="link ml-4 text-[12.5px]" @click="openDraft(p)">新版本</button>
              </td>
            </tr>
            <tr v-if="!data.policies.length"><td colspan="8" class="py-16 text-center text-ink-3">数据库中暂无响应策略。</td></tr>
          </tbody>
        </table>
        <p class="mt-6 text-[12.5px] leading-relaxed text-ink-3">策略版本不可原地修改：变更即新建版本，经起草人提交、其他审批员批准后生效，旧版本同时退役。自动执行在动作具备经验证的回滚证据前不可配置。主机限速仅在适配器实测支持后启用。</p>
      </section>
    </Transition>
    </LoadState></div>

    <Drawer :open="!!picked" :title="picked ? `阻断 ${target(picked)}` : ''" :kicker="picked ? `#${picked.id}` : ''" @close="picked = null">
      <template v-if="picked">
        <h3 class="label mb-4">影响摘要</h3>
        <dl class="border-t border-ink">
          <div v-for="[k, v] in [
            ['目标资产', picked.assetKey],
            ['动作', `${picked.actionRequest.actionType} · 仅追加规则`],
            ['范围', target(picked)],
            ['时限', `${ttl(picked)} 分钟后自动解除`],
            ['策略快照', `${picked.actionRequest.policyKey} ${picked.actionRequest.policyVersion}`],
            ['申请理由', picked.actionRequest.reason ?? '—'],
            ['申请人', picked.requester],
            ['过期', fmtTime(picked.expiresAt)],
          ]" :key="k" class="grid grid-cols-[7rem_1fr] border-b border-ink-hair py-3 text-[13px]">
            <dt class="text-ink-3">{{ k }}</dt><dd class="num">{{ v }}</dd>
          </div>
        </dl>
        <label class="mt-10 block"><span class="label">决定理由</span><textarea v-model="reason" rows="3" maxlength="1000" class="field mt-2 h-auto resize-none py-2" placeholder="记录到审批台账" /></label>
        <p v-if="isMine(picked)" class="mt-6 border-l-2 border-threat pl-4 text-[12.5px] leading-relaxed text-threat">你是该动作的申请人，不能审批本人申请。请由其他响应审批员处理。</p>
      </template>
      <template #foot>
        <button class="link text-[13px]" :disabled="busy || isMine(picked) || !can('approval.decide')" @click="decide(false)">拒绝</button>
        <button class="act" :disabled="busy || isMine(picked) || !can('approval.decide')" @click="decide(true)">批准</button>
      </template>
    </Drawer>

    <Drawer :open="!!policy" :title="policy ? `${policy.policyKey} v${policy.version}` : ''" :kicker="policy ? `策略 #${policy.id}` : ''" @close="policy = null">
      <template v-if="policy">
        <dl class="border-t border-ink">
          <div v-for="[k, v] in [
            ['状态', policyStatusLabel[policy.status] ?? policy.status],
            ['环境', policy.environment],
            ['动作', policy.actionType],
            ['允许目标', policy.actionParams?.allowedTargets?.join(', ') ?? '—'],
            ['TTL 上限', `${policy.actionParams?.maxTtlSeconds ?? '—'} 秒（策略上限 ${policy.maxDurationSeconds} 秒）`],
            ['审批要求', policy.approvalRequired ? '人工审批' : '免审批'],
            ['起草理由', policy.changeReason ?? '—'],
            ['审批理由', policy.decisionReason ?? '—'],
            ['内容哈希', policy.contentSha256 ? policy.contentSha256.slice(0, 16) + '…' : '—'],
            ['登记', fmtTime(policy.createdAt)],
          ]" :key="k" class="grid grid-cols-[7rem_1fr] border-b border-ink-hair py-3 text-[13px]">
            <dt class="text-ink-3">{{ k }}</dt><dd class="num break-all">{{ v }}</dd>
          </div>
        </dl>
        <label v-if="canReview(policy) || canRetire(policy)" class="mt-10 block"><span class="label">理由</span><textarea v-model="policyReason" rows="3" maxlength="1000" class="field mt-2 h-auto resize-none py-2" placeholder="记录到审计" /></label>
        <p v-if="policy.status === 'pending' && isAuthor(policy)" class="mt-6 border-l-2 border-threat pl-4 text-[12.5px] leading-relaxed text-threat">你是该版本的起草人，不能审批本人版本。</p>
      </template>
      <template #foot>
        <template v-if="canAuthorAct(policy)">
          <button class="link text-[13px]" :disabled="busy" @click="policyAction('withdraw', {}, '已撤回。')">撤回</button>
          <button v-if="policy?.status === 'draft'" class="act" :disabled="busy" @click="policyAction('submit', {}, '已提交审批。')">提交审批</button>
        </template>
        <template v-if="canReview(policy)">
          <button class="link text-[13px]" :disabled="busy" @click="policyAction('decision', { decision: 'reject' }, '已驳回。', true)">驳回</button>
          <button class="act" :disabled="busy" @click="policyAction('decision', { decision: 'approve' }, '已批准；该版本生效，旧版本已退役。', true)">批准生效</button>
        </template>
        <button v-if="canRetire(policy)" class="act-ghost" :disabled="busy" @click="policyAction('retire', {}, '已退役。', true)">退役</button>
      </template>
    </Drawer>

    <Drawer :open="!!withdrawing" :title="withdrawing ? `撤回申请 #${withdrawing.id}` : ''" :kicker="withdrawing?.eventKey ?? ''" @close="withdrawing = null">
      <template v-if="withdrawing">
        <p class="text-[13px] leading-relaxed text-ink-2">阻断 <span class="num">{{ target(withdrawing) }}</span> · {{ withdrawing.assetKey }} · TTL {{ ttl(withdrawing) }} min</p>
        <label class="mt-8 block"><span class="label">撤回理由</span><textarea v-model="withdrawReason" rows="3" maxlength="1000" class="field mt-2 h-auto resize-none py-2" placeholder="记录到审批台账" /></label>
        <p class="mt-6 text-[12.5px] leading-relaxed text-ink-3">仅待审批的本人申请可撤回；若审批人已先作出决定，撤回会失败并显示原因。</p>
      </template>
      <template #foot>
        <button class="link text-[13px]" @click="withdrawing = null">取消</button>
        <button class="act" :disabled="busy" @click="withdraw">确认撤回</button>
      </template>
    </Drawer>

    <Drawer :open="drafting" :title="baseId ? `${form.policyKey} 新版本` : '新建响应策略'" kicker="temporary_block" @close="drafting = false">
      <div class="space-y-6">
        <label v-if="!baseId" class="block"><span class="label">策略键</span><input v-model="form.policyKey" class="field mt-2" maxlength="64" placeholder="小写字母、数字、. _ -" /></label>
        <label class="block"><span class="label">环境</span><input v-model="form.environment" class="field mt-2" maxlength="32" /></label>
        <label class="block"><span class="label">允许目标（IPv4，逗号分隔）</span><input v-model="form.targets" class="field mt-2 num" placeholder="192.0.2.25" /></label>
        <label class="block"><span class="label">动作 TTL 上限（秒）</span><input v-model.number="form.maxTtlSeconds" type="number" min="1" max="3600" class="field mt-2 num" /></label>
        <label class="block"><span class="label">策略最大持续时间（秒，≤ 3600）</span><input v-model.number="form.maxDurationSeconds" type="number" min="1" max="3600" class="field mt-2 num" /></label>
        <label class="block"><span class="label">起草理由</span><textarea v-model="form.reason" rows="3" maxlength="1000" class="field mt-2 h-auto resize-none py-2" /></label>
        <p class="text-[12.5px] leading-relaxed text-ink-3">人工审批恒为开启，自动执行不可选。登记后为草稿，须提交并由其他审批员批准。</p>
      </div>
      <template #foot>
        <button class="link text-[13px]" @click="drafting = false">取消</button>
        <button class="act" :disabled="busy" @click="saveDraft">登记草稿</button>
      </template>
    </Drawer>
  </div>
</template>
