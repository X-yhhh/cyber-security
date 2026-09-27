<script setup lang="ts">
/**
 * 受控响应：审批队列、审批台账、本人申请、策略（只读）。
 * 审批决定调用 POST /approvals/{id}/decision；申请人不能审批本人申请由后端强制，
 * 前端仅提前禁用按钮。真实执行器未开放，执行状态如实显示为“未开放”。
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
import { approvalLabel, execLabel, fmtTime, type LedgerView, type PolicyView } from '@/api/types'
import { approvalTone, execTone, statusTone } from '@/data/tones'
import { toast } from '@/composables/toast'
import { errText, optional, useLoad } from '@/composables/load'

const { data, loading, error, reload } = useLoad(async () => {
  const [ledger, mine, policies] = await Promise.all([
    can('approval.read') ? optional(api.get<LedgerView[]>('/approvals/ledger'), []) : [],
    can('action.request') ? api.get<LedgerView[]>('/actions/mine') : [],
    can('response.policy.read') ? api.get<PolicyView[]>('/response-policies') : [],
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
    await api.post(`/approvals/${a.id}/decision`, { decision: ok ? 'approve' : 'reject', reason: reason.value.trim() })
    toast(ok ? '已批准；执行器未开放，不会触发真实阻断。' : '已驳回。')
    picked.value = null
    reason.value = ''
    await reload()
  } catch (e) { toast(errText(e), 'threat') } finally { busy.value = false }
}
const target = (a: LedgerView) => a.actionRequest.parameters?.targetAddress ?? '—'
const ttl = (a: LedgerView) => Math.round((a.actionRequest.parameters?.ttlSeconds ?? 0) / 60)
const tabs = computed(() => [
  ...(can('approval.read') ? [{ value: 'approvals' as const, label: '审批', count: pending.value.length }, { value: 'ledger' as const, label: '审批台账', count: data.value.ledger.length }] : []),
  ...(can('action.request') ? [{ value: 'mine' as const, label: '我的申请', count: data.value.mine.length }] : []),
  ...(can('response.policy.read') ? [{ value: 'policies' as const, label: '策略', count: data.value.policies.length }] : []),
])
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
          <thead><tr><th>申请</th><th>目标</th><th>策略</th><th>申请 / 审批人</th><th>审批</th><th>执行</th></tr></thead>
          <tbody>
            <tr v-for="a in (tab === 'ledger' ? data.ledger : data.mine)" :key="a.id">
              <td><span class="num block">#{{ a.id }} · {{ a.eventKey }}</span><span class="text-[12px] text-ink-3">{{ fmtTime(a.createdAt) }}</span></td>
              <td><span class="num block">{{ target(a) }}</span><span class="text-[12px] text-ink-3">{{ a.assetKey }} · TTL {{ ttl(a) }}m</span></td>
              <td class="num text-ink-2">{{ a.actionRequest.policyKey }} {{ a.actionRequest.policyVersion }}</td>
              <td class="text-[12.5px] text-ink-2">{{ a.requester }}<br /><span class="text-ink-3">{{ a.reviewer ?? '—' }}</span></td>
              <td><Tag :tone="approvalTone[a.status]" :label="approvalLabel[a.status] ?? a.status" /></td>
              <td><Tag :tone="a.executionStatus ? execTone[a.executionStatus] : 'mute'" :label="a.executionStatus ? execLabel[a.executionStatus] ?? a.executionStatus : '未开放'" /></td>
            </tr>
            <tr v-if="!(tab === 'ledger' ? data.ledger : data.mine).length"><td colspan="6" class="py-16 text-center text-ink-3">数据库中暂无记录。</td></tr>
          </tbody>
        </table>
        <p class="mt-6 text-[12.5px] text-ink-3">执行端点当前固定返回 <span class="num">503 ACTION_EXECUTION_UNAVAILABLE</span>，不调用适配器、不写执行记录。</p>
      </section>

      <section v-else key="p">
        <table class="table">
          <thead><tr><th>策略</th><th>环境</th><th>动作</th><th>TTL 上限</th><th>允许目标</th><th>审批要求</th><th>状态</th></tr></thead>
          <tbody>
            <tr v-for="p in data.policies" :key="p.id">
              <td><span class="num block">{{ p.policyKey }}</span><span class="num text-[12px] text-ink-3">{{ p.version }}</span></td>
              <td class="text-ink-2">{{ p.environment }}</td>
              <td class="num text-ink-2">{{ p.actionType }}</td>
              <td class="num">{{ Math.floor(Math.min(p.actionParams?.maxTtlSeconds ?? p.maxDurationSeconds, p.maxDurationSeconds) / 60) }} min</td>
              <td class="num text-[12px] text-ink-2">{{ p.actionParams?.allowedTargets?.join(', ') ?? '—' }}</td>
              <td class="text-ink-2">{{ p.approvalRequired ? '人工审批' : '免审批' }}{{ p.autoExecute ? ' · 自动' : '' }}</td>
              <td><Tag :tone="statusTone[p.status]" :label="p.status" /></td>
            </tr>
            <tr v-if="!data.policies.length"><td colspan="7" class="py-16 text-center text-ink-3">数据库中暂无响应策略。</td></tr>
          </tbody>
        </table>
        <p class="mt-6 text-[12.5px] leading-relaxed text-ink-3">首期策略只读，不开放编辑。主机限速仅在适配器实测支持后启用，此前不会伪装为阻断或宣称已限速。</p>
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
  </div>
</template>
