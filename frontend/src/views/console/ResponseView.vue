<script setup lang="ts">
/**
 * 受控响应：审批队列、执行台账、策略（只读）三段。
 * 当前用户是分析员，演示"申请人不能审批本人申请"；执行端点未开放时如实显示。
 */
import { computed, reactive, ref } from 'vue'
import { RouterLink } from 'vue-router'
import PageHead from '@/components/PageHead.vue'
import Segmented from '@/components/Segmented.vue'
import Tag from '@/components/Tag.vue'
import Drawer from '@/components/Drawer.vue'
import { actions as seed, approvalLabel, assetName, execLabel, policies, type ResponseAction } from '@/data/demo'
import { approvalTone, execTone } from '@/data/tones'
import { toast } from '@/composables/toast'

const me = 'analyst · 陈'
const list = reactive(structuredClone(seed))
const tab = ref<'approvals' | 'ledger' | 'policies'>('approvals')
const pending = computed(() => list.filter((a) => a.approval === 'pending'))
const picked = ref<ResponseAction | null>(null)
const reason = ref('')

function decide(ok: boolean) {
  const a = picked.value
  if (!a) return
  if (a.requester === me) return toast('申请人与审批人必须不同，已拒绝本次决定并记录审计。', 'threat')
  a.approval = ok ? 'approved' : 'rejected'
  a.approver = me
  picked.value = null
}
</script>

<template>
  <div>
    <PageHead no="03" title="受控响应" desc="动作只能作用于登记且授权有效的资产，并须命中 active 策略白名单。审批只更新台账；真实防火墙执行器尚未开放。">
      <template #kicker>Response</template>
    </PageHead>

    <Segmented v-model="tab" :options="[
      { value: 'approvals', label: '审批', count: pending.length },
      { value: 'ledger', label: '执行台账', count: list.length },
      { value: 'policies', label: '策略', count: policies.length },
    ]" />

    <Transition name="fade" mode="out-in">
      <!-- 审批：每条一行，打开抽屉查看影响摘要后决定 -->
      <section v-if="tab === 'approvals'" key="a" class="mt-10">
        <ul class="border-t border-ink">
          <li v-for="a in pending" :key="a.id" class="grid grid-cols-1 items-center gap-6 border-b border-ink-hair py-7 md:grid-cols-[1fr_auto]">
            <div>
              <p class="num text-[12px] text-ink-3">{{ a.id }} · 来自 <RouterLink :to="{ name: 'event-detail', params: { id: a.eventId } }" class="link">{{ a.eventId }}</RouterLink> · 申请人 {{ a.requester }}</p>
              <p class="mt-3 text-[1.25rem] font-light">阻断 <span class="num">{{ a.target }}</span></p>
              <p class="num mt-2 text-[12.5px] text-ink-3">{{ assetName(a.assetId) }} · {{ a.action }} · TTL {{ a.ttl }} min · {{ a.policy }}</p>
            </div>
            <div class="flex items-center gap-8">
              <span class="num text-[12px] text-ink-3">过期 {{ a.expiresAt }}</span>
              <button class="act-ghost" @click="picked = a">审查</button>
            </div>
          </li>
          <li v-if="!pending.length" class="py-20 text-center text-ink-3">没有待审批的动作。</li>
        </ul>
      </section>

      <section v-else-if="tab === 'ledger'" key="l" class="mt-10">
        <table class="table">
          <thead><tr><th>动作</th><th>目标</th><th>策略</th><th>申请 / 审批</th><th>审批</th><th>执行</th><th>幂等键</th></tr></thead>
          <tbody>
            <tr v-for="a in list" :key="a.id">
              <td><span class="num block">{{ a.id }}</span><span class="text-[12px] text-ink-3">{{ a.requestedAt }}</span></td>
              <td><span class="num block">{{ a.target }}</span><span class="text-[12px] text-ink-3">{{ assetName(a.assetId) }} · TTL {{ a.ttl }}m</span></td>
              <td class="num text-ink-2">{{ a.policy }}</td>
              <td class="text-[12.5px] text-ink-2">{{ a.requester }}<br /><span class="text-ink-3">{{ a.approver ?? '—' }}</span></td>
              <td><Tag :tone="approvalTone[a.approval]" :label="approvalLabel[a.approval]" /></td>
              <td><Tag :tone="a.approval === 'approved' ? execTone[a.execution] : 'mute'" :label="a.approval === 'approved' ? execLabel[a.execution] : '—'" /></td>
              <td class="num text-[12px] text-ink-3">{{ a.idempotencyKey }}</td>
            </tr>
          </tbody>
        </table>
        <p class="mt-6 text-[12.5px] text-ink-3">执行端点当前固定返回 <span class="num">503 ACTION_EXECUTION_UNAVAILABLE</span>，不调用适配器、不写执行记录。</p>
      </section>

      <section v-else key="p" class="mt-10">
        <table class="table">
          <thead><tr><th>策略</th><th>环境</th><th>动作白名单</th><th>TTL 上限</th><th>审批要求</th><th>状态</th></tr></thead>
          <tbody>
            <tr v-for="p in policies" :key="p.id">
              <td><span class="block">{{ p.name }}</span><span class="num text-[12px] text-ink-3">{{ p.id }}</span></td>
              <td class="text-ink-2">{{ p.env === 'range' ? '靶场' : '实网' }}</td>
              <td class="num text-ink-2">{{ p.actions.join(', ') }}</td>
              <td class="num">{{ p.maxTtl }} min</td>
              <td class="text-ink-2">{{ p.approval }}</td>
              <td><Tag :tone="p.status === 'active' ? 'ok' : 'mute'" :label="p.status === 'active' ? '生效' : '草稿'" /></td>
            </tr>
          </tbody>
        </table>
        <p class="mt-6 text-[12.5px] leading-relaxed text-ink-3">首期策略只读，不开放编辑。主机限速仅在适配器实测支持后启用，此前不会伪装为阻断或宣称已限速。</p>
      </section>
    </Transition>

    <Drawer :open="!!picked" :title="picked ? `阻断 ${picked.target}` : ''" :kicker="picked?.id" @close="picked = null">
      <template v-if="picked">
        <h3 class="label mb-4">影响摘要</h3>
        <dl class="border-t border-ink">
          <div v-for="[k, v] in [
            ['目标资产', `${assetName(picked.assetId)} · 实网 · 授权至 2026-12-31`],
            ['动作', `${picked.action} · 仅追加规则`],
            ['范围', picked.target],
            ['时限', `${picked.ttl} 分钟后自动解除`],
            ['策略快照', picked.policy],
            ['回滚', '删除该条临时规则 · 已验证'],
            ['保护目标', '管理会话、默认网关不受影响'],
            ['申请人', picked.requester],
          ]" :key="k" class="grid grid-cols-[7rem_1fr] border-b border-ink-hair py-3 text-[13px]">
            <dt class="text-ink-3">{{ k }}</dt><dd class="num">{{ v }}</dd>
          </div>
        </dl>
        <label class="mt-10 block"><span class="label">决定理由</span><textarea v-model="reason" rows="3" class="field mt-2 h-auto resize-none py-2" placeholder="记录到审批台账" /></label>
        <p v-if="picked.requester === me" class="mt-6 border-l-2 border-threat pl-4 text-[12.5px] leading-relaxed text-threat">你是该动作的申请人，不能审批本人申请。请由响应审批员处理。</p>
      </template>
      <template #foot>
        <button class="link text-[13px]" @click="decide(false)">拒绝</button>
        <button class="act" :disabled="picked?.requester === me" @click="decide(true)">批准</button>
      </template>
    </Drawer>
  </div>
</template>
