<script setup lang="ts">
/**
 * 告警与事件页「规则」页签：确定性检测规则版本台账（GET /detection-rules）。
 *
 * - 登记：POST /detection-rules，新版本为 pending；条件结构与特征契约由后端校验（400 显示原因码）。
 * - 审批：POST /detection-rules/{id}/decision，登记人本人不显示按钮（后端同样拒绝 403）。
 *   批准后同一规则键的原 active 版本同事务退役；驳回在库中记为 retired 且无批准人。
 * 规则只产生告警，不触发处置。详情、基于旧版本起草与退役属于阶段 2，本页不提供。
 */
import { computed, ref, watch } from 'vue'
import Tag from '@/components/Tag.vue'
import Drawer from '@/components/Drawer.vue'
import LoadState from '@/components/LoadState.vue'
import { api } from '@/api/client'
import { can, session } from '@/api/session'
import { fmtTime, lifecycleStatusLabel, severityLabel, type DetectionRuleView, type Severity } from '@/api/types'
import { severityTone, statusTone } from '@/data/tones'
import { toast } from '@/composables/toast'
import { errText, useLoad } from '@/composables/load'

const V4 = 'unsw-nb15-flow-v4'
const SEVERITIES: Severity[] = ['low', 'medium', 'high', 'critical']
const CONDITION_TEMPLATE = JSON.stringify({
  all: [{ field: 'features.proto', op: 'eq', value: 'tcp' }],
  window: { seconds: 60, aggregate: 'count', threshold: 30, groupBy: 'asset' },
}, null, 2)

const { data: rules, loading, error, reload } = useLoad(() => api.get<DetectionRuleView[]>('/detection-rules'), [] as DetectionRuleView[])

interface Clause { field: string; op: string; value: unknown }
interface Window { seconds: number; aggregate: string; field?: string; threshold: number }
function parse(text: string): Record<string, unknown> {
  try {
    const v: unknown = JSON.parse(text)
    return v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : {}
  } catch { return {} }
}
const clausesOf = (r: DetectionRuleView) => (Array.isArray(parse(r.conditionJson).all) ? parse(r.conditionJson).all : []) as Clause[]
const windowOf = (r: DetectionRuleView) => (parse(r.conditionJson).window ?? null) as Window | null
const OP: Record<string, string> = { eq: '=', ne: '≠', gt: '>', gte: '≥', lt: '<', lte: '≤' }
function summary(r: DetectionRuleView) {
  const w = windowOf(r)
  const n = clausesOf(r).length
  if (!w) return `逐条 · ${n} 项条件`
  return `${w.seconds} 秒 ${w.aggregate === 'sum' ? `Σ ${w.field ?? '?'}` : '计数'} ≥ ${w.threshold} · ${n} 项过滤`
}

/** 按规则键分组，组内保持后端顺序（id 降序，最新版本在前）。 */
const groups = computed(() => {
  const m = new Map<string, DetectionRuleView[]>()
  for (const r of rules.value) m.set(r.ruleKey, [...(m.get(r.ruleKey) ?? []), r])
  return [...m.entries()]
})

const busy = ref(false)
const picked = ref<DetectionRuleView | null>(null)
const reason = ref('')
watch(picked, () => { reason.value = '' }, { flush: 'sync' })
const canDecide = computed(() => !!picked.value && picked.value.status === 'pending' && can('detection.rule.approve')
  && picked.value.requestedBy !== session.user?.id)
const pickedScope = computed(() => picked.value ? parse(picked.value.scopeJson) : {})

async function decide(decision: 'approve' | 'reject') {
  if (!picked.value || !reason.value.trim()) return toast('请填写审批理由。', 'warn')
  busy.value = true
  try {
    await api.post(`/detection-rules/${picked.value.id}/decision`, { decision, reason: reason.value.trim() })
    toast(decision === 'approve' ? '规则已启用，同键原生效版本已退役。' : '规则已驳回。')
    picked.value = null
    await reload()
  } catch (e) { toast(errText(e), 'threat') } finally { busy.value = false }
}

// ---- 登记新版本 ----
const creating = ref(false)
const blank = () => ({ ruleKey: '', version: '1', severity: 'medium' as Severity, contract: V4, condition: CONDITION_TEMPLATE, reason: '' })
const form = ref(blank())
async function create() {
  const f = form.value
  let condition: unknown
  try { condition = JSON.parse(f.condition) } catch { condition = null }
  if (!condition || typeof condition !== 'object' || Array.isArray(condition)) return toast('条件须为 JSON 对象。', 'warn')
  if (!f.reason.trim()) return toast('请填写登记理由。', 'warn')
  busy.value = true
  try {
    await api.post('/detection-rules', {
      ruleKey: f.ruleKey.trim(), version: f.version.trim(), severity: f.severity, condition,
      scope: f.contract.trim() ? { featureContractVersion: f.contract.trim() } : {}, reason: f.reason.trim(),
    })
    toast('规则已登记为待审批，须由其他审批人启用。')
    creating.value = false
    form.value = blank()
    await reload()
  } catch (e) { toast(errText(e), 'threat') } finally { busy.value = false }
}
</script>

<template>
  <section>
    <div v-if="can('detection.rule.manage')" class="mb-6 flex justify-end"><button class="act-ghost" @click="creating = true">登记规则版本</button></div>
    <LoadState :loading="loading" :error="error">
      <table class="table">
        <thead><tr><th>规则</th><th>条件</th><th>严重度</th><th>状态</th><th>登记 / 批准</th><th class="text-right">更新</th></tr></thead>
        <tbody v-for="[key, versions] in groups" :key="key">
          <tr v-for="(r, i) in versions" :key="r.id" class="row-link" tabindex="0" @click="picked = r" @keydown.enter="picked = r">
            <td><span class="num block" :class="i ? 'text-ink-3' : ''">{{ i ? '' : key }}</span><span class="num text-[12px] text-ink-3">v{{ r.version }} · #{{ r.id }}</span></td>
            <td class="num text-[12.5px] text-ink-2">{{ summary(r) }}</td>
            <td><Tag :tone="severityTone[r.severity]" :label="severityLabel[r.severity] ?? r.severity" /></td>
            <td><Tag :tone="statusTone[r.status]" :label="lifecycleStatusLabel[r.status] ?? r.status" /></td>
            <td class="num text-ink-2">{{ r.requestedBy == null ? '—' : `#${r.requestedBy}` }} / {{ r.approvedBy == null ? '—' : `#${r.approvedBy}` }}</td>
            <td class="num text-right text-ink-3">{{ fmtTime(r.updatedAt) }}</td>
          </tr>
        </tbody>
        <tbody v-if="!rules.length"><tr><td colspan="6" class="py-16 text-center text-ink-3">数据库中暂无检测规则。</td></tr></tbody>
      </table>
      <p class="mt-6 text-[12.5px] leading-relaxed text-ink-3">每个规则键同时只有一个生效版本；批准新版本时原生效版本自动退役，驳回的版本同样记为已退役且无批准人。规则只产生告警，不触发处置。</p>
    </LoadState>

    <Drawer :open="!!picked" :title="picked ? `${picked.ruleKey} v${picked.version}` : ''" :kicker="picked ? `RULE #${picked.id}` : ''" @close="picked = null">
      <template v-if="picked">
        <dl class="border-t border-ink">
          <div v-for="[k, v] in [
            ['状态', lifecycleStatusLabel[picked.status] ?? picked.status],
            ['严重度', severityLabel[picked.severity] ?? picked.severity],
            ['特征契约', String(pickedScope.featureContractVersion ?? '—')],
            ['登记人', picked.requestedBy == null ? '—' : `#${picked.requestedBy}`],
            ['批准人', picked.approvedBy == null ? '—' : `#${picked.approvedBy}`],
            ['登记', fmtTime(picked.createdAt)],
            ['更新', fmtTime(picked.updatedAt)],
          ]" :key="k" class="grid grid-cols-[6rem_1fr] border-b border-ink-hair py-3 text-[13px]">
            <dt class="text-ink-3">{{ k }}</dt><dd class="num break-all">{{ v }}</dd>
          </div>
        </dl>
        <h3 class="label mb-3 mt-10">{{ windowOf(picked) ? '逐条过滤（全部满足）' : '条件（全部满足）' }}</h3>
        <p v-for="(c, i) in clausesOf(picked)" :key="i" class="num border-b border-ink-hair py-2 text-[12.5px] text-ink-2">{{ c.field }} {{ OP[c.op] ?? c.op }} {{ JSON.stringify(c.value) }}</p>
        <template v-if="windowOf(picked)">
          <h3 class="label mb-3 mt-10">时间窗聚合</h3>
          <dl class="border-t border-ink">
            <div v-for="[k, v] in [
              ['窗口', `${windowOf(picked)!.seconds} 秒（同时为抑制期）`],
              ['聚合', windowOf(picked)!.aggregate === 'sum' ? `求和 ${windowOf(picked)!.field}` : '计数'],
              ['阈值', `≥ ${windowOf(picked)!.threshold}`],
              ['分组', '按资产'],
            ]" :key="k" class="grid grid-cols-[6rem_1fr] border-b border-ink-hair py-3 text-[13px]">
              <dt class="text-ink-3">{{ k }}</dt><dd class="num">{{ v }}</dd>
            </div>
          </dl>
        </template>
        <template v-if="canDecide">
          <label class="mt-10 block"><span class="label">审批理由</span><textarea v-model="reason" rows="3" maxlength="1000" class="field mt-2 h-auto resize-none py-2" placeholder="写入审计" /></label>
        </template>
        <p v-else-if="picked.status === 'pending' && picked.requestedBy === session.user?.id" class="mt-10 text-[12.5px] text-ink-3">本人登记的规则须由其他审批人决定。</p>
      </template>
      <template v-if="canDecide" #foot>
        <button class="link text-[13px]" :disabled="busy" @click="decide('reject')">驳回</button>
        <button class="act" :disabled="busy" @click="decide('approve')">批准启用</button>
      </template>
    </Drawer>

    <Drawer :open="creating" title="登记规则版本" kicker="DETECTION RULE" @close="creating = false">
      <div class="space-y-6">
        <div class="grid grid-cols-[1fr_6rem] gap-4">
          <label class="block"><span class="label">规则键</span><input v-model="form.ruleKey" class="field num mt-2" maxlength="64" placeholder="小写字母、数字、. _ -" /></label>
          <label class="block"><span class="label">版本</span><input v-model="form.version" class="field num mt-2" maxlength="32" /></label>
        </div>
        <div class="grid grid-cols-2 gap-4">
          <label class="block"><span class="label">严重度</span><select v-model="form.severity" class="field mt-2"><option v-for="s in SEVERITIES" :key="s" :value="s">{{ severityLabel[s] }}</option></select></label>
          <label class="block"><span class="label">特征契约（可空）</span><input v-model="form.contract" class="field num mt-2" maxlength="64" /></label>
        </div>
        <label class="block"><span class="label">条件 JSON</span><textarea v-model="form.condition" rows="12" spellcheck="false" class="field num mt-2 h-auto resize-y py-2 text-[12px]" /></label>
        <label class="block"><span class="label">登记理由</span><textarea v-model="form.reason" rows="3" maxlength="1000" class="field mt-2 h-auto resize-none py-2" placeholder="阈值依据、离线检出与能力局限" /></label>
        <p class="text-[12px] leading-relaxed text-ink-3">条件只能读取 features.* 与 metadata.* 字段，最多 16 项，运算限 eq/ne/gt/gte/lt/lte。可选 window 块：seconds 10～3600，aggregate 为 count 或 sum（sum 须指定 features.* 字段），threshold &gt; 0，只按资产分组。</p>
      </div>
      <template #foot>
        <button class="link text-[13px]" @click="creating = false">取消</button>
        <button class="act" :disabled="busy || !form.ruleKey.trim() || !form.version.trim()" @click="create">登记</button>
      </template>
    </Drawer>
  </section>
</template>
