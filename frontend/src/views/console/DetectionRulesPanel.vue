<script setup lang="ts">
/**
 * 告警与事件页「规则」页签：确定性检测规则版本台账（GET /detection-rules）。
 *
 * - 登记：POST /detection-rules，新版本为 pending；条件结构与特征契约由后端校验（400 显示原因码）。
 * - 审批：POST /detection-rules/{id}/decision，登记人本人不显示按钮（后端同样拒绝 403）。
 *   批准后同一规则键的原 active 版本同事务退役；驳回在库中记为 retired 且无批准人。
 * - 详情：打开抽屉时读 GET /detection-rules/{id}，以单条详情为准（列表行只作初值）。
 * - 基于此版本起草：POST /detection-rules/{id}/versions，只填版本与理由；severity / condition / scope 勾选覆盖才提交，
 *   省略则由后端复制来源版本。新版本为 pending，仍须他人批准。
 * - 退役：POST /detection-rules/{id}/retire，仅 active 版本，需 detection.rule.approve。
 * 规则只产生告警，不触发处置。
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
/** 打开详情：先用列表行展示，再以单条详情接口覆盖；读取失败保留列表数据并提示。 */
let detailSeq = 0
async function open(r: DetectionRuleView) {
  picked.value = r
  const mine = ++detailSeq
  try {
    const fresh = await api.get<DetectionRuleView>(`/detection-rules/${r.id}`)
    if (mine === detailSeq && picked.value?.id === r.id) picked.value = fresh
  } catch (e) {
    if (mine === detailSeq) toast(errText(e), 'threat')
  }
}
const canRetire = computed(() => !!picked.value && picked.value.status === 'active' && can('detection.rule.approve'))
const canVersion = computed(() => !!picked.value && can('detection.rule.manage'))
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

async function retire() {
  if (!picked.value || !reason.value.trim()) return toast('请填写退役理由。', 'warn')
  busy.value = true
  try {
    await api.post(`/detection-rules/${picked.value.id}/retire`, { reason: reason.value.trim() })
    toast('规则已退役，不再产生告警。')
    picked.value = null
    await reload()
  } catch (e) { toast(errText(e), 'threat') } finally { busy.value = false }
}

// ---- 基于已有版本起草 ----
const versioning = ref<DetectionRuleView | null>(null)
const vform = ref({ version: '', reason: '', overSeverity: false, severity: 'medium' as Severity, overCondition: false, condition: '', overScope: false, contract: '' })
function openVersion() {
  const b = picked.value
  if (!b) return
  vform.value = {
    version: '', reason: '', overSeverity: false, severity: b.severity, overCondition: false,
    condition: JSON.stringify(parse(b.conditionJson), null, 2), overScope: false, contract: String(parse(b.scopeJson).featureContractVersion ?? ''),
  }
  versioning.value = b
  picked.value = null
}
async function createVersion() {
  const b = versioning.value
  const f = vform.value
  if (!b) return
  if (!f.version.trim()) return toast('请填写新版本号。', 'warn')
  if (!f.reason.trim()) return toast('请填写起草理由。', 'warn')
  const body: Record<string, unknown> = { version: f.version.trim(), reason: f.reason.trim() }
  if (f.overSeverity) body.severity = f.severity
  if (f.overCondition) {
    let condition: unknown
    try { condition = JSON.parse(f.condition) } catch { condition = null }
    if (!condition || typeof condition !== 'object' || Array.isArray(condition)) return toast('条件须为 JSON 对象。', 'warn')
    body.condition = condition
  }
  if (f.overScope) body.scope = f.contract.trim() ? { featureContractVersion: f.contract.trim() } : {}
  busy.value = true
  try {
    await api.post(`/detection-rules/${b.id}/versions`, body)
    toast('新版本已登记为待审批，须由其他审批人启用。')
    versioning.value = null
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
          <tr v-for="(r, i) in versions" :key="r.id" class="row-link" tabindex="0" @click="open(r)" @keydown.enter="open(r)">
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
      <p class="mt-6 text-[12.5px] leading-relaxed text-ink-3">每个规则键同时只有一个生效版本；批准新版本时原生效版本自动退役，驳回的版本同样记为已退役且无批准人。退役生效版本后该规则键不再产生告警，不会自动回退旧版本。规则只产生告警，不触发处置。</p>
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
        <template v-if="canDecide || canRetire">
          <label class="mt-10 block"><span class="label">{{ canRetire ? '退役理由' : '审批理由' }}</span><textarea v-model="reason" rows="3" maxlength="1000" class="field mt-2 h-auto resize-none py-2" placeholder="写入审计" /></label>
        </template>
        <p v-else-if="picked.status === 'pending' && picked.requestedBy === session.user?.id" class="mt-10 text-[12.5px] text-ink-3">本人登记的规则须由其他审批人决定。</p>
      </template>
      <template v-if="canDecide || canRetire || canVersion" #foot>
        <button v-if="canVersion" class="link text-[13px]" :disabled="busy" @click="openVersion">基于此版本起草</button>
        <template v-if="canDecide">
          <button class="link text-[13px]" :disabled="busy" @click="decide('reject')">驳回</button>
          <button class="act" :disabled="busy" @click="decide('approve')">批准启用</button>
        </template>
        <button v-if="canRetire" class="act-ghost" :disabled="busy" @click="retire">退役</button>
      </template>
    </Drawer>

    <Drawer :open="!!versioning" :title="versioning ? `${versioning.ruleKey} 新版本` : ''" :kicker="versioning ? `基于 v${versioning.version} · #${versioning.id}` : ''" @close="versioning = null">
      <div class="space-y-6">
        <label class="block"><span class="label">新版本号</span><input v-model="vform.version" class="field num mt-2" maxlength="32" /></label>
        <div>
          <label class="flex items-center gap-2 text-[13px]"><input v-model="vform.overSeverity" type="checkbox" class="h-3.5 w-3.5 accent-ink" /> 覆盖严重度</label>
          <select v-if="vform.overSeverity" v-model="vform.severity" class="field mt-2" aria-label="严重度"><option v-for="s in SEVERITIES" :key="s" :value="s">{{ severityLabel[s] }}</option></select>
        </div>
        <div>
          <label class="flex items-center gap-2 text-[13px]"><input v-model="vform.overScope" type="checkbox" class="h-3.5 w-3.5 accent-ink" /> 覆盖特征契约范围</label>
          <input v-if="vform.overScope" v-model="vform.contract" class="field num mt-2" maxlength="64" aria-label="特征契约（可空）" />
        </div>
        <div>
          <label class="flex items-center gap-2 text-[13px]"><input v-model="vform.overCondition" type="checkbox" class="h-3.5 w-3.5 accent-ink" /> 覆盖条件</label>
          <textarea v-if="vform.overCondition" v-model="vform.condition" rows="12" spellcheck="false" aria-label="条件 JSON" class="field num mt-2 h-auto resize-y py-2 text-[12px]" />
        </div>
        <label class="block"><span class="label">起草理由</span><textarea v-model="vform.reason" rows="3" maxlength="1000" class="field mt-2 h-auto resize-none py-2" placeholder="变更依据与离线检出" /></label>
        <p class="text-[12px] leading-relaxed text-ink-3">未勾选的字段由后端从来源版本复制；规则键不可更改。新版本为待审批，须由其他审批人启用，原版本内容不变。</p>
      </div>
      <template #foot>
        <button class="link text-[13px]" @click="versioning = null">取消</button>
        <button class="act" :disabled="busy" @click="createVersion">登记新版本</button>
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
