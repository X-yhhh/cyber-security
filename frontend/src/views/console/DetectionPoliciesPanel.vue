<script setup lang="ts">
/**
 * 告警与事件页「检测策略」页签：分级映射 / 事件关联 / 风险评分的版本台账（GET /detection-policies）。
 *
 * - 起草：POST /detection-policies（新建）或 /{id}/versions（基于旧版本复制，类型沿用来源）；新版本为 draft。
 * - 起草人：提交（draft → pending）、撤回（draft/pending → retired，填理由）。
 * - 审批人：批准/驳回他人待审版本；退役 active 版本（不自动回退旧版，缺活动策略时检测失败）。
 * 版本号由后端分配；按钮可见性只是提示，职责分离、状态冲突与内容哈希校验以后端为准（403/409 显示原因）。
 */
import { computed, ref } from 'vue'
import Tag from '@/components/Tag.vue'
import Drawer from '@/components/Drawer.vue'
import LoadState from '@/components/LoadState.vue'
import { api } from '@/api/client'
import { can, session } from '@/api/session'
import { detectionPolicyTypeLabel, fmtTime, lifecycleStatusLabel, type DetectionPolicyType, type DetectionPolicyView } from '@/api/types'
import { statusTone } from '@/data/tones'
import { toast } from '@/composables/toast'
import { errText, useLoad } from '@/composables/load'

const TYPES: DetectionPolicyType[] = ['severity_mapping', 'correlation', 'risk_score']
/** 新建时的参数模板，与 V13 预置版本一致；分级映射须显式给出 modelSignal 分层开关。 */
const TEMPLATES: Record<DetectionPolicyType, Record<string, unknown>> = {
  severity_mapping: {
    model: [{ minScore: 0.9, severity: 'critical' }, { minScore: 0.7, severity: 'high' }, { minScore: 0, severity: 'medium' }],
    modelSignal: { enabled: false, countThreshold: 3, highScore: 0.99 },
  },
  correlation: { windowSeconds: 900, dimensions: ['asset'] },
  risk_score: {
    severityWeight: { low: 0.25, medium: 0.5, high: 0.75, critical: 1 },
    criticalityWeight: { low: 0.5, medium: 0.75, high: 0.9, critical: 1 }, repeatStep: 0.05, repeatCap: 0.2,
  },
}

const { data: policies, loading, error, reload } = useLoad(() => api.get<DetectionPolicyView[]>('/detection-policies'), [] as DetectionPolicyView[])

function parse(text: string | null): Record<string, unknown> {
  if (!text) return {}
  try {
    const v: unknown = JSON.parse(text)
    return v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : {}
  } catch { return {} }
}
const show = (v: unknown) => (typeof v === 'object' && v !== null ? JSON.stringify(v) : String(v))

/** 按类型分组，组内保持后端顺序；未知类型归入末尾，不丢弃。 */
const groups = computed(() => {
  const keys = [...TYPES, ...new Set(policies.value.map((p) => p.policyType).filter((t) => !TYPES.includes(t as DetectionPolicyType)))]
  return keys.map((t) => [t, policies.value.filter((p) => p.policyType === t)] as const).filter(([, l]) => l.length)
})
const hasOpen = (type: string) => policies.value.some((p) => p.policyType === type && ['draft', 'pending'].includes(p.status))

const busy = ref(false)
const picked = ref<DetectionPolicyView | null>(null)
const reason = ref('')
const pickedConfig = computed(() => Object.entries(parse(picked.value?.configJson ?? null)))
const isAuthor = (p: DetectionPolicyView | null) => !!p && p.createdBy != null && p.createdBy === session.user?.id
const canSubmit = computed(() => can('detection.policy.manage') && isAuthor(picked.value) && picked.value?.status === 'draft')
const canWithdraw = computed(() => can('detection.policy.manage') && isAuthor(picked.value) && ['draft', 'pending'].includes(picked.value?.status ?? ''))
const canDecide = computed(() => can('detection.policy.approve') && picked.value?.status === 'pending' && picked.value.createdBy != null && !isAuthor(picked.value))
const canRetire = computed(() => can('detection.policy.approve') && picked.value?.status === 'active')
const needsReason = computed(() => canWithdraw.value || canDecide.value || canRetire.value)
const canCopy = (p: DetectionPolicyView) => can('detection.policy.manage') && !hasOpen(p.policyType)

function open(p: DetectionPolicyView) { picked.value = p; reason.value = '' }

async function act(path: string, body: Record<string, unknown> | null, done: string) {
  const p = picked.value
  if (!p) return
  if (body && !reason.value.trim()) return toast('请填写理由。', 'warn')
  busy.value = true
  try {
    await api.post(`/detection-policies/${p.id}/${path}`, body ? { ...body, reason: reason.value.trim() } : undefined)
    toast(done)
    picked.value = null
    await reload()
  } catch (e) { toast(errText(e), 'threat') } finally { busy.value = false }
}
const submit = () => act('submit', null, '已提交审批，须由其他审批人决定。')
const withdraw = () => act('withdraw', {}, '已撤回，该版本记为已退役。')
const decide = (decision: 'approve' | 'reject') => act('decision', { decision }, decision === 'approve' ? '已批准；该类型原生效版本已退役。' : '已驳回。')
const retire = () => act('retire', {}, '已退役；该类型暂无生效版本时检测会失败，请尽快启用新版本。')

// ---- 起草（新建或基于旧版本复制）----
const drafting = ref(false)
const base = ref<DetectionPolicyView | null>(null)
const form = ref({ policyType: 'severity_mapping' as DetectionPolicyType, config: '', reason: '' })
function openDraft(from: DetectionPolicyView | null) {
  base.value = from
  const type = (from?.policyType ?? TYPES.find((t) => !hasOpen(t)) ?? 'severity_mapping') as DetectionPolicyType
  const config = from ? parse(from.configJson) : TEMPLATES[type]
  // 旧版分级映射可能没有 modelSignal；新版本必须显式给出，复制时补入关闭状态的默认值
  if (type === 'severity_mapping' && !('modelSignal' in config)) config.modelSignal = TEMPLATES.severity_mapping.modelSignal
  form.value = { policyType: type, config: JSON.stringify(config, null, 2), reason: '' }
  picked.value = null
  drafting.value = true
}
function changeType(t: DetectionPolicyType) {
  form.value.policyType = t
  form.value.config = JSON.stringify(TEMPLATES[t], null, 2)
}

/** modelSignal 前端预检：恰含 enabled/countThreshold/highScore；计数为 2～10000 整数，高分在 (0,1]。返回错误文案或空串。 */
function checkModelSignal(config: Record<string, unknown>): string {
  const s = config.modelSignal
  if (!s || typeof s !== 'object' || Array.isArray(s)) return '分级映射须包含 modelSignal 对象。'
  const o = s as Record<string, unknown>
  if (Object.keys(o).sort().join() !== 'countThreshold,enabled,highScore') return 'modelSignal 只能且必须包含 enabled、countThreshold、highScore。'
  if (typeof o.enabled !== 'boolean') return 'modelSignal.enabled 须为布尔值。'
  if (!Number.isInteger(o.countThreshold) || (o.countThreshold as number) < 2 || (o.countThreshold as number) > 10000) return '信号提升计数须为 2～10000 的整数。'
  if (typeof o.highScore !== 'number' || !(o.highScore > 0 && o.highScore <= 1)) return '高分阈值须在 (0, 1] 区间。'
  return ''
}

/** 分级映射的 modelSignal 以表单编辑，写回 JSON 文本，避免手改 JSON 时漏字段。 */
const signal = computed(() => {
  if (form.value.policyType !== 'severity_mapping') return null
  const s = parse(form.value.config).modelSignal
  return s && typeof s === 'object' && !Array.isArray(s) ? s as Record<string, unknown> : null
})
function setSignal(key: 'enabled' | 'countThreshold' | 'highScore', value: unknown) {
  const config = parse(form.value.config)
  const s = { ...(signal.value ?? TEMPLATES.severity_mapping.modelSignal as Record<string, unknown>), [key]: value }
  config.modelSignal = s
  form.value.config = JSON.stringify(config, null, 2)
}

async function saveDraft() {
  let config: unknown
  try { config = JSON.parse(form.value.config) } catch { config = null }
  if (!config || typeof config !== 'object' || Array.isArray(config)) return toast('参数须为 JSON 对象。', 'warn')
  if (form.value.policyType === 'severity_mapping') {
    const bad = checkModelSignal(config as Record<string, unknown>)
    if (bad) return toast(bad, 'warn')
  }
  if (!form.value.reason.trim()) return toast('请填写起草理由。', 'warn')
  busy.value = true
  try {
    if (base.value) await api.post(`/detection-policies/${base.value.id}/versions`, { config, reason: form.value.reason.trim() })
    else await api.post('/detection-policies', { policyType: form.value.policyType, config, reason: form.value.reason.trim() })
    toast('草稿已登记；提交后须由其他审批人批准才生效。')
    drafting.value = false
    await reload()
  } catch (e) { toast(errText(e), 'threat') } finally { busy.value = false }
}
</script>
<template>
  <section>
    <div v-if="can('detection.policy.manage')" class="mb-6 flex justify-end">
      <button class="act-ghost" :disabled="TYPES.every(hasOpen)" @click="openDraft(null)">起草策略版本</button>
    </div>
    <LoadState :loading="loading" :error="error">
      <table class="table">
        <thead><tr><th>类型</th><th>版本</th><th>状态</th><th>起草 / 审批</th><th>来源</th><th class="text-right">登记</th><th></th></tr></thead>
        <tbody v-for="[type, versions] in groups" :key="type">
          <tr v-for="(p, i) in versions" :key="p.id" class="row-link" tabindex="0" @click="open(p)" @keydown.enter="open(p)">
            <td><span class="block" :class="i ? 'text-ink-3' : ''">{{ i ? '' : detectionPolicyTypeLabel[type] ?? type }}</span><span v-if="!i" class="num text-[12px] text-ink-3">{{ type }}</span></td>
            <td class="num">{{ p.version }} <span class="text-[12px] text-ink-3">#{{ p.id }}</span></td>
            <td><Tag :tone="statusTone[p.status]" :label="lifecycleStatusLabel[p.status] ?? p.status" /></td>
            <td class="num text-ink-2">{{ p.createdBy == null ? '预置' : `#${p.createdBy}` }} / {{ p.reviewedBy == null ? '—' : `#${p.reviewedBy}` }}</td>
            <td class="num text-[12.5px] text-ink-3">{{ p.basedOnPolicyId ? `基于 #${p.basedOnPolicyId}` : '—' }}</td>
            <td class="num text-right text-ink-3">{{ fmtTime(p.createdAt) }}</td>
            <td class="whitespace-nowrap text-right"><button v-if="canCopy(p)" class="link text-[12.5px]" @click.stop="openDraft(p)">基于此版本起草</button></td>
          </tr>
        </tbody>
        <tbody v-if="!policies.length"><tr><td colspan="7" class="py-16 text-center text-ink-3">数据库中暂无检测策略。</td></tr></tbody>
      </table>
      <p class="mt-6 text-[12.5px] leading-relaxed text-ink-3">每类策略同时只有一个生效版本，同类型已有草稿或待审版本时不能再起草。版本内容不可修改；批准新版本时原生效版本自动退役。退役不会自动回退旧版本，该类型无生效版本时检测失败。</p>
    </LoadState>

    <Drawer :open="!!picked" :title="picked ? `${detectionPolicyTypeLabel[picked.policyType] ?? picked.policyType} ${picked.version}` : ''" :kicker="picked ? `POLICY #${picked.id}` : ''" @close="picked = null">
      <template v-if="picked">
        <dl class="border-t border-ink">
          <div v-for="[k, v] in [
            ['状态', lifecycleStatusLabel[picked.status] ?? picked.status],
            ['类型', picked.policyType],
            ['起草人', picked.createdBy == null ? '预置' : `#${picked.createdBy}`],
            ['基于', picked.basedOnPolicyId ? `#${picked.basedOnPolicyId}` : '—'],
            ['起草理由', picked.changeReason ?? '—'],
            ['提交', fmtTime(picked.submittedAt)],
            ['审批人', picked.reviewedBy == null ? '—' : `#${picked.reviewedBy}`],
            ['审批', fmtTime(picked.reviewedAt)],
            ['审批理由', picked.decisionReason ?? '—'],
            ['退役', picked.retiredAt ? `${fmtTime(picked.retiredAt)} · #${picked.retiredBy ?? '—'}` : '—'],
            ['内容哈希', picked.contentSha256 ? picked.contentSha256.slice(0, 16) + '…' : '—'],
          ]" :key="k" class="grid grid-cols-[6rem_1fr] border-b border-ink-hair py-3 text-[13px]">
            <dt class="text-ink-3">{{ k }}</dt><dd class="num break-all">{{ v }}</dd>
          </div>
        </dl>
        <h3 class="label mb-3 mt-10">参数</h3>
        <dl class="border-t border-ink">
          <div v-for="[k, v] in pickedConfig" :key="k" class="grid grid-cols-[9rem_1fr] border-b border-ink-hair py-2.5 text-[12.5px]">
            <dt class="num text-ink-3">{{ k }}</dt><dd class="num break-all">{{ show(v) }}</dd>
          </div>
          <p v-if="!pickedConfig.length" class="py-3 text-[12.5px] text-ink-3">参数无法解析。</p>
        </dl>
        <label v-if="needsReason" class="mt-10 block"><span class="label">理由</span><textarea v-model="reason" rows="3" maxlength="1000" class="field mt-2 h-auto resize-none py-2" placeholder="写入审计" /></label>
        <p v-if="picked.status === 'pending' && isAuthor(picked)" class="mt-6 text-[12.5px] text-ink-3">本人起草的版本须由其他审批人决定。</p>
      </template>
      <template v-if="canSubmit || canWithdraw || canDecide || canRetire || (picked && canCopy(picked))" #foot>
        <button v-if="picked && canCopy(picked)" class="link text-[13px]" :disabled="busy" @click="openDraft(picked)">基于此版本起草</button>
        <button v-if="canWithdraw" class="link text-[13px]" :disabled="busy" @click="withdraw">撤回</button>
        <button v-if="canSubmit" class="act" :disabled="busy" @click="submit">提交审批</button>
        <template v-if="canDecide">
          <button class="link text-[13px]" :disabled="busy" @click="decide('reject')">驳回</button>
          <button class="act" :disabled="busy" @click="decide('approve')">批准生效</button>
        </template>
        <button v-if="canRetire" class="act-ghost" :disabled="busy" @click="retire">退役</button>
      </template>
    </Drawer>

    <Drawer :open="drafting" :title="base ? `基于 ${base.version} 起草` : '起草检测策略'" kicker="DETECTION POLICY" @close="drafting = false">
      <div class="space-y-6">
        <label class="block"><span class="label">类型</span>
          <select :value="form.policyType" class="field mt-2" :disabled="!!base" @change="changeType(($event.target as HTMLSelectElement).value as DetectionPolicyType)">
            <option v-for="t in TYPES" :key="t" :value="t" :disabled="hasOpen(t)">{{ detectionPolicyTypeLabel[t] }}{{ hasOpen(t) ? '（已有未决版本）' : '' }}</option>
          </select>
        </label>
        <fieldset v-if="form.policyType === 'severity_mapping'" class="border-t border-ink pt-4">
          <legend class="label">模型信号分层（modelSignal）</legend>
          <label class="mt-3 flex items-center gap-2 text-[13px]"><input type="checkbox" class="h-3.5 w-3.5 accent-ink" :checked="signal?.enabled === true" @change="setSignal('enabled', ($event.target as HTMLInputElement).checked)" /> 启用：低于高分的模型命中记为信号，不进人工队列</label>
          <div class="mt-4 grid grid-cols-2 gap-4">
            <label class="block"><span class="label">提升计数（2～10000）</span><input type="number" min="2" max="10000" step="1" class="field num mt-2" :value="signal?.countThreshold" @input="setSignal('countThreshold', Number(($event.target as HTMLInputElement).value))" /></label>
            <label class="block"><span class="label">高分阈值（0, 1]</span><input type="number" min="0" max="1" step="0.01" class="field num mt-2" :value="signal?.highScore" @input="setSignal('highScore', Number(($event.target as HTMLInputElement).value))" /></label>
          </div>
        </fieldset>
        <label class="block"><span class="label">参数 JSON</span><textarea v-model="form.config" rows="12" spellcheck="false" class="field num mt-2 h-auto resize-y py-2 text-[12px]" /></label>
        <label class="block"><span class="label">起草理由</span><textarea v-model="form.reason" rows="3" maxlength="1000" class="field mt-2 h-auto resize-none py-2" placeholder="变更依据与影响" /></label>
        <p class="text-[12px] leading-relaxed text-ink-3">版本号由后端分配。分级映射 model 档位按 minScore 严格递减且最后一档为 0；事件关联只支持按资产、窗口 60～86400 秒；风险评分权重在 [0, 1]。登记后为草稿，须提交并由其他审批人批准。</p>
      </div>
      <template #foot>
        <button class="link text-[13px]" @click="drafting = false">取消</button>
        <button class="act" :disabled="busy" @click="saveDraft">登记草稿</button>
      </template>
    </Drawer>
  </section>
</template>
