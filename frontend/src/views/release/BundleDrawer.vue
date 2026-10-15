<script setup lang="ts">
/**
 * 发布组合详情抽屉（发布管理 `?tab=bundles&id=`，待办中心的组合封存与批准直达这里）。
 *
 * 内容：状态时间线（申请 → 导入报告 → 封存 → 批准 → 激活，暂停/退役为旁路终态）、组成（模型、策略与模式、评价计划、能力）、
 * 关联报告（评价运行，需 evaluation.read）、资产绑定（bindings 子资源）；哈希与修订号收进「技术细节」。
 * 后端只返回创建与最近更新时间，时间线中其余阶段只标是否到达，不推测时间。
 *
 * 操作（抽屉内切换模式，不叠加抽屉；写后重读并通知父页面）：
 * - 导入报告（evaluation.run，候选）、封存（bundle.request，候选，须含一次 final 通过报告）、撤回候选（bundle.request，候选/已封存）；
 * - 批准 / 驳回（bundle.approve，已封存；申请人本人由后端拒绝，组合查询不返回申请人，入口照常显示）；
 * - 激活（bundle.approve，已批准/已激活，按资产与有效授权一一对应）、退役（bundle.approve，已批准/已暂停）；
 * - 暂停（automation.stop，已批准/已激活）：立即停止新命令，现有规则的清理以处置记录为准。
 */
import { computed, reactive, ref, watch } from 'vue'
import { RouterLink } from 'vue-router'
import { Archive, CirclePause, FileInput, Lock, Plus, Rocket, Undo2, X } from 'lucide-vue-next'
import Drawer from '@/components/Drawer.vue'
import Tag from '@/components/Tag.vue'
import IdText from '@/components/IdText.vue'
import LoadState from '@/components/LoadState.vue'
import { errText } from '@/composables/load'
import { toast } from '@/composables/toast'
import { can } from '@/api/session'
import { fmtTime } from '@/api/types'
import { assetsApi, assetTitle, bindingStatusLabel, type Asset, type Authorization } from '@/api/v2/assets'
import { isSha256, releaseApi, type AssetBinding, type Evaluation, type ReleaseBundle, type ReleasePolicy } from '@/api/v2/release'
import { bindingTone, bundleTone, capabilityTone, evaluationTone } from '@/data/tones'
import {
  bundleStatusLabel, capabilityName, ensureIndex, envLabel, evaluationStatusLabel, isObject, levelLabel, modeLabel, modelName,
  planName, policyTitle, releaseErr, releaseIndex, runKindLabel, short,
} from './shared'

const props = defineProps<{ id: string }>()
const emit = defineEmits<{ close: []; changed: [] }>()

type Mode = 'view' | 'import' | 'seal' | 'approve' | 'reject' | 'activate' | 'suspend' | 'withdraw' | 'retire'
const mode = ref<Mode>('view')
const bundle = ref<ReleaseBundle | null>(null)
const policy = ref<ReleasePolicy | null>(null)
const reports = ref<Evaluation[] | null>(null)
const bindings = ref<AssetBinding[] | null>(null)
const assets = ref(new Map<string, Asset>())
const loading = ref(false)
const error = ref('')
let seq = 0

async function load() {
  const mine = ++seq
  loading.value = !bundle.value || bundle.value.id !== props.id
  error.value = ''
  try {
    const b = await releaseApi.getBundle(props.id)
    if (mine !== seq) return
    bundle.value = b
    void ensureIndex('models'); void ensureIndex('capabilities'); void ensureIndex('plans')
    const [p, e, bd] = await Promise.all([
      releaseApi.getPolicy(b.policyId).catch(() => null),
      can('evaluation.read') ? releaseApi.listEvaluations({ limit: 200 }).then((page) => page.items.filter((x) => x.bundleId === b.id)).catch(() => null) : Promise.resolve(null),
      releaseApi.listBundleBindings(b.id).then((r) => r.items).catch(() => null),
    ])
    if (mine !== seq) return
    policy.value = p; reports.value = e; bindings.value = bd
    if (bd?.length) loadAssets()
  } catch (err) { if (mine === seq) { bundle.value = null; error.value = errText(err) } } finally { if (mine === seq) loading.value = false }
}
let assetsLoaded = false
function loadAssets() {
  if (assetsLoaded || !can('resource.read')) return
  assetsLoaded = true
  assetsApi.listAssets({ limit: 200 }).then((p) => { assets.value = new Map(p.items.map((a) => [a.id, a])) }).catch(() => { assetsLoaded = false })
}
watch(() => props.id, (id) => {
  mode.value = 'view'; policy.value = null; reports.value = null; bindings.value = null
  if (id) void load(); else { seq++; bundle.value = null }
}, { immediate: true })

const assetLabel = (id: string) => { const a = assets.value.get(id); return a ? assetTitle(a) : `资产 ${short(id)}` }
const status = computed(() => bundle.value?.status ?? '')
const subject = computed(() => (isObject(bundle.value?.subject) ? bundle.value!.subject as Record<string, unknown> : {}))
const capabilityIds = computed(() => (Array.isArray(subject.value.capabilityIds) ? (subject.value.capabilityIds as unknown[]).map(String) : []))
const protocolVersions = computed(() => (isObject(subject.value.protocolVersions) ? Object.entries(subject.value.protocolVersions).map(([k, v]) => [k, String(v)] as [string, string]) : []))
const policyMode = computed(() => {
  const d = policy.value?.definition
  return d && typeof d.mode === 'string' ? d.mode : null
})
const sealedIds = computed(() => {
  const m = bundle.value?.sealedManifest
  if (!isObject(m) || !Array.isArray(m.reports)) return new Set<string>()
  return new Set(m.reports.map((r) => (isObject(r) ? String(r.evaluationId) : String(r))))
})

/* ---------------- 状态时间线 ---------------- */
const STAGES = [
  { key: 'candidate', label: '申请（候选）', note: '组合不可变，导入评价报告' },
  { key: 'evaluated', label: '封存清单', note: '冻结报告摘要，等待批准' },
  { key: 'approved', label: '独立批准', note: '申请人以外的批准人' },
  { key: 'active', label: '按资产激活', note: '逐个核验授权与能力' },
] as const
const reached = computed(() => {
  const s = status.value
  const i = STAGES.findIndex((x) => x.key === s)
  if (i >= 0) return i
  if (s === 'suspended') return bindings.value?.length ? 3 : 2
  if (s === 'retired') return bundle.value?.sealedManifestSha256 ? 1 : 0
  return 0
})
const terminal = computed(() => (status.value === 'suspended' || status.value === 'retired' ? status.value : null))
const timeOf = (i: number) => {
  const b = bundle.value
  if (!b) return null
  if (i === 0) return b.createdAt
  if (!terminal.value && i === reached.value) return b.updatedAt
  return null
}
const sortedReports = computed(() => [...(reports.value ?? [])].sort((a, b) => a.createdAt.localeCompare(b.createdAt)))
const stateNote = computed(() => {
  switch (status.value) {
    case 'candidate': return { text: '候选：导入签名评价报告并封存后才能批准。评估失败保留候选与失败报告，不会伪造封存。', tone: '' }
    case 'evaluated': return { text: '已封存待批：须由申请人以外、具有批准权限的人批准；批准不等于激活。', tone: '' }
    case 'approved': return { text: '已批准，尚未在任何资产上生效。激活时逐个资产核验有效授权与能力等级。', tone: '' }
    case 'active': return { text: '已在部分资产上激活。暂停会立即停止新命令。', tone: '' }
    case 'suspended': return { text: '已暂停：不再下发新命令。现有规则是否已清理以处置记录为准。', tone: 'note-warn' }
    case 'retired': return { text: '已退役（终态），只作记录。', tone: '' }
    default: return { text: `状态：${status.value}`, tone: '' }
  }
})

/* ---------------- 可用操作 ---------------- */
const canImport = computed(() => can('evaluation.run') && status.value === 'candidate')
const canSeal = computed(() => can('bundle.request') && status.value === 'candidate')
const canWithdraw = computed(() => can('bundle.request') && ['candidate', 'evaluated'].includes(status.value))
const canDecide = computed(() => can('bundle.approve') && status.value === 'evaluated' && !!bundle.value?.sealedManifestSha256)
const canActivate = computed(() => can('bundle.approve') && ['approved', 'active'].includes(status.value))
const canSuspend = computed(() => can('automation.stop') && ['approved', 'active'].includes(status.value))
const canRetire = computed(() => can('bundle.approve') && ['approved', 'suspended'].includes(status.value))
const anyFoot = computed(() => canImport.value || canSeal.value || canDecide.value || canActivate.value)

const busy = ref(false)
const formError = ref('')
const reason = ref('')
const report = reactive({ reportRef: '', sha256: '', runnerIdentity: '' })
const sealPick = ref<string[]>([])
const sealManual = ref('')
const revokeExisting = ref(true)
const pairs = ref<{ assetId: string; authorizationId: string }[]>([])
const authorizations = ref(new Map<string, Authorization[]>())

function enter(m: Mode) {
  mode.value = m
  formError.value = ''
  reason.value = ''
  if (m === 'import') Object.assign(report, { reportRef: '', sha256: '', runnerIdentity: '' })
  if (m === 'seal') { sealPick.value = sortedReports.value.filter((r) => r.status === 'passed').map((r) => r.id); sealManual.value = '' }
  if (m === 'suspend') revokeExisting.value = true
  if (m === 'activate') { pairs.value = [{ assetId: '', authorizationId: '' }]; loadAssets() }
}

/** 激活：只列与组合环境一致、运行中的资产；授权按资产读取并只保留有效期内的已批准授权。 */
const activatable = computed(() => [...assets.value.values()].filter((a) => a.environment === bundle.value?.environment && a.status === 'active'))
function pickAsset(i: number, assetId: string) {
  pairs.value[i] = { assetId, authorizationId: '' }
  if (!assetId || authorizations.value.has(assetId)) return
  assetsApi.listAuthorizations({ assetId, status: 'active', limit: 50 })
    .then((p) => { authorizations.value = new Map(authorizations.value).set(assetId, p.items.filter((a) => a.validity === 'valid')) })
    .catch(() => { authorizations.value = new Map(authorizations.value).set(assetId, []) })
}

const runKinds = (ids: string[]) => new Set((reports.value ?? []).filter((r) => ids.includes(r.id)).map((r) => r.runKind))
const sealHint = computed(() => {
  if (bundle.value?.environment === 'research' || policyMode.value === 'alert_only') return '须包含一次最终（final）评价报告。'
  return '须包含最终（final）、平台（platform）与灰度（canary）评价报告；只告警策略与研究环境只需最终报告。'
})

async function run(call: () => Promise<unknown>, done: string) {
  busy.value = true
  formError.value = ''
  try {
    await call()
    toast(done)
    emit('changed')
    mode.value = 'view'
    await load()
  } catch (e) { formError.value = releaseErr(e, 'bundle') } finally { busy.value = false }
}

function confirm(decision?: 'approve' | 'reject') {
  const b = bundle.value
  if (!b) return
  const why = reason.value.trim()
  switch (mode.value) {
    case 'import': {
      const body = { reportRef: report.reportRef.trim(), sha256: report.sha256.trim().toLowerCase(), runnerIdentity: report.runnerIdentity.trim() }
      if (!body.reportRef || !body.runnerIdentity) { formError.value = '报告引用与签发身份都必填。'; return }
      if (!isSha256(body.sha256)) { formError.value = 'SHA-256 须为 64 位小写十六进制。'; return }
      void run(() => releaseApi.importBundleReport(b.id, body), '已导入报告；通过与否以签名报告为准。')
      return
    }
    case 'seal': {
      const ids = can('evaluation.read') ? sealPick.value : sealManual.value.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean)
      if (!ids.length) { formError.value = '至少选择一份通过的评价报告。'; return }
      if (can('evaluation.read')) {
        const kinds = runKinds(ids)
        if (!kinds.has('final')) { formError.value = '封存必须包含一次最终（final）评价报告。'; return }
        if (b.environment !== 'research' && policyMode.value !== 'alert_only' && !(kinds.has('platform') && kinds.has('canary'))) { formError.value = '该组合还需平台（platform）与灰度（canary）报告才能封存。'; return }
      }
      void run(() => releaseApi.sealBundle(b.id, b.revision, ids), '已封存，组合进入「已封存待批」。')
      return
    }
    case 'approve': case 'reject': {
      if (!why) { formError.value = '请填写理由，理由会写入审计。'; return }
      const d = decision ?? (mode.value === 'approve' ? 'approve' : 'reject')
      void run(() => releaseApi.decideBundle(b.id, b.revision, { decision: d, reason: why }), d === 'approve' ? '已批准；激活需另行按资产执行。' : '已驳回。')
      return
    }
    case 'activate': {
      const rows = pairs.value.filter((p) => p.assetId)
      if (!rows.length) { formError.value = '至少选择一个资产。'; return }
      if (rows.some((p) => !p.authorizationId)) { formError.value = '每个资产都要选择一份有效授权。'; return }
      if (new Set(rows.map((p) => p.assetId)).size !== rows.length) { formError.value = '同一资产只能出现一次。'; return }
      void run(() => releaseApi.activateBundle(b.id, b.revision, { assetIds: rows.map((p) => p.assetId), authorizationIds: rows.map((p) => p.authorizationId) }), '已受理激活；逐个资产核验后生效，不代表命令已执行。')
      return
    }
    case 'suspend':
      if (!why) { formError.value = '请填写暂停理由，理由会写入审计。'; return }
      void run(() => releaseApi.suspendBundle(b.id, b.revision, { reason: why, revokeExisting: revokeExisting.value }), '已暂停；新命令已停止，清理状态见处置记录。')
      return
    case 'withdraw': case 'retire':
      if (!why) { formError.value = '请填写理由，理由会写入审计。'; return }
      void run(() => releaseApi.retireBundle(b.id, b.revision, why), mode.value === 'withdraw' ? '已撤回候选组合。' : '已退役发布组合。')
  }
}

const modeTitle: Record<Mode, string> = {
  view: '', import: '导入评价报告', seal: '封存发布清单', approve: '批准发布组合', reject: '驳回发布组合',
  activate: '按资产激活', suspend: '暂停发布组合', withdraw: '撤回候选组合', retire: '退役发布组合',
}
const capabilities = computed(() => capabilityIds.value.map((id) => ({ id, name: capabilityName(id), level: releaseIndex.capabilities.get(id)?.level ?? null })))
</script>

<template>
  <Drawer :open="!!id" :title="bundle ? (mode === 'view' ? `发布组合 ${short(bundle.bundleKey)}` : modeTitle[mode]) : '发布组合'" :kicker="bundle ? `${modelName(bundle.modelId)} · ${envLabel[bundle.environment] ?? bundle.environment}` : '发布组合'" @close="emit('close')">
    <LoadState :loading="loading" :error="error">
      <template v-if="bundle">
        <template v-if="mode === 'view'">
          <p class="note mb-5" :class="stateNote.tone">{{ stateNote.text }}</p>

          <h3 class="section-title">状态时间线</h3>
          <ol class="relative mb-7 ml-1.5 border-l border-ink-line">
            <template v-for="(s, i) in STAGES" :key="s.key">
              <li class="relative pb-4 pl-5">
                <span class="absolute -left-[5px] top-1.5 h-2.5 w-2.5 rounded-full border" :class="i < reached || (i === reached && !terminal) ? (i === reached ? 'border-ink bg-ink' : 'border-ink bg-paper') : 'border-ink-line bg-paper'" aria-hidden="true" />
                <div class="flex items-baseline justify-between gap-3">
                  <span class="text-[13px]" :class="i <= reached ? 'text-ink' : 'text-ink-4'">{{ s.label }}<span v-if="i === reached && !terminal" class="ml-2 text-[11.5px] text-ink-3">当前</span></span>
                  <span class="num text-[11.5px] text-ink-4">{{ timeOf(i) ? fmtTime(timeOf(i)) : i <= reached ? '已完成' : '' }}</span>
                </div>
                <p class="text-[12px] text-ink-4">{{ s.note }}</p>
                <ul v-if="i === 0 && sortedReports.length" class="mt-2 space-y-1">
                  <li v-for="r in sortedReports" :key="r.id" class="flex items-center gap-2 text-[12px]">
                    <FileInput :size="12" :stroke-width="1.5" class="text-ink-4" aria-hidden="true" />
                    <span class="text-ink-2">导入报告 · {{ runKindLabel[r.runKind] ?? r.runKind }}</span>
                    <Tag :tone="evaluationTone[r.status]" :label="evaluationStatusLabel[r.status] ?? r.status" />
                    <span class="num ml-auto text-ink-4">{{ fmtTime(r.createdAt) }}</span>
                  </li>
                </ul>
              </li>
            </template>
            <li v-if="terminal" class="relative pl-5">
              <span class="absolute -left-[5px] top-1.5 h-2.5 w-2.5 rounded-full border" :class="terminal === 'suspended' ? 'border-warn bg-warn' : 'border-ink-3 bg-ink-3'" aria-hidden="true" />
              <div class="flex items-baseline justify-between gap-3">
                <span class="text-[13px] text-ink">{{ bundleStatusLabel[terminal] }}<span class="ml-2 text-[11.5px] text-ink-3">当前</span></span>
                <span class="num text-[11.5px] text-ink-4">{{ fmtTime(bundle.updatedAt) }}</span>
              </div>
            </li>
          </ol>

          <h3 class="section-title">组成</h3>
          <dl class="kv">
            <div><dt>状态</dt><dd><Tag pill :tone="bundleTone[status]" :label="bundleStatusLabel[status] ?? status" /></dd></div>
            <div><dt>模型</dt><dd><RouterLink class="link" :to="{ path: '/console/release/models', query: { tab: 'models', id: bundle.modelId } }">{{ modelName(bundle.modelId) }}</RouterLink></dd></div>
            <div><dt>决策策略</dt><dd>
              <RouterLink class="link" :to="{ query: { tab: 'policies', id: bundle.policyId } }">{{ policy ? `${policyTitle(policy)} · ${policy.version}` : `策略 ${short(bundle.policyId)}` }}</RouterLink>
              <Tag v-if="policyMode" class="ml-2" :tone="policyMode === 'alert_only' ? 'mute' : 'warn'" :label="modeLabel[policyMode] ?? policyMode" />
            </dd></div>
            <div><dt>评价计划</dt><dd class="num">{{ planName(bundle.planId) }}</dd></div>
            <div><dt>环境</dt><dd>{{ envLabel[bundle.environment] ?? bundle.environment }}</dd></div>
            <div><dt>能力</dt><dd>
              <ul v-if="capabilities.length" class="space-y-1">
                <li v-for="c in capabilities" :key="c.id" class="flex flex-wrap items-center gap-2">
                  <span class="num text-[12.5px]">{{ c.name }}</span>
                  <Tag v-if="c.level" :tone="capabilityTone[c.level]" :label="levelLabel[c.level] ?? c.level" />
                </li>
              </ul>
              <span v-else class="text-ink-4">—</span>
            </dd></div>
          </dl>

          <h3 class="section-title mt-8">关联报告</h3>
          <p v-if="reports === null" class="text-[12.5px] text-ink-3">{{ can('evaluation.read') ? '报告读取失败。' : '没有评价读取权限，不显示报告。' }}</p>
          <p v-else-if="!sortedReports.length" class="text-[12.5px] text-ink-3">尚未导入评价报告。</p>
          <ul v-else class="divide-y divide-ink-hair rounded border border-ink-hair">
            <li v-for="r in sortedReports" :key="r.id" class="flex items-center justify-between gap-3 px-3.5 py-2.5 text-[12.5px]">
              <span class="min-w-0">
                <span class="flex items-center gap-2"><span class="text-ink">{{ runKindLabel[r.runKind] ?? r.runKind }}</span><Tag :tone="evaluationTone[r.status]" :label="evaluationStatusLabel[r.status] ?? r.status" /></span>
                <span class="num block truncate text-[11.5px] text-ink-4">{{ r.runnerIdentity }} · {{ fmtTime(r.createdAt) }}</span>
              </span>
              <span class="shrink-0 text-[12px]" :class="sealedIds.has(r.id) ? 'text-ink-2' : 'text-ink-4'">{{ sealedIds.has(r.id) ? '已纳入封存' : '未纳入' }}</span>
            </li>
          </ul>

          <h3 class="section-title mt-8">资产绑定</h3>
          <p v-if="bindings === null" class="text-[12.5px] text-ink-3">绑定读取失败。</p>
          <p v-else-if="!bindings.length" class="text-[12.5px] text-ink-3">尚未在任何资产上激活。</p>
          <ul v-else class="divide-y divide-ink-hair rounded border border-ink-hair">
            <li v-for="x in bindings" :key="x.id" class="flex items-center justify-between gap-3 px-3.5 py-2.5 text-[12.5px]">
              <span class="min-w-0">
                <RouterLink class="link block truncate" :to="{ name: 'assets-list-detail', params: { id: x.assetId }, query: { tab: 'releases' } }">{{ assetLabel(x.assetId) }}</RouterLink>
                <span class="num text-[11.5px] text-ink-4">授权 {{ short(x.authorizationId) }} · r{{ x.authorizationRevision }} · {{ fmtTime(x.createdAt) }}</span>
              </span>
              <Tag pill :tone="bindingTone[x.status]" :label="bindingStatusLabel[x.status] ?? x.status" />
            </li>
          </ul>

          <details class="mt-7 text-[12.5px]">
            <summary class="cursor-pointer text-ink-3 hover:text-ink">技术细节</summary>
            <dl class="kv mt-2">
              <div><dt>组合 ID</dt><dd><IdText :value="bundle.id" /></dd></div>
              <div><dt>组合键 / 版本</dt><dd class="num break-all">{{ bundle.bundleKey }} · {{ bundle.version }}</dd></div>
              <div><dt>subject 摘要</dt><dd><IdText :value="bundle.subjectSha256" :length="16" /></dd></div>
              <div><dt>封存清单摘要</dt><dd><IdText v-if="bundle.sealedManifestSha256" :value="bundle.sealedManifestSha256" :length="16" /><span v-else class="text-ink-4">未封存</span></dd></div>
              <div v-for="[k, v] in protocolVersions" :key="k"><dt class="num">{{ k }}</dt><dd class="num break-all">{{ v }}</dd></div>
              <div><dt>修订号</dt><dd class="num">{{ bundle.revision }}</dd></div>
            </dl>
          </details>

          <div v-if="canWithdraw || canSuspend || canRetire" class="mt-6 flex flex-wrap gap-5">
            <button v-if="canWithdraw" type="button" class="link text-[12.5px] text-threat" @click="enter('withdraw')"><Undo2 :size="13" :stroke-width="1.5" />撤回候选</button>
            <button v-if="canSuspend" type="button" class="link text-[12.5px] text-threat" @click="enter('suspend')"><CirclePause :size="13" :stroke-width="1.5" />暂停组合</button>
            <button v-if="canRetire" type="button" class="link text-[12.5px] text-threat" @click="enter('retire')"><Archive :size="13" :stroke-width="1.5" />退役组合</button>
          </div>
        </template>

        <!-- 导入报告 -->
        <form v-else-if="mode === 'import'" class="form" @submit.prevent="confirm()">
          <p class="note">登记 runner 签发的评价报告；后端核验签名、subject 与评价计划摘要。报告不反向写入组合，lab 会话报告须从验证记录导入。</p>
          <label class="form-field"><span class="label">报告引用</span><input v-model="report.reportRef" class="field num" maxlength="512" placeholder="受控制品根内的相对路径" autocomplete="off" /></label>
          <label class="form-field"><span class="label">报告 SHA-256</span><input v-model="report.sha256" class="field num" maxlength="64" placeholder="64 位小写十六进制" autocomplete="off" /></label>
          <label class="form-field"><span class="label">签发身份</span><input v-model="report.runnerIdentity" class="field num" maxlength="128" placeholder="runner 身份" autocomplete="off" />
            <span class="form-hint">须为可信签发身份；导入成功不等于通过，结果以报告的 passed 为准。</span></label>
        </form>

        <!-- 封存 -->
        <div v-else-if="mode === 'seal'" class="form">
          <p class="note">封存后组合进入「已封存待批」，清单只引用所选报告的摘要。{{ sealHint }}</p>
          <fieldset v-if="can('evaluation.read')" class="form-field">
            <legend class="label mb-2">通过的评价报告</legend>
            <p v-if="!sortedReports.some((r) => r.status === 'passed')" class="text-[12.5px] text-ink-3">还没有通过的报告，请先导入。</p>
            <label v-for="r in sortedReports.filter((x) => x.status === 'passed')" :key="r.id" class="flex items-center gap-2.5 border-b border-ink-hair py-2 text-[12.5px] last:border-b-0">
              <input v-model="sealPick" type="checkbox" :value="r.id" />
              <span class="text-ink">{{ runKindLabel[r.runKind] ?? r.runKind }}</span>
              <span class="num text-ink-4">{{ short(r.id) }}</span>
              <span class="num ml-auto text-ink-4">{{ fmtTime(r.createdAt) }}</span>
            </label>
          </fieldset>
          <label v-else class="form-field"><span class="label">评价运行 ID（逗号或换行分隔）</span>
            <textarea v-model="sealManual" rows="3" class="field num resize-none text-[12px]" />
            <span class="form-hint">没有评价读取权限，无法列出报告；类型要求由后端核验。</span></label>
        </div>

        <!-- 批准 / 驳回 -->
        <div v-else-if="mode === 'approve' || mode === 'reject'" class="form">
          <p class="note" :class="mode === 'reject' ? 'note-warn' : ''">
            <template v-if="mode === 'approve'">批准后组合进入「已批准」，仍需按资产激活才会生效。申请人本人不能批准，后端会拒绝。</template>
            <template v-else>驳回后组合结束，申请人需要重新申请新的组合。</template>
          </p>
          <label class="form-field"><span class="label">理由</span><textarea v-model="reason" rows="3" maxlength="1000" class="field resize-none" placeholder="写入审计" /></label>
        </div>

        <!-- 激活 -->
        <div v-else-if="mode === 'activate'" class="form">
          <p class="note">逐个资产核验有效授权与能力等级；只告警以外的模式在 lab 资产上需要 lab 自动（仅 lab）或授权自动能力。受理不代表命令已执行。</p>
          <div v-for="(p, i) in pairs" :key="i" class="grid grid-cols-[minmax(0,1fr)_minmax(0,1fr)_1.75rem] items-end gap-2">
            <label class="form-field"><span class="label">资产</span>
              <select class="field" :value="p.assetId" @change="pickAsset(i, ($event.target as HTMLSelectElement).value)">
                <option value="">选择资产</option>
                <option v-for="a in activatable" :key="a.id" :value="a.id">{{ assetTitle(a) }}</option>
              </select>
            </label>
            <label class="form-field"><span class="label">有效授权</span>
              <select v-model="p.authorizationId" class="field num" :disabled="!p.assetId">
                <option value="">{{ p.assetId && authorizations.get(p.assetId)?.length === 0 ? '该资产没有有效授权' : '选择授权' }}</option>
                <option v-for="a in authorizations.get(p.assetId) ?? []" :key="a.id" :value="a.id">{{ short(a.id) }} · 至 {{ fmtTime(a.validUntil) }}</option>
              </select>
            </label>
            <button v-if="pairs.length > 1" type="button" class="mb-1.5 rounded p-1 text-ink-3 hover:bg-paper-soft hover:text-ink" aria-label="移除该资产" @click="pairs.splice(i, 1)"><X :size="14" :stroke-width="1.5" /></button>
          </div>
          <button type="button" class="link self-start text-[12.5px]" @click="pairs.push({ assetId: '', authorizationId: '' })"><Plus :size="13" :stroke-width="1.5" />再加一个资产</button>
          <p v-if="!activatable.length" class="text-[12.5px] text-ink-3">没有与组合环境（{{ envLabel[bundle.environment] ?? bundle.environment }}）一致的运行中资产。</p>
        </div>

        <!-- 暂停 -->
        <div v-else-if="mode === 'suspend'" class="form">
          <p class="note note-warn">暂停立即停止该组合在所有资产上的新命令，绑定同时暂停。暂停不等于规则已清理，清理状态以处置记录为准。</p>
          <label class="flex items-center gap-2 text-[13px]"><input v-model="revokeExisting" type="checkbox" />同时撤销已生效的规则</label>
          <label class="form-field"><span class="label">理由</span><textarea v-model="reason" rows="3" maxlength="1000" class="field resize-none" placeholder="写入审计" /></label>
        </div>

        <!-- 撤回 / 退役 -->
        <div v-else class="form">
          <p class="note note-threat">
            <template v-if="mode === 'withdraw'">撤回后候选组合直接退役，不能恢复；需要时重新申请新的组合。</template>
            <template v-else>退役后组合不能再激活。仍有生效的资产绑定时会被拒绝（409 RESOURCE_IN_USE），请先暂停。</template>
          </p>
          <label class="form-field"><span class="label">理由</span><textarea v-model="reason" rows="3" maxlength="1000" class="field resize-none" placeholder="写入审计" /></label>
        </div>

        <p v-if="formError" class="mt-4 text-[12.5px] text-threat" role="alert">{{ formError }}</p>
      </template>
    </LoadState>

    <template v-if="bundle && (mode !== 'view' || anyFoot)" #foot>
      <template v-if="mode === 'view'">
        <button v-if="canImport" type="button" class="act-ghost" @click="enter('import')"><FileInput :size="14" :stroke-width="1.5" />导入报告</button>
        <button v-if="canSeal" type="button" class="act" @click="enter('seal')"><Lock :size="14" :stroke-width="1.5" />封存清单</button>
        <template v-if="canDecide">
          <button type="button" class="act-ghost" @click="enter('reject')">驳回</button>
          <button type="button" class="act" @click="enter('approve')">批准组合</button>
        </template>
        <button v-if="canActivate" type="button" class="act" @click="enter('activate')"><Rocket :size="14" :stroke-width="1.5" />按资产激活</button>
      </template>
      <template v-else>
        <button type="button" class="act-ghost" :disabled="busy" @click="enter('view')">返回</button>
        <button type="button" :class="['suspend', 'withdraw', 'retire', 'reject'].includes(mode) ? 'act-danger' : 'act'" :disabled="busy" @click="confirm()">
          {{ { import: '导入报告', seal: '确认封存', approve: '确认批准', reject: '确认驳回', activate: '确认激活', suspend: '确认暂停', withdraw: '确认撤回', retire: '确认退役', view: '' }[mode] }}
        </button>
      </template>
    </template>
  </Drawer>
</template>
