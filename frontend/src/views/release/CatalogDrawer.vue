<script setup lang="ts">
import { useActionError } from '@/composables/actionError'
/**
 * 模型 / 数据集详情抽屉（模型与数据集页 `?tab=models|datasets&id=`，待办中心的待校验模型直达这里）。
 *
 * 业务字段在前：显示名、说明、状态、发布资格（模型恒为 candidateOnly）、manifest 摘要与校验结果；
 * 键、引用、哈希与修订号收进「技术细节」。抽屉内切换模式，不叠加抽屉：查看 → 编辑资料 / 发起校验 / 退役。
 * - 编辑只改显示名与说明（model.manage / dataset.manage），带 If-Match；manifest 不可修改。
 * - 发起校验需 model.validate，校验配置固定为 host-guard-onnx-v1；202 返回的是校验报告，页面随后重读模型。
 * - 退役需理由；仍被引用时后端返回 409 RESOURCE_IN_USE，按对象写明处理建议。
 */
import { computed, reactive, ref, watch } from 'vue'
import { Archive, FlaskConical, Pencil } from 'lucide-vue-next'
import Drawer from '@/components/Drawer.vue'
import Tag from '@/components/Tag.vue'
import IdText from '@/components/IdText.vue'
import LoadState from '@/components/LoadState.vue'
import { errText } from '@/composables/load'
import { toast } from '@/composables/toast'
import { can } from '@/api/session'
import { fmtTime } from '@/api/types'
import { MODEL_VALIDATION_PROFILE_ID, releaseApi, type ModelValidation, type ReleaseDataset, type ReleaseModel } from '@/api/v2/release'
import { catalogTone } from '@/data/tones'
import { datasetStatusLabel, isObject, modelStatusLabel, modelTitle, profileLabel, releaseErr } from './shared'

const props = defineProps<{ kind: 'models' | 'datasets'; id: string }>()
const emit = defineEmits<{ close: []; changed: [] }>()

type Mode = 'view' | 'edit' | 'validate' | 'retire'
const mode = ref<Mode>('view')
const row = ref<ReleaseModel | ReleaseDataset | null>(null)
const validation = ref<ModelValidation | null>(null)
const loading = ref(false)
const error = ref('')
let seq = 0
async function load() {
  const mine = ++seq
  loading.value = !row.value || row.value.id !== props.id
  error.value = ''
  try {
    if (props.kind === 'models') {
      const [m, v] = await Promise.all([releaseApi.getModel(props.id), releaseApi.getModelValidations(props.id).catch(() => null)])
      if (mine !== seq) return
      row.value = m
      validation.value = v ?? (isObject(m.validation) ? m.validation as ModelValidation : null)
    } else {
      const d = await releaseApi.getDataset(props.id)
      if (mine === seq) row.value = d
    }
  } catch (e) { if (mine === seq) { row.value = null; error.value = errText(e) } } finally { if (mine === seq) loading.value = false }
}
watch(() => [props.kind, props.id] as const, ([, id]) => { mode.value = 'view'; validation.value = null; if (id) void load(); else { seq++; row.value = null } }, { immediate: true })

const model = computed(() => (props.kind === 'models' ? row.value as ReleaseModel | null : null))
const dataset = computed(() => (props.kind === 'datasets' ? row.value as ReleaseDataset | null : null))
const noun = computed(() => (props.kind === 'models' ? '模型' : '数据集'))
const status = computed(() => (model.value ? model.value.validationStatus : dataset.value?.status ?? ''))
const statusText = computed(() => (props.kind === 'models' ? modelStatusLabel : datasetStatusLabel)[status.value] ?? status.value)
const title = computed(() => {
  if (model.value) return modelTitle(model.value)
  if (dataset.value) return dataset.value.displayName || dataset.value.datasetKey
  return `${noun.value}详情`
})
const retired = computed(() => status.value === 'retired')
const manage = computed(() => !!row.value && can(props.kind === 'models' ? 'model.manage' : 'dataset.manage'))
const validatable = computed(() => !!model.value && !retired.value && can('model.validate'))

/* manifest 摘要：只取业务上有意义的字段，其余进入技术细节。 */
const manifest = computed(() => {
  const m = model.value?.manifest
  if (!isObject(m)) return null
  const runtime = isObject(m.runtime) ? m.runtime : {}
  const scope = Array.isArray(m.supportedScope) ? m.supportedScope.filter(isObject) : []
  const len = (v: unknown) => (Array.isArray(v) ? v.length : null)
  return {
    version: typeof m.modelVersion === 'string' ? m.modelVersion : null,
    algorithm: [m.algorithm, m.algorithmVersion].filter((x) => typeof x === 'string').join(' · ') || null,
    profiles: Array.isArray(m.profiles) ? m.profiles.map((p) => profileLabel[String(p)] ?? String(p)).join('、') : null,
    calibration: typeof m.scoreCalibration === 'string' ? m.scoreCalibration : null,
    runtime: runtime.format ? `${String(runtime.format).toUpperCase()}${runtime.opset ? ` · opset ${runtime.opset}` : ''}` : null,
    features: len(m.numericFeatures) !== null ? `数值 ${len(m.numericFeatures)} 项 · 类别 ${len(m.categoricalFeatures) ?? 0} 项` : null,
    scope: scope.length ? scope.map((s) => [s.addressFamily, s.transport, s.direction].filter(Boolean).join('/')).join('，') : null,
    createdAt: typeof m.createdAt === 'string' ? m.createdAt : null,
    candidateOnly: m.candidateOnly === true,
    hashes: Object.entries(m).filter(([k, v]) => k.endsWith('Sha256') && typeof v === 'string') as [string, string][],
  }
})
const datasetFacts = computed(() => {
  const p = dataset.value?.payload
  if (!isObject(p)) return { facts: [] as [string, string][], hashes: [] as [string, string][] }
  const scalar = (v: unknown) => typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean'
  const entries = Object.entries(p).filter(([k, v]) => scalar(v) && !['datasetKey', 'version'].includes(k))
  return {
    facts: entries.filter(([k]) => !k.endsWith('Sha256')).slice(0, 8).map(([k, v]) => [k, String(v)] as [string, string]),
    hashes: entries.filter(([k]) => k.endsWith('Sha256')).map(([k, v]) => [k, String(v)] as [string, string]),
  }
})
const validationExtra = computed(() => {
  const v = validation.value
  if (!v) return []
  return Object.entries(v).filter(([k, x]) => !['status', 'reasonCode'].includes(k) && x !== null && typeof x !== 'object').slice(0, 8)
})
const stateNote = computed(() => {
  if (props.kind === 'datasets') return retired.value ? { text: '已退役，不能再被新的评价计划引用。', tone: '' } : { text: '启用中，可被评价计划引用；被引用后不能退役。', tone: '' }
  switch (status.value) {
    case 'pending': return { text: '已登记为候选，尚未校验。校验确认 manifest 与 ONNX 制品符合契约，不产生发布资格。', tone: '' }
    case 'validated': return { text: '校验通过，模型仍只是候选；进入发布须经发布组合的评价、封存与独立批准。', tone: '' }
    case 'failed': return { text: `校验未通过${validation.value?.reasonCode ? `（${validation.value.reasonCode}）` : ''}，不能用于发布组合。可修正制品后重新登记或再次校验。`, tone: 'note-threat' }
    case 'retired': return { text: '已退役，不能再用于新的发布组合或研究回放。', tone: '' }
    default: return { text: `状态：${statusText.value}`, tone: '' }
  }
})

/* ---------------- 写操作 ---------------- */
const busy = ref(false)
const formError = useActionError()
const edit = reactive({ displayName: '', notes: '' })
const reason = ref('')
function enter(m: Mode) {
  mode.value = m
  formError.value = ''
  reason.value = ''
  if (m === 'edit' && row.value) Object.assign(edit, { displayName: row.value.displayName ?? '', notes: row.value.notes ?? '' })
}
async function run(call: () => Promise<unknown>, done: string, kind: 'model' | 'dataset') {
  busy.value = true
  formError.value = ''
  try {
    await call()
    toast(done)
    emit('changed')
    mode.value = 'view'
    await load()
  } catch (e) { formError.value = releaseErr(e, kind) } finally { busy.value = false }
}
function confirm() {
  const r = row.value
  if (!r) return
  const kind = props.kind === 'models' ? 'model' : 'dataset'
  if (mode.value === 'edit') {
    const displayName = edit.displayName.trim(), notes = edit.notes.trim()
    if (displayName.length > 128) { formError.value = '显示名最多 128 个字符。'; return }
    const body: { displayName?: string | null; notes?: string | null } = {}
    if (displayName !== (r.displayName ?? '')) body.displayName = displayName || null
    if (notes !== (r.notes ?? '')) body.notes = notes || null
    if (!Object.keys(body).length) { formError.value = '没有需要保存的修改。'; return }
    void run(() => (props.kind === 'models' ? releaseApi.updateModel(r.id, r.revision, body) : releaseApi.updateDataset(r.id, r.revision, body)), '已保存资料。', kind)
  } else if (mode.value === 'retire') {
    if (!reason.value.trim()) { formError.value = '请填写理由，理由会写入审计。'; return }
    void run(() => (props.kind === 'models' ? releaseApi.retireModel(r.id, r.revision, reason.value.trim()) : releaseApi.retireDataset(r.id, r.revision, reason.value.trim())), `已退役${noun.value}。`, kind)
  } else if (mode.value === 'validate') {
    void run(async () => {
      const v = await releaseApi.validateModel(r.id)
      validation.value = v
    }, '校验已完成，结果见下方。', kind)
  }
}
</script>

<template>
  <Drawer :open="!!id" :title="title" :kicker="noun" @close="emit('close')">
    <LoadState :loading="loading" :error="error">
      <template v-if="row">
        <template v-if="mode === 'view'">
          <p class="note mb-5" :class="stateNote.tone">{{ stateNote.text }}</p>
          <dl class="kv">
            <div><dt>状态</dt><dd><Tag pill :tone="catalogTone[status]" :label="statusText" /></dd></div>
            <div v-if="model"><dt>发布资格</dt><dd><Tag tone="mute" label="仅候选" /><span class="ml-2 text-[12px] text-ink-3">登记与校验都不授予发布资格</span></dd></div>
            <div><dt>显示名</dt><dd>{{ row.displayName || '—' }}</dd></div>
            <div><dt>说明</dt><dd class="whitespace-pre-line">{{ row.notes || '—' }}</dd></div>
            <div><dt>版本</dt><dd class="num">{{ row.version }}</dd></div>
            <div><dt>登记</dt><dd class="num">{{ fmtTime(row.createdAt) }}</dd></div>
            <div><dt>最近更新</dt><dd class="num">{{ fmtTime(row.updatedAt) }}</dd></div>
          </dl>

          <template v-if="model">
            <h3 class="section-title mt-8">校验结果</h3>
            <div v-if="validation" class="rounded border border-ink-hair px-4 py-3">
              <div class="flex items-center justify-between gap-3">
                <Tag :tone="validation.status === 'validated' ? 'ok' : 'threat'" :label="validation.status === 'validated' ? '校验通过' : '校验未通过'" />
                <span class="num text-[12px] text-ink-3">{{ MODEL_VALIDATION_PROFILE_ID }}</span>
              </div>
              <p v-if="validation.reasonCode" class="num mt-2 text-[12.5px] text-threat">{{ validation.reasonCode }}</p>
              <dl v-if="validationExtra.length" class="kv mt-2 text-[12.5px]">
                <div v-for="[k, v] in validationExtra" :key="k"><dt class="num">{{ k }}</dt><dd class="num break-all">{{ v }}</dd></div>
              </dl>
            </div>
            <p v-else class="text-[12.5px] text-ink-3">尚未校验。{{ validatable ? '可在下方发起校验。' : '' }}</p>

            <h3 class="section-title mt-8">manifest 摘要</h3>
            <dl v-if="manifest" class="kv">
              <div><dt>模型版本</dt><dd class="num">{{ manifest.version ?? '—' }}</dd></div>
              <div><dt>算法</dt><dd class="num">{{ manifest.algorithm ?? '—' }}</dd></div>
              <div><dt>快照类型</dt><dd>{{ manifest.profiles ?? '—' }}</dd></div>
              <div><dt>特征</dt><dd>{{ manifest.features ?? '—' }}</dd></div>
              <div><dt>适用范围</dt><dd class="num">{{ manifest.scope ?? '—' }}</dd></div>
              <div><dt>分数校准</dt><dd class="num">{{ manifest.calibration ?? '—' }}</dd></div>
              <div><dt>运行时</dt><dd class="num">{{ manifest.runtime ?? '—' }}</dd></div>
              <div><dt>candidateOnly</dt><dd>{{ manifest.candidateOnly ? '是（只能作为候选）' : '未声明' }}</dd></div>
              <div><dt>训练产出</dt><dd class="num">{{ manifest.createdAt ? fmtTime(manifest.createdAt) : '—' }}</dd></div>
            </dl>
            <p v-else class="text-[12.5px] text-ink-3">未保存 manifest 内容。</p>
          </template>

          <template v-else-if="dataset">
            <h3 class="section-title mt-8">manifest 摘要</h3>
            <dl v-if="datasetFacts.facts.length" class="kv">
              <div v-for="[k, v] in datasetFacts.facts" :key="k"><dt class="num">{{ k }}</dt><dd class="num break-all">{{ v }}</dd></div>
            </dl>
            <p v-else class="text-[12.5px] text-ink-3">manifest 中没有可摘要的字段。</p>
          </template>

          <details class="mt-7 text-[12.5px]">
            <summary class="cursor-pointer text-ink-3 hover:text-ink">技术细节</summary>
            <dl class="kv mt-2">
              <div><dt>{{ noun }} ID</dt><dd><IdText :value="row.id" /></dd></div>
              <div><dt>{{ model ? '模型键' : '数据集键' }}</dt><dd class="num break-all">{{ model ? model.modelKey : dataset?.datasetKey }}</dd></div>
              <div><dt>manifest 引用</dt><dd class="num break-all">{{ row.manifestRef }}</dd></div>
              <div><dt>manifest 摘要</dt><dd><IdText :value="row.manifestSha256" :length="16" /></dd></div>
              <div v-if="model"><dt>制品摘要</dt><dd><IdText :value="model.artifactSha256" :length="16" /></dd></div>
              <template v-if="manifest">
                <div v-for="[k, v] in manifest.hashes.filter(([key]) => key !== 'artifactSha256')" :key="k"><dt class="num">{{ k }}</dt><dd><IdText :value="v" :length="16" /></dd></div>
              </template>
              <div v-for="[k, v] in datasetFacts.hashes" :key="k"><dt class="num">{{ k }}</dt><dd><IdText :value="v" :length="16" /></dd></div>
              <div><dt>修订号</dt><dd class="num">{{ row.revision }}</dd></div>
            </dl>
          </details>
          <button v-if="manage && !retired" type="button" class="link mt-6 text-[12.5px] text-threat" @click="enter('retire')"><Archive :size="13" :stroke-width="1.5" />退役{{ noun }}</button>
        </template>

        <form v-else-if="mode === 'edit'" class="form" @submit.prevent="confirm">
          <p class="note">只能修改显示名与说明；manifest 内容不可修改，换版本须重新登记。</p>
          <label class="form-field"><span class="label">显示名</span><input v-model="edit.displayName" class="field" maxlength="128" :placeholder="`留空则显示${noun}键`" /></label>
          <label class="form-field"><span class="label">说明</span><textarea v-model="edit.notes" rows="4" maxlength="1000" class="field resize-none" /></label>
        </form>

        <div v-else-if="mode === 'validate'" class="form">
          <p class="note">按固定的校验配置核对 manifest、ONNX 制品与特征契约。校验只改变校验状态，不产生发布资格。</p>
          <label class="form-field"><span class="label">校验配置</span>
            <select class="field num" disabled aria-label="校验配置"><option :value="MODEL_VALIDATION_PROFILE_ID">{{ MODEL_VALIDATION_PROFILE_ID }}</option></select>
            <span class="form-hint">当前只支持这一种配置，不能选择其他配置。</span>
          </label>
        </div>

        <div v-else>
          <p class="note note-threat mb-5">
            退役后{{ noun }}不能再被新的{{ model ? '发布组合、策略或研究回放' : '评价计划' }}引用，已有记录保留。
            仍被引用时退役会被拒绝（409 RESOURCE_IN_USE）。
          </p>
          <label class="form-field"><span class="label">理由</span><textarea v-model="reason" rows="3" maxlength="1000" class="field resize-none" placeholder="写入审计" /></label>
        </div>
        <p v-if="formError" class="mt-4 text-[12.5px] text-threat" role="alert">{{ formError }}</p>
      </template>
    </LoadState>

    <template v-if="row && (mode !== 'view' || manage || validatable)" #foot>
      <template v-if="mode === 'view'">
        <button v-if="manage && !retired" type="button" class="act-ghost" @click="enter('edit')"><Pencil :size="14" :stroke-width="1.5" />编辑资料</button>
        <button v-if="validatable" type="button" class="act" @click="enter('validate')"><FlaskConical :size="14" :stroke-width="1.5" />发起校验</button>
      </template>
      <template v-else>
        <button type="button" class="act-ghost" :disabled="busy" @click="enter('view')">返回</button>
        <button type="button" :class="mode === 'retire' ? 'act-danger' : 'act'" :disabled="busy" @click="confirm">
          {{ mode === 'edit' ? '保存资料' : mode === 'validate' ? '开始校验' : `确认退役` }}
        </button>
      </template>
    </template>
  </Drawer>
</template>
