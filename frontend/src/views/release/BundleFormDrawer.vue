<script setup lang="ts">
import { useActionError } from '@/composables/actionError'
/**
 * 申请发布组合（bundle.request）：选择已校验模型、已审核策略与评价计划，组成不可变的候选组合。
 *
 * - 能力集合必须与策略声明的 supportedCapabilityIds 完全一致（后端校验），因此随策略自动带出、不可单独增删。
 * - 评价计划默认取策略绑定的计划；冻结计划（P6 原件）可带出特征档案与提取器摘要，其余情况手填。
 * - 协议版本默认取当前控制面接受的版本，可修改；不一致时后端拒绝（CONTRACT_UNSUPPORTED）。
 * 选项列表只在表单打开时读取；没有评价读取权限时评价计划改为手填 ID。
 */
import { computed, reactive, ref, watch } from 'vue'
import Drawer from '@/components/Drawer.vue'
import Tag from '@/components/Tag.vue'
import { toast } from '@/composables/toast'
import { can } from '@/api/session'
import { isUuid } from '@/api/v2/detect'
import { isSha256, releaseApi, type BundleRequest, type EvaluationPlan, type ReleaseModel, type ReleasePolicy } from '@/api/v2/release'
import { capabilityTone } from '@/data/tones'
import { capabilityName, DEFAULT_PROTOCOL_VERSIONS, ensureIndex, envLabel, isObject, levelLabel, modeLabel, modelTitle, policyTitle, releaseErr, releaseIndex } from './shared'

const props = defineProps<{ open: boolean }>()
const emit = defineEmits<{ created: [id: string]; close: [] }>()

const models = ref<ReleaseModel[]>([])
const policies = ref<ReleasePolicy[]>([])
const plans = ref<EvaluationPlan[] | null>(null)
const loadError = ref('')
const form = reactive({
  modelId: '', policyId: '', evaluationPlanId: '', environment: 'lab' as BundleRequest['environment'],
  featureProfileSha256: '', extractorSha256: '', versions: { ...DEFAULT_PROTOCOL_VERSIONS },
})
const error = useActionError()
const busy = ref(false)

watch(() => props.open, (v) => {
  if (!v) return
  Object.assign(form, { modelId: '', policyId: '', evaluationPlanId: '', environment: 'lab', featureProfileSha256: '', extractorSha256: '', versions: { ...DEFAULT_PROTOCOL_VERSIONS } })
  error.value = ''
  loadError.value = ''
  void ensureIndex('capabilities')
  Promise.all([
    releaseApi.listModels({ status: 'validated', limit: 200 }).then((p) => { models.value = p.items }),
    releaseApi.listPolicies({ status: 'reviewed', limit: 200 }).then((p) => { policies.value = p.items }),
    can('evaluation.read') ? releaseApi.listEvaluationPlans({ limit: 200 }).then((p) => { plans.value = p.items }) : Promise.resolve(),
  ]).catch((e: unknown) => { loadError.value = releaseErr(e) })
})

const policyOptions = computed(() => policies.value.filter((p) => !form.modelId || p.modelId === form.modelId))
const policy = computed(() => policies.value.find((p) => p.id === form.policyId) ?? null)
const capabilityIds = computed(() => policy.value?.definition?.supportedCapabilityIds ?? [])
const plan = computed(() => plans.value?.find((p) => p.id === form.evaluationPlanId) ?? null)
const frozen = computed(() => {
  const payload = plan.value?.payload
  if (!isObject(payload) || payload.kind !== 'p6-frozen' || !isObject(payload.plan)) return null
  return payload.plan
})

watch(() => form.modelId, () => { if (policy.value && policy.value.modelId !== form.modelId) form.policyId = '' })
watch(policy, (p) => { if (p?.planId) form.evaluationPlanId = p.planId })
watch(frozen, (f) => {
  if (!f) return
  if (typeof f.featureProfileSha256 === 'string') form.featureProfileSha256 = f.featureProfileSha256
  if (typeof f.extractorSha256 === 'string') form.extractorSha256 = f.extractorSha256
})

async function submit() {
  const feature = form.featureProfileSha256.trim().toLowerCase(), extractor = form.extractorSha256.trim().toLowerCase()
  if (!form.modelId) { error.value = '请选择已校验的模型。'; return }
  if (!form.policyId) { error.value = '请选择该模型的已审核策略。'; return }
  if (!isUuid(form.evaluationPlanId.trim())) { error.value = '请选择或填写评价计划 ID。'; return }
  if (!isSha256(feature) || !isSha256(extractor)) { error.value = '特征档案与提取器摘要须为 64 位小写十六进制。'; return }
  if (!capabilityIds.value.length) { error.value = '所选策略没有声明支持的能力，不能组成发布组合。'; return }
  const versions = Object.fromEntries(Object.entries(form.versions).map(([k, v]) => [k, v.trim()]))
  if (Object.values(versions).some((v) => !v)) { error.value = '四项协议版本都必填。'; return }
  const body: BundleRequest = {
    modelId: form.modelId, policyId: form.policyId, evaluationPlanId: form.evaluationPlanId.trim(), environment: form.environment,
    featureProfileSha256: feature, extractorSha256: extractor, protocolVersions: versions, capabilityIds: [...capabilityIds.value],
  }
  error.value = ''
  busy.value = true
  try {
    const r = await releaseApi.requestBundle(body)
    toast('已申请发布组合，状态为候选。请导入评价报告后封存。')
    emit('created', r.id)
  } catch (e) { error.value = releaseErr(e) } finally { busy.value = false }
}
const VERSION_LABELS: Record<string, string> = { observation: '观察契约', decision: '决策契约', evaluation: '评价口径', health: '采集健康' }
</script>

<template>
  <Drawer :open="open" title="申请发布组合" kicker="发布管理" @close="emit('close')">
    <form class="form" @submit.prevent="submit">
      <p class="note">组合一经申请不可修改；仅改阈值也要用新策略重新申请。申请不授予执行权，须经评价、封存与独立批准。</p>
      <p v-if="loadError" class="text-[12.5px] text-threat" role="alert">{{ loadError }}</p>

      <label class="form-field"><span class="label">模型（已校验）</span>
        <select v-model="form.modelId" class="field">
          <option value="">{{ models.length ? '选择模型' : '没有已校验的模型' }}</option>
          <option v-for="m in models" :key="m.id" :value="m.id">{{ modelTitle(m) }} · {{ m.version }}</option>
        </select>
      </label>
      <label class="form-field"><span class="label">决策策略（已审核）</span>
        <select v-model="form.policyId" class="field" :disabled="!form.modelId">
          <option value="">{{ form.modelId && !policyOptions.length ? '该模型没有已审核的策略' : '选择策略' }}</option>
          <option v-for="p in policyOptions" :key="p.id" :value="p.id">{{ policyTitle(p) }} · {{ p.version }} · {{ modeLabel[p.definition?.mode] ?? p.definition?.mode }}</option>
        </select>
        <span class="form-hint">策略须绑定同一模型与评价计划；草稿策略不能进入组合。</span>
      </label>

      <div v-if="policy" class="form-field">
        <span class="label">能力（随策略带出）</span>
        <ul class="space-y-1 rounded border border-ink-hair px-3 py-2">
          <li v-for="id in capabilityIds" :key="id" class="flex items-center gap-2 text-[12.5px]">
            <span class="num">{{ capabilityName(id) }}</span>
            <Tag v-if="releaseIndex.capabilities.get(id)" :tone="capabilityTone[releaseIndex.capabilities.get(id)!.level]" :label="levelLabel[releaseIndex.capabilities.get(id)!.level] ?? releaseIndex.capabilities.get(id)!.level" />
          </li>
          <li v-if="!capabilityIds.length" class="text-[12.5px] text-ink-3">策略未声明能力</li>
        </ul>
        <span class="form-hint">必须与策略声明的支持能力完全一致，不能单独增删。</span>
      </div>

      <label class="form-field"><span class="label">评价计划</span>
        <select v-if="plans" v-model="form.evaluationPlanId" class="field num">
          <option value="">选择评价计划</option>
          <option v-for="p in plans" :key="p.id" :value="p.id">{{ p.planKey }} · {{ p.version }}</option>
        </select>
        <input v-else v-model="form.evaluationPlanId" class="field num" placeholder="评价计划 ID" autocomplete="off" />
        <span class="form-hint">默认取策略绑定的计划。{{ plans ? '' : '没有评价读取权限，请手填 ID。' }}</span>
      </label>

      <label class="form-field"><span class="label">环境</span>
        <select v-model="form.environment" class="field">
          <option v-for="e in ['research', 'lab', 'authorized'] as const" :key="e" :value="e">{{ envLabel[e] }}</option>
        </select>
        <span class="form-hint">研究组合只用于研究回放；lab 与授权组合激活时按资产环境核验能力等级。</span>
      </label>

      <label class="form-field"><span class="label">特征档案摘要</span>
        <input v-model="form.featureProfileSha256" class="field num" maxlength="64" placeholder="64 位小写十六进制" autocomplete="off" />
      </label>
      <label class="form-field"><span class="label">提取器摘要</span>
        <input v-model="form.extractorSha256" class="field num" maxlength="64" placeholder="64 位小写十六进制" autocomplete="off" />
        <span class="form-hint">{{ frozen ? '已从冻结评价计划带出，可核对。' : '须与模型契约登记的提取器一致。' }}</span>
      </label>

      <fieldset class="form-field">
        <legend class="label mb-2">协议版本</legend>
        <div class="grid grid-cols-[5rem_minmax(0,1fr)] items-center gap-x-3 gap-y-2">
          <template v-for="(_, k) in form.versions" :key="k">
            <span class="text-[12.5px] text-ink-3">{{ VERSION_LABELS[k] ?? k }}</span>
            <input v-model="form.versions[k]" class="field num text-[12px]" autocomplete="off" />
          </template>
        </div>
        <span class="form-hint">默认取当前控制面接受的版本；不一致时申请会被拒绝。</span>
      </fieldset>

      <p v-if="error" class="text-[12.5px] text-threat" role="alert">{{ error }}</p>
    </form>
    <template #foot>
      <button type="button" class="act-ghost" @click="emit('close')">取消</button>
      <button type="button" class="act" :disabled="busy" @click="submit">申请组合</button>
    </template>
  </Drawer>
</template>
