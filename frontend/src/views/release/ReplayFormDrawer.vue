<script setup lang="ts">
import { useActionError } from '@/composables/actionError'
/**
 * 新建研究回放（evaluation.run）：选择已校验模型与其已审核策略，登记固定 1 倍速的研究回放。
 * 后端要求同一模型与策略存在已批准的研究环境组合（否则 REPLAY_BUNDLE_NOT_APPROVED）；请求中不含任何真实目标引用。
 * 回放的开始、完成与失败由受控 runner 登记，浏览器不重放流量。
 */
import { computed, reactive, ref, watch } from 'vue'
import Drawer from '@/components/Drawer.vue'
import { toast } from '@/composables/toast'
import { isUuid } from '@/api/v2/detect'
import { isSha256, releaseApi, type ReleaseModel, type ReleasePolicy } from '@/api/v2/release'
import { modelTitle, policyTitle, releaseErr } from './shared'

const props = defineProps<{ open: boolean }>()
const emit = defineEmits<{ created: [id: string]; close: [] }>()

const models = ref<ReleaseModel[]>([])
const policies = ref<ReleasePolicy[]>([])
const form = reactive({ scenarioId: '', scenarioSha256: '', modelId: '', policyId: '' })
const error = useActionError()
const busy = ref(false)
watch(() => props.open, (v) => {
  if (!v) return
  Object.assign(form, { scenarioId: '', scenarioSha256: '', modelId: '', policyId: '' })
  error.value = ''
  Promise.all([
    releaseApi.listModels({ status: 'validated', limit: 200 }).then((p) => { models.value = p.items }),
    releaseApi.listPolicies({ status: 'reviewed', limit: 200 }).then((p) => { policies.value = p.items }),
  ]).catch((e: unknown) => { error.value = releaseErr(e) })
})
const policyOptions = computed(() => policies.value.filter((p) => p.modelId === form.modelId))
watch(() => form.modelId, () => { if (!policyOptions.value.some((p) => p.id === form.policyId)) form.policyId = '' })

async function submit() {
  const scenarioId = form.scenarioId.trim(), sha = form.scenarioSha256.trim().toLowerCase()
  if (!isUuid(scenarioId)) { error.value = '场景 ID 须为 UUID。'; return }
  if (!isSha256(sha)) { error.value = '场景摘要须为 64 位小写十六进制。'; return }
  if (!form.modelId || !form.policyId) { error.value = '请选择模型与策略。'; return }
  error.value = ''
  busy.value = true
  try {
    const r = await releaseApi.createReplayRun({ scenarioId, scenarioSha256: sha, modelId: form.modelId, policyId: form.policyId, speed: 1 })
    toast('已登记研究回放，等待 runner 开始。')
    emit('created', r.id)
  } catch (e) { error.value = releaseErr(e) } finally { busy.value = false }
}
</script>

<template>
  <Drawer :open="open" title="新建研究回放" kicker="验证记录 · 研究回放" @close="emit('close')">
    <form class="form" @submit.prevent="submit">
      <p class="note">研究回放只用于研究环境，须有同一模型与策略的已批准研究组合；不包含任何真实目标，也不授予执行权。</p>
      <div class="grid grid-cols-[minmax(0,1fr)] gap-4">
        <label class="form-field"><span class="label">场景 ID</span><input v-model="form.scenarioId" class="field num" placeholder="冻结场景的 UUID" autocomplete="off" /></label>
        <label class="form-field"><span class="label">场景摘要</span><input v-model="form.scenarioSha256" class="field num" maxlength="64" placeholder="64 位小写十六进制" autocomplete="off" /></label>
      </div>
      <label class="form-field"><span class="label">模型（已校验）</span>
        <select v-model="form.modelId" class="field">
          <option value="">{{ models.length ? '选择模型' : '没有已校验的模型' }}</option>
          <option v-for="m in models" :key="m.id" :value="m.id">{{ modelTitle(m) }} · {{ m.version }}</option>
        </select>
      </label>
      <label class="form-field"><span class="label">决策策略（已审核）</span>
        <select v-model="form.policyId" class="field" :disabled="!form.modelId">
          <option value="">{{ form.modelId && !policyOptions.length ? '该模型没有已审核的策略' : '选择策略' }}</option>
          <option v-for="p in policyOptions" :key="p.id" :value="p.id">{{ policyTitle(p) }} · {{ p.version }}</option>
        </select>
      </label>
      <label class="form-field"><span class="label">倍速</span>
        <select class="field num" disabled aria-label="倍速"><option>1×</option></select>
        <span class="form-hint">研究回放固定 1 倍速，不能加速。</span></label>
      <p v-if="error" class="text-[12.5px] text-threat" role="alert">{{ error }}</p>
    </form>
    <template #foot>
      <button type="button" class="act-ghost" @click="emit('close')">取消</button>
      <button type="button" class="act" :disabled="busy" @click="submit">登记回放</button>
    </template>
  </Drawer>
</template>
