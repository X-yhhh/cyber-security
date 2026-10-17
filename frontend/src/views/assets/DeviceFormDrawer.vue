<script setup lang="ts">
import { useActionError } from '@/composables/actionError'
/**
 * 登记传感器 / 执行器（sensor.manage，接口设计第 2 节 POST /sensors、/executors）。
 *
 * 传感器需要采集域 ID（默认生成新的 UUID），执行器需要能力探针引用；探针引用不等于已批准能力。
 * 登记成功的响应带一次性机器凭据，由父页面在单独的抽屉里显示一次。
 */
import { computed, reactive, ref, watch } from 'vue'
import Drawer from '@/components/Drawer.vue'
import { guardAssetEnvLabel } from '@/api/types'
import { isUuid } from '@/api/v2/detect'
import { assetTitle, platformLabel, type Asset, type ExecutorCreate, type Platform, type SensorCreate } from '@/api/v2/assets'

const props = defineProps<{ open: boolean; assets: Asset[]; busy?: boolean; initialKind?: 'sensors' | 'executors'; initialAsset?: string }>()
const emit = defineEmits<{ sensor: [body: SensorCreate]; executor: [body: ExecutorCreate]; close: [] }>()

const kind = ref<'sensors' | 'executors'>('sensors')
const form = reactive({ assetId: '', manualAsset: '', platform: 'macos' as Platform, captureScopeId: '', capabilityProbeRef: '', displayName: '', notes: '' })
const error = useActionError()
/** 退役资产不能接入新设备，下拉中不列出。 */
const choices = computed(() => props.assets.filter((a) => a.status !== 'retired'))

watch(() => props.open, (v) => {
  if (!v) return
  kind.value = props.initialKind ?? 'sensors'
  const preset = choices.value.find((a) => a.id === props.initialAsset)
  Object.assign(form, { assetId: preset?.id ?? '', manualAsset: '', platform: (preset?.labels?.platform as Platform) ?? 'macos', captureScopeId: crypto.randomUUID(), capabilityProbeRef: '', displayName: '', notes: '' })
  error.value = ''
}, { immediate: true })
watch(() => form.assetId, (id) => {
  const p = choices.value.find((a) => a.id === id)?.labels?.platform
  if (p === 'macos' || p === 'windows') form.platform = p
})
const regen = () => { form.captureScopeId = crypto.randomUUID() }

function submit() {
  const assetId = (props.assets.length ? form.assetId : form.manualAsset).trim().toLowerCase()
  if (!isUuid(assetId)) { error.value = props.assets.length ? '请选择资产。' : '资产 ID 须为 UUID。'; return }
  const extra = { ...(form.displayName.trim() ? { displayName: form.displayName.trim() } : {}), ...(form.notes.trim() ? { notes: form.notes.trim() } : {}) }
  if (kind.value === 'sensors') {
    if (!isUuid(form.captureScopeId)) { error.value = '采集域 ID 须为 UUID。'; return }
    error.value = ''
    emit('sensor', { assetId, platform: form.platform, captureScopeId: form.captureScopeId.trim().toLowerCase(), ...extra })
  } else {
    const probe = form.capabilityProbeRef.trim()
    if (!probe) { error.value = '请填写能力探针引用。'; return }
    error.value = ''
    emit('executor', { assetId, platform: form.platform, capabilityProbeRef: probe, ...extra })
  }
}
</script>

<template>
  <Drawer :open="open" title="登记设备" kicker="传感器与执行器" @close="emit('close')">
    <form class="form" @submit.prevent="submit">
      <div class="chips" role="group" aria-label="设备类型">
        <button type="button" class="chip" :aria-pressed="kind === 'sensors'" @click="kind = 'sensors'">传感器（采集）</button>
        <button type="button" class="chip" :aria-pressed="kind === 'executors'" @click="kind = 'executors'">执行器（处置）</button>
      </div>
      <p class="note">{{ kind === 'sensors' ? '传感器登记后即可用凭据接入，但须有已批准的采集配置才能上报观察。' : '执行器登记后为「待心跳确认」，上报能力前不领取命令；登记不等于已批准执行。' }}凭据只在提交后显示一次。</p>

      <label class="form-field"><span class="label">资产</span>
        <select v-if="assets.length" v-model="form.assetId" class="field">
          <option value="" disabled>选择资产</option>
          <option v-for="a in choices" :key="a.id" :value="a.id">{{ assetTitle(a) }} · {{ guardAssetEnvLabel[a.environment] ?? a.environment }}{{ a.status === 'disabled' ? '（已停用）' : '' }}</option>
        </select>
        <input v-else v-model="form.manualAsset" class="field num text-[12px]" placeholder="资产 ID（UUID）" />
      </label>
      <label class="form-field"><span class="label">平台</span>
        <select v-model="form.platform" class="field"><option v-for="(l, k) in platformLabel" :key="k" :value="k">{{ l }}</option></select>
        <span class="form-hint">默认取资产登记的平台。</span>
      </label>
      <label v-if="kind === 'sensors'" class="form-field"><span class="label">采集域 ID</span>
        <span class="flex gap-2"><input v-model="form.captureScopeId" class="field num flex-1 text-[12px]" /><button type="button" class="act-ghost" @click="regen">重新生成</button></span>
      </label>
      <label v-else class="form-field"><span class="label">能力探针引用</span>
        <input v-model="form.capabilityProbeRef" class="field num" maxlength="1000" placeholder="探针报告的受控引用" />
        <span class="form-hint">只是探针引用，不代表能力已批准。</span>
      </label>
      <label class="form-field"><span class="label">显示名</span><input v-model="form.displayName" class="field" maxlength="128" placeholder="可留空" /></label>
      <label class="form-field"><span class="label">说明</span><textarea v-model="form.notes" rows="2" maxlength="1000" class="field resize-none" placeholder="可留空" /></label>
      <p v-if="error" class="text-[12.5px] text-threat" role="alert">{{ error }}</p>
    </form>
    <template #foot>
      <button type="button" class="act-ghost" @click="emit('close')">取消</button>
      <button type="button" class="act" :disabled="busy" @click="submit">登记并签发凭据</button>
    </template>
  </Drawer>
</template>
