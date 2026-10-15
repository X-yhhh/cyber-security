<script setup lang="ts">
/**
 * 登记能力（bundle.request）。字段与后端 GuardCatalog.capability 一致：
 * - 研究级不需要平台报告；其余等级须提供签名平台报告引用，报告中的 capability 必须等于去掉证据位置后的请求体。
 * - 范围缺省为「对端 + 服务端口」；「对端全部入站」只接受 macOS 入站能力，并须带保护集摘要与签名豁免报告。
 * - 地址族与协议当前契约固定为 ipv4 / tcp。
 */
import { computed, reactive, ref, watch } from 'vue'
import Drawer from '@/components/Drawer.vue'
import { toast } from '@/composables/toast'
import { isSha256, releaseApi, type CapabilityRegistration } from '@/api/v2/release'
import { FAMILIES, familyLabel, levelLabel, profileLabel, releaseErr, scopeLabel } from './shared'

const props = defineProps<{ open: boolean }>()
const emit = defineEmits<{ created: [id: string]; close: [] }>()

const empty = () => ({
  capabilityKey: '', version: '', platform: 'macos', adapterVersion: '', direction: 'inbound', family: 'port_scan' as CapabilityRegistration['family'],
  profile: 'flow-prefix-v1' as CapabilityRegistration['profile'], behaviorScope: '', maxMs: '10000', level: 'alert_only' as CapabilityRegistration['level'],
  scope: 'peer_service' as 'peer_service' | 'peer_inbound', evidenceRef: '', evidenceSha256: '', runnerIdentity: '',
  protectionSetSha256: '', exemptionEvidenceRef: '', exemptionEvidenceSha256: '',
})
const form = reactive(empty())
const error = ref('')
const busy = ref(false)
watch(() => props.open, (v) => { if (v) { Object.assign(form, empty()); error.value = '' } })
const inbound = computed(() => form.scope === 'peer_inbound')
watch(() => form.scope, (s) => { if (s === 'peer_inbound') { form.platform = 'macos'; form.direction = 'inbound' } })

async function submit() {
  const t = (s: string) => s.trim()
  const scope = form.behaviorScope.split(/[,，\s]+/).map(t).filter(Boolean)
  const maxMs = Number(form.maxMs)
  if (!t(form.capabilityKey) || !t(form.version) || !t(form.adapterVersion)) { error.value = '能力键、版本与适配器版本都必填。'; return }
  if (!scope.length) { error.value = '请至少填写一项行为范围。'; return }
  if (!Number.isInteger(maxMs) || maxMs <= 0) { error.value = '时延上限须为正整数（毫秒）。'; return }
  if (!t(form.evidenceRef) || !t(form.runnerIdentity) || !isSha256(t(form.evidenceSha256).toLowerCase())) { error.value = '请填写证据引用、64 位证据摘要与签发身份。'; return }
  const body: CapabilityRegistration = {
    capabilityKey: t(form.capabilityKey), version: t(form.version), platform: form.platform, adapterVersion: t(form.adapterVersion),
    addressFamily: 'ipv4', transport: 'tcp', direction: form.direction, family: form.family, profile: form.profile,
    behaviorScope: scope, latencyLimits: { maxMs }, level: form.level,
    evidenceRef: t(form.evidenceRef), evidenceSha256: t(form.evidenceSha256).toLowerCase(), runnerIdentity: t(form.runnerIdentity),
  }
  if (inbound.value) {
    const ps = t(form.protectionSetSha256).toLowerCase(), es = t(form.exemptionEvidenceSha256).toLowerCase()
    if (!isSha256(ps) || !isSha256(es) || !t(form.exemptionEvidenceRef)) { error.value = '「对端全部入站」须填写保护集摘要、豁免报告引用与摘要。'; return }
    Object.assign(body, { scope: 'peer_inbound', protectionSetSha256: ps, exemptionEvidenceRef: t(form.exemptionEvidenceRef), exemptionEvidenceSha256: es })
  }
  error.value = ''
  busy.value = true
  try {
    const r = await releaseApi.registerCapability(body)
    toast(`已登记能力，等级为「${levelLabel[r.level] ?? r.level}」。`)
    emit('created', r.id)
  } catch (e) { error.value = releaseErr(e) } finally { busy.value = false }
}
</script>

<template>
  <Drawer :open="open" title="登记能力" kicker="发布管理" @close="emit('close')">
    <form class="form" @submit.prevent="submit">
      <p class="note">等级按平台、适配器、方向、类别与快照类型分别取得，不能复制另一平台的成绩。研究级以外须有签名平台报告，报告内容与本表一致才会登记。</p>
      <div class="grid grid-cols-2 gap-4">
        <label class="form-field"><span class="label">能力键</span><input v-model="form.capabilityKey" class="field num" maxlength="128" autocomplete="off" /></label>
        <label class="form-field"><span class="label">版本</span><input v-model="form.version" class="field num" maxlength="64" autocomplete="off" /></label>
      </div>
      <div class="grid grid-cols-2 gap-4">
        <label class="form-field"><span class="label">等级</span>
          <select v-model="form.level" class="field"><option v-for="l in ['research', 'alert_only', 'lab_auto', 'authorized_auto'] as const" :key="l" :value="l">{{ levelLabel[l] }}</option></select>
        </label>
        <label class="form-field"><span class="label">执行范围</span>
          <select v-model="form.scope" class="field"><option v-for="s in ['peer_service', 'peer_inbound'] as const" :key="s" :value="s">{{ scopeLabel[s] }}</option></select>
        </label>
      </div>
      <p v-if="form.level === 'lab_auto'" class="form-hint -mt-2">lab 自动（仅 lab）只对 lab 资产有效，不适用于真实主机。</p>
      <div class="grid grid-cols-2 gap-4">
        <label class="form-field"><span class="label">平台</span>
          <select v-model="form.platform" class="field" :disabled="inbound"><option value="macos">macOS</option><option value="windows">Windows</option></select>
        </label>
        <label class="form-field"><span class="label">适配器版本</span><input v-model="form.adapterVersion" class="field num" maxlength="64" autocomplete="off" /></label>
      </div>
      <div class="grid grid-cols-3 gap-4">
        <label class="form-field"><span class="label">攻击类别</span>
          <select v-model="form.family" class="field"><option v-for="f in FAMILIES" :key="f" :value="f">{{ familyLabel[f] }}</option></select>
        </label>
        <label class="form-field"><span class="label">快照类型</span>
          <select v-model="form.profile" class="field"><option v-for="p in ['flow-prefix-v1', 'flow-final-v1'] as const" :key="p" :value="p">{{ profileLabel[p] }}</option></select>
        </label>
        <label class="form-field"><span class="label">方向</span>
          <select v-model="form.direction" class="field" :disabled="inbound"><option value="inbound">入站</option><option value="outbound">出站</option></select>
        </label>
      </div>
      <p class="form-hint -mt-2">地址族与协议由当前契约固定为 ipv4 / tcp。</p>
      <div class="grid grid-cols-[minmax(0,1fr)_8rem] gap-4">
        <label class="form-field"><span class="label">行为范围</span><input v-model="form.behaviorScope" class="field num" placeholder="如 slowloris, slowhttptest" autocomplete="off" />
          <span class="form-hint">逗号分隔，须与平台报告一致。</span></label>
        <label class="form-field"><span class="label">时延上限（ms）</span><input v-model="form.maxMs" class="field num" inputmode="numeric" /></label>
      </div>

      <h3 class="section-title mt-2">证据</h3>
      <label class="form-field"><span class="label">平台报告引用</span><input v-model="form.evidenceRef" class="field num" maxlength="512" placeholder="受控制品根内的相对路径" autocomplete="off" /></label>
      <label class="form-field"><span class="label">平台报告 SHA-256</span><input v-model="form.evidenceSha256" class="field num" maxlength="64" placeholder="64 位小写十六进制" autocomplete="off" /></label>
      <label class="form-field"><span class="label">签发身份</span><input v-model="form.runnerIdentity" class="field num" maxlength="128" autocomplete="off" /></label>
      <template v-if="inbound">
        <label class="form-field"><span class="label">保护集摘要</span><input v-model="form.protectionSetSha256" class="field num" maxlength="64" autocomplete="off" /></label>
        <label class="form-field"><span class="label">豁免报告引用</span><input v-model="form.exemptionEvidenceRef" class="field num" maxlength="512" autocomplete="off" /></label>
        <label class="form-field"><span class="label">豁免报告 SHA-256</span><input v-model="form.exemptionEvidenceSha256" class="field num" maxlength="64" autocomplete="off" />
          <span class="form-hint">「对端全部入站」只接受 macOS（PF）入站能力，豁免报告须通过且保护集摘要一致。</span></label>
      </template>
      <p v-if="error" class="text-[12.5px] text-threat" role="alert">{{ error }}</p>
    </form>
    <template #foot>
      <button type="button" class="act-ghost" @click="emit('close')">取消</button>
      <button type="button" class="act" :disabled="busy" @click="submit">登记能力</button>
    </template>
  </Drawer>
</template>
