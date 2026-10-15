<script setup lang="ts">
/**
 * 资产授权申请（authorization.request，接口设计第 2 节 POST /assets/{id}/authorizations）。
 *
 * 字段与后端校验一致：接口 1—16 个（字母数字与 _ . : -，最长 96）；执行范围最多 32 条，只支持 TCP / IPv4，
 * peer_inbound 必须为入站且不带端口，peer_service 端口 1—65535；生效时间早于到期时间且到期晚于现在；
 * 证明只填受控引用，不贴原文。申请为待批准状态，不创建防火墙规则，须由申请人以外的审批人批准。
 */
import { computed, reactive, ref, watch } from 'vue'
import { Plus, Trash2 } from 'lucide-vue-next'
import Drawer from '@/components/Drawer.vue'
import { isUuid } from '@/api/v2/detect'
import {
  AUTHORIZATION_FIELDS, INTERFACE_RE, assetsApi, directionLabel, scopeLabel, type AuthorizationRequest,
} from '@/api/v2/assets'
import { can } from '@/api/session'
import { guardCapabilityLevelLabel, type GuardCapability } from '@/api/types'

const props = defineProps<{ open: boolean; assetName: string; busy?: boolean }>()
const emit = defineEmits<{ submit: [body: AuthorizationRequest]; close: [] }>()

interface Row { capabilityId: string; direction: 'inbound' | 'outbound'; scope: 'peer_service' | 'peer_inbound'; servicePort: string }
const blankRow = (): Row => ({ capabilityId: '', direction: 'inbound', scope: 'peer_service', servicePort: '' })

/** datetime-local 的本地时间字符串。 */
const local = (d: Date) => {
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`
}
const form = reactive({ interfaces: '', observationAllowed: true, validFrom: '', validUntil: '', evidenceRef: '', rows: [] as Row[] })
const error = ref('')

/** 能力目录为全局对象；读取失败（资产范围身份）时退回手填能力 ID。 */
const capabilities = ref<GuardCapability[]>([])
let capsLoaded = false
watch(() => props.open, (v) => {
  if (!v) return
  const now = new Date()
  Object.assign(form, { interfaces: '', observationAllowed: true, validFrom: local(now), validUntil: local(new Date(now.getTime() + 30 * 86_400_000)), evidenceRef: '', rows: [] })
  error.value = ''
  if (!capsLoaded && can('resource.read')) {
    capsLoaded = true
    assetsApi.listCapabilities().then((p) => { capabilities.value = p.items }).catch(() => { /* 退回手填 */ })
  }
}, { immediate: true })

const capLabel = (c: GuardCapability) => `${c.capabilityKey} ${c.version} · ${guardCapabilityLevelLabel[c.level] ?? c.level}`
const interfaceList = computed(() => form.interfaces.split(/[\s,，]+/).map((s) => s.trim()).filter(Boolean))
function addRow() { if (form.rows.length < 32) form.rows.push(blankRow()) }
function setScope(r: Row, scope: Row['scope']) {
  r.scope = scope
  if (scope === 'peer_inbound') { r.direction = 'inbound'; r.servicePort = '' }
}

function submit() {
  const ifs = interfaceList.value
  if (!ifs.length || ifs.length > 16) { error.value = '接口须填写 1—16 个。'; return }
  const badIf = ifs.find((i) => !INTERFACE_RE.test(i))
  if (badIf) { error.value = `接口标识「${badIf}」不合法：只能包含字母、数字与 _ . : -，最长 96 个字符。`; return }
  const from = new Date(form.validFrom), until = new Date(form.validUntil)
  if (Number.isNaN(from.getTime()) || Number.isNaN(until.getTime())) { error.value = '请填写生效与到期时间。'; return }
  if (until <= from) { error.value = '到期时间须晚于生效时间。'; return }
  if (until.getTime() <= Date.now()) { error.value = '到期时间须晚于现在。'; return }
  const evidence = form.evidenceRef.trim()
  if (!evidence) { error.value = '请填写授权证明引用。'; return }
  const scopes: Record<string, unknown>[] = []
  for (const [i, r] of form.rows.entries()) {
    if (!isUuid(r.capabilityId)) { error.value = `第 ${i + 1} 条执行范围：请选择能力。`; return }
    const base = { capabilityId: r.capabilityId.trim().toLowerCase(), direction: r.direction, transport: 'tcp', addressFamily: 'ipv4' }
    if (r.scope === 'peer_inbound') scopes.push({ ...base, scope: 'peer_inbound', direction: 'inbound', servicePort: null })
    else {
      const port = Number(r.servicePort)
      if (!Number.isInteger(port) || port < 1 || port > 65535) { error.value = `第 ${i + 1} 条执行范围：端口须为 1—65535 的整数。`; return }
      scopes.push({ ...base, scope: 'peer_service', servicePort: port })
    }
  }
  error.value = ''
  emit('submit', {
    [AUTHORIZATION_FIELDS.interfaces]: ifs,
    [AUTHORIZATION_FIELDS.observationAllowed]: form.observationAllowed,
    [AUTHORIZATION_FIELDS.executionScopes]: scopes,
    [AUTHORIZATION_FIELDS.validFrom]: from.toISOString(),
    [AUTHORIZATION_FIELDS.validUntil]: until.toISOString(),
    [AUTHORIZATION_FIELDS.evidenceRef]: evidence,
  })
}
</script>

<template>
  <Drawer :open="open" title="申请授权" :kicker="assetName" @close="emit('close')">
    <form class="form" @submit.prevent="submit">
      <p class="note">申请提交后为「待批准」，不会创建任何防火墙规则；须由申请人以外的审批人批准后生效。</p>

      <label class="form-field"><span class="label">采集接口</span>
        <input v-model="form.interfaces" class="field num" placeholder="en0, en1" autocomplete="off" />
        <span class="form-hint">主机本地接口标识，逗号分隔，1—16 个。采集配置只能使用这里批准的接口。</span>
      </label>
      <label class="check"><input v-model="form.observationAllowed" type="checkbox" />允许观察（采集流量并做检测）</label>

      <div class="grid grid-cols-2 gap-4">
        <label class="form-field"><span class="label">生效时间</span><input v-model="form.validFrom" type="datetime-local" class="field num" /></label>
        <label class="form-field"><span class="label">到期时间</span><input v-model="form.validUntil" type="datetime-local" class="field num" /></label>
      </div>

      <fieldset class="form-field" aria-label="执行范围">
        <div class="mb-1.5 flex items-center justify-between">
          <span class="label">执行范围<span class="ml-1 text-ink-4">{{ form.rows.length }} / 32</span></span>
          <button type="button" class="link text-[12.5px]" :disabled="form.rows.length >= 32" @click="addRow"><Plus :size="13" :stroke-width="1.5" />添加范围</button>
        </div>
        <p v-if="!form.rows.length" class="rounded border border-dashed border-ink-line px-4 py-4 text-center text-[12.5px] text-ink-3">不添加执行范围时只授权观察，不允许任何阻断命令。</p>
        <ol v-else class="space-y-3">
          <li v-for="(r, i) in form.rows" :key="i" class="rounded border border-ink-line p-3">
            <div class="mb-2.5 flex items-center justify-between text-[12px] text-ink-3">
              <span>范围 {{ i + 1 }} · TCP / IPv4</span>
              <button type="button" class="link text-[12px]" :aria-label="`删除范围 ${i + 1}`" @click="form.rows.splice(i, 1)"><Trash2 :size="13" :stroke-width="1.5" />删除</button>
            </div>
            <label class="form-field"><span class="label">能力</span>
              <select v-if="capabilities.length" v-model="r.capabilityId" class="field">
                <option value="" disabled>选择已登记的能力</option>
                <option v-for="c in capabilities" :key="c.id" :value="c.id">{{ capLabel(c) }}</option>
              </select>
              <input v-else v-model="r.capabilityId" class="field num text-[12px]" placeholder="能力 ID（UUID）" />
            </label>
            <div class="mt-2.5 grid grid-cols-3 gap-2.5">
              <label class="form-field"><span class="label">范围</span>
                <select :value="r.scope" class="field" @change="setScope(r, ($event.target as HTMLSelectElement).value as Row['scope'])">
                  <option v-for="(l, k) in scopeLabel" :key="k" :value="k">{{ l }}</option>
                </select>
              </label>
              <label class="form-field"><span class="label">方向</span>
                <select v-model="r.direction" class="field" :disabled="r.scope === 'peer_inbound'">
                  <option v-for="(l, k) in directionLabel" :key="k" :value="k">{{ l }}</option>
                </select>
              </label>
              <label class="form-field"><span class="label">服务端口</span>
                <input v-model="r.servicePort" class="field num" inputmode="numeric" :disabled="r.scope === 'peer_inbound'" :placeholder="r.scope === 'peer_inbound' ? '全部端口' : '1—65535'" />
              </label>
            </div>
          </li>
        </ol>
      </fieldset>

      <label class="form-field"><span class="label">授权证明引用</span>
        <input v-model="form.evidenceRef" class="field num" maxlength="1000" placeholder="受控文档编号或引用" />
        <span class="form-hint">只填受控证明的引用，不贴原文。</span>
      </label>
      <p v-if="error" class="text-[12.5px] text-threat" role="alert">{{ error }}</p>
    </form>
    <template #foot>
      <button type="button" class="act-ghost" @click="emit('close')">取消</button>
      <button type="button" class="act" :disabled="busy" @click="submit">提交申请</button>
    </template>
  </Drawer>
</template>
