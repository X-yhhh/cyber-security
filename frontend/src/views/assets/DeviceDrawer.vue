<script setup lang="ts">
import { useActionError } from '@/composables/actionError'
/**
 * 传感器 / 执行器详情抽屉（传感器与执行器页 `?tab=sensors|executors&id=`）。
 *
 * 抽屉内切换模式，不叠加第二个抽屉：查看 → 编辑资料 / 停用 / 启用 / 轮换凭据 / 起草采集配置（仅传感器）。
 * - 停用即吊销旧凭据；启用不恢复旧凭据，后端返回 credentialRotationRequired 时提示再轮换。
 * - 轮换成功后关闭本抽屉，由父页面在单独的抽屉里一次性显示新凭据。
 * - 采集配置草稿字段与后端校验一致，默认按该传感器最近一份配置预填；批准仍需他人并经代理验证。
 * 写操作需 sensor.manage，带幂等键，资料与状态变更带 If-Match；写后重新读取。
 */
import { computed, reactive, ref, watch } from 'vue'
import { KeyRound, PauseCircle, Pencil, Power, FilePlus2, RefreshCw } from 'lucide-vue-next'
import Drawer from '@/components/Drawer.vue'
import Tag from '@/components/Tag.vue'
import IdText from '@/components/IdText.vue'
import LoadState from '@/components/LoadState.vue'
import { errText } from '@/composables/load'
import { toast } from '@/composables/toast'
import { can } from '@/api/session'
import { fmtTime, guardHealthStateLabel, guardMachineStatusLabel, type GuardHeartbeat } from '@/api/types'
import {
  assetsApi, CAPTURE_CONTRACT, CAPTURE_HEALTH_VERSIONS, CONFIG_FIELDS, configStatusLabel, INTERFACE_RE, MAX_BATCH_SIZE, platformLabel, SHA256_RE,
  type ConfigDraft, type Executor, type IssuedCredential, type Sensor, type SensorConfig,
} from '@/api/v2/assets'
import { isUuid } from '@/api/v2/detect'
import { configTone, healthStateTone, machineStatusTone } from '@/data/tones'

type Kind = 'sensors' | 'executors'
const props = defineProps<{ kind: Kind; id: string; assetLabel: (id: string | null | undefined) => string; beat?: GuardHeartbeat }>()
const emit = defineEmits<{ close: []; changed: []; issued: [c: IssuedCredential & { title: string; deviceKind: string }]; drafted: [configId: string, sensorId: string] }>()

const noun = computed(() => (props.kind === 'sensors' ? '传感器' : '执行器'))
type Mode = 'view' | 'edit' | 'disable' | 'enable' | 'rotate' | 'draft'
const mode = ref<Mode>('view')
const device = ref<Sensor | Executor | null>(null)
const loading = ref(false)
const error = ref('')
const configs = ref<SensorConfig[]>([])
let seq = 0
async function load() {
  const mine = ++seq
  loading.value = !device.value || device.value.id !== props.id
  error.value = ''
  try {
    const d = props.kind === 'sensors' ? await assetsApi.getSensor(props.id) : await assetsApi.getExecutor(props.id)
    if (mine !== seq) return
    device.value = d
    if (props.kind === 'sensors') {
      const page = await assetsApi.listConfigs({ sensorId: props.id, limit: 5 }).catch(() => null)
      if (mine === seq) configs.value = page?.items ?? []
    }
  } catch (e) { if (mine === seq) { device.value = null; error.value = errText(e) } } finally { if (mine === seq) loading.value = false }
}
watch(() => [props.kind, props.id] as const, ([, id]) => { mode.value = 'view'; configs.value = []; if (id) void load(); else { seq++; device.value = null } }, { immediate: true })

const sensor = computed(() => (props.kind === 'sensors' ? device.value as Sensor | null : null))
const executor = computed(() => (props.kind === 'executors' ? device.value as Executor | null : null))
const title = computed(() => (device.value ? device.value.displayName || `${noun.value} ${device.value.id.slice(0, 8)}` : `${noun.value}详情`))
const status = computed(() => device.value?.status ?? '')
const lastBeat = computed(() => (sensor.value ? sensor.value.lastHeartbeatAt : executor.value?.lastHeartbeat ?? null))
const stateNote = computed(() => {
  const s = status.value
  if (s === 'revoked') return { text: '已吊销（终态）：凭据失效，不能再启用或轮换。', tone: 'note-threat' }
  if (s === 'offline' || s === 'suspended') return { text: '已停用：旧凭据已吊销。重新启用后须轮换凭据，设备才能再次接入。', tone: 'note-warn' }
  if (s === 'pending') return { text: '待心跳确认：执行器上报能力前不会领取命令，登记不等于已批准执行。', tone: '' }
  return { text: '心跳只表示机器在线，不代表采集健康；采集健康以健康窗口为准。', tone: '' }
})
const manage = computed(() => can('sensor.manage') && !!device.value)
const revoked = computed(() => status.value === 'revoked')
const disabled = computed(() => status.value === 'offline' || status.value === 'suspended')

/* ---------------- 模式 ---------------- */
const busy = ref(false)
const reason = ref('')
const formError = useActionError()
const edit = reactive({ displayName: '', notes: '' })
const draft = reactive({ interfaceId: '', addressFamily: 'ipv4' as 'ipv4' | 'ipv6', captureScopeId: '', captureHealthVersion: CAPTURE_HEALTH_VERSIONS[0] as string, maxBatchSize: '256', profileSha256: '', buildSha256: '' })
const prefilled = ref(false)

function enter(m: Mode) {
  reason.value = ''
  formError.value = ''
  if (m === 'edit' && device.value) Object.assign(edit, { displayName: device.value.displayName ?? '', notes: device.value.notes ?? '' })
  if (m === 'draft') {
    const last = configs.value.find((c) => c.definition)?.definition
    prefilled.value = !!last
    Object.assign(draft, {
      interfaceId: last?.interfaceIds?.[0] ?? '', addressFamily: last?.addressFamily === 'ipv6' ? 'ipv6' : 'ipv4',
      captureScopeId: last?.captureScopeId ?? crypto.randomUUID(), captureHealthVersion: last?.captureHealthVersion ?? CAPTURE_HEALTH_VERSIONS[0],
      maxBatchSize: String(last?.limits?.maxBatchSize ?? 256), profileSha256: last?.profileSha256 ?? '', buildSha256: last?.buildSha256 ?? '',
    })
  }
  mode.value = m
}

async function run(fn: () => Promise<unknown>, done: string, after?: () => void) {
  busy.value = true
  try {
    await fn()
    toast(done)
    emit('changed')
    if (after) after()
    else { mode.value = 'view'; await load() }
  } catch (e) { formError.value = errText(e) } finally { busy.value = false }
}

function saveEdit() {
  const d = device.value
  if (!d) return
  const displayName = edit.displayName.trim(), notes = edit.notes.trim()
  const body: { displayName?: string | null; notes?: string | null } = {}
  if (displayName !== (d.displayName ?? '')) body.displayName = displayName || null
  if (notes !== (d.notes ?? '')) body.notes = notes || null
  if (!Object.keys(body).length) { formError.value = '没有需要保存的修改。'; return }
  void run(() => assetsApi.updateMachine(props.kind, d.id, d.revision, body), '已保存资料。')
}
function changeStatus(to: 'active' | 'disabled') {
  const d = device.value
  if (!d) return
  if (!reason.value.trim()) { formError.value = '请填写理由，理由会写入审计。'; return }
  busy.value = true
  assetsApi.changeMachineStatus(props.kind, d.id, d.revision, to, reason.value.trim())
    .then(async (r) => {
      toast(to === 'disabled' ? `已停用${noun.value}，旧凭据已吊销。` : r.credentialRotationRequired ? `已启用${noun.value}；须轮换凭据后才能接入。` : `已启用${noun.value}。`)
      emit('changed')
      mode.value = 'view'
      await load()
    })
    .catch((e: unknown) => { formError.value = errText(e) })
    .finally(() => { busy.value = false })
}
function rotate() {
  const d = device.value
  if (!d) return
  busy.value = true
  assetsApi.rotateCredential(props.kind, d.id, reason.value.trim())
    .then((c) => {
      emit('changed')
      emit('issued', { ...c, title: `新凭据 · ${title.value}`, deviceKind: noun.value })
      emit('close')
    })
    .catch((e: unknown) => { formError.value = errText(e) })
    .finally(() => { busy.value = false })
}
function submitDraft() {
  const d = device.value
  if (!d) return
  const iface = draft.interfaceId.trim(), batch = Number(draft.maxBatchSize)
  const profile = draft.profileSha256.trim().toLowerCase(), build = draft.buildSha256.trim().toLowerCase(), scope = draft.captureScopeId.trim().toLowerCase()
  if (!INTERFACE_RE.test(iface)) { formError.value = '接口标识只能包含字母、数字与 _ . : -，最长 96 个字符。'; return }
  if (!isUuid(scope)) { formError.value = '采集域 ID 须为 UUID。'; return }
  if (!Number.isInteger(batch) || batch < 1 || batch > MAX_BATCH_SIZE) { formError.value = `批量上限须为 1—${MAX_BATCH_SIZE} 的整数。`; return }
  if (!SHA256_RE.test(profile)) { formError.value = '特征档案摘要须为 64 位小写十六进制。'; return }
  if (!SHA256_RE.test(build)) { formError.value = '构建摘要须为 64 位小写十六进制。'; return }
  const body: ConfigDraft = {
    [CONFIG_FIELDS.contractVersion]: CAPTURE_CONTRACT, [CONFIG_FIELDS.profileSha256]: profile, [CONFIG_FIELDS.captureHealthVersion]: draft.captureHealthVersion,
    [CONFIG_FIELDS.interfaceIds]: [iface], [CONFIG_FIELDS.limits]: { maxBatchSize: batch }, [CONFIG_FIELDS.captureScopeId]: scope,
    [CONFIG_FIELDS.addressFamily]: draft.addressFamily, [CONFIG_FIELDS.buildSha256]: build,
  }
  busy.value = true
  assetsApi.draftConfig(d.id, body)
    .then((r) => { toast('已起草采集配置，等待他人批准。'); emit('changed'); emit('drafted', r.id, d.id) })
    .catch((e: unknown) => { formError.value = errText(e) })
    .finally(() => { busy.value = false })
}

const regenScope = () => { draft.captureScopeId = crypto.randomUUID() }
const modeTitle: Record<Mode, string> = { view: '', edit: '编辑资料', disable: '停用', enable: '启用', rotate: '轮换凭据', draft: '起草采集配置' }
</script>

<template>
  <Drawer :open="!!id" :title="mode === 'view' ? title : `${modeTitle[mode]} · ${title}`" :kicker="noun" @close="emit('close')">
    <LoadState :loading="loading" :error="error">
      <template v-if="device">
        <!-- 查看 -->
        <template v-if="mode === 'view'">
          <p class="note mb-5" :class="stateNote.tone">{{ stateNote.text }}</p>
          <div class="grid grid-cols-2 overflow-hidden rounded border border-ink-line">
            <div class="px-4 py-3">
              <p class="text-[12px] text-ink-3">登记状态</p>
              <p class="mt-1.5"><Tag pill :tone="machineStatusTone[device.status]" :label="guardMachineStatusLabel[device.status] ?? device.status" /></p>
            </div>
            <div class="border-l border-ink-hair px-4 py-3">
              <p class="text-[12px] text-ink-3">存活（心跳）</p>
              <p class="mt-1.5">
                <Tag v-if="beat" :tone="healthStateTone[beat.healthState]" :label="guardHealthStateLabel[beat.healthState] ?? beat.healthState" />
                <span v-else class="text-[12.5px] text-ink-4">{{ can('ops.read') ? '尚无心跳' : '无运行状态权限' }}</span>
              </p>
            </div>
          </div>

          <dl class="kv mt-4">
            <div><dt>资产</dt><dd>{{ assetLabel(device.assetId) }}</dd></div>
            <div><dt>平台</dt><dd>{{ platformLabel[device.platform] ?? device.platform }}</dd></div>
            <div v-if="sensor"><dt>代理版本</dt><dd class="num">{{ sensor.agentVersion }}</dd></div>
            <div v-if="executor"><dt>适配器版本</dt><dd class="num">{{ executor.adapterVersion }}</dd></div>
            <div><dt>最近心跳</dt><dd class="num">{{ fmtTime(lastBeat) }}</dd></div>
            <div v-if="sensor"><dt>登记</dt><dd class="num">{{ fmtTime(sensor.registeredAt) }}</dd></div>
            <div><dt>说明</dt><dd class="whitespace-pre-line">{{ device.notes || '—' }}</dd></div>
          </dl>

          <template v-if="sensor">
            <h3 class="section-title mt-7">采集配置</h3>
            <p v-if="!configs.length" class="text-[12.5px] text-ink-3">还没有采集配置。传感器须有已批准的配置才能上报观察。</p>
            <ul v-else class="divide-y divide-ink-hair rounded border border-ink-line">
              <li v-for="c in configs" :key="c.id">
                <RouterLink :to="{ path: '/console/assets/agents', query: { tab: 'configs', sensorId: sensor.id, id: c.id } }" class="flex items-center justify-between gap-3 px-3.5 py-2.5 text-[12.5px] hover:bg-paper-soft">
                  <span class="num truncate text-ink-2">{{ c.definition?.interfaceIds?.join(', ') ?? '—' }} · {{ c.definition?.addressFamily ?? '—' }}</span>
                  <span class="flex shrink-0 items-center gap-2"><Tag :tone="configTone[c.status]" :label="configStatusLabel[c.status] ?? c.status" /><span class="num text-ink-4">{{ fmtTime(c.createdAt) }}</span></span>
                </RouterLink>
              </li>
            </ul>
          </template>

          <div v-if="manage && !revoked" class="mt-7 flex flex-wrap gap-2.5">
            <button type="button" class="act-ghost act-sm" @click="enter('edit')"><Pencil :size="13" :stroke-width="1.5" />编辑资料</button>
            <button v-if="sensor" type="button" class="act-ghost act-sm" @click="enter('draft')"><FilePlus2 :size="13" :stroke-width="1.5" />起草采集配置</button>
            <button type="button" class="act-ghost act-sm" @click="enter('rotate')"><RefreshCw :size="13" :stroke-width="1.5" />轮换凭据</button>
          </div>

          <details class="mt-7 text-[12.5px]">
            <summary class="cursor-pointer text-ink-3 hover:text-ink">技术细节</summary>
            <dl class="kv mt-2">
              <div><dt>{{ noun }} ID</dt><dd><IdText :value="device.id" /></dd></div>
              <div v-if="sensor"><dt>代理键</dt><dd><IdText :value="sensor.agentKey" /></dd></div>
              <div><dt>启动标识</dt><dd><IdText :value="sensor ? sensor.guardBootId : executor?.bootId" /></dd></div>
              <div v-if="executor"><dt>能力摘要</dt><dd><IdText :value="executor.capabilityHash" :length="16" /></dd></div>
              <div v-if="beat?.currentConfig"><dt>当前配置摘要</dt><dd><IdText :value="beat.currentConfig.contentSha256" :length="16" /></dd></div>
              <div><dt>修订号</dt><dd class="num">{{ device.revision }}</dd></div>
            </dl>
          </details>
        </template>

        <!-- 编辑资料 -->
        <form v-else-if="mode === 'edit'" class="form" @submit.prevent="saveEdit">
          <label class="form-field"><span class="label">显示名</span><input v-model="edit.displayName" class="field" maxlength="128" placeholder="可留空" /></label>
          <label class="form-field"><span class="label">说明</span><textarea v-model="edit.notes" rows="4" maxlength="1000" class="field resize-none" placeholder="可留空" /></label>
          <p class="form-hint">只修改展示资料，不影响凭据、配置与心跳。</p>
        </form>

        <!-- 停用 / 启用 -->
        <div v-else-if="mode === 'disable' || mode === 'enable'">
          <p class="note mb-5" :class="mode === 'disable' ? 'note-threat' : ''">
            <template v-if="mode === 'disable'">停用后立即吊销该{{ noun }}的机器凭据，设备无法再上报或领取命令{{ executor ? '；已下发的封禁按回执与到期流程清理' : '' }}。重新启用不会恢复旧凭据。</template>
            <template v-else>启用只恢复登记状态，不恢复旧凭据。启用后须轮换凭据并把新凭据写入主机，设备才能再次接入。</template>
          </p>
          <label class="form-field"><span class="label">理由</span><textarea v-model="reason" rows="3" maxlength="1000" class="field resize-none" placeholder="写入审计" /></label>
        </div>

        <!-- 轮换凭据 -->
        <div v-else-if="mode === 'rotate'">
          <p class="note note-warn mb-5">轮换会立即使旧凭据失效，新凭据只显示一次。请先准备好更新主机上的凭据，避免设备断开时间过长。</p>
          <label class="form-field"><span class="label">理由（可选）</span><textarea v-model="reason" rows="3" maxlength="1000" class="field resize-none" placeholder="写入审计" /></label>
        </div>

        <!-- 起草采集配置 -->
        <form v-else-if="mode === 'draft'" class="form" @submit.prevent="submitDraft">
          <p class="note">{{ prefilled ? '已按该传感器最近一份配置预填。' : '' }}草稿须由起草人以外的审批人批准；接口须在资产有效授权允许观察的接口内，批准时由后端核验。</p>
          <div class="grid grid-cols-[minmax(0,1fr)_8rem] gap-4">
            <label class="form-field"><span class="label">采集接口</span><input v-model="draft.interfaceId" class="field num" maxlength="96" placeholder="en0" autocomplete="off" /></label>
            <label class="form-field"><span class="label">地址族</span>
              <select v-model="draft.addressFamily" class="field"><option value="ipv4">IPv4</option><option value="ipv6">IPv6</option></select>
            </label>
          </div>
          <label class="form-field"><span class="label">采集域 ID</span>
            <span class="flex gap-2"><input v-model="draft.captureScopeId" class="field num flex-1 text-[12px]" /><button type="button" class="act-ghost" @click="regenScope">重新生成</button></span>
            <span class="form-hint">沿用已有采集域时须与原接口、地址族一致；新接口使用新的 ID。</span>
          </label>
          <div class="grid grid-cols-[minmax(0,1fr)_8rem] gap-4">
            <label class="form-field"><span class="label">采集健康版本</span>
              <select v-model="draft.captureHealthVersion" class="field num text-[12px]"><option v-for="v in CAPTURE_HEALTH_VERSIONS" :key="v" :value="v">{{ v }}</option></select>
            </label>
            <label class="form-field"><span class="label">批量上限</span><input v-model="draft.maxBatchSize" class="field num" inputmode="numeric" :placeholder="`1—${MAX_BATCH_SIZE}`" /></label>
          </div>
          <label class="form-field"><span class="label">特征档案摘要（SHA-256）</span>
            <input v-model="draft.profileSha256" class="field num text-[12px]" maxlength="64" placeholder="64 位小写十六进制" autocomplete="off" />
            <span class="form-hint">须等于控制面当前特征档案的摘要，否则后端以契约不支持拒绝。</span>
          </label>
          <label class="form-field"><span class="label">构建摘要（SHA-256）</span>
            <input v-model="draft.buildSha256" class="field num text-[12px]" maxlength="64" placeholder="64 位小写十六进制" autocomplete="off" />
          </label>
          <p class="text-[12px] text-ink-3">采集契约 <span class="num text-ink-2">{{ CAPTURE_CONTRACT }}</span>（固定）</p>
        </form>

        <p v-if="formError" class="mt-4 text-[12.5px] text-threat" role="alert">{{ formError }}</p>
      </template>
    </LoadState>

    <template v-if="device && manage && !revoked" #foot>
      <template v-if="mode === 'view'">
        <button v-if="disabled" type="button" class="act-ghost" @click="enter('enable')"><Power :size="14" :stroke-width="1.5" />启用{{ noun }}</button>
        <button v-else type="button" class="act-danger" @click="enter('disable')"><PauseCircle :size="14" :stroke-width="1.5" />停用{{ noun }}</button>
      </template>
      <template v-else>
        <button type="button" class="act-ghost" :disabled="busy" @click="mode = 'view'; formError = ''">返回</button>
        <button v-if="mode === 'edit'" type="button" class="act" :disabled="busy" @click="saveEdit">保存资料</button>
        <button v-else-if="mode === 'disable'" type="button" class="act-danger" :disabled="busy" @click="changeStatus('disabled')">确认停用</button>
        <button v-else-if="mode === 'enable'" type="button" class="act" :disabled="busy" @click="changeStatus('active')">确认启用</button>
        <button v-else-if="mode === 'rotate'" type="button" class="act" :disabled="busy" @click="rotate"><KeyRound :size="14" :stroke-width="1.5" />生成新凭据</button>
        <button v-else-if="mode === 'draft'" type="button" class="act" :disabled="busy" @click="submitDraft">提交草稿</button>
      </template>
    </template>
  </Drawer>
</template>
