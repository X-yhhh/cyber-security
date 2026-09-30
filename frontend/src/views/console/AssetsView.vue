<script setup lang="ts">
/**
 * 资产与传感器（开发路线 §4.1）。
 * - 资产：登记、修改关键性/责任人/状态（active ↔ disabled，→ retired 为终态）、授权申请/他人批准/撤销。
 *   停用、退役或撤销授权后，相关接入与处置由后端立即 fail-closed。
 * - 传感器：登记（一次性签发凭据）、详情、平台修改、配置版本起草 → 他人审批 → 启用、凭据轮换/吊销、下线。
 * 凭据只在签发或轮换的那次响应中显示，关闭抽屉即从页面状态中清除。按钮可见性只是提示，授权与状态迁移以后端为准。
 */
import { computed, ref, watch } from 'vue'
import PageHead from '@/components/PageHead.vue'
import Segmented from '@/components/Segmented.vue'
import Tag from '@/components/Tag.vue'
import Drawer from '@/components/Drawer.vue'
import LoadState from '@/components/LoadState.vue'
import { api, type Page } from '@/api/client'
import { can, session } from '@/api/session'
import { fmtTime, lifecycleStatusLabel, type AssetView, type AuthorizationView, type SensorDetail, type SensorView } from '@/api/types'
import { statusTone } from '@/data/tones'
import { toast } from '@/composables/toast'
import { errText, useLoad } from '@/composables/load'

const V4 = 'unsw-nb15-flow-v4'
const { data, loading, error, reload } = useLoad(async () => {
  const [assets, sensors] = await Promise.all([
    can('asset.read') ? api.get<Page<AssetView>>('/assets?size=100').then((p) => p.items) : [],
    can('sensor.read') ? api.get<SensorView[]>('/sensors') : [],
  ])
  return { assets, sensors }
}, { assets: [] as AssetView[], sensors: [] as SensorView[] })

const tab = ref<'assets' | 'sensors'>('assets')
const busy = ref(false)
const label = (s: string) => lifecycleStatusLabel[s] ?? s
const envLabel = (e: string) => (e === 'range' ? '隔离靶场' : e === 'production' ? '授权实网' : e)
/** 包装写操作：成功后提示并从数据库重读，不做本地乐观修改。 */
async function act(fn: () => Promise<unknown>, done: string, after?: () => Promise<void> | void) {
  busy.value = true
  try {
    await fn()
    toast(done)
    await reload()
    await after?.()
  } catch (e) { toast(errText(e), 'threat') } finally { busy.value = false }
}
function parseJson(text: string, what: string): Record<string, unknown> | null {
  try {
    const v: unknown = JSON.parse(text)
    if (v && typeof v === 'object') return v as Record<string, unknown>
  } catch { /* 下方统一提示 */ }
  toast(`${what}须为 JSON 对象或数组。`, 'warn')
  return null
}

// ---------------- 资产 ----------------
const picked = ref<AssetView | null>(null)
const auths = ref<AuthorizationView[]>([])
const authError = ref('')
const assetForm = ref({ criticality: 'medium', owner: '', status: 'active' })
const authReason = ref('')
let authRequest = 0
async function loadAuths() {
  const request = ++authRequest
  const id = picked.value?.id
  auths.value = []
  authError.value = ''
  if (!picked.value || !can('asset.authorization.read')) return
  try {
    const result = await api.get<AuthorizationView[]>(`/assets/${id}/authorizations`)
    if (request === authRequest && picked.value?.id === id) auths.value = result
  } catch (e) { if (request === authRequest && picked.value?.id === id) authError.value = errText(e) }
}
watch(picked, (a) => {
  if (a) assetForm.value = { criticality: a.criticality, owner: a.owner ?? '', status: a.status }
  authReason.value = ''
  loadAuths()
})
/** 与后端一致的合法状态：retired 为终态。 */
const statusOptions = computed(() => picked.value?.status === 'retired' ? ['retired'] : ['active', 'disabled', 'retired'])
const refreshPicked = async () => {
  const id = picked.value?.id
  picked.value = id == null ? null : data.value.assets.find((a) => a.id === id) ?? null
  await loadAuths()
}
const saveAsset = () => act(() => api.put(`/assets/${picked.value!.id}`, { ...assetForm.value, owner: assetForm.value.owner.trim() || null }),
  assetForm.value.status === picked.value?.status ? '资产已更新。' : `资产状态已改为 ${label(assetForm.value.status)}。`, refreshPicked)
const approveAuth = (a: AuthorizationView) => act(() => api.post(`/assets/${a.assetId}/authorizations/${a.id}/approve`), '授权已批准并写入审计。', loadAuths)
function revokeAuth(a: AuthorizationView) {
  if (!authReason.value.trim()) return toast('请先填写撤销理由。', 'warn')
  return act(() => api.post(`/assets/${a.assetId}/authorizations/${a.id}/revoke`, { reason: authReason.value.trim() }),
    '授权已撤销；未有其他有效授权时，接入与处置将被拒绝。', loadAuths)
}
const canRevoke = (a: AuthorizationView) => ['pending', 'active'].includes(a.status)
  && (can('asset.authorization.manage') || can('asset.authorization.approve'))

const requesting = ref(false)
const authForm = ref({ ref: '', from: '', until: '', scope: '{"purpose":"passive-monitoring"}' })
function openRequest() {
  const now = new Date()
  const iso = (d: Date) => d.toISOString().slice(0, 16)
  authForm.value = { ref: '', from: iso(now), until: iso(new Date(now.getTime() + 7 * 86_400_000)), scope: '{"purpose":"passive-monitoring"}' }
  requesting.value = true
}
function submitRequest() {
  const scope = parseJson(authForm.value.scope, '授权范围')
  if (!scope || !picked.value) return
  const f = authForm.value
  return act(() => api.post(`/assets/${picked.value!.id}/authorizations`, {
    authorizationRef: f.ref.trim(), scope, validFrom: new Date(f.from + 'Z').toISOString(), validUntil: new Date(f.until + 'Z').toISOString(),
  }), '授权申请已登记，须由其他管理员批准。', async () => { requesting.value = false; await loadAuths() })
}

const creatingAsset = ref(false)
const newAsset = ref({ assetKey: '', assetType: 'host', environment: 'lab', criticality: 'medium', owner: '' })
const createAsset = () => act(() => api.post('/assets', { ...newAsset.value, assetKey: newAsset.value.assetKey.trim(), owner: newAsset.value.owner.trim() || null, labels: {} }),
  '资产已登记。', () => { creatingAsset.value = false; newAsset.value = { assetKey: '', assetType: 'host', environment: 'lab', criticality: 'medium', owner: '' } })

// ---------------- 传感器 ----------------
const sensorId = ref<number | null>(null)
const sensor = ref<SensorDetail | null>(null)
const sensorError = ref('')
const platform = ref('')
const sensorReason = ref('')
/** 只显示一次的新凭据；关闭抽屉即清除。 */
const issued = ref<{ credential: string; note: string } | null>(null)
let sensorRequest = 0
async function loadSensor() {
  const request = ++sensorRequest
  const id = sensorId.value
  sensor.value = null
  sensorError.value = ''
  if (sensorId.value == null) { sensor.value = null; return }
  try {
    const result = await api.get<SensorDetail>(`/sensors/${id}`)
    if (request !== sensorRequest || sensorId.value !== id) return
    sensor.value = result
    platform.value = result.sensor.platform
  } catch (e) { if (request === sensorRequest && sensorId.value === id) sensorError.value = errText(e) }
}
watch(sensorId, () => { sensorReason.value = ''; issued.value = null; drafting.value = false; loadSensor() }, { flush: 'sync' })
const mine = (requestedBy: number | null) => requestedBy != null && requestedBy === session.user?.id
const sensorActive = computed(() => sensor.value?.sensor.status !== 'revoked')
const sid = () => sensor.value!.sensor.id
const savePlatform = () => act(() => api.put(`/sensors/${sid()}`, { platform: platform.value.trim() }), '平台标识已更新。', loadSensor)
function decideConfig(configId: number, decision: 'approve' | 'reject') {
  if (!sensorReason.value.trim()) return toast('请先填写审批理由。', 'warn')
  return act(() => api.post(`/sensors/${sid()}/configs/${configId}/decision`, { decision, reason: sensorReason.value.trim() }),
    decision === 'approve' ? '配置已批准；启用后才会下发到传感器。' : '配置已驳回。', loadSensor)
}
const activateConfig = (configId: number) => act(() => api.post(`/sensors/${sid()}/configs/${configId}/activate`),
  '配置已启用，旧版本已退役；传感器须以新配置版本上报。', loadSensor)
async function rotate() {
  const id = sid()
  busy.value = true
  try {
    const r = await api.post<{ credential: string; expiresAt: string }>(`/sensors/${id}/credentials/rotate`)
    if (sensorId.value !== id) return
    issued.value = { credential: r.credential, note: `旧凭据已失效；新凭据有效期至 ${fmtTime(r.expiresAt)}。` }
    toast('凭据已轮换。')
    await loadSensor()
  } catch (e) { toast(errText(e), 'threat') } finally { busy.value = false }
}
function withReason(path: string, done: string) {
  if (!sensorReason.value.trim()) return toast('请先填写理由。', 'warn')
  return act(() => api.post(`/sensors/${sid()}/${path}`, { reason: sensorReason.value.trim() }), done, loadSensor)
}

const drafting = ref(false)
const configForm = ref({ configVersion: '', flowWindowSeconds: 60, featureContractVersion: V4, interfaceScope: '{"interfaces":["en0"]}', filterPolicy: '{}', samplingPolicy: '{}', reason: '' })
function openDraft() {
  const active = sensor.value?.configs.find((c) => c.status === 'active')
  configForm.value = {
    configVersion: '', flowWindowSeconds: active?.flowWindowSeconds ?? 60, featureContractVersion: active?.featureContractVersion ?? V4,
    interfaceScope: active?.interfaceScopeJson ?? '{"interfaces":["en0"]}', filterPolicy: active?.filterPolicyJson ?? '{}',
    samplingPolicy: active?.samplingPolicyJson ?? '{}', reason: '',
  }
  drafting.value = true
}
function submitDraft() {
  const f = configForm.value
  const interfaceScope = parseJson(f.interfaceScope, '接口范围')
  const filterPolicy = interfaceScope && parseJson(f.filterPolicy, '过滤策略')
  const samplingPolicy = filterPolicy && parseJson(f.samplingPolicy, '采样策略')
  if (!samplingPolicy) return
  if (!f.reason.trim()) return toast('请填写起草理由。', 'warn')
  return act(() => api.post(`/sensors/${sid()}/configs`, {
    configVersion: f.configVersion.trim(), interfaceScope, filterPolicy, samplingPolicy, flowWindowSeconds: Number(f.flowWindowSeconds),
    featureContractVersion: f.featureContractVersion.trim(), reason: f.reason.trim(),
  }), '配置版本已起草，须由其他管理员批准。', async () => { drafting.value = false; await loadSensor() })
}

const registering = ref(false)
const reg = ref({ agentKey: '', assetId: 0, dataSourceId: 0, platform: 'macos', agentVersion: '0.1.0', configVersion: 'cfg-1', flowWindowSeconds: 60, interfaceScope: '{"interfaces":["en0"]}' })
async function register() {
  const f = reg.value
  const interfaceScope = parseJson(f.interfaceScope, '接口范围')
  if (!interfaceScope) return
  busy.value = true
  try {
    const r = await api.post<{ sensorId: number; credential: string; expiresAt: string }>('/sensors', {
      agentKey: f.agentKey.trim(), assetId: Number(f.assetId), dataSourceId: Number(f.dataSourceId), platform: f.platform.trim(),
      agentVersion: f.agentVersion.trim(), capabilities: {},
      config: { configVersion: f.configVersion.trim(), interfaceScope, filterPolicy: {}, flowWindowSeconds: Number(f.flowWindowSeconds), featureContractVersion: V4, samplingPolicy: {} },
    })
    registering.value = false
    await reload()
    sensorId.value = r.sensorId
    issued.value = { credential: r.credential, note: `传感器已登记；凭据有效期至 ${fmtTime(r.expiresAt)}，请立即写入传感器主机的钥匙串。` }
  } catch (e) { toast(errText(e), 'threat') } finally { busy.value = false }
}
</script>

<template>
  <div>
    <PageHead no="05" title="资产与传感器" desc="处置只能引用已登记资产。靶场与实网分区标记；授权过期、撤销或资产停用后，相关动作一律被拒绝。">
      <template #kicker>Assets</template>
    </PageHead>

    <Segmented v-model="tab" :options="[{ value: 'assets', label: '资产', count: data.assets.length }, { value: 'sensors', label: '传感器', count: data.sensors.length }]" />

    <LoadState :loading="loading" :error="error">
    <Transition name="fade" mode="out-in">
      <section v-if="tab === 'assets'" key="a" class="mt-10">
        <div v-if="can('asset.manage')" class="mb-6 flex justify-end"><button class="act-ghost" @click="creatingAsset = true">登记资产</button></div>
        <table class="table">
          <thead><tr><th>资产</th><th>类型</th><th>环境</th><th>关键性</th><th>负责人</th><th class="text-right">状态</th></tr></thead>
          <tbody>
            <tr v-for="a in data.assets" :key="a.id" class="row-link" tabindex="0" @click="picked = a" @keydown.enter="picked = a">
              <td><span class="block num">{{ a.assetKey }}</span><span class="num text-[12px] text-ink-3">#{{ a.id }}</span></td>
              <td class="text-ink-2">{{ a.assetType }}</td>
              <td><span class="text-[12.5px]" :class="a.environment === 'range' ? 'text-warn' : 'text-ink-2'">{{ envLabel(a.environment) }}</span></td>
              <td class="text-ink-2">{{ a.criticality }}</td>
              <td class="text-ink-2">{{ a.owner }}</td>
              <td class="text-right"><Tag :tone="statusTone[a.status]" :label="label(a.status)" /></td>
            </tr>
            <tr v-if="!data.assets.length"><td colspan="6" class="py-16 text-center text-ink-3">数据库中暂无授权范围内的登记资产。</td></tr>
          </tbody>
        </table>
      </section>

      <div v-else key="s" class="mt-10">
        <div v-if="can('sensor.manage')" class="mb-6 flex justify-end"><button class="act-ghost" @click="registering = true">登记传感器</button></div>
        <p v-if="!data.sensors.length" class="py-16 text-center text-ink-3">数据库中暂无登记传感器。</p>
        <div class="grid gap-x-12 gap-y-16 lg:grid-cols-3">
          <section v-for="s in data.sensors" :key="s.id" class="cursor-pointer border-t border-ink pt-5" tabindex="0" role="button" :aria-label="`传感器 ${s.agentKey} 详情`" @click="sensorId = s.id" @keydown.enter="sensorId = s.id">
            <div class="flex items-start justify-between">
              <div>
                <p class="text-[15px] num">{{ s.assetKey }}</p>
                <p class="num mt-1 text-[12px] text-ink-3">{{ s.agentKey }} · {{ s.platform }} · v{{ s.agentVersion }}</p>
              </div>
              <Tag :tone="statusTone[s.status]" :label="label(s.status)" />
            </div>
            <dl class="mt-8 grid grid-cols-2 gap-y-6">
              <div v-for="[k, v] in [['观察流', s.flowsSeen], ['输出流', s.flowsEmitted], ['丢弃', s.flowsDropped], ['最大队列', s.queueDepthMax]] as [string, number | null][]" :key="k">
                <dt class="label">{{ k }}</dt><dd class="num mt-1.5 text-[1.25rem] font-light">{{ v == null ? '—' : Number(v).toLocaleString() }}</dd>
              </div>
            </dl>
            <p class="num mt-6 text-[12px] text-ink-3">心跳 {{ fmtTime(s.lastHeartbeatAt) }} · 窗口截至 {{ fmtTime(s.healthWindowEnd) }}</p>
            <p class="num mt-1 text-[12px] text-ink-3">配置 {{ s.configVersion ?? '—' }} · 流窗口 {{ s.flowWindowSeconds ?? '—' }}s</p>
          </section>
        </div>
        <p class="mt-10 text-[12px] text-ink-3">传感器只观测所在主机的可见流量，不代表全网覆盖。</p>
      </div>
    </Transition>
    </LoadState>

    <!-- 资产详情 -->
    <Drawer :open="!!picked" :title="picked?.assetKey ?? ''" :kicker="picked ? `ASSET #${picked.id}` : ''" @close="picked = null">
      <template v-if="picked">
        <dl class="border-t border-ink">
          <div v-for="[k, v] in [['类型', picked.assetType], ['环境', picked.environment === 'range' ? '隔离靶场（外联隔离由网络层保证）' : envLabel(picked.environment)], ['状态', label(picked.status)]]" :key="k" class="grid grid-cols-[6rem_1fr] border-b border-ink-hair py-3 text-[13px]">
            <dt class="text-ink-3">{{ k }}</dt><dd class="num">{{ v }}</dd>
          </div>
        </dl>
        <div v-if="can('asset.manage') && picked.status !== 'retired'" class="mt-8 grid grid-cols-3 gap-4">
          <label class="block"><span class="label">关键性</span><select v-model="assetForm.criticality" class="field mt-2"><option v-for="c in ['low', 'medium', 'high', 'critical']" :key="c" :value="c">{{ c }}</option></select></label>
          <label class="block"><span class="label">负责人</span><input v-model="assetForm.owner" class="field mt-2" maxlength="128" /></label>
          <label class="block"><span class="label">状态</span><select v-model="assetForm.status" class="field mt-2"><option v-for="s in statusOptions" :key="s" :value="s">{{ label(s) }}</option></select></label>
          <button class="link col-span-3 justify-self-start text-[12.5px]" :disabled="busy" @click="saveAsset">保存资产</button>
          <p v-if="assetForm.status === 'retired'" class="col-span-3 text-[12px] text-threat">退役为终态，之后不能再修改。</p>
        </div>
        <p v-else-if="picked.status === 'retired'" class="mt-6 text-[12.5px] text-ink-3">资产已退役；记录与历史告警保留。</p>

        <div class="mb-4 mt-12 flex items-center justify-between">
          <h3 class="label">授权记录</h3>
          <button v-if="can('asset.authorization.manage') && picked.status === 'active'" class="link text-[12.5px]" @click="openRequest">申请授权</button>
        </div>
        <p v-if="!can('asset.authorization.read')" class="text-[13px] text-ink-3">当前身份无权查看授权记录。</p>
        <p v-else-if="authError" class="text-[13px] text-threat">{{ authError }}</p>
        <ol v-else class="border-l border-ink-hair">
          <li v-for="a in auths" :key="a.id" class="relative pb-6 pl-6">
            <span class="absolute -left-[3px] top-2 h-[5px] w-[5px]" :class="a.status === 'active' ? 'bg-ok' : 'bg-ink-4'" />
            <p class="flex items-center gap-3 text-[13px]"><Tag :tone="statusTone[a.status]" :label="label(a.status)" /> 申请 {{ a.requestedBy ?? '—' }} · 批准 {{ a.approvedBy ?? '—' }}</p>
            <p class="num mt-1 text-[12px] text-ink-3">{{ fmtTime(a.validFrom) }} — {{ fmtTime(a.validUntil) }} · {{ a.authorizationRef }}</p>
            <p v-if="a.revokedAt" class="mt-1 text-[12px] text-ink-3">撤销 {{ a.revokedBy ?? '—' }} · {{ fmtTime(a.revokedAt) }} · {{ a.revokeReason }}</p>
            <div class="mt-2 flex gap-5">
              <button v-if="a.status === 'pending' && can('asset.authorization.approve') && a.requestedBy !== session.user?.username" class="link text-[12.5px]" :disabled="busy" @click="approveAuth(a)">批准</button>
              <button v-if="canRevoke(a)" class="link text-[12.5px]" :disabled="busy" @click="revokeAuth(a)">撤销</button>
            </div>
          </li>
          <li v-if="!auths.length" class="pl-6 text-[13px] text-ink-3">暂无授权记录。</li>
        </ol>
        <label v-if="auths.some(canRevoke)" class="mt-4 block"><span class="label">撤销理由</span><input v-model="authReason" class="field mt-2" maxlength="1000" placeholder="撤销前必填，写入审计" /></label>
        <p class="mt-8 text-[12px] leading-relaxed text-ink-3">授权证明原文保存在受控密钥系统，业务库仅保存引用。申请人不能批准本人提交的授权；撤销属于收紧操作，申请或批准权限任一即可。</p>
      </template>
    </Drawer>

    <Drawer :open="requesting" title="申请资产授权" :kicker="picked?.assetKey" @close="requesting = false">
      <div class="space-y-6">
        <label class="block"><span class="label">授权证明引用</span><input v-model="authForm.ref" class="field mt-2 num" maxlength="255" placeholder="vault://… 或书面授权编号" /></label>
        <label class="block"><span class="label">生效（UTC）</span><input v-model="authForm.from" type="datetime-local" class="field mt-2 num" /></label>
        <label class="block"><span class="label">到期（UTC）</span><input v-model="authForm.until" type="datetime-local" class="field mt-2 num" /></label>
        <label class="block"><span class="label">授权范围（JSON 对象）</span><textarea v-model="authForm.scope" rows="3" class="field mt-2 h-auto resize-none py-2 num" /></label>
      </div>
      <template #foot>
        <button class="link text-[13px]" @click="requesting = false">取消</button>
        <button class="act" :disabled="busy || !authForm.ref.trim()" @click="submitRequest">提交申请</button>
      </template>
    </Drawer>

    <Drawer :open="creatingAsset" title="登记资产" kicker="ASSET" @close="creatingAsset = false">
      <div class="space-y-6">
        <label class="block"><span class="label">资产标识</span><input v-model="newAsset.assetKey" class="field mt-2 num" maxlength="128" /></label>
        <label class="block"><span class="label">类型</span><input v-model="newAsset.assetType" class="field mt-2" maxlength="48" /></label>
        <label class="block"><span class="label">环境</span><select v-model="newAsset.environment" class="field mt-2"><option value="lab">lab</option><option value="range">range（隔离靶场）</option><option value="authorized">authorized（授权实网）</option></select></label>
        <label class="block"><span class="label">关键性</span><select v-model="newAsset.criticality" class="field mt-2"><option v-for="c in ['low', 'medium', 'high', 'critical']" :key="c" :value="c">{{ c }}</option></select></label>
        <label class="block"><span class="label">负责人</span><input v-model="newAsset.owner" class="field mt-2" maxlength="128" /></label>
        <p class="text-[12.5px] text-ink-3">只有全局平台管理员可以登记资产。登记后仍须申请并经他人批准授权，才能接入或处置。</p>
      </div>
      <template #foot>
        <button class="link text-[13px]" @click="creatingAsset = false">取消</button>
        <button class="act" :disabled="busy || !newAsset.assetKey.trim()" @click="createAsset">登记</button>
      </template>
    </Drawer>

    <!-- 传感器详情 -->
    <Drawer :open="sensorId != null" :title="sensor?.sensor.agentKey ?? '传感器'" :kicker="sensor ? `SENSOR #${sensor.sensor.id} · ${sensor.sensor.assetKey}` : ''" @close="sensorId = null">
      <p v-if="sensorError" class="text-[13px] text-threat">{{ sensorError }}</p>
      <template v-else-if="sensor">
        <div v-if="issued" class="mb-8 border-l-2 border-warn pl-4">
          <p class="label">新凭据（只显示这一次）</p>
          <p class="num mt-2 select-all break-all text-[12.5px]">{{ issued.credential }}</p>
          <p class="mt-2 text-[12px] text-ink-3">{{ issued.note }}</p>
        </div>
        <dl class="border-t border-ink">
          <div v-for="[k, v] in [['状态', label(sensor.sensor.status)], ['版本', sensor.sensor.agentVersion], ['登记', fmtTime(sensor.sensor.registeredAt)], ['心跳', fmtTime(sensor.sensor.lastHeartbeatAt)],
            ['凭据', sensor.credential ? `${label(sensor.credential.status)} · 有效期至 ${fmtTime(sensor.credential.expiresAt)}` : '—'],
            ['最近轮换', fmtTime(sensor.credential?.rotatedAt)]]" :key="k" class="grid grid-cols-[6rem_1fr] border-b border-ink-hair py-3 text-[13px]">
            <dt class="text-ink-3">{{ k }}</dt><dd class="num">{{ v }}</dd>
          </div>
        </dl>
        <div v-if="can('sensor.manage') && sensorActive" class="mt-6 flex items-end gap-4">
          <label class="block flex-1"><span class="label">平台</span><input v-model="platform" class="field mt-2 num" maxlength="32" /></label>
          <button class="link text-[12.5px]" :disabled="busy || platform.trim() === sensor.sensor.platform" @click="savePlatform">保存</button>
        </div>

        <div class="mb-4 mt-12 flex items-center justify-between">
          <h3 class="label">配置版本</h3>
          <button v-if="can('sensor.manage') && sensorActive" class="link text-[12.5px]" @click="openDraft">起草新版本</button>
        </div>
        <ol class="border-l border-ink-hair">
          <li v-for="c in sensor.configs" :key="c.id" class="relative pb-6 pl-6">
            <span class="absolute -left-[3px] top-2 h-[5px] w-[5px]" :class="c.status === 'active' ? 'bg-ok' : 'bg-ink-4'" />
            <p class="flex items-center gap-3 text-[13px]"><span class="num">{{ c.configVersion }}</span><Tag :tone="statusTone[c.status]" :label="label(c.status)" /></p>
            <p class="num mt-1 text-[12px] text-ink-3">{{ c.featureContractVersion }} · 流窗口 {{ c.flowWindowSeconds }}s · 起草 {{ c.requestedByName ?? '登记时写入' }} · 批准 {{ c.approvedByName ?? '—' }}</p>
            <p v-if="c.changeReason" class="mt-1 text-[12px] text-ink-3">{{ c.changeReason }}</p>
            <p v-if="c.decisionReason" class="mt-1 text-[12px] text-ink-3">审批：{{ c.decisionReason }}</p>
            <div v-if="sensorActive" class="mt-2 flex gap-5">
              <template v-if="c.status === 'pending' && can('sensor.config.approve') && !mine(c.requestedBy)">
                <button class="link text-[12.5px]" :disabled="busy" @click="decideConfig(c.id, 'approve')">批准</button>
                <button class="link text-[12.5px]" :disabled="busy" @click="decideConfig(c.id, 'reject')">驳回</button>
              </template>
              <span v-else-if="c.status === 'pending' && mine(c.requestedBy)" class="text-[12px] text-ink-3">待其他管理员审批</span>
              <button v-if="c.status === 'approved' && can('sensor.manage')" class="link text-[12.5px]" :disabled="busy" @click="activateConfig(c.id)">启用</button>
            </div>
          </li>
        </ol>

        <template v-if="can('sensor.manage') && sensorActive">
          <label class="mt-8 block"><span class="label">理由（审批、吊销、下线必填）</span><textarea v-model="sensorReason" rows="2" maxlength="1000" class="field mt-2 h-auto resize-none py-2" /></label>
          <p class="mt-4 text-[12px] leading-relaxed text-ink-3">轮换后旧凭据立即失效；吊销后不能再轮换，须重新登记传感器。下线会同时吊销凭据并退役配置，不可恢复；登记、批次与健康记录保留。</p>
        </template>
      </template>
      <template v-if="sensor && can('sensor.manage') && sensorActive" #foot>
        <button class="link text-[13px]" :disabled="busy" @click="withReason('decommission', '传感器已下线，凭据已吊销。')">下线</button>
        <button v-if="sensor.credential?.status === 'active'" class="link text-[13px]" :disabled="busy" @click="withReason('credentials/revoke', '凭据已吊销，立即失效。')">吊销凭据</button>
        <button v-if="sensor.credential?.status === 'active'" class="act" :disabled="busy" @click="rotate">轮换凭据</button>
      </template>
    </Drawer>

    <Drawer :open="drafting" title="起草配置版本" :kicker="sensor?.sensor.agentKey" @close="drafting = false">
      <div class="space-y-6">
        <label class="block"><span class="label">配置版本</span><input v-model="configForm.configVersion" class="field mt-2 num" maxlength="64" placeholder="如 cfg-2" /></label>
        <label class="block"><span class="label">特征契约</span><input v-model="configForm.featureContractVersion" class="field mt-2 num" maxlength="64" /></label>
        <label class="block"><span class="label">流时间窗（秒）</span><input v-model.number="configForm.flowWindowSeconds" type="number" min="1" max="3600" class="field mt-2 num" /></label>
        <label class="block"><span class="label">接口范围（JSON）</span><textarea v-model="configForm.interfaceScope" rows="2" class="field mt-2 h-auto resize-none py-2 num" /></label>
        <label class="block"><span class="label">过滤策略（JSON）</span><textarea v-model="configForm.filterPolicy" rows="2" class="field mt-2 h-auto resize-none py-2 num" /></label>
        <label class="block"><span class="label">采样策略（JSON）</span><textarea v-model="configForm.samplingPolicy" rows="2" class="field mt-2 h-auto resize-none py-2 num" /></label>
        <label class="block"><span class="label">起草理由</span><textarea v-model="configForm.reason" rows="2" maxlength="1000" class="field mt-2 h-auto resize-none py-2" /></label>
        <p class="text-[12.5px] leading-relaxed text-ink-3">配置字段不能包含命令、脚本或外部地址。起草后须由其他管理员批准，再显式启用。</p>
      </div>
      <template #foot>
        <button class="link text-[13px]" @click="drafting = false">取消</button>
        <button class="act" :disabled="busy || !configForm.configVersion.trim()" @click="submitDraft">起草</button>
      </template>
    </Drawer>

    <Drawer :open="registering" title="登记传感器" kicker="SENSOR" @close="registering = false">
      <div class="space-y-6">
        <label class="block"><span class="label">传感器标识</span><input v-model="reg.agentKey" class="field mt-2 num" maxlength="128" /></label>
        <label class="block"><span class="label">资产</span><select v-model.number="reg.assetId" class="field mt-2"><option :value="0" disabled>选择已授权资产</option><option v-for="a in data.assets.filter((x) => x.status === 'active')" :key="a.id" :value="a.id">{{ a.assetKey }} #{{ a.id }}</option></select></label>
        <label class="block"><span class="label">数据源 ID</span><input v-model.number="reg.dataSourceId" type="number" min="1" class="field mt-2 num" /></label>
        <label class="block"><span class="label">平台 / 版本</span>
          <span class="mt-2 grid grid-cols-2 gap-4"><input v-model="reg.platform" class="field num" maxlength="32" /><input v-model="reg.agentVersion" class="field num" maxlength="64" /></span></label>
        <label class="block"><span class="label">首个配置版本 / 流时间窗（秒）</span>
          <span class="mt-2 grid grid-cols-2 gap-4"><input v-model="reg.configVersion" class="field num" maxlength="64" /><input v-model.number="reg.flowWindowSeconds" type="number" min="1" class="field num" /></span></label>
        <label class="block"><span class="label">接口范围（JSON）</span><textarea v-model="reg.interfaceScope" rows="2" class="field mt-2 h-auto resize-none py-2 num" /></label>
        <p class="text-[12.5px] leading-relaxed text-ink-3">资产必须有有效授权；契约固定为 {{ V4 }}。设备凭据只在登记成功后显示一次。</p>
      </div>
      <template #foot>
        <button class="link text-[13px]" @click="registering = false">取消</button>
        <button class="act" :disabled="busy || !reg.agentKey.trim() || !reg.assetId || !reg.dataSourceId" @click="register">登记</button>
      </template>
    </Drawer>
  </div>
</template>
