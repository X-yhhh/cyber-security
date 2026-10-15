<script setup lang="ts">
/**
 * 传感器与执行器（资产与接入 / Agents，前端设计文档第 10.7 节，任务单 F4）。
 *
 * 分段「传感器 · 执行器 · 采集配置 · 机器凭据 · 健康窗口」，按权限展开；分段、资产、状态、搜索、传感器、判定与打开的对象（`id`）
 * 同步到 URL。待办中心的配置审批（`?tab=configs&sensorId=&id=`）与设备异常（`?tab=sensors|executors&id=`）直接打开对应抽屉。
 * - 存活来自心跳投影（ops.read），只表示机器在线；采集健康以健康窗口为准，沿用原运行健康页的四态与口径：
 *   服务端判定与当前状态分列，`replay_healthy` 显示「文件回放健康」并注明不代表现场采集，文件回放的内核丢包显示「不适用」。
 * - 凭据只在登记或轮换的响应抽屉中显示一次，关闭即从页面状态清除。
 * - 写操作需 sensor.manage（批准配置需 authorization.approve），带幂等键，写后重新读取。
 */
import { computed, ref, watch } from 'vue'
import { Activity, ArrowRight, Clock, Cpu, FileCog, HeartPulse, KeyRound, Plus, RadioTower, Search, ShieldCheck, X } from 'lucide-vue-next'
import PageHead from '@/components/PageHead.vue'
import Panel from '@/components/Panel.vue'
import Segmented from '@/components/Segmented.vue'
import StatBand from '@/components/StatBand.vue'
import Tag from '@/components/Tag.vue'
import LoadState from '@/components/LoadState.vue'
import CursorPager from '@/components/CursorPager.vue'
import { useCursor } from '@/composables/cursor'
import { errText } from '@/composables/load'
import { queryString, useQueryState } from '@/composables/query'
import { useSummary } from '@/composables/summary'
import { visibleTabs, type TabOption } from '@/composables/tabs'
import { toast } from '@/composables/toast'
import { can, session } from '@/api/session'
import {
  fmtTime, guardHealthStateLabel, guardMachineClientTypeLabel, guardMachineStatusLabel, guardVerificationLabel,
  type GuardHealthWindow, type GuardHeartbeat,
} from '@/api/types'
import { isUuid } from '@/api/v2/detect'
import {
  assetsApi, assetTitle, clientStatusLabel, configStatusLabel, platformLabel,
  type Asset, type ExecutorCreate, type Executor, type IssuedCredential, type MachineClient, type Sensor, type SensorConfig, type SensorCreate,
} from '@/api/v2/assets'
import { configTone, healthStateTone, machineClientTone, machineStatusTone, verificationTone } from '@/data/tones'
import ConfigDrawer from './ConfigDrawer.vue'
import ConfirmDrawer from './ConfirmDrawer.vue'
import CredentialDrawer from './CredentialDrawer.vue'
import DeviceDrawer from './DeviceDrawer.vue'
import DeviceFormDrawer from './DeviceFormDrawer.vue'

type Tab = 'sensors' | 'executors' | 'configs' | 'credentials' | 'health'
const ALL_TABS: readonly TabOption<Tab>[] = [
  { value: 'sensors', label: '传感器', anyOf: ['resource.read'] },
  { value: 'executors', label: '执行器', anyOf: ['resource.read'] },
  { value: 'configs', label: '采集配置', anyOf: ['resource.read'] },
  { value: 'credentials', label: '机器凭据', anyOf: ['sensor.manage', 'iam.manage'] },
  { value: 'health', label: '健康窗口', anyOf: ['ops.read'] },
]
const tabs = computed(() => visibleTabs(ALL_TABS, session.user?.permissions))
const STATUS: Record<Tab, readonly string[]> = {
  sensors: ['pending', 'active', 'offline', 'revoked'],
  executors: ['pending', 'active', 'suspended', 'revoked'],
  configs: ['draft', 'pending', 'approved', 'active', 'retired', 'rejected'],
  credentials: ['active', 'disabled', 'revoked'],
  health: [],
}
const VERIFICATIONS = Object.keys(guardVerificationLabel)
const isTab = (v: string): v is Tab => ALL_TABS.some((t) => t.value === v)

const tab = ref<Tab>('sensors')
const assetFilter = ref('')
const status = ref('')
const q = ref('')
const qDraft = ref('')
const sensorFilter = ref('')
const verification = ref('')
const clientType = ref('')
const openId = ref('')
const uuidParam = (v: Parameters<typeof queryString>[0]) => (isUuid(queryString(v)) ? queryString(v).trim() : '')
useQueryState({
  tab: { state: tab, default: 'sensors', parse: (v) => (isTab(queryString(v)) ? queryString(v) as Tab : 'sensors') },
  assetId: { state: assetFilter, default: '', parse: uuidParam },
  status: { state: status, default: '', parse: (v, query) => (STATUS[(isTab(queryString(query.tab)) ? queryString(query.tab) : 'sensors') as Tab].includes(queryString(v)) ? queryString(v) : '') },
  q: { state: q, default: '', parse: (v) => queryString(v).trim().slice(0, 128) },
  sensorId: { state: sensorFilter, default: '', parse: uuidParam },
  verification: { state: verification, default: '', parse: (v) => (VERIFICATIONS.includes(queryString(v)) ? queryString(v) : '') },
  type: { state: clientType, default: '', parse: (v) => (['sensor', 'executor'].includes(queryString(v)) ? queryString(v) : '') },
  id: { state: openId, default: '', parse: uuidParam },
}, () => { qDraft.value = q.value })

/** 当前分段不可见时（直达地址、权限变化）切到第一个可见分段。 */
watch(tabs, (list) => { if (list.length && !list.some((t) => t.value === tab.value)) tab.value = list[0].value }, { immediate: true })

/* ---------------- 名称辅助：资产、传感器、执行器 ---------------- */
const assets = ref<Asset[]>([])
const sensorIndex = ref(new Map<string, Sensor>())
const executorIndex = ref(new Map<string, Executor>())
if (can('resource.read')) {
  assetsApi.listAssets({ limit: 200 }).then((p) => { assets.value = p.items }).catch(() => { /* 退回截断 ID */ })
}
let indexLoaded = false
function loadIndex() {
  if (indexLoaded || !can('resource.read')) return
  indexLoaded = true
  assetsApi.listSensors({ limit: 200 }).then((p) => { sensorIndex.value = new Map(p.items.map((s) => [s.id, s])) }).catch(() => {})
  assetsApi.listExecutors({ limit: 200 }).then((p) => { executorIndex.value = new Map(p.items.map((s) => [s.id, s])) }).catch(() => {})
}
const assetLabel = (id: string | null | undefined) => {
  if (!id) return '—'
  const a = assets.value.find((x) => x.id === id)
  return a ? assetTitle(a) : id.slice(0, 8)
}
const deviceLabel = (d: { id: string; displayName?: string | null } | undefined, id: string | null | undefined, noun: string) =>
  (d?.displayName ? d.displayName : id ? `${noun} ${id.slice(0, 8)}` : '—')
const sensorLabel = (id: string | null | undefined) => deviceLabel(id ? sensorIndex.value.get(id) : undefined, id, '传感器')
const executorLabel = (id: string | null | undefined) => deviceLabel(id ? executorIndex.value.get(id) : undefined, id, '执行器')

/* ---------------- 列表 ---------------- */
const base = () => ({ assetId: assetFilter.value || undefined, status: status.value || undefined })
const lists = {
  sensors: useCursor<Sensor>((cursor) => assetsApi.listSensors({ ...base(), q: q.value || undefined, cursor }), false),
  executors: useCursor<Executor>((cursor) => assetsApi.listExecutors({ ...base(), q: q.value || undefined, cursor }), false),
  configs: useCursor<SensorConfig>((cursor) => assetsApi.listConfigs({ ...base(), sensorId: sensorFilter.value || undefined, cursor }), false),
  credentials: useCursor<MachineClient>((cursor) => assetsApi.listMachineClients({ ...base(), clientType: clientType.value || undefined, cursor }), false),
  health: useCursor<GuardHealthWindow>((cursor) => assetsApi.listHealthWindows({ assetId: assetFilter.value || undefined, sensorId: sensorFilter.value || undefined, verificationStatus: verification.value || undefined, cursor }), false),
}
const active = computed(() => lists[tab.value])

/** 心跳投影按资产读取一次（最多 200 条），用于存活列。 */
const beats = ref(new Map<string, GuardHeartbeat>())
let beatsFor: string | null = null
function loadBeats() {
  if (!can('ops.read') || beatsFor === assetFilter.value) return
  const key = assetFilter.value
  beatsFor = key
  const qy = { assetId: key || undefined, limit: 200 }
  Promise.allSettled([assetsApi.listSensorHeartbeats(qy), assetsApi.listExecutorHeartbeats(qy)]).then((rs) => {
    if (beatsFor !== key) return
    const m = new Map<string, GuardHeartbeat>()
    for (const r of rs) if (r.status === 'fulfilled') for (const h of r.value.items) m.set(h.id, h)
    beats.value = m
  })
}

const opened = new Set<Tab>()
function openTab(t: Tab) {
  if (opened.has(t) || !tabs.value.some((x) => x.value === t)) return
  opened.add(t)
  lists[t].reset()
  if (t === 'sensors' || t === 'executors') loadBeats()
  if (t === 'configs' || t === 'credentials' || t === 'health') loadIndex()
}
watch(tab, (t) => {
  /* 状态取值随分段不同；搜索只用于传感器与执行器。外部链接同时带来的有效筛选保留。 */
  if (status.value && !STATUS[t].includes(status.value)) status.value = ''
  if (q.value && t !== 'sensors' && t !== 'executors') { q.value = ''; qDraft.value = '' }
  openTab(t)
}, { immediate: true })
/** 读条件变化：当前分段从第一页重读，其他分段下次打开时重读。 */
watch([assetFilter, status, q, sensorFilter, verification, clientType], () => {
  opened.clear()
  openTab(tab.value)
})
let typing: ReturnType<typeof setTimeout> | undefined
watch(qDraft, (v) => { clearTimeout(typing); typing = setTimeout(() => { q.value = v.trim().slice(0, 128) }, 350) })
const reloadAll = () => { opened.clear(); beatsFor = null; indexLoaded = false; openTab(tab.value) }

/* ---------------- 读数带 ---------------- */
const summary = useSummary()
const stats = computed(() => [
  { key: 'sensors', label: '采集不健康', value: summary.data.ops?.sensorsUnhealthy, icon: RadioTower, tone: 'threat' as const, hint: '按最近健康窗口判定' },
  { key: 'executors', label: '执行器不健康', value: summary.data.ops?.executorsUnhealthy, icon: Cpu, tone: 'threat' as const, hint: '按心跳判定' },
  { key: 'configs', label: '待我批准的采集配置', value: summary.data.pendingApprovals?.sensorConfigs, icon: ShieldCheck, tone: 'signal' as const, hint: '排除本人起草' },
  { key: 'last', label: '最近健康窗口', value: summary.data.ops ? fmtTime(summary.data.ops.lastHealthAt) : undefined, icon: Clock, hint: '服务端接收时间' },
])

/* ---------------- 抽屉：设备 / 配置 ---------------- */
const deviceOpen = computed(() => ((tab.value === 'sensors' || tab.value === 'executors') && openId.value ? openId.value : ''))
const configOpen = computed(() => (tab.value === 'configs' && openId.value ? openId.value : ''))
const open = (id: string) => { openId.value = id }
const close = () => { openId.value = '' }
function onDrafted(configId: string, sensorId: string) {
  tab.value = 'configs'
  sensorFilter.value = sensorId
  openId.value = configId
}

/* 登记设备与一次性凭据 */
const formOpen = ref(false)
const busy = ref(false)
const issued = ref<(IssuedCredential & { title: string; deviceKind: string }) | null>(null)
async function register(kind: 'sensors' | 'executors', body: SensorCreate | ExecutorCreate) {
  busy.value = true
  try {
    const c = kind === 'sensors' ? await assetsApi.createSensor(body as SensorCreate) : await assetsApi.createExecutor(body as ExecutorCreate)
    formOpen.value = false
    const noun = kind === 'sensors' ? '传感器' : '执行器'
    issued.value = { ...c, title: `${noun}已登记`, deviceKind: noun }
    if (tab.value !== kind) tab.value = kind
    reloadAll()
  } catch (e) { toast(errText(e), 'threat') } finally { busy.value = false }
}

/* 吊销机器凭据 */
const revoking = ref<MachineClient | null>(null)
function confirmRevoke(reason: string) {
  const c = revoking.value
  if (!c) return
  busy.value = true
  assetsApi.revokeMachineClient(c.id, reason)
    .then(() => { toast('已吊销机器凭据，关联设备同时吊销。'); revoking.value = null; reloadAll() })
    .catch((e: unknown) => toast(errText(e), 'threat'))
    .finally(() => { busy.value = false })
}

/* ---------------- 显示辅助 ---------------- */
const tabLabel = computed(() => ALL_TABS.find((t) => t.value === tab.value)?.label ?? '')
const tabIcon = computed(() => ({ sensors: RadioTower, executors: Cpu, configs: FileCog, credentials: KeyRound, health: HeartPulse })[tab.value])
const statusLabel = (s: string) => (tab.value === 'configs' ? configStatusLabel[s] : tab.value === 'credentials' ? clientStatusLabel[s] : guardMachineStatusLabel[s]) ?? s
const filtered = computed(() => !!(assetFilter.value || status.value || q.value || sensorFilter.value || verification.value || clientType.value))
function clearFilters() { assetFilter.value = ''; status.value = ''; q.value = ''; qDraft.value = ''; sensorFilter.value = ''; verification.value = ''; clientType.value = '' }
const emptyText = computed(() => {
  if (filtered.value) return '当前筛选条件下没有记录。'
  return ({ sensors: '你的资产范围内还没有登记传感器。', executors: '你的资产范围内还没有登记执行器。', configs: '你的资产范围内还没有采集配置。', credentials: '你的资产范围内没有机器凭据。', health: '你的资产范围内还没有接收到健康窗口。' })[tab.value]
})
const beat = (id: string) => beats.value.get(id)
const stale = (h: GuardHeartbeat | undefined) => !h || h.healthState !== 'healthy'
const counters = (w: GuardHealthWindow) => {
  const a = w.counterStart, b = w.counterEnd
  const d = (x: number | null, y: number | null) => (x === null || y === null ? '未知' : String(y - x))
  return `收包 +${d(a.packetsSeen, b.packetsSeen)} · 内核丢包 ${b.kernelDrops === null ? (w.captureSource === 'file_replay' ? '不适用' : '未知') : d(a.kernelDrops, b.kernelDrops)} · 容量丢弃 ${d(a.capacityDrops, b.capacityDrops)}`
}
const sensors = computed(() => lists.sensors.items.value)
const executors = computed(() => lists.executors.items.value)
</script>

<template>
  <div>
    <PageHead title="传感器与执行器" desc="采集与执行两类机器身份、采集配置、机器凭据与采集健康。心跳只表示机器在线，采集健康以健康窗口为准。">
      <button v-if="can('sensor.manage')" type="button" class="act" @click="formOpen = true"><Plus :size="15" :stroke-width="1.5" />登记设备</button>
    </PageHead>

    <StatBand class="mb-5" label="接入概览" :stats="stats" />

    <p v-if="!tabs.length" class="panel px-5 py-10 text-center text-[13px] text-ink-3">当前身份没有查看传感器、执行器或健康窗口的权限。</p>
    <template v-else>
      <Segmented v-model="tab" :options="tabs" />

      <Panel class="mt-4" :title="tabLabel" :icon="tabIcon" flush>
        <template #actions>
          <span v-if="tab === 'sensors' || tab === 'executors'" class="text-[12px] text-ink-3">{{ can('ops.read') ? '存活按心跳投影，最多对照 200 台' : '无运行状态权限，不显示存活' }}</span>
          <span v-else-if="tab === 'health'" class="text-[12px] text-ink-3">当前状态 = 服务端判定 + 10 秒新鲜度</span>
        </template>
        <template #toolbar>
          <div class="toolbar w-full" role="search">
            <label v-if="tab === 'sensors' || tab === 'executors'" class="toolbar-field"><Search :size="14" :stroke-width="1.5" aria-hidden="true" />
              <input v-model="qDraft" type="search" class="field !w-48" maxlength="128" :placeholder="tab === 'sensors' ? '按显示名或代理键搜索' : '按显示名搜索'" aria-label="搜索设备" />
            </label>
            <label v-if="assets.length" class="toolbar-field"><span>资产</span>
              <select v-model="assetFilter" class="field" aria-label="资产筛选">
                <option value="">全部资产</option>
                <option v-for="a in assets" :key="a.id" :value="a.id">{{ assetTitle(a) }}</option>
              </select>
            </label>
            <label v-if="STATUS[tab].length" class="toolbar-field"><span>状态</span>
              <select v-model="status" class="field" aria-label="状态筛选">
                <option value="">全部状态</option>
                <option v-for="s in STATUS[tab]" :key="s" :value="s">{{ statusLabel(s) }}</option>
              </select>
            </label>
            <label v-if="tab === 'credentials'" class="toolbar-field"><span>类型</span>
              <select v-model="clientType" class="field" aria-label="凭据类型">
                <option value="">全部类型</option>
                <option value="sensor">采集身份</option>
                <option value="executor">执行身份</option>
              </select>
            </label>
            <label v-if="tab === 'health'" class="toolbar-field"><span>服务端判定</span>
              <select v-model="verification" class="field" aria-label="服务端判定">
                <option value="">全部</option>
                <option v-for="s in VERIFICATIONS" :key="s" :value="s">{{ guardVerificationLabel[s] }}</option>
              </select>
            </label>
            <span v-if="sensorFilter && (tab === 'configs' || tab === 'health')" class="chip" aria-pressed="true">
              {{ sensorLabel(sensorFilter) }}<button type="button" class="-mr-1 opacity-80 hover:opacity-100" aria-label="取消按传感器筛选" @click="sensorFilter = ''"><X :size="12" :stroke-width="1.5" /></button>
            </span>
            <button v-if="filtered" type="button" class="link text-[12.5px]" @click="clearFilters">清除筛选</button>
          </div>
        </template>

        <LoadState :loading="active.loading.value" :error="active.error.value" :empty="!active.items.value.length" :empty-text="emptyText">
          <!-- 传感器 -->
          <table v-if="tab === 'sensors'" class="table min-w-[880px]">
            <thead><tr><th>传感器</th><th>资产</th><th>平台 / 版本</th><th>登记状态</th><th>存活</th><th class="text-right">最近心跳</th></tr></thead>
            <tbody>
              <tr v-for="s in sensors" :key="s.id" class="row-link" tabindex="0" :aria-current="openId === s.id ? 'true' : undefined" @click="open(s.id)" @keydown.enter="open(s.id)">
                <td><span class="block text-ink">{{ s.displayName || `传感器 ${s.id.slice(0, 8)}` }}</span><span class="num text-[11.5px] text-ink-4">{{ s.agentKey.slice(0, 8) }}</span></td>
                <td class="max-w-[12rem] truncate text-ink-2">{{ assetLabel(s.assetId) }}</td>
                <td class="whitespace-nowrap"><span class="text-ink-2">{{ platformLabel[s.platform] ?? s.platform }}</span><span class="num ml-2 text-[11.5px] text-ink-4">{{ s.agentVersion }}</span></td>
                <td><Tag pill :tone="machineStatusTone[s.status]" :label="guardMachineStatusLabel[s.status] ?? s.status" /></td>
                <td><Tag v-if="beat(s.id)" :tone="healthStateTone[beat(s.id)!.healthState]" :label="guardHealthStateLabel[beat(s.id)!.healthState] ?? beat(s.id)!.healthState" /><span v-else class="text-ink-4">—</span></td>
                <td class="num whitespace-nowrap text-right" :class="stale(beat(s.id)) ? 'text-ink-4' : 'text-ink-2'">{{ fmtTime(s.lastHeartbeatAt) }}</td>
              </tr>
            </tbody>
          </table>

          <!-- 执行器 -->
          <table v-else-if="tab === 'executors'" class="table min-w-[880px]">
            <thead><tr><th>执行器</th><th>资产</th><th>平台 / 适配器</th><th>登记状态</th><th>存活</th><th>活动规则 / 待恢复</th><th class="text-right">最近心跳</th></tr></thead>
            <tbody>
              <tr v-for="e in executors" :key="e.id" class="row-link" tabindex="0" :aria-current="openId === e.id ? 'true' : undefined" @click="open(e.id)" @keydown.enter="open(e.id)">
                <td class="text-ink">{{ e.displayName || `执行器 ${e.id.slice(0, 8)}` }}</td>
                <td class="max-w-[12rem] truncate text-ink-2">{{ assetLabel(e.assetId) }}</td>
                <td class="whitespace-nowrap"><span class="text-ink-2">{{ platformLabel[e.platform] ?? e.platform }}</span><span class="num ml-2 text-[11.5px] text-ink-4">{{ e.adapterVersion }}</span></td>
                <td><Tag pill :tone="machineStatusTone[e.status]" :label="guardMachineStatusLabel[e.status] ?? e.status" /></td>
                <td><Tag v-if="beat(e.id)" :tone="healthStateTone[beat(e.id)!.healthState]" :label="guardHealthStateLabel[beat(e.id)!.healthState] ?? beat(e.id)!.healthState" /><span v-else class="text-ink-4">—</span></td>
                <td class="num text-ink-2">{{ beat(e.id)?.reported?.activeRuleCount ?? '—' }} / {{ beat(e.id)?.reported?.pendingRecovery == null ? '—' : beat(e.id)!.reported!.pendingRecovery ? '是' : '否' }}</td>
                <td class="num whitespace-nowrap text-right" :class="stale(beat(e.id)) ? 'text-ink-4' : 'text-ink-2'">{{ fmtTime(e.lastHeartbeat) }}</td>
              </tr>
            </tbody>
          </table>

          <!-- 采集配置 -->
          <table v-else-if="tab === 'configs'" class="table min-w-[880px]">
            <thead><tr><th>传感器</th><th>资产</th><th>接口 / 地址族</th><th>批量上限</th><th>状态</th><th class="text-right">起草</th></tr></thead>
            <tbody>
              <tr v-for="c in lists.configs.items.value" :key="c.id" class="row-link" tabindex="0" :aria-current="openId === c.id ? 'true' : undefined" @click="open(c.id)" @keydown.enter="open(c.id)">
                <td class="text-ink">{{ sensorLabel(c.sensorId) }}</td>
                <td class="max-w-[12rem] truncate text-ink-2">{{ assetLabel(c.assetId) }}</td>
                <td class="num text-ink-2">{{ c.definition?.interfaceIds?.join(', ') ?? '—' }}<span class="ml-2 text-[11.5px] text-ink-4">{{ c.definition?.addressFamily ?? '' }}</span></td>
                <td class="num text-ink-2">{{ c.definition?.limits?.maxBatchSize ?? '—' }}</td>
                <td><Tag pill :tone="configTone[c.status]" :label="configStatusLabel[c.status] ?? c.status" /></td>
                <td class="num whitespace-nowrap text-right text-ink-3">{{ fmtTime(c.createdAt) }}</td>
              </tr>
            </tbody>
          </table>

          <!-- 机器凭据 -->
          <table v-else-if="tab === 'credentials'" class="table min-w-[880px]">
            <thead><tr><th>类型</th><th>绑定设备</th><th>资产</th><th>状态</th><th>登记</th><th>最近使用</th><th>到期</th><th /></tr></thead>
            <tbody>
              <tr v-for="c in lists.credentials.items.value" :key="c.id">
                <td class="whitespace-nowrap text-ink-2">{{ guardMachineClientTypeLabel[c.clientType] ?? c.clientType }}</td>
                <td>
                  <RouterLink v-if="c.sensorId" class="link text-[13px]" :to="{ query: { tab: 'sensors', id: c.sensorId } }">{{ sensorLabel(c.sensorId) }}</RouterLink>
                  <RouterLink v-else-if="c.executorId" class="link text-[13px]" :to="{ query: { tab: 'executors', id: c.executorId } }">{{ executorLabel(c.executorId) }}</RouterLink>
                  <span v-else class="text-ink-4">—</span>
                </td>
                <td class="max-w-[12rem] truncate text-ink-2">{{ assetLabel(c.assetId) }}</td>
                <td><Tag pill :tone="machineClientTone[c.status]" :label="clientStatusLabel[c.status] ?? c.status" /></td>
                <td class="num whitespace-nowrap text-ink-3">{{ fmtTime(c.createdAt) }}</td>
                <td class="num whitespace-nowrap text-ink-3">{{ fmtTime(c.lastUsedAt) }}</td>
                <td class="num whitespace-nowrap text-ink-3">{{ c.expiresAt ? fmtTime(c.expiresAt) : '不过期' }}</td>
                <td class="text-right">
                  <button v-if="can('sensor.manage') && c.status !== 'revoked'" type="button" class="act-danger act-sm" @click="revoking = c">吊销</button>
                </td>
              </tr>
            </tbody>
          </table>

          <!-- 健康窗口：沿用原运行健康页的四态与口径 -->
          <table v-else class="table min-w-[960px]">
            <thead><tr><th>服务端判定</th><th>当前状态</th><th>来源 / 版本</th><th>窗口结束</th><th>计数变化</th><th class="text-right">序号 / 传感器</th></tr></thead>
            <tbody>
              <tr v-for="w in lists.health.items.value" :key="w.id">
                <td>
                  <Tag :tone="verificationTone[w.verificationStatus ?? '']" :label="w.verificationStatus ? (guardVerificationLabel[w.verificationStatus] ?? w.verificationStatus) : '无判定'" />
                  <span v-if="w.verificationStatus === 'replay_healthy'" class="block text-[11.5px] text-ink-4">不代表现场采集健康</span>
                </td>
                <td><Tag :tone="healthStateTone[w.healthState]" :label="guardHealthStateLabel[w.healthState] ?? w.healthState" /></td>
                <td><span class="block text-ink-2">{{ w.captureSource === 'file_replay' ? '文件回放' : w.captureSource === 'live' ? '现场采集' : (w.captureSource ?? '—') }}</span><span class="num text-[11.5px] text-ink-4">{{ w.healthVersion ?? '—' }}</span></td>
                <td><span class="num block text-ink-2">{{ fmtTime(w.intervalEnd) }}</span><span class="num text-[11.5px] text-ink-4">接收 {{ fmtTime(w.receivedAt) }}<template v-if="w.captureGap"> · 有缺口</template></span></td>
                <td class="num text-[12px] text-ink-3">{{ counters(w) }}</td>
                <td class="text-right"><span class="num text-ink-3">#{{ w.sequence }}</span><button v-if="w.sensorId" type="button" class="link ml-2 text-[12.5px]" @click="sensorFilter = w.sensorId">{{ sensorLabel(w.sensorId) }}</button></td>
              </tr>
            </tbody>
          </table>
        </LoadState>

        <template #foot>
          <CursorPager :count="active.items.value.length" :has-next="!!active.next.value" :has-prev="!!active.stack.value.length"
            :busy="active.turning.value" :label="tabLabel" @next="active.forward()" @prev="active.back()" />
        </template>
      </Panel>

      <!-- 口径说明：放在相关分段下方，一句话 -->
      <p v-if="tab === 'health'" class="mt-3 flex items-center gap-2 text-[12px] text-ink-3"><Activity :size="13" :stroke-width="1.5" aria-hidden="true" />文件回放健康只证明 lab 回放窗口完整，不代表现场采集健康，也不用于预算恢复。</p>
      <p v-else-if="tab === 'credentials'" class="mt-3 flex items-center gap-2 text-[12px] text-ink-3"><KeyRound :size="13" :stroke-width="1.5" aria-hidden="true" />台账不含凭据明文或摘要；新凭据只在登记或轮换时显示一次。</p>
      <p v-else-if="tab === 'configs'" class="mt-3 flex items-center gap-2 text-[12px] text-ink-3"><ArrowRight :size="13" :stroke-width="1.5" aria-hidden="true" />在传感器详情中起草配置；批准须由起草人以外的审批人完成。</p>
    </template>

    <DeviceDrawer v-if="tab === 'sensors' || tab === 'executors'" :kind="tab" :id="deviceOpen" :asset-label="assetLabel" :beat="deviceOpen ? beat(deviceOpen) : undefined"
      @close="close" @changed="reloadAll" @issued="(c) => { issued = c }" @drafted="onDrafted" />
    <ConfigDrawer :id="configOpen" :asset-label="assetLabel" :sensor-label="sensorLabel" @close="close" @changed="reloadAll" />
    <DeviceFormDrawer :open="formOpen" :assets="assets" :busy="busy" :initial-kind="tab === 'executors' ? 'executors' : 'sensors'" :initial-asset="assetFilter"
      @sensor="(b) => register('sensors', b)" @executor="(b) => register('executors', b)" @close="formOpen = false" />
    <CredentialDrawer :issued="issued" @close="issued = null" />
    <ConfirmDrawer v-if="revoking" :open="!!revoking" title="吊销机器凭据" :kicker="revoking.sensorId ? sensorLabel(revoking.sensorId) : executorLabel(revoking.executorId)"
      note="吊销后凭据立即失效，关联的传感器或执行器同时变为已吊销（终态），不能再启用或轮换，只能重新登记设备。" tone="threat" confirm-label="确认吊销" danger :busy="busy"
      @confirm="confirmRevoke" @close="revoking = null">
      <dl class="kv">
        <div><dt>类型</dt><dd>{{ guardMachineClientTypeLabel[revoking.clientType] ?? revoking.clientType }}</dd></div>
        <div><dt>资产</dt><dd>{{ assetLabel(revoking.assetId) }}</dd></div>
        <div><dt>最近使用</dt><dd class="num">{{ fmtTime(revoking.lastUsedAt) }}</dd></div>
      </dl>
    </ConfirmDrawer>
  </div>
</template>
