<script setup lang="ts">
/**
 * 资产详情整页（/console/assets/list/:id，前端设计文档第 10.7 节，任务单 F4）。
 *
 * 分段「概况 · 授权 · 接入设备 · 活动发布」，分段、授权状态筛选与定位的授权（`id`）同步到 URL；只读取打开过的分段。
 * - 停用资产后显示「新命令已暂停」；退役为终态，不再提供启用入口（后端同样以 409 拒绝）。
 * - 写操作：编辑资料、停用/启用、退役（asset.manage，If-Match）；申请授权、撤回本人待批申请（authorization.request）；
 *   批准、驳回、撤销授权（authorization.approve，本人申请的不显示）。requestedBy 与会话 id 同口径；历史归属为空时由后端判定，
 *   自批与撤回他人申请由后端 403 拒绝。写后重新读取，不做乐观更新。
 * - 面包屑第三段显示资产显示名（useCrumbLabel，F0R.5）。
 */
import { computed, nextTick, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import {
  ArrowLeft, ArrowRight, Ban, CalendarClock, Cpu, FileKey2, PackageCheck, PauseCircle, Pencil, Power, RadioTower, Server, ShieldCheck, Archive,
} from 'lucide-vue-next'
import Panel from '@/components/Panel.vue'
import SectionTabs from '@/components/SectionTabs.vue'
import Tag from '@/components/Tag.vue'
import IdText from '@/components/IdText.vue'
import LoadState from '@/components/LoadState.vue'
import CursorPager from '@/components/CursorPager.vue'
import { useCrumbLabel } from '@/composables/crumb'
import { useCursor } from '@/composables/cursor'
import { errText } from '@/composables/load'
import { queryString, useQueryState } from '@/composables/query'
import { toast } from '@/composables/toast'
import type { TabOption } from '@/composables/tabs'
import { ApiError } from '@/api/client'
import { can, session } from '@/api/session'
import { isUuid } from '@/api/v2/detect'
import {
  fmtTime, guardAssetEnvLabel, guardBundleStatusLabel, guardCapabilityLevelLabel, guardHealthStateLabel, guardMachineStatusLabel,
  type GuardCapability, type GuardHeartbeat, type GuardReleaseBundle,
} from '@/api/types'
import {
  assetPlatform, assetsApi, assetStatusLabel, assetTitle, authorizationStatusLabel, bindingStatusLabel, CRITICALITIES, criticalityLabel,
  directionLabel, platformLabel, scopeLabel, validityLabel,
  type Asset, type AssetBinding, type AssetUpdate, type Authorization, type AuthorizationRequest, type Executor, type Sensor,
} from '@/api/v2/assets'
import { assetStatusTone, authorizationTone, bindingTone, bundleTone, healthStateTone, machineStatusTone, validityTone } from '@/data/tones'
import AssetFormDrawer from './AssetFormDrawer.vue'
import AuthorizationDrawer from './AuthorizationDrawer.vue'
import ConfirmDrawer from './ConfirmDrawer.vue'

const route = useRoute()
const assetId = computed(() => String(route.params.id ?? ''))

type Tab = 'overview' | 'authorizations' | 'devices' | 'releases'
const TABS: readonly Tab[] = ['overview', 'authorizations', 'devices', 'releases']
const AUTH_STATUSES = ['pending', 'active', 'expired', 'revoked'] as const
const tab = ref<Tab>('overview')
const authStatus = ref('')
const focusId = ref('')
useQueryState({
  tab: { state: tab, default: 'overview', parse: (v) => ((TABS as readonly string[]).includes(queryString(v)) ? queryString(v) as Tab : 'overview') },
  status: { state: authStatus, default: '', parse: (v) => ((AUTH_STATUSES as readonly string[]).includes(queryString(v)) ? queryString(v) : '') },
  id: { state: focusId, default: '', parse: (v) => (isUuid(queryString(v)) ? queryString(v).trim() : '') },
})
const tabs: readonly TabOption<Tab>[] = [
  { value: 'overview', label: '概况' },
  { value: 'authorizations', label: '授权', anyOf: ['resource.read'] },
  { value: 'devices', label: '接入设备', anyOf: ['resource.read'] },
  { value: 'releases', label: '活动发布', anyOf: ['resource.read'] },
]

/* ---------------- 资产 ---------------- */
const asset = ref<Asset | null>(null)
const loading = ref(true)
const error = ref('')
const notFound = ref(false)
useCrumbLabel(computed(() => (asset.value ? assetTitle(asset.value) : undefined)))
let seq = 0
async function loadAsset() {
  const mine = ++seq
  loading.value = !asset.value
  error.value = ''
  notFound.value = false
  try {
    const a = await assetsApi.getAsset(assetId.value)
    if (mine === seq) asset.value = a
  } catch (e) {
    if (mine !== seq) return
    if (e instanceof ApiError && e.status === 404) notFound.value = true
    else error.value = errText(e)
  } finally { if (mine === seq) loading.value = false }
}

/* ---------------- 接入事实（概况与接入设备共用，打开时读取一次） ---------------- */
interface Facts { loading: boolean; error: string; auths: Authorization[]; sensors: Sensor[]; executors: Executor[]; beats: Map<string, GuardHeartbeat> }
const facts = ref<Facts>({ loading: false, error: '', auths: [], sensors: [], executors: [], beats: new Map() })
let factsFor = ''
async function loadFacts(force = false) {
  const id = assetId.value
  if (!can('resource.read') || (!force && factsFor === id)) return
  factsFor = id
  facts.value = { ...facts.value, loading: true, error: '' }
  const ops = can('ops.read')
  const [auths, sensors, executors, sBeats, eBeats] = await Promise.allSettled([
    assetsApi.listAuthorizations({ assetId: id, limit: 200 }),
    assetsApi.listSensors({ assetId: id, limit: 200 }),
    assetsApi.listExecutors({ assetId: id, limit: 200 }),
    ops ? assetsApi.listSensorHeartbeats({ assetId: id, limit: 200 }) : Promise.resolve(null),
    ops ? assetsApi.listExecutorHeartbeats({ assetId: id, limit: 200 }) : Promise.resolve(null),
  ])
  if (factsFor !== id) return
  const beats = new Map<string, GuardHeartbeat>()
  for (const r of [sBeats, eBeats]) if (r.status === 'fulfilled' && r.value) for (const h of r.value.items) beats.set(h.id, h)
  const failed = [auths, sensors, executors].find((r) => r.status === 'rejected') as PromiseRejectedResult | undefined
  facts.value = {
    loading: false, error: failed ? errText(failed.reason) : '', beats,
    auths: auths.status === 'fulfilled' ? auths.value.items : [],
    sensors: sensors.status === 'fulfilled' ? sensors.value.items : [],
    executors: executors.status === 'fulfilled' ? executors.value.items : [],
  }
}
const activeAuths = computed(() => facts.value.auths.filter((a) => a.status === 'active' && a.validity === 'valid').length)
const pendingAuths = computed(() => facts.value.auths.filter((a) => a.status === 'pending').length)

/* ---------------- 授权分段 ---------------- */
const auths = useCursor<Authorization>((cursor) => assetsApi.listAuthorizations({ assetId: assetId.value, status: authStatus.value || undefined, cursor }), false)
const capabilities = ref<Map<string, GuardCapability>>(new Map())
let capsTried = false
function loadCaps() {
  if (capsTried || !can('resource.read')) return
  capsTried = true
  assetsApi.listCapabilities().then((p) => { capabilities.value = new Map(p.items.map((c) => [c.id, c])) }).catch(() => { /* 资产范围身份看不到能力目录，显示 ID */ })
}
const capName = (id: string | null) => {
  const c = id ? capabilities.value.get(id) : undefined
  return c ? `${c.capabilityKey} · ${guardCapabilityLevelLabel[c.level] ?? c.level}` : null
}

/* ---------------- 活动发布分段 ---------------- */
interface Release { binding: AssetBinding; bundle: GuardReleaseBundle }
const releases = ref<{ loading: boolean; error: string; denied: boolean; items: Release[] }>({ loading: false, error: '', denied: false, items: [] })
let releasesFor = ''
async function loadReleases(force = false) {
  const id = assetId.value
  if (!force && releasesFor === id) return
  releasesFor = id
  releases.value = { loading: true, error: '', denied: false, items: [] }
  try {
    const pages = await Promise.all([assetsApi.listBundles('active'), assetsApi.listBundles('suspended')])
    const bundles = pages.flatMap((p) => p.items)
    const bound = await Promise.all(bundles.map(async (bundle) => (await assetsApi.listBundleBindings(bundle.id)).items
      .filter((b) => b.assetId === id).map((binding) => ({ binding, bundle }))))
    if (releasesFor !== id) return
    const order: Record<string, number> = { active: 0, suspended: 1 }
    releases.value = { loading: false, error: '', denied: false, items: bound.flat().sort((x, y) => (order[x.binding.status] ?? 2) - (order[y.binding.status] ?? 2) || y.binding.createdAt.localeCompare(x.binding.createdAt)) }
  } catch (e) {
    if (releasesFor !== id) return
    const denied = e instanceof ApiError && e.status === 403
    releases.value = { loading: false, error: denied ? '' : errText(e), denied, items: [] }
  }
}

/* ---------------- 分段读取：只读取打开过的分段 ---------------- */
const opened = new Set<Tab>()
function openTab(t: Tab, force = false) {
  if (!force && opened.has(t)) return
  opened.add(t)
  if (t === 'overview' || t === 'devices') void loadFacts(force)
  if (t === 'authorizations') { loadCaps(); auths.reset() }
  if (t === 'releases') void loadReleases(force)
}
watch(assetId, (id) => {
  if (!id) return
  asset.value = null
  opened.clear(); factsFor = ''; releasesFor = ''
  void loadAsset()
  openTab(tab.value)
}, { immediate: true })
watch(tab, (t) => openTab(t))
watch(authStatus, () => { if (opened.has('authorizations')) auths.reset() })

/** 待办跳转定位的授权：加载后滚动到该卡片。 */
watch(() => [auths.items.value, focusId.value] as const, async ([items, id]) => {
  if (!id || tab.value !== 'authorizations' || !items.some((a) => a.id === id)) return
  await nextTick()
  document.getElementById(`auth-${id}`)?.scrollIntoView({ block: 'center', behavior: 'smooth' })
})

/* ---------------- 有效期 ---------------- */
const now = Date.now()
function span(a: Authorization) {
  const from = Date.parse(a.validFrom), until = Date.parse(a.validUntil)
  const pct = until > from ? Math.min(100, Math.max(0, ((now - from) / (until - from)) * 100)) : 0
  const days = Math.ceil((until - now) / 86_400_000)
  const left = a.validity === 'expired' ? '已过有效期' : a.validity === 'not_yet_valid' ? `${fmtTime(a.validFrom)} 起生效` : days <= 1 ? '不足 1 天到期' : `剩余 ${days} 天`
  return { pct, left, soon: a.validity === 'valid' && days <= 7 }
}

/* ---------------- 写操作 ---------------- */
const busy = ref(false)
async function run(fn: () => Promise<unknown>, done: string, after: () => void | Promise<void>) {
  busy.value = true
  try {
    await fn()
    toast(done)
    await after()
  } catch (e) { toast(errText(e), 'threat') } finally { busy.value = false }
}
const refreshAll = async () => {
  await loadAsset()
  for (const t of [...opened]) { opened.delete(t); openTab(t, true) }
}

/* 编辑资料 */
const editOpen = ref(false)
function saveAsset(body: AssetUpdate) {
  const a = asset.value
  if (!a) return
  void run(() => assetsApi.updateAsset(a.id, a.revision, body), '已保存资产资料。', async () => { editOpen.value = false; await loadAsset() })
}

/* 停用 / 启用 / 退役：二次确认并写明影响 */
type StatusOp = 'disable' | 'enable' | 'retire'
const statusOp = ref<StatusOp | null>(null)
const statusCopy: Record<StatusOp, { title: string; note: string; confirm: string; danger: boolean; tone: 'warn' | 'threat' | 'plain'; status: 'active' | 'disabled' | 'retired'; done: string }> = {
  disable: { title: '停用资产', note: '停用后控制面立即暂停向该资产下发新命令，活动发布绑定同时暂停。已生效的封禁不会因此自动解除，如需解除请到处置记录撤销。可以重新启用，但已暂停的发布绑定不会自动恢复。', confirm: '确认停用', danger: true, tone: 'warn', status: 'disabled', done: '已停用资产，新命令已暂停。' },
  enable: { title: '启用资产', note: '启用后资产恢复为运行中。之前暂停的发布绑定不会自动恢复，需要在发布管理中重新激活。', confirm: '确认启用', danger: false, tone: 'plain', status: 'active', done: '已启用资产。' },
  retire: { title: '退役资产', note: '退役是终态：新命令与活动发布绑定立即暂停，之后不能再启用该资产。已生效的封禁不会因此自动解除。', confirm: '确认退役', danger: true, tone: 'threat', status: 'retired', done: '已退役资产。' },
}
function confirmStatus() {
  const a = asset.value, op = statusOp.value
  if (!a || !op) return
  void run(() => assetsApi.updateAsset(a.id, a.revision, { status: statusCopy[op].status }), statusCopy[op].done, async () => { statusOp.value = null; await refreshAll() })
}

/* 申请授权 */
const requestOpen = ref(false)
function submitRequest(body: AuthorizationRequest) {
  const a = asset.value
  if (!a) return
  void run(() => assetsApi.requestAuthorization(a.id, body), '已提交授权申请，等待他人批准。', async () => {
    requestOpen.value = false
    authStatus.value = ''
    if (tab.value !== 'authorizations') tab.value = 'authorizations'
    opened.delete('authorizations'); opened.delete('overview'); factsFor = ''
    openTab('authorizations', true)
  })
}

/* 授权操作 */
type AuthOp = 'approve' | 'reject' | 'revoke' | 'withdraw'
const authOp = ref<{ op: AuthOp; auth: Authorization } | null>(null)
const authCopy: Record<AuthOp, { title: string; note: string; confirm: string; danger: boolean; tone: 'warn' | 'threat' | 'plain'; done: string }> = {
  approve: { title: '批准授权', note: '批准后授权在有效期内生效，但不会创建防火墙规则；采集仍须批准采集配置，处置仍须活动发布组合并满足全部硬约束。', confirm: '批准授权', danger: false, tone: 'plain', done: '已批准授权。' },
  reject: { title: '驳回授权申请', note: '驳回后该申请结束，申请人需要重新提交。', confirm: '驳回申请', danger: true, tone: 'warn', done: '已驳回授权申请。' },
  revoke: { title: '撤销授权', note: '撤销后授权修订号提高，控制面拒绝该资产依赖此授权的新命令，并排队撤销已有规则。受理不等于规则已清理，清理结果以执行器回执为准。', confirm: '确认撤销', danger: true, tone: 'threat', done: '已受理撤销，规则清理请看处置记录回执。' },
  withdraw: { title: '撤回授权申请', note: '只能撤回你本人提交、仍待批准的申请。撤回后申请结束。', confirm: '撤回申请', danger: true, tone: 'warn', done: '已撤回授权申请。' },
}
const mine = (by: number | string | null | undefined) => by !== undefined && by !== null && session.user != null && String(by) === String(session.user.id)
/** 申请人字段缺失时视为未知：入口照常显示，由后端判定。 */
const notMine = (a: Authorization) => !mine(a.requestedBy)
const maybeMine = (a: Authorization) => a.requestedBy === undefined || a.requestedBy === null || mine(a.requestedBy)
const retired = computed(() => asset.value?.status === 'retired')
function confirmAuth(reason: string) {
  const cur = authOp.value
  if (!cur) return
  const { op, auth: a } = cur
  const call = op === 'approve' || op === 'reject'
    ? () => assetsApi.decideAuthorization(a.id, a.revision, op, reason)
    : op === 'revoke' ? () => assetsApi.revokeAuthorization(a.id, a.revision, reason) : () => assetsApi.withdrawAuthorization(a.id, a.revision, reason)
  void run(call, authCopy[op].done, () => { authOp.value = null; auths.reset(); factsFor = ''; opened.delete('overview') })
}

const beat = (id: string) => facts.value.beats.get(id)
const deviceName = (d: { displayName?: string | null; id: string }, fallback: string) => d.displayName || `${fallback} ${d.id.slice(0, 8)}`
const releaseLink = (bundleId: string) => ({ path: '/console/release/bundles', query: { tab: 'bundles', id: bundleId } })
</script>

<template>
  <div>
    <RouterLink to="/console/assets/list" class="link mb-5 text-[13px] text-ink-3"><ArrowLeft :size="14" :stroke-width="1.5" /> 资产</RouterLink>

    <p v-if="notFound" class="panel px-5 py-12 text-center text-[13px] text-ink-3">资产不存在，或不在你的资产范围内。</p>
    <LoadState v-else :loading="loading" :error="error">
      <div v-if="asset">
        <!-- 页头：资产卡 -->
        <header class="panel mb-4 overflow-hidden">
          <div class="flex flex-col gap-5 p-5 lg:flex-row lg:items-start lg:justify-between">
            <div class="flex min-w-0 gap-4">
              <span class="inline-flex h-11 w-11 shrink-0 items-center justify-center rounded border" :class="asset.status === 'active' ? 'border-ink-line text-ink' : asset.status === 'disabled' ? 'border-warn/40 bg-warn-soft text-warn' : 'border-ink-line bg-paper-soft text-ink-4'" aria-hidden="true">
                <Server :size="20" :stroke-width="1.5" />
              </span>
              <div class="min-w-0">
                <p class="flex flex-wrap items-center gap-2.5 text-[12px] text-ink-3">
                  <span class="num">{{ asset.assetKey }}</span>
                  <Tag :tone="asset.environment === 'authorized' ? 'ok' : asset.environment === 'lab' ? 'warn' : 'mute'" :label="`${guardAssetEnvLabel[asset.environment] ?? asset.environment}环境`" />
                  <Tag pill :tone="assetStatusTone[asset.status]" :label="assetStatusLabel[asset.status] ?? asset.status" />
                </p>
                <h1 class="mt-1.5 truncate text-[1.5rem] font-medium leading-snug tracking-[-0.01em] text-ink">{{ assetTitle(asset) }}</h1>
                <p class="mt-1 text-[12.5px] text-ink-3">
                  {{ platformLabel[assetPlatform(asset) ?? ''] ?? assetPlatform(asset) ?? '平台未知' }}<span class="mx-2 text-ink-line">|</span>关键性 {{ criticalityLabel[asset.criticality] ?? asset.criticality }}<span class="mx-2 text-ink-line">|</span>责任人 {{ asset.owner || '—' }}
                </p>
              </div>
            </div>
            <div class="flex shrink-0 flex-wrap items-center gap-2.5">
              <template v-if="can('asset.manage')">
                <button type="button" class="act-ghost" @click="editOpen = true"><Pencil :size="14" :stroke-width="1.5" />编辑资料</button>
                <button v-if="asset.status === 'active'" type="button" class="act-ghost" @click="statusOp = 'disable'"><PauseCircle :size="14" :stroke-width="1.5" />停用资产</button>
                <button v-else-if="asset.status === 'disabled'" type="button" class="act-ghost" @click="statusOp = 'enable'"><Power :size="14" :stroke-width="1.5" />启用资产</button>
                <button v-if="!retired" type="button" class="act-danger" @click="statusOp = 'retire'"><Archive :size="14" :stroke-width="1.5" />退役</button>
              </template>
              <button v-if="can('authorization.request') && !retired" type="button" class="act" @click="requestOpen = true"><FileKey2 :size="15" :stroke-width="1.5" />申请授权</button>
            </div>
          </div>
          <!-- 停用 / 退役：新命令已暂停 -->
          <div v-if="asset.status !== 'active'" class="flex items-start gap-3 border-t px-5 py-3 text-[12.5px] leading-relaxed" :class="asset.status === 'disabled' ? 'border-warn/30 bg-warn-soft' : 'border-ink-hair bg-paper-soft'" role="status">
            <PauseCircle :size="16" :stroke-width="1.5" class="mt-0.5 shrink-0" :class="asset.status === 'disabled' ? 'text-warn' : 'text-ink-3'" aria-hidden="true" />
            <p v-if="asset.status === 'disabled'"><span class="font-medium text-ink">新命令已暂停。</span><span class="text-ink-2">资产已停用，控制面不再向它下发新命令，活动发布绑定已暂停；重新启用后绑定不会自动恢复。</span></p>
            <p v-else><span class="font-medium text-ink">新命令已暂停。</span><span class="text-ink-2">资产已退役（终态），不能再启用。</span></p>
          </div>
        </header>

        <SectionTabs v-model="tab" :options="tabs" label="资产详情分段" class="mb-4" />

        <!-- 概况 -->
        <div v-if="tab === 'overview'" class="grid items-start gap-5 xl:grid-cols-[minmax(0,1fr)_20rem]">
          <Panel title="资料" :icon="Server">
            <dl class="kv">
              <div><dt>显示名</dt><dd>{{ asset.displayName || '—' }}</dd></div>
              <div><dt>资产键</dt><dd class="num">{{ asset.assetKey }}</dd></div>
              <div><dt>环境</dt><dd>{{ guardAssetEnvLabel[asset.environment] ?? asset.environment }}<span class="ml-2 text-[12px] text-ink-4">登记后不可修改</span></dd></div>
              <div><dt>平台</dt><dd>{{ platformLabel[assetPlatform(asset) ?? ''] ?? assetPlatform(asset) ?? '—' }}</dd></div>
              <div><dt>关键性</dt><dd class="flex items-center gap-2">
                <span class="inline-flex gap-0.5" aria-hidden="true"><span v-for="(c, n) in CRITICALITIES" :key="c" class="h-2.5 w-1.5 rounded-[1px]" :class="n <= CRITICALITIES.indexOf(asset.criticality as never) ? (asset.criticality === 'critical' ? 'bg-threat' : asset.criticality === 'high' ? 'bg-warn' : 'bg-ink-3') : 'bg-ink-hair'" /></span>
                {{ criticalityLabel[asset.criticality] ?? asset.criticality }}</dd></div>
              <div><dt>责任人</dt><dd>{{ asset.owner || '—' }}</dd></div>
              <div><dt>说明</dt><dd class="whitespace-pre-line">{{ asset.notes || '—' }}</dd></div>
              <div><dt>登记</dt><dd class="num">{{ fmtTime(asset.createdAt) }}</dd></div>
              <div><dt>最近更新</dt><dd class="num">{{ fmtTime(asset.updatedAt) }}</dd></div>
            </dl>
          </Panel>
          <aside class="space-y-4">
            <Panel title="接入摘要" :icon="ShieldCheck" desc="最多统计各 200 条">
              <LoadState :loading="facts.loading" :error="facts.error">
                <ul class="divide-y divide-ink-hair text-[13px]">
                  <li><button type="button" class="flex w-full items-center justify-between py-2.5 text-left hover:text-ink" @click="tab = 'authorizations'">
                    <span class="text-ink-2">有效授权</span><span class="flex items-center gap-2"><span class="num text-[15px] text-ink">{{ activeAuths }}</span><ArrowRight :size="13" :stroke-width="1.5" class="text-ink-4" /></span></button></li>
                  <li><button type="button" class="flex w-full items-center justify-between py-2.5 text-left" @click="authStatus = 'pending'; tab = 'authorizations'">
                    <span class="text-ink-2">待批准申请</span><span class="flex items-center gap-2"><span class="num text-[15px]" :class="pendingAuths ? 'text-signal' : 'text-ink'">{{ pendingAuths }}</span><ArrowRight :size="13" :stroke-width="1.5" class="text-ink-4" /></span></button></li>
                  <li><button type="button" class="flex w-full items-center justify-between py-2.5 text-left" @click="tab = 'devices'">
                    <span class="text-ink-2">传感器</span><span class="flex items-center gap-2"><span class="num text-[15px] text-ink">{{ facts.sensors.length }}</span><ArrowRight :size="13" :stroke-width="1.5" class="text-ink-4" /></span></button></li>
                  <li><button type="button" class="flex w-full items-center justify-between py-2.5 text-left" @click="tab = 'devices'">
                    <span class="text-ink-2">执行器</span><span class="flex items-center gap-2"><span class="num text-[15px] text-ink">{{ facts.executors.length }}</span><ArrowRight :size="13" :stroke-width="1.5" class="text-ink-4" /></span></button></li>
                </ul>
              </LoadState>
            </Panel>
          </aside>
          <details class="tech-details xl:col-span-2">
            <summary>技术细节</summary>
            <dl class="kv">
              <div><dt>资产 ID</dt><dd><IdText :value="asset.id" /></dd></div>
              <div><dt>资产类型</dt><dd class="num">{{ asset.assetType }}</dd></div>
              <div><dt>修订号</dt><dd class="num">{{ asset.revision }}</dd></div>
              <div><dt>标签</dt><dd class="num break-all">{{ asset.labels ? JSON.stringify(asset.labels) : '—' }}</dd></div>
            </dl>
          </details>
        </div>

        <!-- 授权 -->
        <Panel v-else-if="tab === 'authorizations'" title="授权记录" :icon="FileKey2" flush>
          <template #actions><span class="text-[12px] text-ink-3">批准不创建防火墙规则</span></template>
          <template #toolbar>
            <div class="chips" role="group" aria-label="授权状态">
              <button type="button" class="chip" :aria-pressed="authStatus === ''" @click="authStatus = ''">全部</button>
              <button v-for="s in AUTH_STATUSES" :key="s" type="button" class="chip" :aria-pressed="authStatus === s" @click="authStatus = s">{{ authorizationStatusLabel[s] }}</button>
            </div>
          </template>
          <LoadState :loading="auths.loading.value" :error="auths.error.value" :empty="!auths.items.value.length" :empty-text="authStatus ? '该状态下没有授权记录。' : '该资产还没有授权记录。'">
            <ul class="divide-y divide-ink-hair">
              <li v-for="a in auths.items.value" :id="`auth-${a.id}`" :key="a.id" class="px-5 py-4 transition-colors" :class="focusId === a.id ? 'bg-paper-soft shadow-[inset_2px_0_0_#14161A]' : ''">
                <div class="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                  <div class="min-w-0 flex-1">
                    <p class="flex flex-wrap items-center gap-2.5">
                      <Tag pill :tone="authorizationTone[a.status]" :label="authorizationStatusLabel[a.status] ?? a.status" />
                      <Tag :tone="validityTone[a.validity]" :label="validityLabel[a.validity] ?? a.validity" />
                      <span class="text-[12px] text-ink-3">申请于 <span class="num">{{ fmtTime(a.createdAt) }}</span></span>
                      <span class="num text-[11.5px] text-ink-4">r{{ a.revision }}</span>
                    </p>
                    <!-- 有效期条：起止与当前时刻 -->
                    <div class="mt-3 max-w-xl">
                      <div class="flex items-center justify-between text-[12px] text-ink-3">
                        <span class="flex items-center gap-1.5"><CalendarClock :size="13" :stroke-width="1.5" aria-hidden="true" /><span class="num">{{ fmtTime(a.validFrom) }}</span> — <span class="num">{{ fmtTime(a.validUntil) }}</span></span>
                        <span :class="span(a).soon ? 'text-warn' : ''">{{ span(a).left }}</span>
                      </div>
                      <span class="mt-1.5 block h-1 overflow-hidden rounded-full bg-ink-hair" aria-hidden="true">
                        <span class="block h-full rounded-full" :class="a.validity === 'valid' && a.status === 'active' ? (span(a).soon ? 'bg-warn' : 'bg-ok') : 'bg-ink-4'" :style="{ width: `${span(a).pct}%` }" />
                      </span>
                    </div>
                    <dl class="mt-3 grid gap-x-6 gap-y-1.5 text-[12.5px] sm:grid-cols-[auto_minmax(0,1fr)]">
                      <dt class="text-ink-3">采集接口</dt>
                      <dd class="flex flex-wrap gap-1.5"><span v-for="i in a.scope.interfaces ?? []" :key="i" class="num rounded-sm bg-paper-soft px-1.5 text-[12px] text-ink-2">{{ i }}</span><span v-if="!a.scope.interfaces?.length" class="text-ink-4">—</span></dd>
                      <dt class="text-ink-3">允许观察</dt>
                      <dd class="text-ink-2">{{ a.scope.observationAllowed === true ? '是' : a.scope.observationAllowed === false ? '否' : '—' }}</dd>
                      <dt class="text-ink-3">执行范围</dt>
                      <dd>
                        <span v-if="!a.scope.executionScopes?.length" class="text-ink-3">无（只授权观察，不允许阻断命令）</span>
                        <ul v-else class="space-y-1">
                          <li v-for="(s, i) in a.scope.executionScopes" :key="i" class="flex flex-wrap items-center gap-x-2 text-ink-2">
                            <span>{{ directionLabel[s.direction ?? ''] ?? s.direction }} · {{ scopeLabel[s.scope ?? 'peer_service'] ?? s.scope }}</span>
                            <span class="num text-ink">{{ s.scope === 'peer_inbound' ? '全部端口' : `${(s.transport ?? 'tcp').toUpperCase()}/${s.servicePort ?? '—'}` }}</span>
                            <span class="text-ink-4">能力</span><span v-if="capName(s.capabilityId)" class="text-ink-2">{{ capName(s.capabilityId) }}</span><IdText v-else :value="s.capabilityId" :copy="false" />
                          </li>
                        </ul>
                      </dd>
                    </dl>
                  </div>
                  <div class="flex shrink-0 flex-wrap items-center gap-2">
                    <template v-if="a.status === 'pending'">
                      <template v-if="can('authorization.approve') && notMine(a)">
                        <button type="button" class="act-ghost act-sm" @click="authOp = { op: 'reject', auth: a }">驳回</button>
                        <button type="button" class="act-ghost act-sm" @click="authOp = { op: 'approve', auth: a }"><ShieldCheck :size="13" :stroke-width="1.5" />批准授权</button>
                      </template>
                      <button v-if="can('authorization.request') && maybeMine(a)" type="button" class="link text-[12.5px]" @click="authOp = { op: 'withdraw', auth: a }">撤回申请</button>
                    </template>
                    <button v-else-if="a.status === 'active' && can('authorization.approve')" type="button" class="act-danger act-sm" @click="authOp = { op: 'revoke', auth: a }"><Ban :size="13" :stroke-width="1.5" />撤销授权</button>
                  </div>
                </div>
              </li>
            </ul>
          </LoadState>
          <template #foot>
            <CursorPager :count="auths.items.value.length" :has-next="!!auths.next.value" :has-prev="!!auths.stack.value.length"
              :busy="auths.turning.value" label="授权" @next="auths.forward()" @prev="auths.back()" />
          </template>
        </Panel>

        <!-- 接入设备 -->
        <div v-else-if="tab === 'devices'" class="grid items-start gap-5 xl:grid-cols-2">
          <Panel v-for="kind in (['sensors', 'executors'] as const)" :key="kind" :title="kind === 'sensors' ? '传感器' : '执行器'" :icon="kind === 'sensors' ? RadioTower : Cpu"
            :desc="can('ops.read') ? '存活来自心跳，只表示机器在线' : '没有运行状态读取权限，不显示存活'">
            <template #actions>
              <RouterLink class="link text-[12.5px]" :to="{ path: '/console/assets/agents', query: { tab: kind, assetId: asset.id } }">在传感器与执行器中管理<ArrowRight :size="13" :stroke-width="1.5" /></RouterLink>
            </template>
            <LoadState :loading="facts.loading" :error="facts.error" :empty="!(kind === 'sensors' ? facts.sensors : facts.executors).length" :empty-text="kind === 'sensors' ? '该资产还没有登记传感器。' : '该资产还没有登记执行器。'">
              <ul class="space-y-2.5">
                <li v-for="d in (kind === 'sensors' ? facts.sensors : facts.executors)" :key="d.id">
                  <RouterLink :to="{ path: '/console/assets/agents', query: { tab: kind, id: d.id } }" class="flex items-center gap-3 rounded border border-ink-line px-3.5 py-3 transition-colors hover:border-ink-4">
                    <span class="dot shrink-0" :class="{ 'bg-ok': healthStateTone[beat(d.id)?.healthState ?? ''] === 'ok', 'bg-warn': healthStateTone[beat(d.id)?.healthState ?? ''] === 'warn', 'bg-threat': healthStateTone[beat(d.id)?.healthState ?? ''] === 'threat', 'bg-ink-4': !beat(d.id) || healthStateTone[beat(d.id)!.healthState] === 'mute' || healthStateTone[beat(d.id)!.healthState] === 'signal' }" aria-hidden="true" />
                    <span class="min-w-0 flex-1">
                      <span class="block truncate text-[13.5px] text-ink">{{ deviceName(d, kind === 'sensors' ? '传感器' : '执行器') }}</span>
                      <span class="num block truncate text-[11.5px] text-ink-4">{{ platformLabel[d.platform] ?? d.platform }} · {{ kind === 'sensors' ? (d as Sensor).agentVersion : (d as Executor).adapterVersion }}</span>
                    </span>
                    <span class="shrink-0 text-right">
                      <Tag pill :tone="machineStatusTone[d.status]" :label="guardMachineStatusLabel[d.status] ?? d.status" />
                      <span v-if="beat(d.id)" class="mt-1 block text-[11.5px] text-ink-3">{{ guardHealthStateLabel[beat(d.id)!.healthState] ?? beat(d.id)!.healthState }} · <span class="num">{{ fmtTime(beat(d.id)!.receivedAt) }}</span></span>
                    </span>
                  </RouterLink>
                </li>
              </ul>
            </LoadState>
          </Panel>
        </div>

        <!-- 活动发布 -->
        <Panel v-else-if="tab === 'releases'" title="活动发布" :icon="PackageCheck" flush desc="绑定到该资产的发布组合；激活、暂停在发布管理中操作">
          <p v-if="releases.denied" class="px-5 pb-6 pt-2 text-[13px] text-ink-3">发布组合是全局对象，需要全局读取权限；资产范围内的身份看不到这一分段。</p>
          <LoadState v-else :loading="releases.loading" :error="releases.error" :empty="!releases.items.length" empty-text="该资产没有生效中或已暂停的发布绑定。">
            <table class="table min-w-[760px]">
              <thead><tr><th>发布组合</th><th>组合状态</th><th>绑定状态</th><th>依据授权</th><th>绑定时间</th><th /></tr></thead>
              <tbody>
                <tr v-for="r in releases.items" :key="r.binding.id">
                  <td><span class="num block text-ink">{{ r.bundle.bundleKey }}</span><span class="num text-[11.5px] text-ink-4">{{ r.bundle.version }} · {{ guardAssetEnvLabel[r.bundle.environment] ?? r.bundle.environment }}</span></td>
                  <td><Tag pill :tone="bundleTone[r.bundle.status]" :label="guardBundleStatusLabel[r.bundle.status] ?? r.bundle.status" /></td>
                  <td><Tag :tone="bindingTone[r.binding.status]" :label="bindingStatusLabel[r.binding.status] ?? r.binding.status" /></td>
                  <td><IdText :value="r.binding.authorizationId" /><span v-if="r.binding.authorizationRevision != null" class="num ml-1 text-[11.5px] text-ink-4">r{{ r.binding.authorizationRevision }}</span></td>
                  <td class="num whitespace-nowrap text-ink-3">{{ fmtTime(r.binding.createdAt) }}</td>
                  <td class="text-right"><RouterLink class="link text-[12.5px]" :to="releaseLink(r.bundle.id)">查看组合<ArrowRight :size="13" :stroke-width="1.5" /></RouterLink></td>
                </tr>
              </tbody>
            </table>
          </LoadState>
          <template #foot><span>按生效中与已暂停的发布组合（各最多 50 个）查找本资产的绑定。</span></template>
        </Panel>
      </div>
    </LoadState>

    <AssetFormDrawer :open="editOpen" :asset="asset" :busy="busy" @update="saveAsset" @close="editOpen = false" />
    <AuthorizationDrawer :open="requestOpen" :asset-name="asset ? assetTitle(asset) : ''" :busy="busy" @submit="submitRequest" @close="requestOpen = false" />
    <ConfirmDrawer v-if="statusOp" :open="!!statusOp" :title="statusCopy[statusOp].title" :kicker="asset ? assetTitle(asset) : ''" :note="statusCopy[statusOp].note"
      :tone="statusCopy[statusOp].tone" :confirm-label="statusCopy[statusOp].confirm" :danger="statusCopy[statusOp].danger" reason="none" :busy="busy"
      @confirm="confirmStatus" @close="statusOp = null" />
    <ConfirmDrawer v-if="authOp" :open="!!authOp" :title="authCopy[authOp.op].title" :kicker="asset ? assetTitle(asset) : ''" :note="authCopy[authOp.op].note"
      :tone="authCopy[authOp.op].tone" :confirm-label="authCopy[authOp.op].confirm" :danger="authCopy[authOp.op].danger" :busy="busy"
      @confirm="confirmAuth" @close="authOp = null">
      <dl class="kv">
        <div><dt>授权状态</dt><dd>{{ authorizationStatusLabel[authOp.auth.status] ?? authOp.auth.status }}</dd></div>
        <div><dt>有效期</dt><dd class="num">{{ fmtTime(authOp.auth.validFrom) }} — {{ fmtTime(authOp.auth.validUntil) }}</dd></div>
        <div><dt>采集接口</dt><dd class="num">{{ authOp.auth.scope.interfaces?.join(', ') || '—' }}</dd></div>
        <div><dt>执行范围</dt><dd>{{ authOp.auth.scope.executionScopes?.length ?? 0 }} 条</dd></div>
      </dl>
      <p v-if="authOp.op === 'approve'" class="mt-4 text-[12px] leading-relaxed text-ink-3">授权须由申请人以外的审批人批准；如果这是你本人的申请，后端会拒绝。</p>
    </ConfirmDrawer>
  </div>
</template>
