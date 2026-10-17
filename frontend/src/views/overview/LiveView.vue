<script setup lang="ts">
/**
 * 实时态势（态势 / 实时态势，任务单 F6，前端设计文档第 10.1 节）。
 *
 * 数据与权限（各块按权限分别显示，前端只隐藏入口，裁剪以后端为准）：
 * - 趋势与今日计数：GET /stats/live（B5.2 契约，见 api/v2/stats.ts）。入站与告警需 detection.read，拦截需 action.read；
 * - 最新判定：GET /decisions 最近 20 条（detection.read），点击按归并关系进入事件；
 * - 设备在线：GET sensor-heartbeats / executor-heartbeats（ops.read），心跳新鲜（10 秒内）即在线，不代表采集健康。
 *
 * 刷新：默认每 3 秒轮询，可选 1/3/5/10 秒；15 分钟视图按相同间隔出点，历史范围保留聚合并显示实际桶宽。
 * 页面不可见或手动暂停时停止轮询；切换范围或间隔立即重读一次，保留暂停状态，并用请求序号作废旧响应。
 * 缺口：stats 中 null 表示该时段没有采集覆盖，折线断开、不补 0，并写明“传感器未接入，最后一次数据 <时间>”。
 */
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { Activity, Cpu, Pause, Play, Radio, RadioTower, ShieldAlert, ShieldBan, Siren, Waves } from 'lucide-vue-next'
import PageHead from '@/components/PageHead.vue'
import Panel from '@/components/Panel.vue'
import StatBand, { type Stat } from '@/components/StatBand.vue'
import TrendChart, { type TrendSeries } from '@/components/TrendChart.vue'
import SectionTabs from '@/components/SectionTabs.vue'
import LoadState from '@/components/LoadState.vue'
import IdText from '@/components/IdText.vue'
import Tag from '@/components/Tag.vue'
import { guard } from '@/api/client'
import { can } from '@/api/session'
import { detectApi } from '@/api/v2/detect'
import { LIVE_INTERVALS, RANGE_LABEL, bucketStart, fetchLiveStats, liveStep, trailingNulls, type LiveInterval, type LiveRange, type LiveStats } from '@/api/v2/stats'
import {
  GUARD_FAMILIES, fmtTime, guardDecisionLabel, guardFamilyLabel, guardSourceLabel,
  type GuardAsset, type GuardDecision, type GuardDecisionEvidence, type GuardHeartbeat, type GuardReadPage,
} from '@/api/types'
import type { ChartTone } from '@/components/chart'
import { decisionTone } from '@/data/tones'
import { errText } from '@/composables/load'
import { toast } from '@/composables/toast'
import { useSummary } from '@/composables/summary'
import { useQueryState } from '@/composables/query'

const DEVICE_POLL_MS = 30000
const router = useRouter()

const canDetect = can('detection.read')
const canAction = can('action.read')
const canOps = can('ops.read')
const wantsStats = canDetect || canAction

const RANGES: LiveRange[] = ['15m', '1h', '24h', '7d']
const isRange = (v: unknown): v is LiveRange => typeof v === 'string' && (RANGES as string[]).includes(v)
const range = ref<LiveRange>('15m')
const interval = ref<LiveInterval>('3')
useQueryState({
  range: { state: range, default: '15m', parse: (v) => isRange(v) ? v : '15m' },
  interval: { state: interval, default: '3', parse: (v) => typeof v === 'string' && (LIVE_INTERVALS as readonly string[]).includes(v) ? v as LiveInterval : '3' },
})
const rangeOptions = RANGES.map((r) => ({ value: r, label: RANGE_LABEL[r] }))

/* ---------- 数据 ---------- */
const stats = ref<LiveStats | null>(null)
const statsError = ref('')
const decisions = ref<GuardDecision[]>([])
const decisionsError = ref('')
const freshIds = ref(new Set<string>())
const sensors = ref<GuardHeartbeat[]>([])
const executors = ref<GuardHeartbeat[]>([])
const devicesLoaded = ref(false)
const devicesError = ref('')
const updatedAt = ref<number | null>(null)
const summary = useSummary()

const assets = ref<GuardAsset[]>([])
void (async () => {
  if (!can('resource.read')) return
  try { assets.value = (await guard.list<GuardAsset>('assets', { limit: 200 })).items } catch { /* 资产名称只是辅助显示 */ }
})()
const assetName = (id: string | null | undefined) => (id ? assets.value.find((a) => a.id === id)?.assetKey ?? null : null)

let seq = 0
let devicesSeq = 0
let lastDevicesAt = 0
/** 读取一轮；设备心跳按经过时间每 30 秒读取，恢复时可强制刷新，不随图表频率变快。各类旧响应按各自序号丢弃。 */
async function refresh(devices = false) {
  const mine = ++seq
  const jobs: Promise<unknown>[] = []
  if (wantsStats) {
    jobs.push(fetchLiveStats(range.value, liveStep(range.value, interval.value))
      .then((d) => { if (mine === seq) { stats.value = d; statsError.value = '' } })
      .catch((e) => { if (mine === seq) statsError.value = errText(e) }))
  }
  if (canDetect) {
    jobs.push(guard.list<GuardDecision>('decisions', { limit: 20 })
      .then((page) => {
        if (mine !== seq) return
        const before = new Set(decisions.value.map((d) => d.id))
        freshIds.value = decisions.value.length ? new Set(page.items.filter((d) => !before.has(d.id)).map((d) => d.id)) : new Set()
        decisions.value = page.items
        decisionsError.value = ''
      })
      .catch((e) => { if (mine === seq) decisionsError.value = errText(e) }))
  }
  if (canOps && (devices || Date.now() - lastDevicesAt >= DEVICE_POLL_MS)) {
    lastDevicesAt = Date.now()
    const devicesMine = ++devicesSeq
    jobs.push(Promise.all([
      guard.read<GuardReadPage<GuardHeartbeat>>('sensor-heartbeats', { limit: 50 }),
      guard.read<GuardReadPage<GuardHeartbeat>>('executor-heartbeats', { limit: 50 }),
    ]).then(([s, e]) => {
      if (devicesMine !== devicesSeq) return
      sensors.value = s.items; executors.value = e.items; devicesLoaded.value = true; devicesError.value = ''
    }).catch((e) => { if (devicesMine === devicesSeq) devicesError.value = errText(e) }))
  }
  await Promise.allSettled(jobs)
  if (mine === seq) updatedAt.value = Date.now()
}

/* ---------- 轮询：页面不可见或手动暂停时停止 ---------- */
const paused = ref(false)
const hidden = ref(typeof document !== 'undefined' && document.visibilityState === 'hidden')
const running = computed(() => !paused.value && !hidden.value)
let timer: ReturnType<typeof setInterval> | undefined
let mounted = false
/** 更换频率只保留一个定时器；离场作废在途响应，避免旧页面继续更新。 */
function startPolling() {
  clearInterval(timer)
  if (!mounted) return
  timer = setInterval(() => {
    if (running.value) void refresh()
  }, Number(interval.value) * 1000)
}
function onVisibility() {
  const was = hidden.value
  hidden.value = document.visibilityState === 'hidden'
  if (was && !hidden.value && !paused.value) { void refresh(true); startPolling() }
}
onMounted(() => {
  mounted = true
  void refresh(true)
  startPolling()
  document.addEventListener('visibilitychange', onVisibility)
})
onBeforeUnmount(() => {
  mounted = false
  seq++
  devicesSeq++
  clearInterval(timer)
  document.removeEventListener('visibilitychange', onVisibility)
})
function togglePause() {
  paused.value = !paused.value
  if (running.value) { void refresh(true); startPolling() }
}
watch([range, interval], () => {
  stats.value = null
  statsError.value = ''
  startPolling()
  void refresh()
})

/* ---------- 图表 ---------- */
const xLabels = computed(() => {
  const s = stats.value
  if (!s) return []
  return Array.from({ length: s.points }, (_, i) => {
    const d = bucketStart(s, i)
    const p = (n: number) => String(n).padStart(2, '0')
    const hm = `${p(d.getHours())}:${p(d.getMinutes())}`
    return s.range === '15m' ? `${hm}:${p(d.getSeconds())}` : s.range === '7d' ? `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}时` : hm
  })
})
const stepText = computed(() => {
  const st = stats.value?.step ?? 0
  return st >= 3600 ? `${st / 3600} 小时` : st >= 60 ? `${st / 60} 分钟` : `${st} 秒`
})
const FAMILY_TONE: Record<string, ChartTone> = { brute_force: 'threat', dos_flood: 'warn', port_scan: 'signal', dos_slow: 'mute' }
const inboundSeries = computed<TrendSeries[]>(() => (stats.value?.inbound ? [{ key: 'inbound', name: '入站观察', tone: 'ink', area: true, points: stats.value.inbound }] : []))
const alertSeries = computed<TrendSeries[]>(() => {
  const s = stats.value
  if (!s) return []
  const out: TrendSeries[] = []
  if (s.alerts) {
    const fams = [...GUARD_FAMILIES.filter((f) => f in s.alerts!), ...Object.keys(s.alerts).filter((f) => !(GUARD_FAMILIES as readonly string[]).includes(f))]
    for (const f of fams.slice(0, 4)) out.push({ key: f, name: `告警 · ${guardFamilyLabel[f] ?? f}`, tone: FAMILY_TONE[f] ?? 'mute', points: s.alerts[f] })
  }
  if (s.blocked) out.push({ key: 'blocked', name: '拦截生效', tone: 'ink', dashed: true, points: s.blocked })
  return out
})
/** 缺口说明：末尾连续无数据的时长与最后一次数据时间。 */
const gapNote = computed(() => {
  const s = stats.value
  if (!s) return ''
  const ref0 = s.inbound ?? s.blocked ?? Object.values(s.alerts ?? {})[0]
  const tail = trailingNulls(ref0)
  if (!ref0 || !tail) return ''
  const last = s.asOf ? fmtTime(s.asOf) : '无记录'
  if (tail >= s.points) return `传感器未接入，最后一次数据 ${last}`
  const secs = tail * s.step
  const dur = secs >= 3600 ? `${Math.round(secs / 360) / 10} 小时` : secs >= 60 ? `${Math.round(secs / 60)} 分钟` : `${secs} 秒`
  return `最近 ${dur}无数据：传感器未接入，最后一次数据 ${last}`
})
const allEmptyText = computed(() => `传感器未接入，最后一次数据 ${stats.value?.asOf ? fmtTime(stats.value.asOf) : '无记录'}`)

function download(csv: string, name: string) {
  if (typeof URL.createObjectURL !== 'function') return
  const url = URL.createObjectURL(new Blob(['﻿', csv], { type: 'text/csv;charset=utf-8' }))
  const a = Object.assign(document.createElement('a'), { href: url, download: name })
  a.click()
  URL.revokeObjectURL(url)
}

/* ---------- 今日计数 ---------- */
const todayStats = computed<Stat[]>(() => {
  const t = stats.value?.today
  return [
    { key: 'inbound', label: '今日入站观察', value: t?.inbound, icon: Radio },
    { key: 'alerts', label: '今日告警', value: t?.alerts, icon: Siren, tone: 'warn' },
    { key: 'blocked', label: '今日拦截生效', value: t?.blocked, icon: ShieldBan },
    { key: 'open', label: '待研判事件', value: t?.openEvents ?? (canDetect ? summary.data.openEvents : undefined), icon: ShieldAlert, tone: 'threat', to: { name: 'detect-events', query: { status: 'open' } } },
  ]
})

/* ---------- 设备 ---------- */
const online = (list: GuardHeartbeat[]) => list.filter((h) => h.freshness === 'fresh').length
const nodes = computed(() => [
  ...sensors.value.map((h) => ({ ...h, kind: '采集' as const })),
  ...executors.value.map((h) => ({ ...h, kind: '执行' as const })),
].sort((a, b) => Number(b.freshness === 'fresh') - Number(a.freshness === 'fresh') || (b.receivedAt ?? '').localeCompare(a.receivedAt ?? '')))
function ago(v: string | null) {
  if (!v) return '无心跳'
  const s = Math.max(0, Math.round(((updatedAt.value ?? Date.now()) - Date.parse(v)) / 1000))
  return s < 60 ? `${s} 秒前` : s < 3600 ? `${Math.floor(s / 60)} 分钟前` : s < 86400 ? `${Math.floor(s / 3600)} 小时前` : `${Math.floor(s / 86400)} 天前`
}

/* ---------- 最新判定 ---------- */
const ev = (d: GuardDecision) => (d.evidence && typeof d.evidence === 'object' ? d.evidence : {}) as GuardDecisionEvidence
const clock = (v: string | null) => {
  if (!v) return '—'
  const d = new Date(v)
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleTimeString('zh-CN', { hour12: false })
}
/** 判定不直接携带事件 ID：在同资产的最近事件中按判定或证据迹归并关系查找；只观察的判定不形成事件。 */
async function openDecision(d: GuardDecision) {
  if (d.decision === 'observe') return toast('仅观察的判定不会归并为事件。', 'warn')
  try {
    const page = await detectApi.listEvents({ assetId: d.assetId, limit: 50 })
    const hit = page.items.find((e) => e.decisionIds?.includes(d.id) || e.episodeIds?.includes(d.episodeId))
    if (hit) return void router.push(`/console/detect/events/${encodeURIComponent(hit.id)}`)
    toast('最近事件中没有找到该判定的归并事件，已打开该资产的事件列表。', 'warn')
    void router.push({ name: 'detect-events', query: { assetId: d.assetId } })
  } catch (e) { toast(errText(e), 'threat') }
}
</script>

<template>
  <div>
    <PageHead title="实时态势" desc="入站观察、告警与拦截的实时趋势，以及最新判定与设备在线情况。各块按你的权限与资产范围显示。" />
    <div class="mb-4 flex flex-wrap items-center gap-2.5">
      <span class="flex items-center gap-2 text-[12.5px]" :class="running ? 'text-ink-2' : 'text-ink-4'" role="status">
        <span class="relative flex h-2 w-2" aria-hidden="true">
          <span v-if="running" class="absolute inline-flex h-full w-full animate-ping rounded-full bg-ok opacity-60" />
          <span class="relative inline-flex h-2 w-2 rounded-full" :class="running ? 'bg-ok' : 'bg-ink-4'" />
        </span>
        {{ running ? `实时 · 每 ${interval} 秒刷新` : hidden ? '页面不可见，已暂停' : '已暂停' }}
        <span v-if="updatedAt" class="num text-ink-4">{{ new Date(updatedAt).toLocaleTimeString('zh-CN', { hour12: false }) }}</span>
      </span>
      <button type="button" class="act-ghost act-sm" :aria-pressed="paused" @click="togglePause">
        <Play v-if="paused" :size="13" :stroke-width="1.5" /><Pause v-else :size="13" :stroke-width="1.5" />{{ paused ? '继续' : '暂停' }}
      </button>
      <label class="inline-flex items-center gap-2 text-[12.5px] text-ink-3">
        <span>刷新间隔</span>
        <select v-model="interval" class="field !h-7 !w-auto" aria-describedby="live-interval-help">
          <option v-for="seconds in LIVE_INTERVALS" :key="seconds" :value="seconds">{{ seconds }} 秒</option>
        </select>
      </label>
      <SectionTabs v-if="wantsStats" v-model="range" :options="rangeOptions" label="时间范围" />
    </div>

    <p id="live-interval-help" class="mb-4 text-[12px] text-ink-3">
      <template v-if="wantsStats">15 分钟视图按刷新间隔出点；较长范围按分钟或小时聚合，实际间隔见图表。</template>
      <template v-else>设备状态每 30 秒更新，恢复监测时立即刷新。</template>
    </p>

    <StatBand v-if="wantsStats" class="mb-5" label="今日计数" :stats="todayStats" />

    <div class="grid items-start gap-5" :class="wantsStats && (canOps || canDetect) ? 'xl:grid-cols-[minmax(0,1fr)_22rem]' : ''">
      <!-- 主栏：趋势 -->
      <div v-if="wantsStats" class="min-w-0 space-y-5">
        <p v-if="statsError" class="note note-threat text-threat" role="alert">{{ statsError }}</p>

        <Panel v-if="canDetect" title="入站观察" :icon="Waves" :desc="stats ? `最近 ${RANGE_LABEL[stats.range]} · 每 ${stepText}一点` : undefined">
          <LoadState :loading="!stats && !statsError" error="">
            <TrendChart v-if="stats" title="入站观察" :x="xLabels" :series="inboundSeries" :height="200" live exportable :empty-text="allEmptyText"
              @export="(csv) => download(csv, `入站观察-${range}.csv`)" />
          </LoadState>
        </Panel>

        <Panel title="告警与拦截" :icon="Activity" :desc="stats ? '告警按攻击类别分线；拦截为执行器回执已生效的动作' : undefined">
          <LoadState :loading="!stats && !statsError" error="">
            <TrendChart v-if="stats" title="告警与拦截" :x="xLabels" :series="alertSeries" :height="220" live exportable :empty-text="allEmptyText"
              @export="(csv) => download(csv, `告警与拦截-${range}.csv`)" />
          </LoadState>
          <template v-if="gapNote || stats" #foot>
            <span v-if="gapNote" class="flex items-center gap-2 text-warn"><span class="dot bg-warn" />{{ gapNote }}</span>
            <span v-else>折线断开处为采集缺口，不补 0。</span>
          </template>
        </Panel>
      </div>

      <!-- 侧栏：设备与最新判定 -->
      <aside v-if="canOps || canDetect" class="min-w-0 space-y-5" :class="wantsStats ? '' : 'grid gap-5 space-y-0 lg:grid-cols-2'">
        <Panel v-if="canOps" title="设备在线" :icon="RadioTower" desc="心跳 10 秒内即在线，不代表采集健康">
          <p v-if="devicesError" class="note note-threat text-threat" role="alert">{{ devicesError }}</p>
          <LoadState v-else :loading="!devicesLoaded" error="" :empty="devicesLoaded && !nodes.length" empty-text="你可见范围内还没有登记的传感器或执行器。">
            <div class="grid grid-cols-2 gap-3">
              <div v-for="g in [{ k: '采集传感器', icon: RadioTower, list: sensors }, { k: '执行器', icon: Cpu, list: executors }]" :key="g.k" class="rounded border border-ink-hair px-3.5 py-3">
                <p class="flex items-center gap-1.5 text-[12px] text-ink-3"><component :is="g.icon" :size="13" :stroke-width="1.5" aria-hidden="true" />{{ g.k }}</p>
                <p class="num mt-1.5 flex items-baseline gap-1 leading-none"><span class="text-[1.5rem] font-light" :class="online(g.list) < g.list.length ? 'text-warn' : 'text-ink'">{{ online(g.list) }}</span><span class="text-[12.5px] text-ink-3">/ {{ g.list.length }} 在线</span></p>
                <span class="mt-2.5 flex gap-1" aria-hidden="true">
                  <span v-for="h in g.list" :key="h.id" class="h-1.5 flex-1 rounded-full" :class="h.freshness === 'fresh' ? 'bg-ok' : 'bg-ink-line'" />
                </span>
              </div>
            </div>
            <ul class="mt-4 space-y-0.5">
              <li v-for="n in nodes.slice(0, 8)" :key="n.id" class="flex items-center gap-2.5 py-1.5 text-[12.5px]">
                <span class="dot shrink-0" :class="n.freshness === 'fresh' ? 'bg-ok' : 'bg-ink-4'" />
                <span class="w-7 shrink-0 text-ink-3">{{ n.kind }}</span>
                <span class="min-w-0 flex-1 truncate text-ink">{{ assetName(n.assetId) ?? '' }}<IdText v-if="!assetName(n.assetId)" :value="n.id" :copy="false" /></span>
                <span class="shrink-0 text-ink-3">{{ ago(n.receivedAt) }}</span>
              </li>
            </ul>
          </LoadState>
        </Panel>

        <Panel v-if="canDetect" title="最新判定" :icon="Siren" flush>
          <template #actions><span class="text-[12px] text-ink-3">最近 20 条</span></template>
          <p v-if="decisionsError" class="note note-threat mx-5 mb-4 text-threat" role="alert">{{ decisionsError }}</p>
          <LoadState v-else :loading="!updatedAt && !decisions.length" error="" :empty="!decisions.length" empty-text="你可见范围内暂无判定记录。">
            <TransitionGroup tag="ol" name="feed" class="max-h-[30rem] overflow-y-auto px-2 pb-2" aria-live="polite">
              <li v-for="d in decisions" :key="d.id">
                <button type="button" class="grid w-full grid-cols-[4.25rem_minmax(0,1fr)_auto] items-center gap-x-3 rounded px-3 py-2 text-left transition-colors duration-700 hover:bg-paper-soft"
                  :class="freshIds.has(d.id) ? 'bg-paper-soft' : ''" @click="openDecision(d)">
                  <span class="num text-[12px] text-ink-3">{{ clock(d.decidedAt ?? d.createdAt) }}</span>
                  <span class="min-w-0">
                    <span class="block truncate text-[13px] text-ink">{{ guardFamilyLabel[ev(d).family ?? ''] ?? ev(d).family ?? '—' }}<span class="text-ink-3"> · {{ guardSourceLabel(ev(d).source, ev(d).ruleId) }}</span></span>
                    <span class="block truncate text-[12px] text-ink-4">{{ assetName(d.assetId) ?? d.assetId.slice(0, 8) }}</span>
                  </span>
                  <Tag :tone="decisionTone[d.decision]" :label="guardDecisionLabel[d.decision] ?? d.decision" />
                </button>
              </li>
            </TransitionGroup>
          </LoadState>
        </Panel>
      </aside>
    </div>
  </div>
</template>

<style scoped>
.feed-enter-active { transition: opacity 0.4s cubic-bezier(0.22, 1, 0.36, 1), transform 0.4s cubic-bezier(0.22, 1, 0.36, 1); }
.feed-enter-from { opacity: 0; transform: translateY(-6px); }
.feed-move { transition: transform 0.4s cubic-bezier(0.22, 1, 0.36, 1); }
</style>
