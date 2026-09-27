<script setup lang="ts">
/**
 * 态势：只回答三个问题——现在有什么需要处理、保护是否降级、模型是否可信。
 * 所有数字来自数据库：事件/审批/传感器/部署各自走对应接口，24 小时告警与质量门禁
 * 来自 /overview 聚合；当前身份无权查看的区块显示为空，不补示例值。
 */
import { computed, ref } from 'vue'
import { RouterLink } from 'vue-router'
import { ArrowRight } from 'lucide-vue-next'
import PageHead from '@/components/PageHead.vue'
import Metric from '@/components/Metric.vue'
import Tag from '@/components/Tag.vue'
import LoadState from '@/components/LoadState.vue'
import { api, type Page } from '@/api/client'
import { can } from '@/api/session'
import { eventStatusLabel, fmtTime, severityLabel, type DeploymentView, type DriftView, type EventView, type LedgerView, type OverviewView, type SensorView } from '@/api/types'
import { eventTone, severityTone, statusTone } from '@/data/tones'
import { optional, useLoad } from '@/composables/load'
import { vReveal } from '@/composables/reveal'

const empty = { events: [] as EventView[], approvals: [] as LedgerView[], sensors: [] as SensorView[], deployments: [] as DeploymentView[], drift: [] as DriftView[], ov: { hourlyAlerts: [], quality24h: { accepted: 0, manualReview: 0, rejected: 0 } } as OverviewView }
const { data, loading, error } = useLoad(async () => {
  const [events, approvals, sensors, deployments, drift, ov] = await Promise.all([
    can('event.read') ? api.get<Page<EventView>>('/events?size=100').then((p) => p.items) : [],
    can('approval.read') ? optional(api.get<LedgerView[]>('/approvals/ledger'), []) : [],
    can('sensor.read') ? api.get<SensorView[]>('/sensors') : [],
    can('model.validation.read') ? api.get<DeploymentView[]>('/model-deployments') : [],
    can('model.validation.read') ? api.get<DriftView[]>('/model-drift-windows') : [],
    api.get<OverviewView>('/overview'),
  ])
  return { events, approvals, sensors, deployments, drift, ov }
}, empty)

const openEvents = computed(() => data.value.events.filter((e) => ['open', 'investigating'].includes(e.status)))
const pending = computed(() => data.value.approvals.filter((a) => a.status === 'pending'))
const active = computed(() => data.value.deployments.find((d) => d.status === 'active'))
const q = computed(() => data.value.ov.quality24h)
const qTotal = computed(() => q.value.accepted + q.value.manualReview + q.value.rejected)
const inferable = computed(() => (qTotal.value ? (q.value.accepted / qTotal.value) * 100 : 0))
const drift = computed(() => data.value.drift.slice(0, 24).reverse())

// 近 24 小时按小时补齐 0，横轴为本地时间
const hours = computed(() => {
  const now = new Date()
  now.setMinutes(0, 0, 0)
  const counts = new Map(data.value.ov.hourlyAlerts.map((h) => [new Date(h.hour + 'Z').getTime(), h.count]))
  return Array.from({ length: 24 }, (_, i) => {
    const t = now.getTime() - (23 - i) * 3600_000
    return { label: String(new Date(t).getHours()).padStart(2, '0') + ':00', v: counts.get(t) ?? 0 }
  })
})
const alerts24 = computed(() => hours.value.reduce((s, h) => s + h.v, 0))
const W = 720
const H = 140
const max = computed(() => Math.max(1, ...hours.value.map((h) => h.v)))
const peak = computed(() => hours.value.reduce((a, b) => (b.v > a.v ? b : a), hours.value[0]))
const pts = computed(() => hours.value.map((h, i) => [(i / 23) * W, H - (h.v / max.value) * (H - 16) - 4] as const))
const path = computed(() => pts.value.map(([x, y], i) => `${i ? 'L' : 'M'}${x.toFixed(1)},${y.toFixed(1)}`).join(' '))
const hover = ref<number | null>(null)
function onMove(e: MouseEvent) {
  const r = (e.currentTarget as SVGElement).getBoundingClientRect()
  hover.value = Math.round(((e.clientX - r.left) / r.width) * 23)
}
const today = new Date().toLocaleDateString('zh-CN')
</script>

<template>
  <div>
    <PageHead no="01" title="态势" :desc="`${today} · 覆盖 ${data.sensors.length} 个已登记传感器主机的本机可见流量。靶场回放事件单独标记，不计入实网指标。`">
      <template #kicker>Overview</template>
      <RouterLink :to="{ name: 'events' }" class="link text-[13px]">查看全部事件 <ArrowRight :size="14" :stroke-width="1.5" /></RouterLink>
    </PageHead>

    <section class="grid grid-cols-2 gap-x-10 gap-y-12 lg:grid-cols-4">
      <Metric v-reveal label="待处理事件" :value="openEvents.length" :note="`严重 ${openEvents.filter((e) => e.severity === 'critical').length} · 高 ${openEvents.filter((e) => e.severity === 'high').length}`" tone="threat" />
      <Metric v-reveal="80" label="24 小时告警" :value="alerts24" note="可见范围内的模型与规则告警" />
      <Metric v-reveal="160" label="待审批动作" :value="pending.length" :note="pending.length ? `最早 ${fmtTime(pending[pending.length - 1].expiresAt, false)} 过期` : '无待审批'" tone="signal" />
      <Metric v-reveal="240" label="可推理比例" :value="inferable" :digits="1" unit="%" :note="qTotal ? `24h 记录 ${qTotal} · 拒绝 ${q.rejected} · 待人工 ${q.manualReview}` : '24h 内无接入记录'" />
    </section>

    <section v-reveal class="mt-24">
      <div class="mb-6 flex items-baseline justify-between">
        <h2 class="text-[15px]">24 小时告警</h2>
        <p class="num text-[12px] text-ink-3">
          <template v-if="hover !== null">{{ hours[hover].label }} · {{ hours[hover].v }} 条</template>
          <template v-else-if="alerts24">峰值 {{ peak.label }} · {{ peak.v }} 条</template>
          <template v-else>24 小时内无告警</template>
        </p>
      </div>
      <svg :viewBox="`0 0 ${W} ${H}`" class="h-[140px] w-full overflow-visible" preserveAspectRatio="none" role="img" aria-label="24 小时告警趋势" @mousemove="onMove" @mouseleave="hover = null">
        <line v-for="g in 4" :key="g" x1="0" :x2="W" :y1="(H / 4) * g" :y2="(H / 4) * g" stroke="#E4E2DB" stroke-width="1" vector-effect="non-scaling-stroke" />
        <path :d="path" fill="none" stroke="#14161A" stroke-width="1.25" vector-effect="non-scaling-stroke" class="draw" />
        <g v-if="hover !== null">
          <line :x1="pts[hover][0]" :x2="pts[hover][0]" y1="0" :y2="H" stroke="#2438E8" stroke-width="1" vector-effect="non-scaling-stroke" />
        </g>
      </svg>
      <div class="num mt-3 flex justify-between text-[10.5px] text-ink-4"><span v-for="i in [0, 6, 12, 18, 23]" :key="i">{{ hours[i].label }}</span></div>
    </section>

    <div class="mt-24 grid gap-16 lg:grid-cols-[1.4fr_1fr]">
      <section v-reveal>
        <h2 class="mb-6 text-[15px]">需要处理</h2>
        <LoadState :loading="loading" :error="error" :empty="!openEvents.length && !pending.length" empty-text="当前没有待处理事件或待审批动作。">
        <ul class="border-t border-ink">
          <li v-for="e in openEvents" :key="e.id">
            <RouterLink :to="{ name: 'event-detail', params: { id: e.id } }" class="group grid grid-cols-[auto_1fr_auto] items-center gap-6 border-b border-ink-hair py-5 transition-colors hover:bg-paper-soft">
              <span class="num w-10 text-[1.5rem] font-light" :class="(e.riskScore ?? 0) > 0.7 ? 'text-threat' : 'text-ink'">{{ e.riskScore == null ? '—' : Math.round(e.riskScore * 100) }}</span>
              <span>
                <span class="block text-[14px] group-hover:text-signal">{{ e.title }}</span>
                <span class="num mt-1 flex gap-4 text-[12px] text-ink-3"><span>{{ e.eventKey }}</span><span>{{ e.alertCount }} 条告警</span><span>{{ fmtTime(e.lastSeenAt) }}</span></span>
              </span>
              <span class="flex flex-col items-end gap-1.5">
                <Tag :tone="severityTone[e.severity]" :label="severityLabel[e.severity]" />
                <Tag :tone="eventTone[e.status]" :label="eventStatusLabel[e.status]" />
              </span>
            </RouterLink>
          </li>
          <li v-for="a in pending" :key="a.id">
            <RouterLink :to="{ name: 'response' }" class="group grid grid-cols-[auto_1fr_auto] items-center gap-6 border-b border-ink-hair py-5 transition-colors hover:bg-paper-soft">
              <span class="num w-10 text-[11px] text-signal">审批</span>
              <span>
                <span class="block text-[14px] group-hover:text-signal">#{{ a.id }} · 阻断 {{ a.actionRequest.parameters?.targetAddress }}</span>
                <span class="num mt-1 flex gap-4 text-[12px] text-ink-3"><span>{{ a.assetKey }}</span><span>TTL {{ Math.round((a.actionRequest.parameters?.ttlSeconds ?? 0) / 60) }} min</span><span>过期 {{ fmtTime(a.expiresAt) }}</span></span>
              </span>
              <ArrowRight :size="14" :stroke-width="1.5" class="text-ink-4 transition-transform group-hover:translate-x-1 group-hover:text-signal" />
            </RouterLink>
          </li>
        </ul>
        </LoadState>
      </section>

      <section v-reveal="120" class="space-y-14">
        <div>
          <h2 class="mb-6 text-[15px]">保护覆盖</h2>
          <ul class="border-t border-ink">
            <li v-for="s in data.sensors" :key="s.id" class="flex items-center justify-between border-b border-ink-hair py-4">
              <span>
                <span class="block text-[13.5px]">{{ s.assetKey }}</span>
                <span class="num text-[11.5px] text-ink-3">{{ s.agentKey }} · 心跳 {{ fmtTime(s.lastHeartbeatAt) }}</span>
              </span>
              <Tag :tone="statusTone[s.status]" :label="s.status" />
            </li>
            <li v-if="!loading && !data.sensors.length" class="border-b border-ink-hair py-4 text-[13px] text-ink-3">暂无已登记传感器。
            </li>
          </ul>
          <p class="mt-4 text-[12px] leading-relaxed text-ink-3">覆盖范围仅为已部署传感器主机的本机可见流量，不代表全网。</p>
        </div>
        <div>
          <h2 class="mb-6 text-[15px]">活动模型</h2>
          <div class="border-t border-ink pt-4">
            <template v-if="active">
              <p class="num text-[13.5px]">{{ active.modelKey }} · {{ active.version }}</p>
              <p class="mt-1 text-[12px] text-ink-3">{{ active.runtimeType }} · {{ active.mode }} · 激活于 {{ fmtTime(active.activatedAt) }} · 权重冻结</p>
            </template>
            <p v-else class="text-[13px] text-ink-3">暂无活动部署，在线推理未启用。</p>
            <div v-if="drift.length" class="mt-5 flex h-8 items-end gap-[3px]" aria-label="最近漂移窗口">
              <span v-for="w in drift" :key="w.id" class="flex-1" :class="w.driftStatus === 'normal' ? 'bg-ink-line' : 'bg-warn'" :style="{ height: `${Math.max(8, Math.min(100, (w.qualityRejectRate ?? 0) * 1000))}%` }" :title="`${fmtTime(w.windowStart)} ${w.driftStatus}`" />
            </div>
            <p class="mt-3 flex justify-between text-[12px] text-ink-3"><span>漂移窗口 · {{ drift.length }}</span><span :class="drift.some((w) => w.driftStatus !== 'normal') ? 'text-warn' : ''">{{ drift.length ? (drift.some((w) => w.driftStatus !== 'normal') ? '存在观察告警' : '无漂移告警') : '暂无漂移统计' }}</span></p>
          </div>
        </div>
      </section>
    </div>
  </div>
</template>

<style scoped>
.draw { stroke-dasharray: 2000; stroke-dashoffset: 2000; animation: draw 1.8s cubic-bezier(.22,1,.36,1) .2s forwards; }
@keyframes draw { to { stroke-dashoffset: 0; } }
</style>
