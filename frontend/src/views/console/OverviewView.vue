<script setup lang="ts">
/**
 * 态势：只回答三个问题——现在有什么需要处理、保护是否降级、模型是否可信。
 * 指标四个、趋势一条、待办一列，不堆砌图表。
 */
import { computed, ref } from 'vue'
import { RouterLink } from 'vue-router'
import { ArrowRight } from 'lucide-vue-next'
import PageHead from '@/components/PageHead.vue'
import Metric from '@/components/Metric.vue'
import Tag from '@/components/Tag.vue'
import { actions, alerts, assetName, driftWindows, events, eventStatusLabel, models, sensors, severityLabel } from '@/data/demo'
import { eventTone, severityTone } from '@/data/tones'
import { vReveal } from '@/composables/reveal'

const openEvents = events.filter((e) => ['open', 'investigating'].includes(e.status))
const pending = actions.filter((a) => a.approval === 'pending')
const active = models.find((m) => m.stage === 'active')!

// 24 小时告警量（示例），用于单条折线
const hourly = [3, 2, 2, 1, 1, 0, 1, 2, 4, 9, 18, 6, 5, 4, 3, 4, 7, 11, 8, 5, 3, 2, 2, 1]
const W = 720
const H = 140
const max = Math.max(...hourly)
const pts = computed(() => hourly.map((v, i) => [(i / (hourly.length - 1)) * W, H - (v / max) * (H - 16) - 4] as const))
const path = computed(() => pts.value.map(([x, y], i) => `${i ? 'L' : 'M'}${x.toFixed(1)},${y.toFixed(1)}`).join(' '))
const hover = ref<number | null>(null)
function onMove(e: MouseEvent) {
  const r = (e.currentTarget as SVGElement).getBoundingClientRect()
  hover.value = Math.round(((e.clientX - r.left) / r.width) * (hourly.length - 1))
}
</script>

<template>
  <div>
    <PageHead no="01" title="态势" desc="2026-09-27 · 覆盖 2 台已授权主机的本机可见流量。靶场回放事件单独标记，不计入实网指标。">
      <template #kicker>Overview</template>
      <RouterLink :to="{ name: 'events' }" class="link text-[13px]">查看全部事件 <ArrowRight :size="14" :stroke-width="1.5" /></RouterLink>
    </PageHead>

    <section class="grid grid-cols-2 gap-x-10 gap-y-12 lg:grid-cols-4">
      <Metric v-reveal label="待处理事件" :value="openEvents.length" note="1 条严重 · 1 条中危" tone="threat" />
      <Metric v-reveal="80" label="今日告警" :value="alerts.length * 17 + 4" note="模型 62% · 规则 38%" />
      <Metric v-reveal="160" label="待审批动作" :value="pending.length" note="最早 11:15 过期" tone="signal" />
      <Metric v-reveal="240" label="可推理比例" :value="98.1" :digits="1" unit="%" note="契约 flow.v2 · 拒绝 1.9%" />
    </section>

    <section v-reveal class="mt-24">
      <div class="mb-6 flex items-baseline justify-between">
        <h2 class="text-[15px]">24 小时告警</h2>
        <p class="num text-[12px] text-ink-3">
          <template v-if="hover !== null">{{ String(hover).padStart(2, '0') }}:00 · {{ hourly[hover] }} 条</template>
          <template v-else>峰值 10:00 · {{ max }} 条</template>
        </p>
      </div>
      <svg :viewBox="`0 0 ${W} ${H}`" class="h-[140px] w-full overflow-visible" preserveAspectRatio="none" role="img" aria-label="24 小时告警趋势" @mousemove="onMove" @mouseleave="hover = null">
        <line v-for="g in 4" :key="g" x1="0" :x2="W" :y1="(H / 4) * g" :y2="(H / 4) * g" stroke="#E4E2DB" stroke-width="1" vector-effect="non-scaling-stroke" />
        <path :d="path" fill="none" stroke="#14161A" stroke-width="1.25" vector-effect="non-scaling-stroke" class="draw" />
        <g v-if="hover !== null">
          <line :x1="pts[hover][0]" :x2="pts[hover][0]" y1="0" :y2="H" stroke="#2438E8" stroke-width="1" vector-effect="non-scaling-stroke" />
        </g>
      </svg>
      <div class="num mt-3 flex justify-between text-[10.5px] text-ink-4"><span>00:00</span><span>06:00</span><span>12:00</span><span>18:00</span><span>23:00</span></div>
    </section>

    <div class="mt-24 grid gap-16 lg:grid-cols-[1.4fr_1fr]">
      <section v-reveal>
        <h2 class="mb-6 text-[15px]">需要处理</h2>
        <ul class="border-t border-ink">
          <li v-for="e in openEvents" :key="e.id">
            <RouterLink :to="{ name: 'event-detail', params: { id: e.id } }" class="group grid grid-cols-[auto_1fr_auto] items-center gap-6 border-b border-ink-hair py-5 transition-colors hover:bg-paper-soft">
              <span class="num w-10 text-[1.5rem] font-light" :class="e.risk.total > 70 ? 'text-threat' : 'text-ink'">{{ e.risk.total }}</span>
              <span>
                <span class="block text-[14px] group-hover:text-signal">{{ e.title }}</span>
                <span class="num mt-1 flex gap-4 text-[12px] text-ink-3"><span>{{ e.id }}</span><span>{{ e.alertCount }} 条告警</span><span>{{ e.lastSeen.slice(11) }}</span></span>
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
                <span class="block text-[14px] group-hover:text-signal">{{ a.id }} · 阻断 {{ a.target }}</span>
                <span class="num mt-1 flex gap-4 text-[12px] text-ink-3"><span>{{ assetName(a.assetId) }}</span><span>TTL {{ a.ttl }} min</span><span>过期 {{ a.expiresAt }}</span></span>
              </span>
              <ArrowRight :size="14" :stroke-width="1.5" class="text-ink-4 transition-transform group-hover:translate-x-1 group-hover:text-signal" />
            </RouterLink>
          </li>
        </ul>
      </section>

      <section v-reveal="120" class="space-y-14">
        <div>
          <h2 class="mb-6 text-[15px]">保护覆盖</h2>
          <ul class="border-t border-ink">
            <li v-for="s in sensors" :key="s.id" class="flex items-center justify-between border-b border-ink-hair py-4">
              <span>
                <span class="block text-[13.5px]">{{ assetName(s.assetId) }}</span>
                <span class="num text-[11.5px] text-ink-3">{{ s.id }} · {{ s.lastHeartbeat }}</span>
              </span>
              <Tag :tone="s.status === 'online' ? 'ok' : s.status === 'degraded' ? 'warn' : 'mute'" :label="s.status === 'online' ? '在线' : s.status === 'degraded' ? '降级' : '离线'" />
            </li>
          </ul>
          <p class="mt-4 text-[12px] leading-relaxed text-ink-3">覆盖范围仅为已部署传感器主机的本机可见流量，不代表全网。</p>
        </div>
        <div>
          <h2 class="mb-6 text-[15px]">活动模型</h2>
          <div class="border-t border-ink pt-4">
            <p class="num text-[13.5px]">{{ active.version }}</p>
            <p class="mt-1 text-[12px] text-ink-3">{{ active.runtime }} · 权重冻结</p>
            <div class="mt-5 flex h-8 items-end gap-[3px]" aria-label="近 24 小时 PSI">
              <span v-for="w in driftWindows" :key="w.window" class="flex-1" :class="w.psi > 0.1 ? 'bg-warn' : 'bg-ink-line'" :style="{ height: `${Math.min(100, w.psi * 600)}%` }" />
            </div>
            <p class="mt-3 flex justify-between text-[12px] text-ink-3"><span>PSI · 24h</span><span class="text-warn">16:00–19:00 观察告警</span></p>
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
