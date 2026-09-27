<script setup lang="ts">
/**
 * 事件详情：左侧证据时间线与研判，右侧风险构成与处置申请。
 * 状态按钮只列出状态机允许的下一步；处置申请要求 TTL 与幂等键，
 * 目标限定在事件已登记资产上。本轮仅本地演示，不写后端。
 */
import { computed, reactive, ref } from 'vue'
import { RouterLink, useRoute } from 'vue-router'
import { ArrowLeft } from 'lucide-vue-next'
import Tag from '@/components/Tag.vue'
import Drawer from '@/components/Drawer.vue'
import { alerts, assetName, assets, eventStatusLabel, eventTransitions, events, policies, severityLabel, type EventStatus, type TimelineItem } from '@/data/demo'
import { eventTone, severityTone } from '@/data/tones'
import { toast } from '@/composables/toast'
import { vReveal } from '@/composables/reveal'

const route = useRoute()
const source = events.find((e) => e.id === route.params.id)
const ev = source ? reactive(structuredClone(source)) : null
const related = computed(() => alerts.filter((a) => a.eventId === ev?.id))
const note = ref('')

function transit(to: EventStatus) {
  if (!ev) return
  ev.timeline.push({ time: now(), actor: 'analyst · 陈', kind: 'transition', text: `${ev.status} → ${to}` })
  ev.status = to
  toast(`状态已更新为「${eventStatusLabel[to]}」（本地演示）`)
}
function addNote() {
  if (!ev || !note.value.trim()) return
  ev.timeline.push({ time: now(), actor: 'analyst · 陈', kind: 'note', text: note.value.trim() })
  note.value = ''
}
const now = () => new Date().toTimeString().slice(0, 8)

// 处置申请
const asking = ref(false)
const form = reactive({ policy: 'POL-07', direction: 'inbound', peer: '', port: '', ttl: 30 })
const policy = computed(() => policies.find((p) => p.id === form.policy)!)
const target = computed(() => assets.find((a) => a.id === ev?.assetIds[0]))
const checks = computed(() => [
  { k: '目标为登记资产', ok: !!target.value },
  { k: '资产授权当前有效', ok: target.value?.authorization.status === 'approved' },
  { k: '策略处于 active', ok: policy.value.status === 'active' },
  { k: '动作在策略白名单内', ok: policy.value.actions.includes(`host.block.${form.direction}`) },
  { k: `TTL ≤ 策略上限 ${policy.value.maxTtl} min`, ok: form.ttl > 0 && form.ttl <= policy.value.maxTtl },
  { k: '对端为单一 IP，非保护目标', ok: /^\d{1,3}(\.\d{1,3}){3}$/.test(form.peer) && !form.peer.startsWith('10.20.0.1') },
])
const allOk = computed(() => checks.value.every((c) => c.ok))
function openAsk() {
  const a = related.value[0]
  if (a) {
    const [ip, port] = a.peer.split(':')
    form.peer = ip
    form.port = port === '*' ? '' : port
  }
  asking.value = true
}
function submitAction() {
  if (!ev || !allOk.value) return
  ev.timeline.push({ time: now(), actor: 'analyst · 陈', kind: 'action', text: `提交阻断申请：${form.peer}${form.port ? ' · TCP/' + form.port : ''}，TTL ${form.ttl} 分钟，等待独立审批` })
  asking.value = false
  toast('已提交处置申请，等待响应审批员决定（本地演示）')
}

const kindMark: Record<TimelineItem['kind'], string> = { alert: 'bg-threat', transition: 'bg-ink', note: 'bg-ink-4', action: 'bg-signal' }
const kindLabel: Record<TimelineItem['kind'], string> = { alert: '告警', transition: '状态', note: '研判', action: '处置' }
</script>

<template>
  <div v-if="ev">
    <RouterLink :to="{ name: 'events' }" class="link mb-10 text-[13px] text-ink-3"><ArrowLeft :size="14" :stroke-width="1.5" /> 告警与事件</RouterLink>

    <header class="mb-16 grid gap-10 lg:grid-cols-[1fr_auto] lg:items-end">
      <div>
        <p class="label mb-5 flex items-center gap-4"><span class="num">{{ ev.id }}</span><Tag :tone="severityTone[ev.severity]" :label="severityLabel[ev.severity]" /><Tag :tone="eventTone[ev.status]" :label="eventStatusLabel[ev.status]" /></p>
        <h1 class="max-w-3xl text-[2rem] font-light leading-snug tracking-[-0.02em]">{{ ev.title }}</h1>
        <p class="num mt-5 flex flex-wrap gap-x-8 gap-y-1 text-[12.5px] text-ink-3">
          <span>资产 {{ ev.assetIds.map(assetName).join('、') }}</span><span>首次 {{ ev.firstSeen }}</span><span>最近 {{ ev.lastSeen }}</span><span>处理人 {{ ev.assignee }}</span>
        </p>
      </div>
      <div class="flex flex-wrap items-center gap-6">
        <button v-for="to in eventTransitions[ev.status]" :key="to" class="link text-[13px]" @click="transit(to)">标记为{{ eventStatusLabel[to] }}</button>
        <button class="act" :disabled="!['investigating', 'contained'].includes(ev.status)" @click="openAsk">申请处置</button>
      </div>
    </header>

    <div class="grid gap-20 lg:grid-cols-[1.35fr_1fr]">
      <section v-reveal>
        <h2 class="mb-8 text-[15px]">证据时间线</h2>
        <ol class="relative ml-1 border-l border-ink-hair">
          <TransitionGroup name="page">
            <li v-for="(t, i) in ev.timeline" :key="i + t.time" class="relative pb-9 pl-8">
              <span class="absolute -left-[3.5px] top-[7px] h-[6px] w-[6px]" :class="kindMark[t.kind]" />
              <p class="num flex gap-4 text-[11.5px] text-ink-3"><span>{{ t.time }}</span><span class="label !text-[10px]">{{ kindLabel[t.kind] }}</span><span>{{ t.actor }}</span></p>
              <p class="mt-2 text-[14px] leading-relaxed">{{ t.text }}</p>
            </li>
          </TransitionGroup>
        </ol>
        <form class="mt-2 flex items-end gap-6 pl-8" @submit.prevent="addNote">
          <label class="flex-1"><span class="label">追加研判</span><input v-model="note" class="field mt-2" placeholder="写下依据，而不是结论" /></label>
          <button type="submit" class="link text-[13px]" :disabled="!note.trim()">添加</button>
        </form>

        <h2 class="mb-6 mt-20 text-[15px]">关联告警</h2>
        <table class="table">
          <thead><tr><th>时间</th><th>告警</th><th>信号</th><th>分数</th><th>对端</th></tr></thead>
          <tbody>
            <tr v-for="a in related" :key="a.id">
              <td class="num text-ink-3">{{ a.time }}</td>
              <td>{{ a.label }} <span class="num text-[12px] text-ink-3">{{ a.id }}</span></td>
              <td class="text-ink-2">{{ a.model }}</td>
              <td class="num">{{ a.signal === 'model' ? a.score.toFixed(3) : '命中' }}</td>
              <td class="num text-ink-2">{{ a.peer }}</td>
            </tr>
          </tbody>
        </table>
      </section>

      <aside v-reveal="120">
        <h2 class="mb-8 text-[15px]">风险构成</h2>
        <p class="num text-[4.5rem] font-extralight leading-none tracking-[-0.04em]" :class="ev.risk.total > 70 ? 'text-threat' : ''">{{ ev.risk.total }}<span class="ml-2 text-[14px] text-ink-3">/ 100</span></p>
        <div class="mt-8 flex h-1.5 w-full bg-paper-deep">
          <span v-for="(p, i) in ev.risk.parts" :key="p.name" class="h-full" :style="{ width: p.value + '%', background: ['#14161A', '#3A3D44', '#6B6E75', '#9A9CA1', '#D9D7D0'][i] }" />
        </div>
        <ul class="mt-8 border-t border-ink">
          <li v-for="(p, i) in ev.risk.parts" :key="p.name" class="grid grid-cols-[10px_1fr_auto] items-baseline gap-4 border-b border-ink-hair py-3.5">
            <span class="h-2 w-2" :style="{ background: ['#14161A', '#3A3D44', '#6B6E75', '#9A9CA1', '#D9D7D0'][i] }" />
            <span><span class="block text-[13.5px]">{{ p.name }}</span><span class="text-[12px] text-ink-3">{{ p.note }}</span></span>
            <span class="num text-[13px]">{{ p.value }}</span>
          </li>
        </ul>
        <p class="mt-6 text-[12px] leading-relaxed text-ink-3">评分规则版本 risk-v1 · 可解释加权。低质量或不完整数据不会被展示为高置信结论。</p>
      </aside>
    </div>

    <Drawer :open="asking" title="申请主机临时阻断" :kicker="`${ev.id} · ${target?.name}`" @close="asking = false">
      <div class="space-y-8">
        <label class="block"><span class="label">策略</span>
          <select v-model="form.policy" class="field mt-2">
            <option v-for="p in policies" :key="p.id" :value="p.id">{{ p.id }} · {{ p.name }}</option>
          </select>
        </label>
        <div class="grid grid-cols-2 gap-8">
          <label class="block"><span class="label">方向</span>
            <select v-model="form.direction" class="field mt-2"><option value="inbound">入站</option><option value="outbound">出站</option></select>
          </label>
          <label class="block"><span class="label">TTL（分钟）</span><input v-model.number="form.ttl" type="number" min="1" class="field num mt-2" /></label>
        </div>
        <div class="grid grid-cols-[1fr_7rem] gap-8">
          <label class="block"><span class="label">对端 IP</span><input v-model="form.peer" class="field num mt-2" /></label>
          <label class="block"><span class="label">端口</span><input v-model="form.port" class="field num mt-2" placeholder="全部" /></label>
        </div>
      </div>

      <h3 class="label mb-4 mt-12">提交前校验</h3>
      <ul class="border-t border-ink">
        <li v-for="c in checks" :key="c.k" class="flex items-center justify-between border-b border-ink-hair py-3 text-[13px]">
          <span :class="c.ok ? '' : 'text-ink-3'">{{ c.k }}</span>
          <Tag :tone="c.ok ? 'ok' : 'threat'" :label="c.ok ? '通过' : '不满足'" />
        </li>
      </ul>
      <p class="mt-6 text-[12px] leading-relaxed text-ink-3">只追加带 TTL 的窄范围规则，不覆盖既有规则，不修改默认策略。申请人不能审批本人申请；任一条件不满足即拒绝提交。</p>
      <template #foot>
        <button class="link text-[13px]" @click="asking = false">取消</button>
        <button class="act" :disabled="!allOk" @click="submitAction">提交审批</button>
      </template>
    </Drawer>
  </div>
  <div v-else class="py-32 text-center">
    <p class="label">404</p>
    <p class="mt-4 text-ink-3">事件不存在，或不在你的授权范围内。</p>
    <RouterLink :to="{ name: 'events' }" class="link mt-8 text-[13px]">返回告警与事件</RouterLink>
  </div>
</template>
