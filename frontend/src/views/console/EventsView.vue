<script setup lang="ts">
/** 告警与事件：事件为主视图，告警为次视图；筛选只保留严重度与状态。 */
import { computed, ref } from 'vue'
import { useRouter } from 'vue-router'
import PageHead from '@/components/PageHead.vue'
import Segmented from '@/components/Segmented.vue'
import Tag from '@/components/Tag.vue'
import Drawer from '@/components/Drawer.vue'
import { alerts, assetName, events, eventStatusLabel, severityLabel, type Alert, type Severity } from '@/data/demo'
import { eventTone, severityTone } from '@/data/tones'

const router = useRouter()
const view = ref<'events' | 'alerts'>('events')
const sev = ref<Severity | 'all'>('all')
const onlyOpen = ref(true)
const q = ref('')

const shownEvents = computed(() =>
  events.filter(
    (e) =>
      (sev.value === 'all' || e.severity === sev.value) &&
      (!onlyOpen.value || ['open', 'investigating', 'contained'].includes(e.status)) &&
      (!q.value || (e.id + e.title).toLowerCase().includes(q.value.toLowerCase())),
  ),
)
const shownAlerts = computed(() =>
  alerts.filter((a) => (sev.value === 'all' || a.severity === sev.value) && (!q.value || (a.id + a.label + a.peer).toLowerCase().includes(q.value.toLowerCase()))),
)
const picked = ref<Alert | null>(null)
const sevs: (Severity | 'all')[] = ['all', 'critical', 'high', 'medium', 'low']
</script>

<template>
  <div>
    <PageHead no="02" title="告警与事件" desc="告警由冻结模型与确定性规则产生，按资产、时间窗与对端归并为事件。只显示全部关联资源都在你授权范围内的事件。">
      <template #kicker>Detection</template>
    </PageHead>

    <Segmented v-model="view" :options="[{ value: 'events', label: '事件', count: events.length }, { value: 'alerts', label: '告警', count: alerts.length }]" />

    <div class="mt-8 flex flex-wrap items-center justify-between gap-6">
      <div class="flex items-center gap-5 text-[13px]">
        <button v-for="s in sevs" :key="s" class="transition-colors" :class="sev === s ? 'text-ink underline decoration-1 underline-offset-[6px]' : 'text-ink-3 hover:text-ink'" @click="sev = s">
          {{ s === 'all' ? '全部' : severityLabel[s] }}
        </button>
        <label v-if="view === 'events'" class="ml-4 flex items-center gap-2 text-ink-3">
          <input v-model="onlyOpen" type="checkbox" class="h-3.5 w-3.5 accent-ink" /> 仅未结案
        </label>
      </div>
      <input v-model="q" class="field w-64" placeholder="搜索编号、标签或对端" aria-label="搜索" />
    </div>

    <Transition name="fade" mode="out-in">
      <table v-if="view === 'events'" key="e" class="table mt-10">
        <thead>
          <tr><th>风险</th><th>事件</th><th>资产</th><th>严重度</th><th>状态</th><th>处理人</th><th class="text-right">最近</th></tr>
        </thead>
        <tbody>
          <tr v-for="e in shownEvents" :key="e.id" class="row-link" tabindex="0" @click="router.push({ name: 'event-detail', params: { id: e.id } })" @keydown.enter="router.push({ name: 'event-detail', params: { id: e.id } })">
            <td class="num w-16 text-[1.25rem] font-light" :class="e.risk.total > 70 ? 'text-threat' : ''">{{ e.risk.total }}</td>
            <td><span class="block">{{ e.title }}</span><span class="num text-[12px] text-ink-3">{{ e.id }} · {{ e.alertCount }} 条告警</span></td>
            <td class="text-ink-2">{{ e.assetIds.map(assetName).join('、') }}</td>
            <td><Tag :tone="severityTone[e.severity]" :label="severityLabel[e.severity]" /></td>
            <td><Tag :tone="eventTone[e.status]" :label="eventStatusLabel[e.status]" /></td>
            <td class="text-ink-2">{{ e.assignee }}</td>
            <td class="num text-right text-ink-3">{{ e.lastSeen.slice(5) }}</td>
          </tr>
          <tr v-if="!shownEvents.length"><td colspan="7" class="py-16 text-center text-ink-3">没有符合条件的事件。</td></tr>
        </tbody>
      </table>

      <table v-else key="a" class="table mt-10">
        <thead>
          <tr><th>时间</th><th>告警</th><th>信号</th><th>分数</th><th>对端</th><th>数据质量</th><th>严重度</th></tr>
        </thead>
        <tbody>
          <tr v-for="a in shownAlerts" :key="a.id" class="row-link" tabindex="0" @click="picked = a" @keydown.enter="picked = a">
            <td class="num text-ink-3">{{ a.time }}</td>
            <td><span class="block">{{ a.label }}</span><span class="num text-[12px] text-ink-3">{{ a.id }} · {{ assetName(a.assetId) }}</span></td>
            <td class="text-ink-2">{{ a.signal === 'model' ? '模型' : '规则' }}</td>
            <td class="num">{{ a.signal === 'model' ? a.score.toFixed(3) : '命中' }}</td>
            <td class="num text-ink-2">{{ a.peer }}</td>
            <td><Tag :tone="a.quality === '可推理' ? 'ok' : a.quality === '待人工' ? 'warn' : 'threat'" :label="a.quality" /></td>
            <td><Tag :tone="severityTone[a.severity]" :label="severityLabel[a.severity]" /></td>
          </tr>
        </tbody>
      </table>
    </Transition>

    <Drawer :open="!!picked" :title="picked?.label ?? ''" :kicker="picked?.id" @close="picked = null">
      <template v-if="picked">
        <dl class="border-t border-ink">
          <div v-for="[k, v] in [
            ['时间', `2026-09-27 ${picked.time}`],
            ['资产', assetName(picked.assetId)],
            ['对端', picked.peer],
            ['信号来源', picked.signal === 'model' ? '冻结模型' : '确定性规则'],
            ['模型 / 规则版本', picked.model],
            ['分数', picked.signal === 'model' ? picked.score.toFixed(3) : '规则命中'],
            ['特征契约', 'flow.v2 · 映射 m-2026.09.2'],
            ['数据质量', picked.quality],
            ['归属事件', picked.eventId],
          ]" :key="k" class="grid grid-cols-[8rem_1fr] border-b border-ink-hair py-3 text-[13px]">
            <dt class="text-ink-3">{{ k }}</dt><dd class="num">{{ v }}</dd>
          </div>
        </dl>
        <p class="mt-6 text-[12.5px] leading-relaxed text-ink-3">告警可回溯到原始来源、特征映射与模型版本。模型分数不单独决定放行或隔离。</p>
      </template>
      <template #foot>
        <button class="act" @click="picked && router.push({ name: 'event-detail', params: { id: picked.eventId } })">打开事件 {{ picked?.eventId }}</button>
      </template>
    </Drawer>
  </div>
</template>
