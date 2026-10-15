<script setup lang="ts">
/**
 * 发布管理 · 验证记录分段（evaluation.read）：「lab 会话 · 评价运行 · 评价计划 · 研究回放」四类，类型同步到 URL 的 record。
 *
 * - lab 会话：会话时间轴（横条长度为运行时长、颜色为运行状态）+ 会话列表；行点击打开资格抽屉，可批准资格或作废，
 *   完整报告与会话事实在 lab 会话详情整页（/console/release/lab/:id）。待办 `?tab=validation&id=` 直接打开抽屉。
 * - 评价运行只读：评价由组合导入报告或 lab 报告登记，没有独立创建入口；通过的报告返回 passed，后端不支持按它筛选。
 * - 评价计划：建立冻结计划（P6 原件引用 + 原字节摘要，evaluation.run）。研究回放：新建（固定 1 倍速，evaluation.run）。
 * lab 会话的开始、中断、恢复、完成、事实追加与报告导入，以及研究回放的推进，均由受控 runner 执行，页面只读展示。
 */
import { computed, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { Bot, ClipboardList, FileClock, GanttChart, ListOrdered, PlayCircle, Search } from 'lucide-vue-next'
import Panel from '@/components/Panel.vue'
import SectionTabs from '@/components/SectionTabs.vue'
import Tag from '@/components/Tag.vue'
import IdText from '@/components/IdText.vue'
import LoadState from '@/components/LoadState.vue'
import CursorPager from '@/components/CursorPager.vue'
import { useCursor } from '@/composables/cursor'
import { fmtTime, guardLabEligibilityLabel, guardLabRunStatusLabel, type GuardLabRun } from '@/api/types'
import { releaseApi, type Evaluation, type EvaluationPlan, type EvaluationQuery, type LabRunStatus, type ReplayRun, type ReplayStatus } from '@/api/v2/release'
import type { ValidationRecord } from '@/router/release'
import { evaluationTone, labEligibilityTone, labRunTone, replayTone } from '@/data/tones'
import LabDrawer from './LabDrawer.vue'
import RecordDrawer from './RecordDrawer.vue'
import PlanFormDrawer from './PlanFormDrawer.vue'
import ReplayFormDrawer from './ReplayFormDrawer.vue'
import { ensureIndex, evaluationStatusLabel, isObject, modelName, planName, policyName, replayStatusLabel, runKindLabel, short } from './shared'

const record = defineModel<ValidationRecord>('record', { required: true })
const q = defineModel<string>('q', { required: true })
const status = defineModel<string>('status', { required: true })
const openId = defineModel<string>('id', { required: true })

const lists = {
  lab: useCursor<GuardLabRun>((cursor) => releaseApi.listLabRuns({ status: (status.value || undefined) as LabRunStatus | undefined, cursor }), false),
  evaluations: useCursor<Evaluation>((cursor) => releaseApi.listEvaluations({ status: (status.value || undefined) as EvaluationQuery['status'], cursor }), false),
  plans: useCursor<EvaluationPlan>((cursor) => releaseApi.listEvaluationPlans({ q: q.value || undefined, cursor }), false),
  replays: useCursor<ReplayRun>((cursor) => releaseApi.listReplayRuns({ status: (status.value || undefined) as ReplayStatus | undefined, cursor }), false),
}
const active = computed(() => lists[record.value])
watch([record, q, status], () => {
  active.value.reset()
  if (record.value === 'evaluations') void ensureIndex('plans')
  if (record.value === 'replays') { void ensureIndex('models'); void ensureIndex('policies') }
}, { immediate: true })

const qDraft = ref(q.value)
watch(q, (v) => { if (v !== qDraft.value.trim()) qDraft.value = v })
let typing: ReturnType<typeof setTimeout> | undefined
watch(qDraft, (v) => { clearTimeout(typing); typing = setTimeout(() => { q.value = v.trim().slice(0, 128) }, 350) })

const STATUS: Partial<Record<ValidationRecord, Record<string, string>>> = {
  lab: guardLabRunStatusLabel,
  evaluations: { pending: '待运行', running: '运行中', completed: '已完成', failed: '未通过' },
  replays: replayStatusLabel,
}
const statusOptions = computed(() => Object.entries(STATUS[record.value] ?? {}).filter(([k]) => k !== 'expired'))
const title = computed(() => ({ lab: 'lab 会话', evaluations: '评价运行', plans: '评价计划', replays: '研究回放' })[record.value])
const icon = computed(() => ({ lab: ListOrdered, evaluations: ClipboardList, plans: FileClock, replays: PlayCircle })[record.value])
const filtered = computed(() => !!(q.value || status.value))
const emptyText = computed(() => (filtered.value ? '当前筛选条件下没有记录。' : `你可见范围内还没有${title.value}。`))
function clearFilters() { q.value = ''; qDraft.value = ''; status.value = '' }

/* ---------------- lab 会话时间轴（沿用原 lab 验证页的主视觉） ---------------- */
const duration = (r: GuardLabRun) => {
  if (!r.startedAt || !r.endedAt) return '—'
  const s = Math.round((Date.parse(r.endedAt) - Date.parse(r.startedAt)) / 1000)
  return s >= 60 ? `${Math.floor(s / 60)} 分 ${s % 60} 秒` : `${s} 秒`
}
const timeline = computed(() => {
  if (record.value !== 'lab') return null
  const now = Date.now()
  const rows = lists.lab.items.value
    .filter((r) => r.startedAt)
    .map((r) => ({ r, s: Date.parse(r.startedAt!), e: r.endedAt ? Date.parse(r.endedAt) : now, open: !r.endedAt }))
    .filter((x) => !Number.isNaN(x.s))
    .sort((a, b) => a.s - b.s)
    .slice(-12)
  if (!rows.length) return null
  const t0 = Math.min(...rows.map((x) => x.s)), t1 = Math.max(...rows.map((x) => x.e))
  const span = Math.max(1, t1 - t0)
  return {
    from: new Date(t0).toISOString(), to: new Date(t1).toISOString(),
    rows: rows.map((x) => ({ ...x, left: ((x.s - t0) / span) * 100, width: Math.max(0.8, ((x.e - x.s) / span) * 100) })),
  }
})
const barBg: Record<string, string> = { ok: 'bg-ok', signal: 'bg-signal', warn: 'bg-warn', threat: 'bg-threat', mute: 'bg-ink-4' }
const router = useRouter()
const openLab = (id: string) => router.push({ name: 'release-lab-detail', params: { id } })

const planKind = (p: EvaluationPlan) => (isObject(p.payload) && p.payload.kind === 'p6-frozen' ? '冻结原件' : '结构化')

/* ---------------- 表单 ---------------- */
const planOpen = ref(false)
const replayOpen = ref(false)
defineExpose({ create: () => { if (record.value === 'plans') planOpen.value = true; else if (record.value === 'replays') replayOpen.value = true } })
function created(id: string) {
  planOpen.value = false
  replayOpen.value = false
  active.value.reset()
  openId.value = id
}
</script>

<template>
  <div>
    <div class="mb-4 flex flex-wrap items-center justify-between gap-3">
      <SectionTabs v-model="record" label="验证记录类型" :options="[
        { value: 'lab', label: 'lab 会话' },
        { value: 'evaluations', label: '评价运行' },
        { value: 'plans', label: '评价计划' },
        { value: 'replays', label: '研究回放' },
      ]" />
      <p class="flex items-center gap-1.5 text-[12px] text-ink-3"><Bot :size="13" :stroke-width="1.5" aria-hidden="true" />lab 会话推进与报告导入由 runner 执行</p>
    </div>

    <Panel v-if="timeline" class="mb-4" title="会话时间轴" :icon="GanttChart" :desc="`当前页 ${lists.lab.items.value.length} 个会话，${fmtTime(timeline.from)} — ${fmtTime(timeline.to)}`">
      <template #actions>
        <span class="flex flex-wrap items-center gap-3 text-[12px] text-ink-3">
          <span v-for="k in ['running', 'completed', 'interrupted', 'failed']" :key="k" class="inline-flex items-center gap-1.5"><span class="dot" :class="barBg[labRunTone[k]]" />{{ guardLabRunStatusLabel[k] ?? k }}</span>
        </span>
      </template>
      <ol class="space-y-1.5">
        <li v-for="x in timeline.rows" :key="x.r.id" class="grid grid-cols-[6.5rem_minmax(0,1fr)_5.5rem] items-center gap-3 text-[12px]">
          <span class="num truncate text-ink-3">{{ fmtTime(x.r.startedAt, false) }} · {{ x.r.id.slice(0, 4) }}</span>
          <span class="relative h-6 rounded-sm bg-paper-soft">
            <button type="button" class="absolute inset-y-1 rounded-sm transition-opacity hover:opacity-80" :class="[barBg[labRunTone[x.r.runStatus]], x.open ? 'animate-pulse' : '']"
              :style="{ left: `${x.left}%`, width: `${x.width}%` }" :aria-label="`会话 ${x.r.id.slice(0, 8)}，${guardLabRunStatusLabel[x.r.runStatus] ?? x.r.runStatus}，${duration(x.r)}`" @click="openId = x.r.id" />
          </span>
          <span class="text-right text-ink-2">{{ x.open ? '进行中' : duration(x.r) }}</span>
        </li>
      </ol>
    </Panel>

    <Panel :title="title" :icon="icon" flush>
      <template #toolbar>
        <div class="toolbar w-full" role="search">
          <label v-if="record === 'plans'" class="toolbar-field"><Search :size="14" :stroke-width="1.5" aria-hidden="true" />
            <input v-model="qDraft" type="search" class="field !w-56" maxlength="128" placeholder="按计划键前缀搜索" aria-label="搜索评价计划" />
          </label>
          <label v-else class="toolbar-field"><span>{{ record === 'lab' ? '运行状态' : '状态' }}</span>
            <select v-model="status" class="field" :aria-label="`${title}状态`">
              <option value="">全部</option>
              <option v-for="[k, l] in statusOptions" :key="k" :value="k">{{ l }}</option>
            </select>
          </label>
          <span v-if="record === 'evaluations'" class="text-[12px] text-ink-4">通过的导入报告显示为「通过」，不能按它筛选</span>
          <button v-if="filtered" type="button" class="link ml-auto text-[12.5px]" @click="clearFilters">清除筛选</button>
        </div>
      </template>

      <LoadState :loading="active.loading.value" :error="active.error.value" :empty="!active.items.value.length" :empty-text="emptyText">
        <!-- lab 会话：资格与运行状态分列 -->
        <table v-if="record === 'lab'" class="table min-w-[880px]">
          <thead><tr><th>会话</th><th>运行</th><th>资格</th><th>证据类别</th><th>发布组合</th><th>开始 / 时长</th><th>有效期至</th><th /></tr></thead>
          <tbody>
            <tr v-for="r in lists.lab.items.value" :key="r.id" class="row-link" tabindex="0" :aria-current="openId === r.id ? 'true' : undefined" @click="openId = r.id" @keydown.enter="openId = r.id">
              <td><IdText :value="r.id" :copy="false" /><span class="num block text-[11.5px] text-ink-4">r{{ r.revision }}</span></td>
              <td class="whitespace-nowrap"><Tag pill :tone="labRunTone[r.runStatus]" :label="guardLabRunStatusLabel[r.runStatus] ?? r.runStatus" /><span v-if="r.timedOut" class="ml-2 text-[12px] text-threat">已超时</span></td>
              <td class="whitespace-nowrap"><Tag :tone="labEligibilityTone[r.effectiveEligibility]" :label="guardLabEligibilityLabel[r.effectiveEligibility] ?? r.effectiveEligibility" /></td>
              <td class="num text-ink-2">{{ r.evidenceKind }}</td>
              <td class="num text-ink-3">{{ short(r.bundleId) }}</td>
              <td><span class="num block text-ink-2">{{ fmtTime(r.startedAt) }}</span><span class="text-[12px] text-ink-4">{{ duration(r) }}</span></td>
              <td class="num whitespace-nowrap text-ink-3">{{ fmtTime(r.validUntil) }}</td>
              <td class="text-right"><button type="button" class="link text-[12.5px]" @click.stop="openLab(r.id)">会话详情</button></td>
            </tr>
          </tbody>
        </table>

        <!-- 评价运行（只读） -->
        <table v-else-if="record === 'evaluations'" class="table min-w-[820px]">
          <thead><tr><th>运行类型</th><th>结果</th><th>评价计划</th><th>发布组合</th><th>签发身份</th><th class="text-right">登记</th></tr></thead>
          <tbody>
            <tr v-for="e in lists.evaluations.items.value" :key="e.id" class="row-link" tabindex="0" :aria-current="openId === e.id ? 'true' : undefined" @click="openId = e.id" @keydown.enter="openId = e.id">
              <td class="whitespace-nowrap text-ink">{{ runKindLabel[e.runKind] ?? e.runKind }}</td>
              <td><Tag :tone="evaluationTone[e.status]" :label="evaluationStatusLabel[e.status] ?? e.status" /></td>
              <td class="num max-w-[12rem] truncate text-ink-2">{{ planName(e.planId) }}</td>
              <td class="num text-ink-3">{{ short(e.bundleId) }}</td>
              <td class="num max-w-[10rem] truncate text-ink-3">{{ e.runnerIdentity }}</td>
              <td class="num whitespace-nowrap text-right text-ink-3">{{ fmtTime(e.createdAt) }}</td>
            </tr>
          </tbody>
        </table>

        <!-- 评价计划 -->
        <table v-else-if="record === 'plans'" class="table min-w-[760px]">
          <thead><tr><th>计划</th><th>版本</th><th>登记方式</th><th>计划摘要</th><th class="text-right">登记</th></tr></thead>
          <tbody>
            <tr v-for="p in lists.plans.items.value" :key="p.id" class="row-link" tabindex="0" :aria-current="openId === p.id ? 'true' : undefined" @click="openId = p.id" @keydown.enter="openId = p.id">
              <td class="num max-w-[16rem] truncate text-ink">{{ p.planKey }}</td>
              <td class="num text-ink-2">{{ p.version }}</td>
              <td class="text-ink-2">{{ planKind(p) }}</td>
              <td><IdText :value="p.planSha256" :length="12" :copy="false" /></td>
              <td class="num whitespace-nowrap text-right text-ink-3">{{ fmtTime(p.createdAt) }}</td>
            </tr>
          </tbody>
        </table>

        <!-- 研究回放 -->
        <table v-else class="table min-w-[820px]">
          <thead><tr><th>场景</th><th>模型</th><th>策略</th><th>倍速</th><th>状态</th><th class="text-right">登记</th></tr></thead>
          <tbody>
            <tr v-for="r in lists.replays.items.value" :key="r.id" class="row-link" tabindex="0" :aria-current="openId === r.id ? 'true' : undefined" @click="openId = r.id" @keydown.enter="openId = r.id">
              <td><IdText :value="r.scenarioId" :copy="false" /></td>
              <td class="max-w-[12rem] truncate text-ink-2">{{ modelName(r.modelId) }}</td>
              <td class="max-w-[12rem] truncate text-ink-2">{{ policyName(r.policyId) }}</td>
              <td class="num text-ink-2">{{ r.speed }}×</td>
              <td><Tag pill :tone="replayTone[r.status]" :label="replayStatusLabel[r.status] ?? r.status" /></td>
              <td class="num whitespace-nowrap text-right text-ink-3">{{ fmtTime(r.createdAt) }}</td>
            </tr>
          </tbody>
        </table>
      </LoadState>
      <template #foot>
        <CursorPager :count="active.items.value.length" :has-next="!!active.next.value" :has-prev="!!active.stack.value.length"
          :busy="active.turning.value" :label="title" @next="active.forward()" @prev="active.back()" />
      </template>
    </Panel>

    <p class="mt-3 text-[12px] text-ink-3">
      <template v-if="record === 'lab'">会话只记录事实，不授予执行权限；来源等级只来自已验签导入的报告，lab 自动（仅 lab）不适用于真实主机。</template>
      <template v-else-if="record === 'evaluations'">评价由发布组合导入报告或 lab 会话报告登记，没有单独的创建入口。</template>
      <template v-else-if="record === 'plans'">冻结计划须在读取测试集前登记，按原文件字节摘要核对，不接受内联改写。</template>
      <template v-else>研究回放固定 1 倍速，只接受已批准的研究组合；回放的开始、完成与失败由 runner 登记。</template>
    </p>

    <LabDrawer v-if="record === 'lab'" :id="openId" @close="openId = ''" @changed="active.reset()" />
    <RecordDrawer v-else :kind="record" :id="openId" @close="openId = ''" />
    <PlanFormDrawer :open="planOpen" @created="created" @close="planOpen = false" />
    <ReplayFormDrawer :open="replayOpen" @created="created" @close="replayOpen = false" />
  </div>
</template>
