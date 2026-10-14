<script setup lang="ts">
/**
 * lab 验证与 G3（13）：lab 验证会话列表（GET /api/v2/lab-validation-runs）。
 *
 * - 资格状态（会话批准、到期、授权失效）与运行状态（registered → running → completed …）分开显示；
 *   effectiveEligibility 由后端按到期与授权当前状态计算，前端不自行推断；
 * - 会话本身不授予执行权限（executionAuthority 恒为 false），清理状态不由会话断言；
 * - 详情页读取签名 G3 报告与已登记的来源等级，lab_auto 只在 lab 资产有效。
 */
import { computed, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { GanttChart, ListOrdered } from 'lucide-vue-next'
import PageHead from '@/components/PageHead.vue'
import IdText from '@/components/IdText.vue'
import Panel from '@/components/Panel.vue'
import Tag from '@/components/Tag.vue'
import LoadState from '@/components/LoadState.vue'
import CursorPager from '@/components/CursorPager.vue'
import { useCursor } from '@/composables/cursor'
import { guard } from '@/api/client'
import { can } from '@/api/session'
import { fmtTime, guardLabEligibilityLabel, guardLabRunStatusLabel, type GuardLabRun } from '@/api/types'
import { labEligibilityTone, labRunTone } from '@/data/tones'

const router = useRouter()
const allowed = can('evaluation.read')
const status = ref('')
const runs = useCursor<GuardLabRun>((cursor) => guard.read<{ items: GuardLabRun[]; nextCursor: string | null }>('lab-validation-runs', { cursor, status: status.value, limit: 50 }), allowed)
watch(status, () => { if (allowed) runs.reset() })

const statuses = Object.keys(guardLabRunStatusLabel)
const duration = (r: GuardLabRun) => {
  if (!r.startedAt || !r.endedAt) return '—'
  const s = Math.round((Date.parse(r.endedAt) - Date.parse(r.startedAt)) / 1000)
  return s >= 60 ? `${Math.floor(s / 60)} 分 ${s % 60} 秒` : `${s} 秒`
}
const open = (r: GuardLabRun) => router.push({ name: 'lab-detail', params: { id: r.id } })
const count = computed(() => runs.items.value.length)

/*
 * 版式（视觉基线 v2，lab 验证）：主视觉为“会话时间轴”，按开始时间把当前页会话画成横条（长度为实际运行时长、颜色为运行状态），
 * 点击横条进入详情；下方为会话列表。时间轴只用后端返回的 startedAt/endedAt，未结束的会话画到当前时间并标注“进行中”。
 */
const labHint = computed(() => `当前页 ${count.value} 个会话`)
const timeline = computed(() => {
  const now = Date.now()
  const rows = runs.items.value
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
</script>

<template>
  <div>
    <PageHead title="lab 验证与 G3" desc="网络隔离 lab 中的 1 倍速联合闭环会话。会话只记录事实，不授予执行权限；来源等级只来自已验签导入的 G3 报告，且 lab_auto 只对 lab 资产有效，不适用于真实主机。">
    </PageHead>

    <Panel v-if="allowed && timeline" class="mb-4" title="会话时间轴" :icon="GanttChart" :desc="`${labHint}，${fmtTime(timeline.from)} — ${fmtTime(timeline.to)}`">
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
              :style="{ left: `${x.left}%`, width: `${x.width}%` }" :aria-label="`会话 ${x.r.id.slice(0, 8)}，${guardLabRunStatusLabel[x.r.runStatus] ?? x.r.runStatus}，${duration(x.r)}`" @click="open(x.r)" />
          </span>
          <span class="text-right text-ink-2">{{ x.open ? '进行中' : duration(x.r) }}</span>
        </li>
      </ol>
      <div class="mt-2 grid grid-cols-[6.5rem_minmax(0,1fr)_5.5rem] gap-3 text-[11px] text-ink-4" aria-hidden="true">
        <span />
        <span class="num flex justify-between border-t border-ink-hair pt-1.5"><span>{{ fmtTime(timeline.from, false) }}</span><span>{{ fmtTime(timeline.to, false) }}</span></span>
        <span />
      </div>
    </Panel>

    <p v-if="!allowed" class="panel px-5 py-10 text-center text-[13px] text-ink-3">当前身份没有评价读取权限（evaluation.read），本页不显示数据。</p>
    <Panel v-else title="验证会话" :icon="ListOrdered" flush>
      <template #toolbar>
        <div class="toolbar w-full">
          <label class="toolbar-field"><span>运行状态</span>
            <select v-model="status" class="field" aria-label="运行状态">
              <option value="">全部</option>
              <option v-for="s in statuses" :key="s" :value="s">{{ guardLabRunStatusLabel[s] }}</option>
            </select>
          </label>
        </div>
      </template>

      <LoadState :loading="runs.loading.value" :error="runs.error.value" :empty="!count" empty-text="数据库中暂无 lab 验证会话。">
        <table class="table">
          <thead><tr><th>会话</th><th>运行</th><th>资格</th><th>证据类别</th><th>发布组合</th><th>开始 / 时长</th><th class="text-right">有效期至</th></tr></thead>
          <tbody>
            <tr v-for="r in runs.items.value" :key="r.id" class="row-link" tabindex="0" @click="open(r)" @keydown.enter="open(r)">
              <td><IdText :value="r.id" :copy="false" /><span class="num block text-[12px] text-ink-4">r{{ r.revision }}</span></td>
              <td class="whitespace-nowrap"><Tag pill :tone="labRunTone[r.runStatus]" :label="guardLabRunStatusLabel[r.runStatus] ?? r.runStatus" /><span v-if="r.timedOut" class="ml-2 text-[12px] text-threat">已超时</span></td>
              <td><Tag :tone="labEligibilityTone[r.effectiveEligibility]" :label="guardLabEligibilityLabel[r.effectiveEligibility] ?? r.effectiveEligibility" /><span v-if="r.blockedReason" class="num ml-2 text-[11.5px] text-ink-4">{{ r.blockedReason }}</span></td>
              <td class="num text-ink-2">{{ r.evidenceKind }}</td>
              <td class="num text-ink-3">{{ r.bundleId?.slice(0, 8) ?? '—' }}</td>
              <td><span class="num block text-ink-2">{{ fmtTime(r.startedAt) }}</span><span class="text-[12px] text-ink-4">{{ duration(r) }}</span></td>
              <td class="num text-right text-ink-3">{{ fmtTime(r.validUntil) }}</td>
            </tr>
          </tbody>
        </table>
      </LoadState>
      <template #foot>
        <CursorPager :count="count" :has-next="!!runs.next.value" :has-prev="!!runs.stack.value.length" :busy="runs.turning.value" label="lab 会话" @next="runs.forward()" @prev="runs.back()" />
      </template>
    </Panel>
  </div>
</template>
