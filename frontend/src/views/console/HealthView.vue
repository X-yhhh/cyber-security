<script setup lang="ts">
/**
 * 健康与审计（14）：B5 只读查询（GET /api/v2/ops/status、health-windows、sensor-heartbeats、
 * executor-heartbeats、audit）。
 *
 * 口径（docs/检测与处置契约.md 健康窗口与 9.2 预算恢复）：
 * - 健康窗口分两列：verificationStatus 是写入时的服务端判定；healthState 再叠加 10 秒新鲜度，
 *   历史窗口即使当时健康，现在也显示为「已过期」；
 * - replay_healthy 只证明 lab 文件回放窗口完整、无容量丢弃，**不代表现场采集健康**，不用于预算恢复；
 * - 心跳只表示机器存活与状态投影，不代表采集健康；
 * - 审计只读追加记录，资源 ID 为外部 UUID 或不可逆引用。
 * 每个分段只在有对应权限时请求，切到该分段时才首次读取。
 */
import { computed, ref, watch } from 'vue'
import { Activity, Clock, Cpu, RadioTower, ServerCog, ShieldX, ScrollText } from 'lucide-vue-next'
import StatBand from '@/components/StatBand.vue'
import PageHead from '@/components/PageHead.vue'
import IdText from '@/components/IdText.vue'
import { countIf } from '@/components/viz'
import { useSummary } from '@/composables/summary'
import Panel from '@/components/Panel.vue'
import { usePageTitle } from '@/composables/page'
import Segmented from '@/components/Segmented.vue'
import Tag from '@/components/Tag.vue'
import LoadState from '@/components/LoadState.vue'
import CursorPager from '@/components/CursorPager.vue'
import { useCursor } from '@/composables/cursor'
import { guard } from '@/api/client'
import { can } from '@/api/session'
import {
  fmtTime, guardHealthStateLabel, guardMachineStatusLabel, guardVerificationLabel,
  type GuardAuditEntry, type GuardHealthWindow, type GuardHeartbeat, type GuardOpsAsset, type GuardReadPage,
} from '@/api/types'
import { auditOutcomeTone, healthStateTone, machineStatusTone, verificationTone } from '@/data/tones'

type View = 'ops' | 'health' | 'sensors' | 'executors' | 'audit'
/** 两级菜单（FE-9）按二级项指定初始分段；F1—F4 拆分本页后删除。 */
const props = defineProps<{ segment?: View }>()
const view = ref<View>(props.segment ?? 'ops')
const opsAllowed = can('ops.read')
const auditAllowed = can('audit.read')
const allowed = (v: View) => (v === 'audit' ? auditAllowed : opsAllowed)

const verificationFilter = ref('')
const actionFilter = ref('')
const appliedAction = ref('')

const read = <T,>(path: string, params: Record<string, string | number | undefined>) => (cursor?: string) =>
  guard.read<GuardReadPage<T>>(path, { ...params, cursor, limit: 50 })
const ops = useCursor<GuardOpsAsset>(read('ops/status', {}), false)
const health = useCursor<GuardHealthWindow>((cursor) => read<GuardHealthWindow>('health-windows', { verificationStatus: verificationFilter.value || undefined })(cursor), false)
const sensors = useCursor<GuardHeartbeat>(read('sensor-heartbeats', {}), false)
const executors = useCursor<GuardHeartbeat>(read('executor-heartbeats', {}), false)
const audit = useCursor<GuardAuditEntry>((cursor) => read<GuardAuditEntry>('audit', { action: appliedAction.value || undefined })(cursor), false)
const lists = { ops, health, sensors, executors, audit }
const active = computed(() => lists[view.value])

/** 首次切到某分段才读取；之后保持当前页，筛选变化时从第一页重读。 */
const opened = new Set<View>()
watch(view, (v) => {
  if (!allowed(v) || opened.has(v)) return
  opened.add(v)
  lists[v].reset()
}, { immediate: true })
watch(verificationFilter, () => { if (opsAllowed) health.reset() })
function applyAction() {
  appliedAction.value = actionFilter.value.trim()
  if (auditAllowed) audit.reset()
}

/** 审计日志菜单行只显示审计，运行健康菜单行不显示审计分段（版式见下）。 */
const auditPage = props.segment === 'audit'
const views = [
  { value: 'ops' as const, label: '运行概况' },
  { value: 'health' as const, label: '采集健康窗口' },
  { value: 'sensors' as const, label: '采集心跳' },
  { value: 'executors' as const, label: '执行心跳' },
  { value: 'audit' as const, label: '审计' },
]
const viewLabel = (v: View) => views.find((x) => x.value === v)!.label
const tabs = views.filter((v) => auditPage || v.value !== 'audit')
const verificationOptions = Object.keys(guardVerificationLabel)
const counters = (w: GuardHealthWindow) => {
  const a = w.counterStart, b = w.counterEnd
  const d = (x: number | null, y: number | null) => (x === null || y === null ? '未知' : String(y - x))
  return `收包 +${d(a.packetsSeen, b.packetsSeen)} · 内核丢包 ${b.kernelDrops === null ? (w.captureSource === 'file_replay' ? '不适用' : '未知') : d(a.kernelDrops, b.kernelDrops)} · 容量丢弃 ${d(a.capacityDrops, b.capacityDrops)}`
}
const short = (v: string | null | undefined) => (v ? v.slice(0, 8) : '—')

/*
 * 版式（视觉基线 v2）：
 * - 运行健康：顶部读数带（不健康数量来自汇总接口），运行概况分段画成“资产状态看板”，每个资产一张卡片；
 *   心跳只表示机器存活，不代表采集健康，两者分开显示。
 * - 审计日志：按日期分组的日志流，左侧时间轴，结果用圆点区分；页头读数为最近 24 小时总数与当前页拒绝数。
 */
const summary = useSummary()
const healthStats = computed(() => [
  { key: 'assets', label: '运行中资产', value: ops.items.value.length ? countIf(ops.items.value, (a) => a.status === 'active') : undefined, icon: ServerCog, tone: 'ok' as const, hint: `当前页 ${ops.items.value.length} 个资产` },
  { key: 'sensors', label: '采集不健康', value: summary.data.ops?.sensorsUnhealthy, icon: RadioTower, tone: 'threat' as const, hint: '按最近健康窗口判定' },
  { key: 'executors', label: '执行器不健康', value: summary.data.ops?.executorsUnhealthy, icon: Cpu, tone: 'threat' as const, hint: '按心跳判定' },
  { key: 'last', label: '最近健康窗口', value: summary.data.ops ? fmtTime(summary.data.ops.lastHealthAt) : undefined, icon: Clock, hint: '服务端接收时间' },
])
const outcomeLabel = (o: string) => (o === 'success' ? '成功' : o === 'denied' ? '拒绝' : o === 'failure' ? '失败' : o === 'rejected' ? '驳回' : o)
const actorLabel = (a: string) => (a === 'machine' ? '机器' : a === 'human' ? '人工' : a === 'system' ? '系统' : a)
const deniedOnPage = computed(() => countIf(audit.items.value, (a) => a.outcome !== 'success'))
/** 审计按本地日期分组，组内保持后端返回顺序（新在前）。 */
const auditDays = computed(() => {
  const out: { day: string; items: GuardAuditEntry[] }[] = []
  for (const a of audit.items.value) {
    const day = fmtTime(a.occurredAt).slice(0, 10)
    const last = out[out.length - 1]
    if (last?.day === day) last.items.push(a)
    else out.push({ day, items: [a] })
  }
  return out
})
const dotBg: Record<string, string> = { ok: 'bg-ok', threat: 'bg-threat', warn: 'bg-warn', signal: 'bg-signal', mute: 'bg-ink-4' }
/** 资产卡片：最近心跳距今超过 2 分钟视为“心跳陈旧”，只作提示，健康以服务端判定为准。 */
const stale = (t: string | null) => !t || Date.now() - Date.parse(t) > 120_000

/** 本页由多个菜单行复用，标题跟随当前菜单项。 */
const pageTitle = usePageTitle('健康与审计')
</script>

<template>
  <div>
    <PageHead v-if="auditPage" :title="pageTitle" desc="追加式审计记录：登录、授权变化、审批、模型激活、执行与回滚都会写入，记录不可改写。">
      <span v-if="auditAllowed && summary.data.recentAuditCount24h !== undefined" class="flex items-baseline gap-2 text-[12.5px] text-ink-3">最近 24 小时<span class="num text-[1.25rem] font-light text-ink">{{ summary.data.recentAuditCount24h }}</span></span>
    </PageHead>
    <template v-else>
      <PageHead :title="pageTitle" desc="采集健康窗口、机器心跳与各资产运行概况。文件回放健康只证明 lab 回放窗口完整，不代表现场采集健康，也不用于预算恢复；心跳只表示机器存活。" />
      <StatBand v-if="opsAllowed" class="mb-5" label="运行概览" :stats="healthStats" />
      <Segmented v-model="view" :options="tabs" />
    </template>

    <p v-if="!allowed(view)" class="panel mt-5 px-5 py-10 text-center text-[13px] text-ink-3">当前身份没有{{ view === 'audit' ? '审计读取权限（audit.read）' : '运行状态读取权限（ops.read）' }}，本分段不显示数据。</p>
    <Panel v-else :class="auditPage ? '' : 'mt-5'" :title="view === 'audit' ? '审计记录' : viewLabel(view)" :icon="view === 'audit' ? ScrollText : view === 'ops' ? ServerCog : Activity" :flush="view !== 'ops' && view !== 'audit'">
      <template v-if="view === 'health' || view === 'audit'" #toolbar>
        <div v-if="view === 'health'" class="toolbar w-full">
          <label class="toolbar-field"><span>服务端判定</span>
            <select v-model="verificationFilter" class="field" aria-label="服务端判定">
              <option value="">全部</option>
              <option v-for="s in verificationOptions" :key="s" :value="s">{{ guardVerificationLabel[s] }}</option>
            </select>
          </label>
          <p class="text-[12px] leading-relaxed text-ink-3">「当前状态」在服务端判定之上叠加 10 秒新鲜度：历史窗口即使当时健康，现在也显示为已过期。</p>
        </div>
        <form v-else class="toolbar w-full" @submit.prevent="applyAction">
          <label class="toolbar-field"><span>动作</span><input v-model="actionFilter" class="field num !w-80" aria-label="动作（精确匹配）" placeholder="精确匹配，如 guard.lab.report_imported" maxlength="128" /></label>
          <button type="submit" class="act-ghost">筛选</button>
          <span class="toolbar-end text-[12.5px] text-ink-3"><ShieldX :size="14" :stroke-width="1.5" :class="deniedOnPage ? 'text-threat' : ''" aria-hidden="true" />当前页拒绝或失败 <span class="num" :class="deniedOnPage ? 'text-threat' : 'text-ink'">{{ deniedOnPage }}</span></span>
        </form>
      </template>

        <LoadState :loading="active.loading.value" :error="active.error.value" :empty="!active.items.value.length">
          <Transition name="fade" mode="out-in">
            <!-- 资产状态看板：每个资产一张卡片，采集与执行分两行 -->
            <ul v-if="view === 'ops'" key="ops" class="grid gap-3 md:grid-cols-2 2xl:grid-cols-3">
              <li v-for="a in ops.items.value" :key="a.id" class="rounded border border-ink-line p-4">
                <div class="flex items-start justify-between gap-3">
                  <div class="min-w-0">
                    <p class="text-[12px] text-ink-3">资产</p>
                    <IdText :value="a.id" />
                  </div>
                  <Tag pill :tone="machineStatusTone[a.status]" :label="guardMachineStatusLabel[a.status] ?? a.status" />
                </div>
                <dl class="mt-3 space-y-2 text-[12.5px]">
                  <div class="flex items-center gap-2.5">
                    <RadioTower :size="14" :stroke-width="1.5" class="text-ink-3" aria-hidden="true" />
                    <dt class="text-ink-2">采集 <span class="num">{{ a.sensorCount }}</span></dt>
                    <dd class="num ml-auto flex items-center gap-1.5" :class="stale(a.lastSensorHeartbeatAt) ? 'text-ink-4' : 'text-ink-2'"><span class="dot" :class="stale(a.lastSensorHeartbeatAt) ? 'bg-ink-4' : 'bg-ok'" />{{ fmtTime(a.lastSensorHeartbeatAt) }}</dd>
                  </div>
                  <div class="flex items-center gap-2.5">
                    <Cpu :size="14" :stroke-width="1.5" class="text-ink-3" aria-hidden="true" />
                    <dt class="text-ink-2">执行 <span class="num">{{ a.executorCount }}</span></dt>
                    <dd class="num ml-auto flex items-center gap-1.5" :class="stale(a.lastExecutorHeartbeatAt) ? 'text-ink-4' : 'text-ink-2'"><span class="dot" :class="stale(a.lastExecutorHeartbeatAt) ? 'bg-ink-4' : 'bg-ok'" />{{ fmtTime(a.lastExecutorHeartbeatAt) }}</dd>
                  </div>
                </dl>
                <div class="mt-3 grid grid-cols-3 gap-2 border-t border-ink-hair pt-3 text-[12px] text-ink-3">
                  <span>健康窗口<span class="num block text-[15px] text-ink">{{ a.healthWindowCount }}</span></span>
                  <span>预算目标<span class="num block text-[15px] text-ink">{{ a.budgetTargetCount }}</span></span>
                  <span>预算重置<span class="num block text-[15px] text-ink">{{ a.budgetResetCount }}</span></span>
                </div>
                <p class="mt-2 text-[11.5px] text-ink-4">最近健康窗口 <span class="num">{{ fmtTime(a.lastHealthReceivedAt) }}</span></p>
              </li>
            </ul>

            <table v-else-if="view === 'health'" key="health" class="table">
              <thead><tr><th>服务端判定</th><th>当前状态</th><th>来源 / 版本</th><th>窗口</th><th>计数变化</th><th class="text-right">序号 / 采集</th></tr></thead>
              <tbody>
                <tr v-for="w in health.items.value" :key="w.id">
                  <td>
                    <Tag :tone="verificationTone[w.verificationStatus ?? '']" :label="w.verificationStatus ? (guardVerificationLabel[w.verificationStatus] ?? w.verificationStatus) : '无判定'" />
                    <span v-if="w.verificationStatus === 'replay_healthy'" class="block text-[11.5px] text-ink-4">不代表现场采集健康</span>
                  </td>
                  <td><Tag :tone="healthStateTone[w.healthState]" :label="guardHealthStateLabel[w.healthState] ?? w.healthState" /></td>
                  <td><span class="block text-ink-2">{{ w.captureSource === 'file_replay' ? '文件回放' : w.captureSource === 'live' ? '现场采集' : (w.captureSource ?? '—') }}</span><span class="num text-[11.5px] text-ink-4">{{ w.healthVersion ?? '—' }}</span></td>
                  <td><span class="num block text-ink-2">{{ fmtTime(w.intervalEnd) }}</span><span class="num text-[11.5px] text-ink-4">接收 {{ fmtTime(w.receivedAt) }}<template v-if="w.captureGap"> · 有缺口</template></span></td>
                  <td class="num text-[12px] text-ink-3">{{ counters(w) }}</td>
                  <td class="num text-right text-ink-3">#{{ w.sequence }} · {{ short(w.sensorId) }}</td>
                </tr>
              </tbody>
            </table>

            <table v-else-if="view === 'sensors' || view === 'executors'" :key="view" class="table">
              <thead><tr><th>身份</th><th>状态</th><th>存活</th><th>{{ view === 'sensors' ? '版本 / 配置' : '适配器 / 能力摘要' }}</th><th>{{ view === 'sensors' ? 'boot' : '活动规则 / 待恢复' }}</th><th class="text-right">最近心跳</th></tr></thead>
              <tbody>
                <tr v-for="h in active.items.value as GuardHeartbeat[]" :key="h.id">
                  <td class="num">{{ short(h.id) }}<span class="block text-[11.5px] text-ink-4">资产 {{ short(h.assetId) }}</span></td>
                  <td><Tag :tone="machineStatusTone[h.status]" :label="guardMachineStatusLabel[h.status] ?? h.status" /></td>
                  <td><Tag :tone="healthStateTone[h.healthState]" :label="guardHealthStateLabel[h.healthState] ?? h.healthState" /></td>
                  <td v-if="view === 'sensors'"><span class="num block text-ink-2">{{ h.agentVersion ?? '—' }}</span><span class="num text-[11.5px] text-ink-4">配置 {{ short(h.currentConfig?.contentSha256) }}</span></td>
                  <td v-else><span class="num block text-ink-2">{{ h.adapterVersion ?? '—' }}</span><span class="num text-[11.5px] text-ink-4">{{ short(h.capabilityHash) }}</span></td>
                  <td v-if="view === 'sensors'" class="num text-ink-3">{{ short(h.bootId) }}</td>
                  <td v-else class="num text-ink-2">{{ h.reported?.activeRuleCount ?? '—' }} / {{ h.reported?.pendingRecovery === null || h.reported?.pendingRecovery === undefined ? '—' : h.reported.pendingRecovery ? '是' : '否' }}</td>
                  <td class="num text-right text-ink-3">{{ fmtTime(h.receivedAt) }}</td>
                </tr>
              </tbody>
            </table>

            <!-- 审计日志流：按日期分组，左侧时间轴 -->
            <div v-else key="audit" class="space-y-6">
              <section v-for="d in auditDays" :key="d.day" :aria-label="d.day">
                <h3 class="num sticky top-14 z-[1] mb-2 bg-paper py-1 text-[12.5px] text-ink-3">{{ d.day }}<span class="ml-2 text-ink-4">{{ d.items.length }} 条</span></h3>
                <ol class="relative ml-1.5 border-l border-ink-hair">
                  <li v-for="a in d.items" :key="a.id" class="relative grid grid-cols-[3.25rem_minmax(0,1fr)] gap-x-3 py-2 pl-5 md:grid-cols-[3.25rem_minmax(0,1fr)_auto]">
                    <span class="absolute -left-[4.5px] top-[14px] h-2 w-2 rounded-full ring-2 ring-paper" :class="dotBg[auditOutcomeTone[a.outcome]]" :title="outcomeLabel(a.outcome)" />
                    <span class="num pt-px text-[12px] text-ink-3">{{ fmtTime(a.occurredAt, false) }}</span>
                    <div class="min-w-0">
                      <p class="flex flex-wrap items-center gap-x-2 gap-y-1">
                        <span class="num break-all text-[13px] text-ink">{{ a.action }}</span>
                        <span v-if="a.outcome !== 'success'" class="pill bg-threat-soft text-threat">{{ outcomeLabel(a.outcome) }}</span>
                      </p>
                      <p class="mt-0.5 flex flex-wrap items-center gap-x-2 text-[12px] text-ink-3">
                        {{ actorLabel(a.actorType) }}<span class="text-ink-line">|</span>{{ a.resourceType ?? '—' }}<IdText v-if="a.resourceId" :value="a.resourceId" :copy="false" />
                      </p>
                    </div>
                    <span class="col-start-2 text-[12px] text-ink-4 md:col-start-auto">请求 <IdText :value="a.requestId" /></span>
                  </li>
                </ol>
              </section>
            </div>
          </Transition>
        </LoadState>

      <template #foot>
        <CursorPager :count="active.items.value.length" :has-next="!!active.next.value" :has-prev="!!active.stack.value.length"
          :busy="active.turning.value" :label="viewLabel(view)" @next="active.forward()" @prev="active.back()" />
      </template>
    </Panel>
  </div>
</template>
