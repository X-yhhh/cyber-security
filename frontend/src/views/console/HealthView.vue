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
import PageHead from '@/components/PageHead.vue'
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

const views = [
  { value: 'ops' as const, label: '运行概况' },
  { value: 'health' as const, label: '采集健康窗口' },
  { value: 'sensors' as const, label: '采集心跳' },
  { value: 'executors' as const, label: '执行心跳' },
  { value: 'audit' as const, label: '审计' },
]
const verificationOptions = Object.keys(guardVerificationLabel)
const counters = (w: GuardHealthWindow) => {
  const a = w.counterStart, b = w.counterEnd
  const d = (x: number | null, y: number | null) => (x === null || y === null ? '未知' : String(y - x))
  return `收包 +${d(a.packetsSeen, b.packetsSeen)} · 内核丢包 ${b.kernelDrops === null ? (w.captureSource === 'file_replay' ? '不适用' : '未知') : d(a.kernelDrops, b.kernelDrops)} · 容量丢弃 ${d(a.capacityDrops, b.capacityDrops)}`
}
const short = (v: string | null | undefined) => (v ? v.slice(0, 8) : '—')
</script>

<template>
  <div>
    <PageHead no="14" title="健康与审计" desc="采集健康窗口、机器心跳、各资产运行概况与 v2 审计。文件回放健康（replay_healthy）只证明 lab 回放窗口完整、无容量丢弃，不代表现场采集健康，也不用于预算恢复；心跳只表示机器存活，不代表采集健康。">
      <template #kicker>Health &amp; audit</template>
    </PageHead>

    <Segmented v-model="view" :options="views" />

    <div class="mt-10">
      <p v-if="!allowed(view)" class="py-10 text-[13px] text-ink-3">当前身份没有{{ view === 'audit' ? '审计读取权限（audit.read）' : '运行状态读取权限（ops.read）' }}，本分段不显示数据。</p>
      <template v-else>
        <div v-if="view === 'health'" class="mb-6 flex flex-wrap items-end gap-6 text-[13px]">
          <label class="w-56"><span class="label">服务端判定</span>
            <select v-model="verificationFilter" class="field mt-1">
              <option value="">全部</option>
              <option v-for="s in verificationOptions" :key="s" :value="s">{{ guardVerificationLabel[s] }}</option>
            </select>
          </label>
          <p class="max-w-xl text-[12.5px] leading-relaxed text-ink-3">「当前状态」在服务端判定之上叠加 10 秒新鲜度：历史窗口即使当时健康，现在也显示为已过期。</p>
        </div>
        <form v-if="view === 'audit'" class="mb-6 flex flex-wrap items-end gap-6 text-[13px]" @submit.prevent="applyAction">
          <label class="w-64"><span class="label">动作（精确匹配）</span><input v-model="actionFilter" class="field mt-1" placeholder="如 guard.lab.report_imported" maxlength="128" /></label>
          <button type="submit" class="link text-[12.5px]">筛选</button>
        </form>

        <LoadState :loading="active.loading.value" :error="active.error.value" :empty="!active.items.value.length">
          <Transition name="fade" mode="out-in">
            <table v-if="view === 'ops'" key="ops" class="table">
              <thead><tr><th>资产</th><th>状态</th><th>采集 / 执行</th><th>最近采集心跳</th><th>最近执行心跳</th><th>健康窗口</th><th class="text-right">预算目标 / 重置</th></tr></thead>
              <tbody>
                <tr v-for="a in ops.items.value" :key="a.id">
                  <td class="num">{{ short(a.id) }}</td>
                  <td><Tag :tone="machineStatusTone[a.status]" :label="guardMachineStatusLabel[a.status] ?? a.status" /></td>
                  <td class="num text-ink-2">{{ a.sensorCount }} / {{ a.executorCount }}</td>
                  <td class="num text-ink-3">{{ fmtTime(a.lastSensorHeartbeatAt) }}</td>
                  <td class="num text-ink-3">{{ fmtTime(a.lastExecutorHeartbeatAt) }}</td>
                  <td><span class="num block text-ink-2">{{ a.healthWindowCount }}</span><span class="num text-[11.5px] text-ink-4">最近 {{ fmtTime(a.lastHealthReceivedAt) }}</span></td>
                  <td class="num text-right text-ink-2">{{ a.budgetTargetCount }} / {{ a.budgetResetCount }}</td>
                </tr>
              </tbody>
            </table>

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

            <table v-else key="audit" class="table">
              <thead><tr><th>结果</th><th>动作</th><th>资源</th><th>主体</th><th>请求</th><th class="text-right">时间</th></tr></thead>
              <tbody>
                <tr v-for="a in audit.items.value" :key="a.id">
                  <td><Tag :tone="auditOutcomeTone[a.outcome]" :label="a.outcome" /></td>
                  <td class="num text-ink-2">{{ a.action }}</td>
                  <td><span class="block text-ink-3">{{ a.resourceType ?? '—' }}</span><span class="num text-[11.5px] text-ink-4">{{ short(a.resourceId) }}</span></td>
                  <td class="text-ink-3">{{ a.actorType }}</td>
                  <td class="num text-ink-4">{{ short(a.requestId) }}</td>
                  <td class="num text-right text-ink-3">{{ fmtTime(a.occurredAt) }}</td>
                </tr>
              </tbody>
            </table>
          </Transition>
        </LoadState>

        <CursorPager :count="active.items.value.length" :has-next="!!active.next.value" :has-prev="!!active.stack.value.length"
          :busy="active.turning.value" :label="views.find((v) => v.value === view)!.label" @next="active.forward()" @prev="active.back()" />
      </template>
    </div>
  </div>
</template>
