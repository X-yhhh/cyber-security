<script setup lang="ts">
/**
 * 事件研判（威胁检测 / Events）：v2 单资产安全事件列表（GET /api/v2/events）。
 *
 * 口径（docs/接口设计.md、权限设计 §7.2）：
 * - 事件由后端按 15 分钟同资产与同攻击家族窗口自动归并，不再混合 v1 告警/规则/检测策略旧表；
 * - 支持按状态（status）与资产（assetId）筛选，游标分页每次切换筛选即重新请求；
 * - 工作台「未结事件」带 `?status=open` 进入本页时，自动同步为初始状态筛选；
 * - 点击行进入整页详情 `/console/detect/events/:id`。
 */
import { ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import PageHead from '@/components/PageHead.vue'
import Tag from '@/components/Tag.vue'
import LoadState from '@/components/LoadState.vue'
import CursorPager from '@/components/CursorPager.vue'
import { useCursor } from '@/composables/cursor'
import { guard } from '@/api/client'
import { detectApi } from '@/api/v2/detect'
import { can } from '@/api/session'
import {
  eventStatusLabel, fmtTime, guardFamilyLabel, severityLabel,
  type EventStatus, type GuardAsset, type GuardGuardEvent,
} from '@/api/types'
import { eventTone, severityTone } from '@/data/tones'

const STATUSES: EventStatus[] = ['open', 'investigating', 'contained', 'resolved', 'false_positive', 'closed']
const isStatus = (v: unknown): v is EventStatus => typeof v === 'string' && (STATUSES as string[]).includes(v)

const route = useRoute()
const router = useRouter()

const statusFilter = ref<EventStatus | ''>(isStatus(route.query.status) ? route.query.status : '')
const assetFilter = ref(typeof route.query.assetId === 'string' ? route.query.assetId : '')

const assets = ref<GuardAsset[]>([])
void (async () => {
  if (!can('resource.read')) return
  try { assets.value = (await guard.list<GuardAsset>('assets', { limit: 200 })).items } catch { /* 资产名称辅助不阻塞事件读取 */ }
})()
const assetLabel = (id: string | null) => (id ? (assets.value.find((a) => a.id === id)?.assetKey ?? id.slice(0, 8)) : '—')

const events = useCursor<GuardGuardEvent>((cursor) =>
  detectApi.listEvents({
    status: statusFilter.value || undefined,
    assetId: assetFilter.value || undefined,
    cursor,
    limit: 50,
  }),
)

watch(() => route.query.status, (q) => {
  const next = isStatus(q) ? q : ''
  if (next !== statusFilter.value) statusFilter.value = next
})

watch([statusFilter, assetFilter], ([s, a]) => {
  const query: Record<string, string> = {}
  if (s) query.status = s
  if (a) query.assetId = a
  void router.replace({ query })
  events.reset()
})

function setStatus(s: EventStatus | '') {
  statusFilter.value = statusFilter.value === s ? '' : s
}

function goDetail(id: string) {
  void router.push(`/console/detect/events/${encodeURIComponent(id)}`)
}
</script>

<template>
  <div>
    <PageHead title="事件研判" desc="单资产范围的安全事件台账：告警与阻断候选判定按 15 分钟同资产同类别窗口归并。状态迁移、指派负责人、追加研判记录与人工处置申请均在事件详情页完成。">
      <template #kicker>Event Investigation</template>
      <label v-if="assets.length" class="w-48 text-[13px]">
        <span class="label">资产筛选</span>
        <select v-model="assetFilter" aria-label="资产筛选" class="field mt-1">
          <option value="">全部授权资产</option>
          <option v-for="a in assets" :key="a.id" :value="a.id">{{ a.assetKey }}</option>
        </select>
      </label>
    </PageHead>

    <!-- 状态筛选：遵循操作控件阶梯第 4 级（无样式 button + 下划线切换） -->
    <div class="flex flex-wrap items-center gap-x-6 gap-y-2 border-b border-ink-hair pb-5 text-[13px]" role="group" aria-label="事件状态筛选">
      <span class="label">状态</span>
      <button type="button" :class="statusFilter === '' ? 'text-ink underline underline-offset-4' : 'text-ink-3 hover:text-ink'" @click="statusFilter = ''">全部</button>
      <button v-for="s in STATUSES" :key="s" type="button"
        :class="statusFilter === s ? 'text-ink underline underline-offset-4' : 'text-ink-3 hover:text-ink'"
        @click="setStatus(s)">
        {{ eventStatusLabel[s] }}
      </button>
    </div>

    <div class="mt-8">
      <LoadState :loading="events.loading.value" :error="events.error.value" :empty="!events.items.value.length" empty-text="当前筛选条件下没有可见的安全事件。">
        <div class="overflow-x-auto">
          <table class="table min-w-[780px]">
            <thead>
              <tr>
                <th>严重度</th>
                <th>事件</th>
                <th>类别</th>
                <th>状态</th>
                <th>处理人</th>
                <th>资产</th>
                <th class="text-right">最近发现</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="e in events.items.value" :key="e.id" class="row-link" tabindex="0"
                @click="goDetail(e.id)" @keydown.enter="goDetail(e.id)">
                <td><Tag :tone="severityTone[e.severity]" :label="severityLabel[e.severity] ?? e.severity" /></td>
                <td>
                  <span class="block text-ink">{{ e.title }}</span>
                  <span class="num text-[12px] text-ink-3">{{ e.eventKey }} · r{{ e.revision }}</span>
                </td>
                <td class="text-ink-2">{{ guardFamilyLabel[e.category] ?? e.category }}</td>
                <td><Tag :tone="eventTone[e.status]" :label="eventStatusLabel[e.status as EventStatus] ?? e.status" /></td>
                <td class="num text-ink-2">{{ e.assigneeId ?? '未指派' }}</td>
                <td class="num text-ink-2">{{ assetLabel(e.guardAssetId) }}</td>
                <td class="num text-right text-ink-3">{{ fmtTime(e.lastSeenAt ?? e.createdAt) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </LoadState>

      <CursorPager :count="events.items.value.length" :has-next="!!events.next.value" :has-prev="!!events.stack.value.length"
        :busy="events.turning.value" label="安全事件" @next="events.forward()" @prev="events.back()" />
    </div>
  </div>
</template>
