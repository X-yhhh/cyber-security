<script setup lang="ts">
/**
 * 误报反馈（威胁检测 / Feedback，任务单 F1R，前端设计文档第 10.6 节）：观察样本标注与他人独立复核。
 *
 * - 分段「待复核 · 我的标注 · 全部」按权限显示：待复核需 `feedback.review`（status=pending，默认排除本人标注），
 *   我的标注需 `feedback.label`，全部需 `detection.read`；分段、状态、资产、时间同步到 URL（tab、status、assetId、range）。
 * - 后端没有“只看本人”的筛选，「我的标注」与「排除本人」只作用于当前页，页面写明。
 * - 职责分离：本人标注不能由本人复核（后端强制拒绝），详情中隐藏复核表单并说明原因；
 *   复核通过只登记为已复核（reviewed），不触发在线重训。
 * - 复核调用 POST /api/v2/feedback/{id}/reviews（{decision, reason}，带 If-Match）。
 */
import { computed, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { Hourglass, Layers, Plus, Tags, UserPen } from 'lucide-vue-next'
import DistBar from '@/components/DistBar.vue'
import { tally } from '@/components/viz'
import { useSummary } from '@/composables/summary'
import PageHead from '@/components/PageHead.vue'
import Panel from '@/components/Panel.vue'
import Tag from '@/components/Tag.vue'
import IdText from '@/components/IdText.vue'
import Drawer from '@/components/Drawer.vue'
import LoadState from '@/components/LoadState.vue'
import CursorPager from '@/components/CursorPager.vue'
import { useCursor } from '@/composables/cursor'
import { usePageTitle } from '@/composables/page'
import { errText } from '@/composables/load'
import { tabKeydown, visibleTabs, type TabOption } from '@/composables/tabs'
import { detectApi, isRange, isUuid, RANGES, rangeFrom, type RangeKey } from '@/api/v2/detect'
import { can, session } from '@/api/session'
import { toast } from '@/composables/toast'
import {
  fmtTime, guardFeedbackLabel, guardFeedbackStatusLabel,
  type GuardFeedback, type GuardObservation,
} from '@/api/types'
import { feedbackReviewTone, feedbackTone } from '@/data/tones'
import { useAssetNames } from './assets'

type Tab = 'pending' | 'mine' | 'all'
type FeedbackStatus = 'pending' | 'reviewed' | 'rejected'
const STATUSES: FeedbackStatus[] = ['pending', 'reviewed', 'rejected']
const isStatus = (v: unknown): v is FeedbackStatus => typeof v === 'string' && (STATUSES as string[]).includes(v)

const TABS: readonly (TabOption<Tab> & { icon: typeof Hourglass })[] = [
  { value: 'pending', label: '待复核', anyOf: ['feedback.review'], icon: Hourglass },
  { value: 'mine', label: '我的标注', anyOf: ['feedback.label'], icon: UserPen },
  { value: 'all', label: '全部', anyOf: ['detection.read'], icon: Layers },
]
const tabs = computed(() => visibleTabs(TABS, session.user?.permissions) as typeof TABS[number][])

const route = useRoute()
const router = useRouter()
/** 初始分段：URL 的 tab 优先；旧链接 `?status=pending`（待办中心）进入待复核；否则取第一个可见分段。 */
function initialTab(): Tab {
  const visible = tabs.value.map((t) => t.value)
  const want = route.query.tab ?? (route.query.status === 'pending' ? 'pending' : undefined)
  return visible.includes(want as Tab) ? (want as Tab) : (visible[0] ?? 'all')
}
const tab = ref<Tab>(initialTab())
const statusFilter = ref<FeedbackStatus | ''>(tab.value !== 'pending' && isStatus(route.query.status) ? route.query.status : '')
const assetFilter = ref(typeof route.query.assetId === 'string' ? route.query.assetId : '')
const range = ref<RangeKey | ''>(isRange(route.query.range) ? route.query.range : '')
const excludeSelf = ref(true)

/** 记录本会话刚刚创建的标注 ID，配合 createdBy 字段识别本人标注。 */
const selfCreatedIds = ref<Set<string>>(new Set())

const isSelf = (f: GuardFeedback | null | undefined): boolean => {
  if (!f) return false
  if (selfCreatedIds.value.has(f.id)) return true
  if (f.createdBy == null || !session.user) return false
  return String(f.createdBy) === String(session.user.id) || String(f.createdBy) === session.user.username
}

const { assets, label: assetLabel } = useAssetNames()

/** 时间下界在筛选变化时计算一次，翻页沿用同一值（游标与筛选绑定）。 */
let from = rangeFrom(range.value)
const feedback = useCursor<GuardFeedback>((cursor) =>
  detectApi.listFeedback({
    status: tab.value === 'pending' ? 'pending' : (statusFilter.value || undefined),
    assetId: assetFilter.value || undefined,
    from,
    cursor,
    limit: 50,
  }),
)

watch([tab, statusFilter, assetFilter, range], () => {
  const query: Record<string, string> = { tab: tab.value }
  if (tab.value !== 'pending' && statusFilter.value) query.status = statusFilter.value
  if (assetFilter.value) query.assetId = assetFilter.value
  if (range.value) query.range = range.value
  void router.replace({ query })
  from = rangeFrom(range.value)
  feedback.reset()
})

/* 版式（视觉基线 v2，误报反馈）：左侧分段与筛选栏 + 右侧标注列表；待复核总数来自汇总接口（排除本人标注），构成按当前页统计。 */
const summary = useSummary()

const pageTitle = usePageTitle('误报反馈')
const current = computed(() => TABS.find((t) => t.value === tab.value)!)
const statusChips: { value: FeedbackStatus | ''; label: string }[] = [
  { value: '', label: '全部' },
  ...STATUSES.map((v) => ({ value: v, label: guardFeedbackStatusLabel[v] ?? v })),
]
const onTabKey = (e: KeyboardEvent) => tabKeydown(e, tabs.value.map((t) => t.value), tab.value, (v) => { tab.value = v })


const visibleItems = computed(() => {
  if (tab.value === 'mine') return feedback.items.value.filter(isSelf)
  if (tab.value === 'pending' && excludeSelf.value) return feedback.items.value.filter((f) => !isSelf(f))
  return feedback.items.value
})
const fbHint = computed(() => `按当前页 ${visibleItems.value.length} 条统计`)
const byLabel = computed(() => tally(visibleItems.value, (f) => f.label, (k) => guardFeedbackLabel[k] ?? k, (k) => feedbackTone[k]))
const emptyText = computed(() => (
  tab.value === 'pending' ? '你可见范围内暂无待你复核的标注。'
    : tab.value === 'mine' ? '当前页中没有你提交的标注。'
      : '你可见范围内暂无符合条件的标注。'))

const canLabel = computed(() => can('feedback.label'))
const canReview = computed(() => can('feedback.review'))

/* 详情抽屉与关联观察 */
const picked = ref<GuardFeedback | null>(null)
const obs = ref<{ loading: boolean; error: string; data: GuardObservation | null }>({ loading: false, error: '', data: null })
const reviewForm = reactive({ decision: 'approve' as 'approve' | 'reject', reason: '', busy: false, error: '' })

watch(picked, async (f) => {
  reviewForm.decision = 'approve'
  reviewForm.reason = ''
  reviewForm.error = ''
  if (!f) { obs.value = { loading: false, error: '', data: null }; return }
  obs.value = { loading: true, error: '', data: null }
  try {
    const data = await detectApi.getObservation(f.observationId)
    obs.value = { loading: false, error: '', data }
  } catch (e) {
    obs.value = { loading: false, error: errText(e), data: null }
  }
})

const canDecidePicked = computed(() =>
  canReview.value && !!picked.value && picked.value.status === 'pending' && !isSelf(picked.value),
)

async function submitReview() {
  if (!picked.value || !canDecidePicked.value) return
  if (!reviewForm.reason.trim()) {
    reviewForm.error = '请填写复核理由'
    return
  }
  reviewForm.busy = true
  reviewForm.error = ''
  try {
    await detectApi.reviewFeedback(
      picked.value.id,
      picked.value.revision,
      reviewForm.decision,
      reviewForm.reason.trim(),
    )
    toast(reviewForm.decision === 'approve' ? '复核已通过，登记为已复核样本' : '已驳回该标注')
    picked.value = null
    feedback.reset()
  } catch (e) {
    reviewForm.error = errText(e)
  } finally {
    reviewForm.busy = false
  }
}

/* 新建标注抽屉 */
const creating = ref(false)
const createForm = reactive({ observationId: '', label: 'attack', evidenceRef: '', busy: false, error: '' })

function openCreate() {
  createForm.observationId = ''
  createForm.label = 'attack'
  createForm.evidenceRef = ''
  createForm.error = ''
  creating.value = true
}

async function submitCreate() {
  if (!isUuid(createForm.observationId)) {
    createForm.error = '观察记录 ID 须为有效的 UUID 格式'
    return
  }
  if (!createForm.evidenceRef.trim()) {
    createForm.error = '请填写证据引用说明'
    return
  }
  createForm.busy = true
  createForm.error = ''
  try {
    const created = await detectApi.createFeedback(
      createForm.observationId.trim(),
      createForm.label,
      createForm.evidenceRef.trim(),
    )
    if (created?.id) selfCreatedIds.value.add(created.id)
    creating.value = false
    toast('标注已提交，等待他人独立复核')
    feedback.reset()
  } catch (e) {
    createForm.error = errText(e)
  } finally {
    createForm.busy = false
  }
}
</script>

<template>
  <div>
    <PageHead :title="pageTitle" desc="对观察快照做真 / 误报标注，并由他人独立复核。">
      <button v-if="canLabel" type="button" class="act" @click="openCreate"><Plus :size="14" :stroke-width="1.5" />新建标注</button>
    </PageHead>

    <div class="grid items-start gap-5 lg:grid-cols-[15rem_minmax(0,1fr)]">
      <!-- 左侧：分段（按权限显示）+ 筛选 + 结论构成 -->
      <aside class="space-y-4 lg:sticky lg:top-20">
        <nav class="panel p-2" role="tablist" aria-label="反馈分段">
          <button v-for="o in tabs" :key="o.value" type="button" role="tab"
            class="flex w-full items-center gap-2.5 rounded px-3 py-2 text-left text-[13.5px] transition-colors"
            :class="tab === o.value ? 'bg-ink text-paper' : 'text-ink-2 hover:bg-paper-soft'"
            :aria-selected="tab === o.value" :tabindex="tab === o.value ? 0 : -1" @click="tab = o.value" @keydown="onTabKey">
            <component :is="o.icon" :size="15" :stroke-width="1.5" aria-hidden="true" />{{ o.label }}
          </button>
        </nav>
        <div class="panel space-y-3 p-4">
          <div v-if="tab !== 'pending'" class="space-y-1.5">
            <p class="label">复核状态</p>
            <div class="chips" role="group" aria-label="复核状态筛选">
              <button v-for="c in statusChips" :key="c.value" type="button" class="chip" :aria-pressed="statusFilter === c.value" @click="statusFilter = c.value">{{ c.label }}</button>
            </div>
          </div>
          <label v-if="assets.length" class="form-field">
            <span class="label">资产</span>
            <select v-model="assetFilter" aria-label="资产筛选" class="field">
              <option value="">全部授权资产</option>
              <option v-for="a in assets" :key="a.id" :value="a.id">{{ a.displayName || a.assetKey }}</option>
            </select>
          </label>
          <label class="form-field">
            <span class="label">提交时间</span>
            <select v-model="range" aria-label="时间范围" class="field">
              <option value="">全部时间</option>
              <option v-for="r in RANGES" :key="r.value" :value="r.value">{{ r.label }}</option>
            </select>
          </label>
          <label v-if="tab === 'pending'" class="check">
            <input v-model="excludeSelf" type="checkbox" />
            <span>排除本人标注</span>
          </label>
          <p v-if="tab === 'pending'" class="text-[12px] leading-relaxed text-ink-3">本人标注须由其他复核人决定。</p>
          <p v-else-if="tab === 'mine'" class="text-[12px] leading-relaxed text-ink-3">只在当前页中筛出你提交的标注。</p>
        </div>
        <div class="panel p-4">
          <p class="mb-3 flex items-center justify-between text-[12.5px] text-ink-3"><span>标注结论</span><span>{{ fbHint }}</span></p>
          <DistBar :segments="byLabel" empty-text="当前页没有标注" />
          <p v-if="summary.data.pendingFeedbackReviews !== undefined" class="mt-4 flex items-baseline justify-between border-t border-ink-hair pt-3 text-[12.5px] text-ink-3">
            待我复核（全部）<span class="num text-[1.25rem] font-light text-ink">{{ summary.data.pendingFeedbackReviews }}</span>
          </p>
        </div>
      </aside>

    <Panel :title="tab === 'all' ? '全部标注' : current.label" :icon="Tags" flush>
      <LoadState :loading="feedback.loading.value" :error="feedback.error.value" :empty="!visibleItems.length" :empty-text="emptyText">
        <table class="table min-w-[740px]">
          <thead>
            <tr>
              <th>标注结论</th>
              <th>复核状态</th>
              <th>观察记录</th>
              <th>证据引用</th>
              <th>资产</th>
              <th class="text-right">提交时间</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="f in visibleItems" :key="f.id" class="row-link" tabindex="0"
              @click="picked = f" @keydown.enter="picked = f">
              <td><Tag :tone="feedbackTone[f.label]" :label="guardFeedbackLabel[f.label] ?? f.label" /></td>
              <td>
                <Tag pill :tone="feedbackReviewTone[f.status]" :label="guardFeedbackStatusLabel[f.status] ?? f.status" />
                <span v-if="isSelf(f)" class="ml-2 text-[11.5px] text-ink-4">本人标注</span>
              </td>
              <td><IdText :value="f.observationId" :copy="false" /></td>
              <td class="max-w-[16rem] truncate text-ink-2" :title="f.evidenceRef">{{ f.evidenceRef }}</td>
              <td class="text-ink-2">{{ assetLabel(f.assetId) }}</td>
              <td class="num text-right text-ink-3">{{ fmtTime(f.createdAt) }}</td>
            </tr>
          </tbody>
        </table>
      </LoadState>

      <template #foot>
        <CursorPager :count="visibleItems.length" :has-next="!!feedback.next.value" :has-prev="!!feedback.stack.value.length"
          :busy="feedback.turning.value" :label="current.label" @next="feedback.forward()" @prev="feedback.back()" />
      </template>
    </Panel>
    </div>

    <!-- 反馈详情与复核抽屉 -->
    <Drawer :open="!!picked" :title="picked ? `${guardFeedbackLabel[picked.label] ?? picked.label} · ${assetLabel(picked.assetId)}` : ''" kicker="标注" @close="picked = null">
      <template v-if="picked">
        <dl class="kv">
          <div v-for="[k, v] in [
            ['标注结论', guardFeedbackLabel[picked.label] ?? picked.label],
            ['复核状态', guardFeedbackStatusLabel[picked.status] ?? picked.status],
            ['资产', assetLabel(picked.assetId)],
            ['证据引用', picked.evidenceRef],
            ['复核意见', picked.reviewReason ?? '—'],
            ['提交时间', fmtTime(picked.createdAt)],
          ]" :key="k">
            <dt>{{ k }}</dt>
            <dd class="break-all">{{ v }}</dd>
          </div>
        </dl>

        <h3 class="section-title mt-8">关联观察</h3>
        <LoadState :loading="obs.loading" :error="obs.error" :empty="!obs.data" empty-text="未能读取关联观察详情。">
          <dl v-if="obs.data" class="kv rounded border border-ink-hair px-3 text-[12.5px]">
            <div v-for="[k, v] in [
              ['对端', obs.data.peerKey ?? '—'],
              ['方向 / 端口', `${obs.data.direction ?? '—'} / ${obs.data.servicePort ?? '—'}`],
              ['快照时刻', fmtTime(obs.data.asOf)],
              ['流标识', obs.data.flowId],
            ]" :key="k">
              <dt>{{ k }}</dt>
              <dd class="num break-all">{{ v }}</dd>
            </div>
          </dl>
        </LoadState>

        <!-- 复核表单：仅 feedback.review、pending 且非本人标注时显示 -->
        <div v-if="canDecidePicked" class="form mt-8 border-t border-ink-hair pt-6 text-[13px]">
          <h3 class="section-title">独立复核决定</h3>
          <label class="form-field">
            <span class="label">复核结论</span>
            <select v-model="reviewForm.decision" aria-label="复核结论" class="field">
              <option value="approve">通过（登记为已复核）</option>
              <option value="reject">驳回</option>
            </select>
            <span class="text-[12px] text-ink-3">复核通过只登记为已复核样本，不会触发在线重训。</span>
          </label>
          <label class="form-field">
            <span class="label">复核理由（必填）</span>
            <textarea v-model="reviewForm.reason" aria-label="复核理由" rows="3" maxlength="1000" class="field resize-none" placeholder="写明核对观察特征与上下文后的复核依据" />
          </label>
          <p v-if="reviewForm.error" role="alert" class="text-[12.5px] text-threat">{{ reviewForm.error }}</p>
        </div>
        <p v-else-if="picked.status === 'pending' && isSelf(picked)" class="note mt-8">
          本人提交的标注须由其他复核人决定，你不能复核。
        </p>

        <details class="tech-details mt-6">
          <summary>技术细节</summary>
          <dl class="kv text-[12px]">
            <div v-for="[k, v] in [
              ['标注 ID', picked.id],
              ['结论键', picked.label],
              ['关联观察', picked.observationId],
              ['特征格式', obs.data?.profile ?? '—'],
              ['观察内容摘要', obs.data?.contentSha256 ?? '—'],
              ['修订', String(picked.revision)],
            ]" :key="k" class="grid-cols-[6rem_minmax(0,1fr)]">
              <dt>{{ k }}</dt><dd class="num break-all">{{ v }}</dd>
            </div>
          </dl>
        </details>
      </template>

      <template v-if="canDecidePicked" #foot>
        <button type="button" class="act-ghost" @click="picked = null">取消</button>
        <button type="button" class="act" :disabled="reviewForm.busy || !reviewForm.reason.trim()" @click="submitReview">
          {{ reviewForm.busy ? '提交中…' : '提交复核' }}
        </button>
      </template>
    </Drawer>

    <!-- 新建标注抽屉 -->
    <Drawer :open="creating" title="新建观察标注" kicker="观察标注" @close="creating = false">
      <div class="form text-[13px]">
        <p class="note">
          输入目标观察记录的外部 UUID 并选择标注结论。提交后状态为待复核（pending），须由另一名复核人独立审核。
        </p>
        <label class="form-field">
          <span class="label">观察记录 UUID</span>
          <input v-model="createForm.observationId" aria-label="观察记录 UUID" class="field num" placeholder="例如 00000000-0000-4000-8000-000000000001" />
        </label>
        <label class="form-field">
          <span class="label">标注结论</span>
          <select v-model="createForm.label" aria-label="新建标注结论" class="field">
            <option v-for="(lbl, k) in guardFeedbackLabel" :key="k" :value="k">{{ lbl }}</option>
          </select>
        </label>
        <label class="form-field">
          <span class="label">证据引用说明</span>
          <textarea v-model="createForm.evidenceRef" aria-label="新建证据引用说明" rows="3" maxlength="1000" class="field resize-none" placeholder="说明标注依据或关联流量摘要" />
          <span class="text-[12px] text-ink-3">提交后为待复核，须由他人独立复核。</span>
        </label>
        <p v-if="createForm.error" role="alert" class="text-[12.5px] text-threat">{{ createForm.error }}</p>
      </div>
      <template #foot>
        <button type="button" class="act-ghost" @click="creating = false">取消</button>
        <button type="button" class="act" :disabled="createForm.busy" @click="submitCreate">
          {{ createForm.busy ? '提交中…' : '提交标注' }}
        </button>
      </template>
    </Drawer>
  </div>
</template>
