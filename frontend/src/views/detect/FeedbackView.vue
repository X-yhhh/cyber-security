<script setup lang="ts">
/**
 * 反馈与复核（威胁检测 / Feedback）：v2 观察样本标注与第二人独立复核（GET/POST /api/v2/feedback）。
 *
 * 口径（docs/检测与处置契约.md、功能模块设计 §3.4、权限设计 §8）：
 * - 人工标注提交后状态为 pending，即使复核通过（reviewed）也**不自动进入在线训练**；
 * - 职责分离（S6）：标注人不能复核本人提交的标注（后端 `access.different(f, "created_by")` 强制拒绝）；
 * - 待复核列表默认排除本人标注；详情抽屉按需读取关联观察（GET /api/v2/observations/{id}）；
 * - 复核调用 POST /api/v2/feedback/{id}/reviews（{decision: 'approve'|'reject', reason}，带 If-Match）。
 */
import { computed, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import PageHead from '@/components/PageHead.vue'
import Tag from '@/components/Tag.vue'
import Drawer from '@/components/Drawer.vue'
import LoadState from '@/components/LoadState.vue'
import CursorPager from '@/components/CursorPager.vue'
import { useCursor } from '@/composables/cursor'
import { errText } from '@/composables/load'
import { guard } from '@/api/client'
import { detectApi, isUuid } from '@/api/v2/detect'
import { can, session } from '@/api/session'
import { toast } from '@/composables/toast'
import {
  fmtTime, guardFeedbackLabel, guardFeedbackStatusLabel,
  type GuardAsset, type GuardFeedback, type GuardObservation,
} from '@/api/types'
import { feedbackReviewTone, feedbackTone } from '@/data/tones'

type FeedbackStatus = 'pending' | 'reviewed' | 'rejected'
const STATUSES: FeedbackStatus[] = ['pending', 'reviewed', 'rejected']
const isStatus = (v: unknown): v is FeedbackStatus => typeof v === 'string' && (STATUSES as string[]).includes(v)

const route = useRoute()
const router = useRouter()
const statusFilter = ref<FeedbackStatus | ''>(isStatus(route.query.status) ? route.query.status : 'pending')
const assetFilter = ref(typeof route.query.assetId === 'string' ? route.query.assetId : '')
const excludeSelf = ref(true)

/** 记录本会话刚刚创建的标注 ID，配合 createdBy 字段识别本人标注。 */
const selfCreatedIds = ref<Set<string>>(new Set())

const isSelf = (f: GuardFeedback | null | undefined): boolean => {
  if (!f) return false
  if (selfCreatedIds.value.has(f.id)) return true
  if (f.createdBy == null || !session.user) return false
  return String(f.createdBy) === String(session.user.id) || String(f.createdBy) === session.user.username
}

const assets = ref<GuardAsset[]>([])
void (async () => {
  if (!can('resource.read')) return
  try { assets.value = (await guard.list<GuardAsset>('assets', { limit: 200 })).items } catch { /* 资产名称辅助不阻塞主列表 */ }
})()
const assetLabel = (id: string | null) => (id ? (assets.value.find((a) => a.id === id)?.assetKey ?? id.slice(0, 8)) : '—')

const feedback = useCursor<GuardFeedback>((cursor) =>
  detectApi.listFeedback({
    status: statusFilter.value || undefined,
    assetId: assetFilter.value || undefined,
    cursor,
    limit: 50,
  }),
)

watch(() => route.query.status, (q) => {
  if (isStatus(q) && q !== statusFilter.value) statusFilter.value = q
})

watch([statusFilter, assetFilter], ([s, a]) => {
  const query: Record<string, string> = {}
  if (s) query.status = s
  if (a) query.assetId = a
  void router.replace({ query })
  feedback.reset()
})

const visibleItems = computed(() => {
  if (statusFilter.value === 'pending' && excludeSelf.value) {
    return feedback.items.value.filter((f) => !isSelf(f))
  }
  return feedback.items.value
})

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
    toast(reviewForm.decision === 'approve' ? '复核已通过（不自动进入在线训练）' : '已驳回该标注')
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
    toast('标注已提交（待第二人独立复核）')
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
    <PageHead title="反馈与复核" desc="针对观察快照的人工真/误报标注与独立复核。标注提交后为待复核（pending），须由非本人的证据复核人决定通过或驳回（职责分离 S6）；复核通过后仅登记为已复核样本，不触发在线重训。">
      <template #kicker>Feedback &amp; Review</template>
      <label v-if="assets.length" class="w-48 text-[13px]">
        <span class="label">资产筛选</span>
        <select v-model="assetFilter" aria-label="资产筛选" class="field mt-1">
          <option value="">全部授权资产</option>
          <option v-for="a in assets" :key="a.id" :value="a.id">{{ a.assetKey }}</option>
        </select>
      </label>
      <button v-if="canLabel" type="button" class="act-ghost" @click="openCreate">新建标注</button>
    </PageHead>

    <!-- 状态筛选与本人排除开关 -->
    <div class="flex flex-wrap items-center justify-between gap-4 border-b border-ink-hair pb-5 text-[13px]" role="group" aria-label="反馈状态筛选">
      <div class="flex flex-wrap items-center gap-x-6 gap-y-2">
        <span class="label">状态</span>
        <button type="button" :class="statusFilter === '' ? 'text-ink underline underline-offset-4' : 'text-ink-3 hover:text-ink'" @click="statusFilter = ''">全部</button>
        <button v-for="s in STATUSES" :key="s" type="button"
          :class="statusFilter === s ? 'text-ink underline underline-offset-4' : 'text-ink-3 hover:text-ink'"
          @click="statusFilter = s">
          {{ guardFeedbackStatusLabel[s] ?? s }}
        </button>
      </div>
      <label v-if="statusFilter === 'pending'" class="flex cursor-pointer items-center gap-2 text-[12.5px] text-ink-2">
        <input v-model="excludeSelf" type="checkbox" class="accent-ink" />
        <span>默认排除本人标注</span>
      </label>
    </div>

    <div class="mt-8">
      <LoadState :loading="feedback.loading.value" :error="feedback.error.value" :empty="!visibleItems.length" empty-text="当前筛选条件下没有可显示的反馈记录。">
        <div class="overflow-x-auto">
          <table class="table min-w-[740px]">
            <thead>
              <tr>
                <th>标注结论</th>
                <th>复核状态</th>
                <th>观察记录</th>
                <th>证据引用</th>
                <th>资产</th>
                <th>修订</th>
                <th class="text-right">提交时间</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="f in visibleItems" :key="f.id" class="row-link" tabindex="0"
                @click="picked = f" @keydown.enter="picked = f">
                <td><Tag :tone="feedbackTone[f.label]" :label="guardFeedbackLabel[f.label] ?? f.label" /></td>
                <td>
                  <Tag :tone="feedbackReviewTone[f.status]" :label="guardFeedbackStatusLabel[f.status] ?? f.status" />
                  <span v-if="isSelf(f)" class="num ml-2 text-[11.5px] text-ink-4">本人标注</span>
                </td>
                <td class="num text-ink-2">{{ f.observationId.slice(0, 8) }}</td>
                <td class="num max-w-[16rem] truncate text-ink-2">{{ f.evidenceRef }}</td>
                <td class="num text-ink-2">{{ assetLabel(f.assetId) }}</td>
                <td class="num text-ink-3">r{{ f.revision }}</td>
                <td class="num text-right text-ink-3">{{ fmtTime(f.createdAt) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </LoadState>

      <CursorPager :count="visibleItems.length" :has-next="!!feedback.next.value" :has-prev="!!feedback.stack.value.length"
        :busy="feedback.turning.value" label="样本反馈" @next="feedback.forward()" @prev="feedback.back()" />
    </div>

    <!-- 反馈详情与复核抽屉 -->
    <Drawer :open="!!picked" :title="picked ? `反馈 ${picked.id.slice(0, 8)}` : ''" kicker="FEEDBACK REVIEW" @close="picked = null">
      <template v-if="picked">
        <p class="mb-8 border-l-2 border-ink-line py-1 pl-4 text-[12.5px] leading-relaxed text-ink-2">
          复核通过仅代表样本结论已由第二人核实，不会自动触发模型在线重训；离线重训须经独立数据集治理与校验流程。
        </p>
        <dl class="border-t border-ink">
          <div v-for="[k, v] in [
            ['反馈 ID', picked.id],
            ['标注结论', `${guardFeedbackLabel[picked.label] ?? picked.label}（${picked.label}）`],
            ['复核状态', guardFeedbackStatusLabel[picked.status] ?? picked.status],
            ['关联观察', picked.observationId],
            ['资产', assetLabel(picked.assetId)],
            ['证据引用', picked.evidenceRef],
            ['复核意见', picked.reviewReason ?? '—'],
            ['修订版本', `r${picked.revision}`],
            ['提交时间', fmtTime(picked.createdAt)],
          ]" :key="k" class="grid grid-cols-[7.5rem_1fr] border-b border-ink-hair py-3 text-[13px]">
            <dt class="text-ink-3">{{ k }}</dt>
            <dd class="num break-all">{{ v }}</dd>
          </div>
        </dl>

        <h3 class="label mb-4 mt-10">关联观察快照</h3>
        <LoadState :loading="obs.loading" :error="obs.error" :empty="!obs.data" empty-text="未能读取关联观察详情。">
          <dl v-if="obs.data" class="border-t border-ink">
            <div v-for="[k, v] in [
              ['流标识', obs.data.flowId],
              ['对端键', obs.data.peerKey ?? '—'],
              ['方向 / 端口', `${obs.data.direction ?? '—'} / ${obs.data.servicePort ?? '—'}`],
              ['Profile', obs.data.profile ?? '—'],
              ['asOf', fmtTime(obs.data.asOf)],
              ['内容哈希', obs.data.contentSha256],
            ]" :key="k" class="grid grid-cols-[7.5rem_1fr] border-b border-ink-hair py-2.5 text-[12.5px]">
              <dt class="text-ink-3">{{ k }}</dt>
              <dd class="num break-all">{{ v }}</dd>
            </div>
          </dl>
        </LoadState>

        <!-- 复核表单：仅 feedback.review、pending 且非本人标注时显示 -->
        <div v-if="canDecidePicked" class="mt-10 border-t border-ink pt-6 space-y-5 text-[13px]">
          <h3 class="label">独立复核决定</h3>
          <label class="block">
            <span class="label">复核结论</span>
            <select v-model="reviewForm.decision" aria-label="复核结论" class="field mt-1">
              <option value="approve">通过（标记为已复核 reviewed）</option>
              <option value="reject">驳回（标记为已驳回 rejected）</option>
            </select>
          </label>
          <label class="block">
            <span class="label">复核理由（必填）</span>
            <textarea v-model="reviewForm.reason" aria-label="复核理由" rows="3" maxlength="1000" class="field mt-1 h-auto resize-none py-2" placeholder="写明核对观察特征与上下文后的复核依据" />
          </label>
          <p v-if="reviewForm.error" role="alert" class="text-[12.5px] text-threat">{{ reviewForm.error }}</p>
        </div>
        <p v-else-if="picked.status === 'pending' && isSelf(picked)" class="mt-10 border-t border-ink pt-4 text-[12.5px] text-ink-3">
          本人标注的反馈须由其他复核人决定（职责分离 S6）。
        </p>
      </template>

      <template v-if="canDecidePicked" #foot>
        <button type="button" class="link text-[13px]" @click="picked = null">取消</button>
        <button type="button" class="act" :disabled="reviewForm.busy || !reviewForm.reason.trim()" @click="submitReview">
          {{ reviewForm.busy ? '提交中…' : '提交复核' }}
        </button>
      </template>
    </Drawer>

    <!-- 新建标注抽屉 -->
    <Drawer :open="creating" title="新建观察标注" kicker="LABEL OBSERVATION" @close="creating = false">
      <div class="space-y-6 text-[13px]">
        <p class="border-l-2 border-signal py-1 pl-4 text-[12.5px] leading-relaxed text-ink-2">
          输入目标观察记录的外部 UUID 并选择标注结论。提交后状态为待复核（pending），须由另一名复核人独立审核。
        </p>
        <label class="block">
          <span class="label">观察记录 UUID</span>
          <input v-model="createForm.observationId" aria-label="观察记录 UUID" class="field num mt-2" placeholder="例如 00000000-0000-4000-8000-000000000001" />
        </label>
        <label class="block">
          <span class="label">标注结论</span>
          <select v-model="createForm.label" aria-label="新建标注结论" class="field mt-2">
            <option v-for="(lbl, k) in guardFeedbackLabel" :key="k" :value="k">{{ lbl }}（{{ k }}）</option>
          </select>
        </label>
        <label class="block">
          <span class="label">证据引用说明</span>
          <textarea v-model="createForm.evidenceRef" aria-label="新建证据引用说明" rows="3" maxlength="1000" class="field mt-2 h-auto resize-none py-2" placeholder="说明标注依据或关联流量摘要" />
        </label>
        <p v-if="createForm.error" role="alert" class="text-[12.5px] text-threat">{{ createForm.error }}</p>
      </div>
      <template #foot>
        <button type="button" class="link text-[13px]" @click="creating = false">取消</button>
        <button type="button" class="act" :disabled="createForm.busy" @click="submitCreate">
          {{ createForm.busy ? '提交中…' : '提交标注' }}
        </button>
      </template>
    </Drawer>
  </div>
</template>
