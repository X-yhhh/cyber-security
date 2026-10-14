<script setup lang="ts">
/**
 * 事件详情（威胁检测 / Events / :id）：单资产安全事件的证据时间线、关联证据组、关联动作与受控写操作。
 *
 * 数据来源（docs/接口设计.md、任务单 B2.4/B2.6/F1）：
 * - GET /api/v2/events/{id}（含 episodeIds、decisionIds、actionable、budgetTargetId、policyId、actionEpisodeId、targetRef、actionableReasonCode）
 * - GET /api/v2/events/{id}/timeline
 * - GET /api/v2/events/{id}/episodes
 * - GET /api/v2/events/{id}/actions（仅在持有 action.read 时请求）
 * - GET /api/v2/assignable-users?assetId=<guardAssetId>（仅在持有 event.manage 时请求）
 *
 * 写操作与权限门控（权限设计 §8）：
 * - 状态迁移（event.manage）：POST /api/v2/events/{id}/transitions（{expectedRevision, to, reason}，带 If-Match）
 * - 指派负责人（event.manage）：PUT /api/v2/events/{id}/assignee（{userId, reason?}，带 If-Match）
 * - 追加研判记录（event.manage）：POST /api/v2/events/{id}/notes（{note}）
 * - 发起人工处置申请（action.request）：POST /api/v2/actions（{episodeId, targetRef, policyId, reason}），
 *   只引用已登记的稳定预算目标与证据迹，不提供 IP / 端口 / 命令输入；不可申请时灰显并写出后端原因码。
 * - 样本标注反馈（feedback.label）：POST /api/v2/feedback（{observationId, label, evidenceRef}）。
 */
import { computed, reactive, ref, watch } from 'vue'
import { RouterLink, useRoute } from 'vue-router'
import { ArrowLeft } from 'lucide-vue-next'
import Tag from '@/components/Tag.vue'
import Drawer from '@/components/Drawer.vue'
import LoadState from '@/components/LoadState.vue'
import { ApiError } from '@/api/client'
import { detectApi } from '@/api/v2/detect'
import { can, session } from '@/api/session'
import { errText, optional } from '@/composables/load'
import { toast } from '@/composables/toast'
import {
  eventStatusLabel, eventTransitions, fmtTime, guardActionableReasonLabel,
  guardFamilyLabel, guardFeedbackLabel, guardSourceLabel, guardTimelineTypeLabel, severityLabel,
  type EventStatus, type GuardAction, type GuardAssignableUser, type GuardEpisode,
  type GuardEpisodeEvidence, type GuardGuardEvent, type GuardTimelineEntry,
} from '@/api/types'
import { actionStateTone, eventTone, severityTone } from '@/data/tones'

const props = defineProps<{ id?: string }>()
const route = useRoute()
const eventId = computed(() => props.id || String(route.params.id ?? ''))

const ev = ref<GuardGuardEvent | null>(null)
const timeline = ref<GuardTimelineEntry[]>([])
const episodes = ref<GuardEpisode[]>([])
const actions = ref<GuardAction[]>([])
const assignableUsers = ref<GuardAssignableUser[]>([])
const loading = ref(true)
const error = ref('')
const notFound = ref(false)
const busy = ref(false)

async function reload() {
  if (!eventId.value) return
  loading.value = true
  error.value = ''
  notFound.value = false
  try {
    const [detail, tl, eps, acts] = await Promise.all([
      detectApi.getEvent(eventId.value),
      detectApi.listEventTimeline(eventId.value),
      detectApi.listEventEpisodes(eventId.value),
      can('action.read')
        ? optional(detectApi.listEventActions(eventId.value), { items: [] })
        : Promise.resolve({ items: [] as GuardAction[] }),
    ])
    ev.value = detail
    timeline.value = [...tl.items].sort((a, b) => b.occurredAt.localeCompare(a.occurredAt))
    episodes.value = eps.items
    actions.value = acts.items
    if (can('event.manage') && detail.guardAssetId) {
      const page = await optional(
        detectApi.listAssignableUsers(detail.guardAssetId),
        { asOf: '', items: [], nextCursor: null },
      )
      assignableUsers.value = page.items
    } else {
      assignableUsers.value = []
    }
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) notFound.value = true
    else error.value = errText(e)
  } finally {
    loading.value = false
  }
}

watch(eventId, () => { void reload() }, { immediate: true })

const canManage = computed(() => can('event.manage'))
const canRequestAction = computed(() => can('action.request'))
const canReadAction = computed(() => can('action.read'))
const canLabel = computed(() => can('feedback.label'))

const nextStatuses = computed<EventStatus[]>(() => {
  const s = ev.value?.status as EventStatus | undefined
  return s && eventTransitions[s] ? eventTransitions[s] : []
})

const actionableReasonText = computed(() => {
  if (!ev.value) return ''
  if (ev.value.actionable) return '满足人工处置申请条件，绑定最新阻断候选目标。'
  const code = ev.value.actionableReasonCode
  if (!code) return '当前事件暂无可执行的阻断候选目标。'
  return `${guardActionableReasonLabel[code] ?? code}（${code}）`
})

const who = (assigneeId: string | null | undefined) => {
  if (!assigneeId) return '未指派'
  const hit = assignableUsers.value.find((u) => u.userKey === assigneeId || u.username === assigneeId)
  if (hit) return `${hit.displayName}（${hit.userKey}）`
  return assigneeId
}

/* 状态迁移 */
const pendingTo = ref<EventStatus | null>(null)
const transitionReason = ref('')
const opError = ref('')

async function submitTransition() {
  if (!ev.value || !pendingTo.value || !transitionReason.value.trim()) return
  busy.value = true
  opError.value = ''
  try {
    await detectApi.transitionEvent(
      ev.value.id,
      ev.value.revision,
      pendingTo.value,
      transitionReason.value.trim(),
    )
    pendingTo.value = null
    transitionReason.value = ''
    toast('事件状态已更新')
    await reload()
  } catch (e) {
    opError.value = errText(e)
  } finally {
    busy.value = false
  }
}

/* 指派负责人 */
const assigning = ref(false)
const assignForm = reactive({ userId: '', reason: '', error: '' })

function openAssign() {
  if (!ev.value) return
  assignForm.userId = ev.value.assigneeId ?? (assignableUsers.value[0]?.userKey ?? '')
  assignForm.reason = ''
  assignForm.error = ''
  assigning.value = true
}

async function submitAssign(unassign = false) {
  if (!ev.value) return
  busy.value = true
  assignForm.error = ''
  try {
    await detectApi.assignEvent(
      ev.value.id,
      ev.value.revision,
      unassign ? null : (assignForm.userId || null),
      assignForm.reason.trim() || undefined,
    )
    assigning.value = false
    toast(unassign ? '已取消指派' : '负责人已更新')
    await reload()
  } catch (e) {
    assignForm.error = errText(e)
  } finally {
    busy.value = false
  }
}

/* 追加研判记录 */
const noteText = ref('')
async function submitNote() {
  if (!ev.value || !noteText.value.trim()) return
  busy.value = true
  opError.value = ''
  try {
    await detectApi.addEventNote(ev.value.id, noteText.value.trim())
    noteText.value = ''
    toast('已追加研判记录')
    await reload()
  } catch (e) {
    opError.value = errText(e)
  } finally {
    busy.value = false
  }
}

/* 人工处置申请（只读引用绑定目标，不提供 IP/端口/命令输入） */
const askingAction = ref(false)
const actionForm = reactive({ reason: '', error: '' })

function openActionDrawer() {
  if (!ev.value?.actionable) return
  actionForm.reason = ''
  actionForm.error = ''
  askingAction.value = true
}

async function submitActionRequest() {
  if (!ev.value || !ev.value.actionable || !ev.value.actionEpisodeId || !ev.value.targetRef || !ev.value.policyId) return
  if (!actionForm.reason.trim()) {
    actionForm.error = '请填写申请理由'
    return
  }
  busy.value = true
  actionForm.error = ''
  try {
    await detectApi.requestManualAction(
      ev.value.actionEpisodeId,
      ev.value.targetRef,
      ev.value.policyId,
      actionForm.reason.trim(),
    )
    askingAction.value = false
    toast('已提交人工处置申请，等待独立审批（S5）')
    await reload()
  } catch (e) {
    actionForm.error = errText(e)
  } finally {
    busy.value = false
  }
}

/* 证据迹详情与样本标注 */
const pickedEpisode = ref<GuardEpisode | null>(null)
const epEvidence = ref<{ loading: boolean; error: string; items: GuardEpisodeEvidence[] }>({ loading: false, error: '', items: [] })
const labelForm = reactive({ open: false, observationId: '', label: 'attack', evidenceRef: '', busy: false, error: '', done: '' })

watch(pickedEpisode, async (ep) => {
  labelForm.open = false
  if (!ep) { epEvidence.value = { loading: false, error: '', items: [] }; return }
  epEvidence.value = { loading: true, error: '', items: [] }
  try {
    const r = await detectApi.listEpisodeEvidence(ep.id)
    epEvidence.value = { loading: false, error: '', items: r.items }
  } catch (e) {
    epEvidence.value = { loading: false, error: errText(e), items: [] }
  }
})

function openLabelFor(obsId: string, refHint: string) {
  labelForm.observationId = obsId
  labelForm.label = 'attack'
  labelForm.evidenceRef = refHint
  labelForm.error = ''
  labelForm.done = ''
  labelForm.open = true
}

async function submitLabel() {
  if (!labelForm.observationId || !labelForm.evidenceRef.trim()) {
    labelForm.error = '请填写证据引用说明'
    return
  }
  labelForm.busy = true
  labelForm.error = ''
  labelForm.done = ''
  try {
    await detectApi.createFeedback(
      labelForm.observationId,
      labelForm.label,
      labelForm.evidenceRef.trim(),
    )
    labelForm.done = '已提交标注（待复核，不自动进入在线训练）'
    toast('标注已提交，等待独立复核')
  } catch (e) {
    labelForm.error = errText(e)
  } finally {
    labelForm.busy = false
  }
}

const mark = (t: string) =>
  t.includes('decision') ? 'bg-threat' : t.includes('transition') ? 'bg-ink' : t.includes('assignment') ? 'bg-signal' : 'bg-ink-4'
</script>

<template>
  <div>
    <RouterLink to="/console/detect/events" class="link mb-10 text-[13px] text-ink-3">
      <ArrowLeft :size="14" :stroke-width="1.5" /> 事件研判
    </RouterLink>

    <LoadState :loading="loading" :error="error && !notFound ? error : ''">
      <div v-if="ev">
        <header class="mb-16 grid gap-10 lg:grid-cols-[1fr_auto] lg:items-end">
          <div>
            <p class="label mb-5 flex flex-wrap items-center gap-4">
              <span class="num">{{ ev.eventKey }}</span>
              <Tag :tone="severityTone[ev.severity]" :label="severityLabel[ev.severity] ?? ev.severity" />
              <Tag :tone="eventTone[ev.status]" :label="eventStatusLabel[ev.status as EventStatus] ?? ev.status" />
              <span class="num text-ink-4">r{{ ev.revision }}</span>
            </p>
            <h1 class="max-w-3xl text-[2rem] font-light leading-snug tracking-[-0.02em]">{{ ev.title }}</h1>
            <p class="num mt-5 flex flex-wrap gap-x-8 gap-y-1 text-[12.5px] text-ink-3">
              <span>资产 {{ ev.guardAssetId ?? '—' }}</span>
              <span>类别 {{ guardFamilyLabel[ev.category] ?? ev.category }}</span>
              <span>处理人 {{ who(ev.assigneeId) }}</span>
              <span>首次 {{ fmtTime(ev.firstSeenAt) }}</span>
              <span>最近 {{ fmtTime(ev.lastSeenAt) }}</span>
            </p>
          </div>

          <div class="flex flex-wrap items-center gap-6">
            <template v-if="canManage">
              <button v-for="to in nextStatuses" :key="to" type="button" class="link text-[13px]"
                @click="pendingTo = to; opError = ''">
                标记为{{ eventStatusLabel[to] }}
              </button>
              <button v-if="ev.status !== 'closed'" type="button" class="link text-[13px]" @click="openAssign">
                {{ ev.assigneeId ? '更换处理人' : '指派' }}
              </button>
            </template>
            <button v-if="canRequestAction" type="button" class="act" :disabled="!ev.actionable || busy"
              :title="actionableReasonText" @click="openActionDrawer">
              申请处置
            </button>
          </div>
        </header>

        <p v-if="opError" role="alert" class="mb-8 border-l-2 border-threat py-1 pl-4 text-[13px] text-threat">{{ opError }}</p>

        <!-- 状态迁移确认栏 -->
        <form v-if="canManage && pendingTo" class="mb-14 flex flex-wrap items-end gap-6 border-l-2 border-signal pl-6" @submit.prevent="submitTransition">
          <label class="min-w-[16rem] flex-1">
            <span class="label">迁移为「{{ eventStatusLabel[pendingTo] }}」的理由</span>
            <input v-model="transitionReason" aria-label="状态迁移理由" class="field mt-2" maxlength="1000" placeholder="说明研判依据；迁往已遏制需存在已生效动作" />
          </label>
          <button type="button" class="link text-[13px] text-ink-3" @click="pendingTo = null">取消</button>
          <button type="submit" class="act-ghost" :disabled="busy || !transitionReason.trim()">确认迁移</button>
        </form>

        <div class="grid gap-20 lg:grid-cols-[1.35fr_1fr]">
          <!-- 左栏：时间线、关联证据组、关联动作 -->
          <section>
            <h2 class="mb-8 flex items-baseline justify-between text-[15px]">
              <span>证据与研判时间线<span class="num ml-2 text-[11px] text-ink-4">{{ timeline.length }}</span></span>
              <span class="label">最新在前</span>
            </h2>
            <ol class="relative ml-1 border-l border-ink-hair">
              <li v-for="t in timeline" :key="t.id" class="relative pb-9 pl-8">
                <span class="absolute -left-[3.5px] top-[7px] h-[6px] w-[6px]" :class="mark(t.entryType)" />
                <p class="num flex flex-wrap gap-4 text-[11.5px] text-ink-3">
                  <span>{{ fmtTime(t.occurredAt) }}</span>
                  <span class="label !text-[10px]">{{ guardTimelineTypeLabel[t.entryType] ?? t.entryType }}</span>
                  <span>{{ t.actorType }}{{ t.actorId ? ' · ' + t.actorId : '' }}</span>
                </p>
                <p class="mt-2 text-[14px] leading-relaxed">{{ t.summary }}</p>
              </li>
              <li v-if="!timeline.length" class="pb-9 pl-8 text-[13px] text-ink-3">暂无时间线记录。</li>
            </ol>

            <form v-if="canManage" class="mt-2 flex items-end gap-6 pl-8" @submit.prevent="submitNote">
              <label class="flex-1">
                <span class="label">追加研判记录</span>
                <input v-model="noteText" aria-label="追加研判记录" class="field mt-2" maxlength="1000" placeholder="写下证据核实与研判依据" />
              </label>
              <button type="submit" class="link text-[13px]" :disabled="busy || !noteText.trim()">添加记录</button>
            </form>

            <!-- 关联证据组 -->
            <h2 class="mb-6 mt-20 flex items-baseline justify-between text-[15px]">
              <span>关联证据组<span class="num ml-2 text-[11px] text-ink-4">{{ episodes.length }}</span></span>
              <span class="label">点击查看证据明细{{ canLabel ? '与标注' : '' }}</span>
            </h2>
            <table class="table">
              <thead>
                <tr><th>桶起点</th><th>对端键</th><th>方向 / 端口</th><th>类别 / 来源</th><th class="text-right">修订</th></tr>
              </thead>
              <tbody>
                <tr v-for="ep in episodes" :key="ep.id" class="row-link" tabindex="0"
                  @click="pickedEpisode = ep" @keydown.enter="pickedEpisode = ep">
                  <td class="num text-ink-3">{{ fmtTime(ep.bucketStart) }}</td>
                  <td>
                    <span class="num block">{{ ep.peerKey }}</span>
                    <span class="num text-[12px] text-ink-3">{{ ep.id.slice(0, 8) }}</span>
                  </td>
                  <td class="num text-ink-2">{{ ep.direction }} / {{ ep.servicePort }}</td>
                  <td>
                    <span class="block text-ink-2">{{ ep.family ? (guardFamilyLabel[ep.family] ?? ep.family) : '—' }}</span>
                    <span class="num text-[12px] text-ink-3">{{ guardSourceLabel(ep.source, ep.ruleId) }}</span>
                  </td>
                  <td class="num text-right text-ink-3">r{{ ep.revision }}</td>
                </tr>
                <tr v-if="!episodes.length"><td colspan="5" class="py-8 text-center text-ink-3">暂无关联证据组。</td></tr>
              </tbody>
            </table>

            <!-- 关联处置动作（仅在持有 action.read 时显示） -->
            <template v-if="canReadAction">
              <h2 class="mb-6 mt-20 flex items-baseline justify-between text-[15px]">
                <span>关联处置动作<span class="num ml-2 text-[11px] text-ink-4">{{ actions.length }}</span></span>
                <span class="label">期望状态与观测状态分列</span>
              </h2>
              <table class="table">
                <thead>
                  <tr><th>动作</th><th>模式</th><th>期望状态</th><th>观测状态</th><th class="text-right">租约截止</th></tr>
                </thead>
                <tbody>
                  <tr v-for="a in actions" :key="a.id">
                    <td>
                      <span class="num block">{{ a.id.slice(0, 8) }}</span>
                      <span class="num text-[12px] text-ink-3">r{{ a.revision }}</span>
                    </td>
                    <td class="num text-ink-2">{{ a.mode }}</td>
                    <td><Tag :tone="actionStateTone[a.desiredState]" :label="a.desiredState" /></td>
                    <td><Tag :tone="actionStateTone[a.observedState]" :label="a.observedState" /></td>
                    <td class="num text-right text-ink-3">{{ fmtTime(a.blockUntil) }}</td>
                  </tr>
                  <tr v-if="!actions.length"><td colspan="5" class="py-8 text-center text-ink-3">该事件尚未产生处置动作。</td></tr>
                </tbody>
              </table>
            </template>
          </section>

          <!-- 右栏：处置资格与绑定目标、事件元数据 -->
          <aside>
            <h2 class="mb-6 text-[15px]">处置资格与绑定目标</h2>
            <p class="mb-6 border-l-2 py-1 pl-4 text-[12.5px] leading-relaxed text-ink-2" :class="ev.actionable ? 'border-ok' : 'border-ink-line'">
              {{ actionableReasonText }}
            </p>
            <dl class="border-t border-ink">
              <div v-for="[k, v] in [
                ['可否申请处置', ev.actionable ? '可申请（存在阻断候选与激活授权）' : '不可申请'],
                ['不可申请原因码', ev.actionableReasonCode ?? '—'],
                ['候选证据迹', ev.actionEpisodeId ?? '—'],
                ['稳定预算目标', ev.budgetTargetId ?? '—'],
                ['目标引用 targetRef', ev.targetRef ?? '—'],
                ['决策策略 policyId', ev.policyId ?? '—'],
                ['关联判定数', String(ev.decisionIds?.length ?? 0)],
              ]" :key="k" class="grid grid-cols-[8.5rem_1fr] border-b border-ink-hair py-2.5 text-[12.5px]">
                <dt class="text-ink-3">{{ k }}</dt>
                <dd class="num break-all">{{ v }}</dd>
              </div>
            </dl>
            <p class="mt-4 text-[12px] leading-relaxed text-ink-3">
              人工处置申请只引用已登记的证据迹与稳定预算目标，不接受手工输入 IP、端口或命令；提交后须由另一名审批人独立批准（职责分离 S5）。
            </p>

            <h3 class="label mb-4 mt-12">事件属性</h3>
            <dl class="border-t border-ink">
              <div v-for="[k, v] in [
                ['事件 ID', ev.id],
                ['事件键', ev.eventKey],
                ['关联资产', ev.guardAssetId ?? '—'],
                ['攻击类别', guardFamilyLabel[ev.category] ?? ev.category],
                ['当前状态', eventStatusLabel[ev.status as EventStatus] ?? ev.status],
                ['当前处理人', who(ev.assigneeId)],
                ['修订版本', `r${ev.revision}`],
                ['首次发现', fmtTime(ev.firstSeenAt)],
                ['最近发现', fmtTime(ev.lastSeenAt)],
                ['创建时间', fmtTime(ev.createdAt)],
                ['结案时间', fmtTime(ev.closedAt)],
              ]" :key="k" class="grid grid-cols-[7.5rem_1fr] border-b border-ink-hair py-2.5 text-[12.5px]">
                <dt class="text-ink-3">{{ k }}</dt>
                <dd class="num break-all">{{ v }}</dd>
              </div>
            </dl>
          </aside>
        </div>

        <!-- 指派负责人抽屉 -->
        <Drawer :open="assigning" title="指派负责人" :kicker="ev.eventKey" @close="assigning = false">
          <div class="space-y-6">
            <p class="text-[13px] text-ink-2">当前处理人：{{ who(ev.assigneeId) }}</p>
            <label class="block">
              <span class="label">可指派人员（按本资产 event.manage 范围过滤）</span>
              <select v-model="assignForm.userId" aria-label="可指派人员" class="field mt-2">
                <option value="">— 请选择负责人 —</option>
                <option v-for="u in assignableUsers" :key="u.userKey" :value="u.userKey">
                  {{ u.displayName }} · {{ u.username }}（{{ u.userKey }}）
                </option>
              </select>
            </label>
            <button v-if="session.user && assignableUsers.some((u) => u.username === session.user?.username)"
              type="button" class="link text-[12.5px]"
              @click="assignForm.userId = assignableUsers.find((u) => u.username === session.user?.username)?.userKey ?? ''">
              指派给我
            </button>
            <label class="block">
              <span class="label">指派说明（可选）</span>
              <textarea v-model="assignForm.reason" aria-label="指派说明" rows="3" maxlength="1000" class="field mt-2 h-auto resize-none py-2" placeholder="写入事件时间线与审计日志" />
            </label>
            <p v-if="assignForm.error" role="alert" class="text-[12.5px] text-threat">{{ assignForm.error }}</p>
            <p class="text-[12px] leading-relaxed text-ink-3">候选列表由 GET /api/v2/assignable-users 提供，仅含对该资产拥有 event.manage 的活跃账号。</p>
          </div>
          <template #foot>
            <button v-if="ev.assigneeId" type="button" class="link text-[13px]" :disabled="busy" @click="submitAssign(true)">取消指派</button>
            <button type="button" class="link text-[13px]" @click="assigning = false">取消</button>
            <button type="button" class="act" :disabled="busy || !assignForm.userId" @click="submitAssign(false)">确认指派</button>
          </template>
        </Drawer>

        <!-- 发起人工处置申请抽屉 -->
        <Drawer :open="askingAction" title="发起人工处置申请" :kicker="ev.eventKey" @close="askingAction = false">
          <div class="space-y-6">
            <p class="border-l-2 border-signal py-1 pl-4 text-[12.5px] leading-relaxed text-ink-2">
              处置申请严格绑定后端已核验的阻断候选证据迹与稳定预算目标，不提供任意 IP、端口或命令输入。提交后进入 pending 状态，须由另一名审批人批准（S5）。
            </p>
            <dl class="border-t border-ink">
              <div v-for="[k, v] in [
                ['绑定证据迹 episodeId', ev.actionEpisodeId ?? '—'],
                ['目标引用 targetRef', ev.targetRef ?? '—'],
                ['稳定预算目标', ev.budgetTargetId ?? '—'],
                ['决策策略 policyId', ev.policyId ?? '—'],
              ]" :key="k" class="grid grid-cols-[9rem_1fr] border-b border-ink-hair py-3 text-[13px]">
                <dt class="text-ink-3">{{ k }}</dt>
                <dd class="num break-all">{{ v }}</dd>
              </div>
            </dl>
            <label class="block">
              <span class="label">申请理由（必填）</span>
              <textarea v-model="actionForm.reason" aria-label="申请理由" rows="3" maxlength="1000" class="field mt-2 h-auto resize-none py-2" placeholder="说明触发人工阻断的研判依据" />
            </label>
            <p v-if="actionForm.error" role="alert" class="text-[12.5px] text-threat">{{ actionForm.error }}</p>
          </div>
          <template #foot>
            <button type="button" class="link text-[13px]" @click="askingAction = false">取消</button>
            <button type="button" class="act" :disabled="busy || !actionForm.reason.trim()" @click="submitActionRequest">提交处置申请</button>
          </template>
        </Drawer>

        <!-- 证据迹详情与标注抽屉 -->
        <Drawer :open="!!pickedEpisode" :title="pickedEpisode ? `证据迹 ${pickedEpisode.id.slice(0, 8)}` : ''" kicker="EVIDENCE EPISODE" @close="pickedEpisode = null">
          <template v-if="pickedEpisode">
            <dl class="border-t border-ink">
              <div v-for="[k, v] in [
                ['对端键', pickedEpisode.peerKey],
                ['方向 / 端口', `${pickedEpisode.direction} / ${pickedEpisode.servicePort}`],
                ['类别', pickedEpisode.family ? (guardFamilyLabel[pickedEpisode.family] ?? pickedEpisode.family) : '—'],
                ['来源', guardSourceLabel(pickedEpisode.source, pickedEpisode.ruleId)],
                ['桶起点', fmtTime(pickedEpisode.bucketStart)],
                ['修订', `r${pickedEpisode.revision}`],
              ]" :key="k" class="grid grid-cols-[7rem_1fr] border-b border-ink-hair py-2.5 text-[13px]">
                <dt class="text-ink-3">{{ k }}</dt>
                <dd class="num break-all">{{ v }}</dd>
              </div>
            </dl>
            <h3 class="label mb-4 mt-8">证据明细</h3>
            <LoadState :loading="epEvidence.loading" :error="epEvidence.error" :empty="!epEvidence.items.length" empty-text="该证据迹暂无明细。">
              <ul class="border-t border-ink">
                <li v-for="x in epEvidence.items" :key="x.id" class="grid grid-cols-[5.5rem_1fr_auto] items-center gap-3 border-b border-ink-hair py-2.5 text-[12.5px]">
                  <span class="num text-ink-3">#{{ x.score == null ? '—' : Number(x.score).toFixed(3) }}</span>
                  <span>
                    <span class="num block">观察 {{ x.observationId.slice(0, 8) }}</span>
                    <span class="num text-[11.5px] text-ink-4">{{ guardSourceLabel(x.source, x.ruleId) }} · asOf {{ fmtTime(x.asOf) }}</span>
                  </span>
                  <button v-if="canLabel" type="button" class="link text-[12px]" @click="openLabelFor(x.observationId, `event:${ev.eventKey}`)">标注</button>
                </li>
              </ul>
            </LoadState>
            <div v-if="canLabel && labelForm.open" class="mt-6 border-t border-ink pt-4 space-y-4 text-[13px]">
              <p class="num text-[12px] text-ink-3">观察 {{ labelForm.observationId }}</p>
              <label class="block">
                <span class="label">标注结论</span>
                <select v-model="labelForm.label" aria-label="标注结论" class="field mt-1">
                  <option v-for="(lbl, k) in guardFeedbackLabel" :key="k" :value="k">{{ lbl }}（{{ k }}）</option>
                </select>
              </label>
              <label class="block">
                <span class="label">证据引用说明</span>
                <input v-model="labelForm.evidenceRef" aria-label="证据引用说明" class="field mt-1" />
              </label>
              <p v-if="labelForm.error" role="alert" class="text-[12.5px] text-threat">{{ labelForm.error }}</p>
              <p v-if="labelForm.done" class="text-[12.5px] text-ok">{{ labelForm.done }}</p>
              <div class="flex items-center gap-4">
                <button type="button" class="act" :disabled="labelForm.busy" @click="submitLabel">{{ labelForm.busy ? '提交中…' : '提交标注' }}</button>
                <button type="button" class="link text-[12.5px]" @click="labelForm.open = false">取消</button>
              </div>
            </div>
          </template>
        </Drawer>
      </div>

      <div v-else-if="notFound" class="py-32 text-center">
        <p class="label">404</p>
        <p class="mt-4 text-ink-3">事件不存在，或不在你的授权范围内。</p>
        <RouterLink to="/console/detect/events" class="link mt-8 text-[13px]">返回事件研判</RouterLink>
      </div>
    </LoadState>
  </div>
</template>
