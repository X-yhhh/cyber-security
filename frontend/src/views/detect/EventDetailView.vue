<script setup lang="ts">
import { useActionError } from '@/composables/actionError'
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
 *   只引用已登记的稳定预算目标与证据组，不提供 IP / 端口 / 命令输入；不可申请时灰显并写出后端原因码。
 * - 样本标注反馈（feedback.label）：POST /api/v2/feedback（{observationId, label, evidenceRef}）。
 */
import { computed, reactive, ref, watch } from 'vue'
import { RouterLink, useRoute } from 'vue-router'
import { ArrowLeft, ArrowRight, Check, ChevronDown, History, Layers, ShieldAlert, ShieldBan, ShieldCheck, ShieldOff } from 'lucide-vue-next'
import Panel from '@/components/Panel.vue'
import IdText from '@/components/IdText.vue'
import Tag from '@/components/Tag.vue'
import Drawer from '@/components/Drawer.vue'
import LoadState from '@/components/LoadState.vue'
import LabelForm from './LabelForm.vue'
import { ApiError } from '@/api/client'
import { assetName, detectApi, type NamedAsset } from '@/api/v2/detect'
import { can, session } from '@/api/session'
import { errText, optional } from '@/composables/load'
import { toast } from '@/composables/toast'
import { useCrumbLabel } from '@/composables/crumb'
import {
  eventStatusLabel, eventTransitions, fmtTime, guardActionableReasonLabel, guardActionModeLabel, guardActionStateLabel,
  guardFamilyLabel, guardSourceLabel, guardTimelineTypeLabel, severityLabel,
  type EventStatus, type GuardAction, type GuardAssignableUser, type GuardEpisode,
  type GuardEpisodeEvidence, type GuardGuardEvent, type GuardTimelineEntry,
} from '@/api/types'
import { actionStateTone, eventTone, severityTone } from '@/data/tones'

const props = defineProps<{ id?: string }>()
const route = useRoute()
const eventId = computed(() => props.id || String(route.params.id ?? ''))

const ev = ref<GuardGuardEvent | null>(null)
useCrumbLabel(computed(() => ev.value?.title))
const timeline = ref<GuardTimelineEntry[]>([])
const episodes = ref<GuardEpisode[]>([])
const actions = ref<GuardAction[]>([])
const assignableUsers = ref<GuardAssignableUser[]>([])
/** 关联资产只显示名称（前端设计文档第 3.5、10.5 节）；无 resource.read 或读取失败时退回截断 ID。 */
const asset = ref<NamedAsset | null>(null)
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
    asset.value = detail.guardAssetId && can('resource.read') ? await optional(detectApi.getAsset(detail.guardAssetId), null) : null
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
const opError = useActionError()

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
const assignForm = reactive({ userId: '', reason: '', error: useActionError() })

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
const actionForm = reactive({ reason: '', error: useActionError() })

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
    toast('已提交人工处置申请，等待他人审批')
    await reload()
  } catch (e) {
    actionForm.error = errText(e)
  } finally {
    busy.value = false
  }
}

/* 证据组详情与样本标注 */
const pickedEpisode = ref<GuardEpisode | null>(null)
const epEvidence = ref<{ loading: boolean; error: string; items: GuardEpisodeEvidence[] }>({ loading: false, error: '', items: [] })
/** 当前要标注的观察；切换证据组时清空。 */
const labelTarget = ref('')

watch(pickedEpisode, async (ep) => {
  labelTarget.value = ''
  if (!ep) { epEvidence.value = { loading: false, error: '', items: [] }; return }
  epEvidence.value = { loading: true, error: '', items: [] }
  try {
    const r = await detectApi.listEpisodeEvidence(ep.id)
    epEvidence.value = { loading: false, error: '', items: r.items }
  } catch (e) {
    epEvidence.value = { loading: false, error: errText(e), items: [] }
  }
})

/**
 * 时间线合并（前端设计文档第 3.5 节第 6 条）：同类型、同主体、5 分钟内的连续系统记录合并为一条，右侧显示 ×N，可展开逐条查看。
 * 人工记录（迁移、指派、研判记录）逐条保留。
 */
const MERGE_MS = 5 * 60_000
interface TimelineGroup { head: GuardTimelineEntry; items: GuardTimelineEntry[] }
const timelineGroups = computed(() => {
  const out: TimelineGroup[] = []
  for (const t of timeline.value) {
    const g = out[out.length - 1]
    const same = g && t.actorType === 'system' && g.head.actorType === 'system' && g.head.entryType === t.entryType
      && (g.head.actorId ?? '') === (t.actorId ?? '') && Date.parse(g.head.occurredAt) - Date.parse(t.occurredAt) <= MERGE_MS
    if (same) g.items.push(t)
    else out.push({ head: t, items: [t] })
  }
  return out
})
const expanded = ref(new Set<string>())
function toggle(id: string) {
  const next = new Set(expanded.value)
  if (next.has(id)) next.delete(id)
  else next.add(id)
  expanded.value = next
}
const actorText = (t: GuardTimelineEntry) => (t.actorType === 'system' ? '系统' : t.actorId ?? '人工')

const mark = (t: string) =>
  t.includes('decision') ? 'bg-threat' : t.includes('transition') ? 'bg-ink' : t.includes('assignment') ? 'bg-signal' : 'bg-ink-4'

/*
 * 版式（视觉基线 v2，事件详情）：页头是“案卷”面板——事件键、标题、关键属性与操作；其下为生命周期进度条
 * （待处理 → 研判中 → 已遏制 → 已解决，误报与已关闭显示为旁路终态）；主栏为时间线、证据组与动作，侧栏为处置资格，
 * 标识符类属性收进“技术细节”折叠区。
 */
const FLOW: EventStatus[] = ['open', 'investigating', 'contained', 'resolved']
const flowIndex = computed(() => (ev.value ? FLOW.indexOf(ev.value.status as EventStatus) : -1))
</script>

<template>
  <div>
    <RouterLink to="/console/detect/events" class="link mb-5 text-[13px] text-ink-3">
      <ArrowLeft :size="14" :stroke-width="1.5" /> 事件研判
    </RouterLink>

    <LoadState :loading="loading" :error="error && !notFound ? error : ''">
      <div v-if="ev">
        <!-- 案卷页头 -->
        <header class="panel mb-4 overflow-hidden">
          <div class="flex flex-col gap-5 p-5 lg:flex-row lg:items-start lg:justify-between">
            <div class="flex min-w-0 gap-4">
              <span class="inline-flex h-11 w-11 shrink-0 items-center justify-center rounded border" :class="ev.severity === 'high' || ev.severity === 'critical' ? 'border-threat/40 bg-threat-soft text-threat' : ev.severity === 'medium' ? 'border-warn/40 bg-warn-soft text-warn' : 'border-ink-line text-ink-2'" aria-hidden="true">
                <ShieldAlert :size="20" :stroke-width="1.5" />
              </span>
              <div class="min-w-0">
                <p class="flex flex-wrap items-center gap-2.5 text-[12px] text-ink-3">
                  <IdText :value="ev.eventKey" :length="20" />
                  <Tag :tone="severityTone[ev.severity]" :label="`严重度 ${severityLabel[ev.severity] ?? ev.severity}`" />
                  <Tag pill :tone="eventTone[ev.status]" :label="eventStatusLabel[ev.status as EventStatus] ?? ev.status" />
                </p>
                <h1 class="mt-1.5 text-[1.5rem] font-medium leading-snug tracking-[-0.01em] text-ink">{{ ev.title }}</h1>
              </div>
            </div>
            <div class="flex shrink-0 flex-wrap items-center gap-2.5">
              <template v-if="canManage">
                <button v-for="to in nextStatuses" :key="to" type="button" class="act-ghost"
                  @click="pendingTo = to; opError = ''">
                  标记为{{ eventStatusLabel[to] }}
                </button>
                <button v-if="ev.status !== 'closed'" type="button" class="act-ghost" @click="openAssign">
                  {{ ev.assigneeId ? '更换处理人' : '指派' }}
                </button>
              </template>
              <button v-if="canRequestAction" type="button" class="act" :disabled="!ev.actionable || busy"
                :title="actionableReasonText" @click="openActionDrawer">
                申请处置
              </button>
            </div>
          </div>
          <dl class="grid grid-cols-2 border-t border-ink-hair text-[12.5px] md:grid-cols-3 xl:grid-cols-5">
            <div v-for="([k, v], i) in [
              ['资产', asset ? assetName(asset) : '—'],
              ['类别', guardFamilyLabel[ev.category] ?? ev.category],
              ['处理人', who(ev.assigneeId)],
              ['首次发现', fmtTime(ev.firstSeenAt)],
              ['最近发现', fmtTime(ev.lastSeenAt)],
            ]" :key="k" class="min-w-0 px-5 py-3" :class="i ? 'xl:border-l xl:border-ink-hair' : ''">
              <dt class="text-ink-3">{{ k }}</dt>
              <dd class="mt-0.5 text-ink" :class="k.includes('发现') ? 'num whitespace-nowrap' : ''">
                <IdText v-if="k === '资产' && !asset && ev.guardAssetId" :value="ev.guardAssetId" />
                <template v-else>{{ v }}</template>
              </dd>
            </div>
          </dl>
        </header>

        <!-- 生命周期进度 -->
        <ol class="mb-5 grid grid-cols-2 gap-2 md:grid-cols-[repeat(4,minmax(0,1fr))_auto]" aria-label="事件生命周期">
          <li v-for="(st, i) in FLOW" :key="st" class="flex items-center gap-2.5 rounded border px-3.5 py-2.5 text-[13px]"
            :class="ev.status === st ? 'border-ink bg-ink text-paper' : i < flowIndex ? 'border-ink-line text-ink-2' : 'border-ink-hair text-ink-4'">
            <span class="num inline-flex h-5 w-5 items-center justify-center rounded-full border text-[11px]" :class="ev.status === st ? 'border-paper/40' : i < flowIndex ? 'border-ink-3 bg-ink-3 text-paper' : 'border-ink-line'">
              <Check v-if="i < flowIndex" :size="11" :stroke-width="2" /><template v-else>{{ i + 1 }}</template>
            </span>
            {{ eventStatusLabel[st] }}
          </li>
          <li class="flex items-center rounded border border-dashed px-3.5 py-2.5 text-[13px]" :class="flowIndex < 0 ? 'border-ink text-ink' : 'border-ink-line text-ink-4'">
            {{ flowIndex < 0 ? `当前：${eventStatusLabel[ev.status as EventStatus] ?? ev.status}` : '误报 / 已关闭' }}
          </li>
        </ol>

        <p v-if="opError" role="alert" class="note note-threat mb-4 text-threat">{{ opError }}</p>

        <!-- 状态迁移确认栏 -->
        <form v-if="canManage && pendingTo" class="panel mb-4 flex flex-wrap items-end gap-3 p-4" @submit.prevent="submitTransition">
          <label class="form-field min-w-[16rem] flex-1">
            <span class="label">迁移为「{{ eventStatusLabel[pendingTo] }}」的理由</span>
            <input v-model="transitionReason" aria-label="状态迁移理由" class="field" maxlength="1000" placeholder="说明研判依据" />
            <span v-if="pendingTo === 'contained'" class="text-[12px] text-ink-3">迁往已遏制需要该事件已有生效的处置动作。</span>
          </label>
          <button type="button" class="act-ghost" @click="pendingTo = null">取消</button>
          <button type="submit" class="act" :disabled="busy || !transitionReason.trim()">确认迁移</button>
        </form>

        <div class="grid items-start gap-5 xl:grid-cols-[minmax(0,1fr)_22rem]">
          <!-- 主栏：时间线、关联证据组、关联动作 -->
          <div class="min-w-0 space-y-5">
            <Panel title="证据与研判时间线" :icon="History">
              <template #actions><span class="text-[12px] text-ink-3">{{ timeline.length }} 条 · 最新在前</span></template>
              <ol class="relative ml-1.5 border-l border-ink-hair">
                <li v-for="g in timelineGroups" :key="g.head.id" class="relative pb-5 pl-6 last:pb-1">
                  <span class="absolute -left-[4.5px] top-[6px] h-2 w-2 rounded-full ring-2 ring-paper" :class="mark(g.head.entryType)" />
                  <p class="flex flex-wrap items-center gap-x-3 gap-y-1 text-[12px] text-ink-3">
                    <span class="num">{{ fmtTime(g.head.occurredAt) }}</span>
                    <span class="pill bg-paper-soft text-ink-2">{{ guardTimelineTypeLabel[g.head.entryType] ?? g.head.entryType }}</span>
                    <span>{{ actorText(g.head) }}</span>
                    <button v-if="g.items.length > 1" type="button" class="link ml-auto text-[12px]" :aria-expanded="expanded.has(g.head.id)"
                      :aria-label="`${expanded.has(g.head.id) ? '收起' : '展开'}合并的 ${g.items.length} 条记录`" @click="toggle(g.head.id)">
                      <span class="num">×{{ g.items.length }}</span><ChevronDown :size="13" :stroke-width="1.5" class="transition-transform" :class="expanded.has(g.head.id) ? 'rotate-180' : ''" />
                    </button>
                  </p>
                  <p class="mt-1 text-[13.5px] leading-relaxed text-ink">{{ g.head.summary }}</p>
                  <ul v-if="g.items.length > 1 && expanded.has(g.head.id)" class="mt-2 space-y-1.5 border-l border-ink-hair pl-3 text-[12.5px]">
                    <li v-for="t in g.items.slice(1)" :key="t.id" class="flex gap-3"><span class="num shrink-0 text-ink-3">{{ fmtTime(t.occurredAt) }}</span><span class="text-ink-2">{{ t.summary }}</span></li>
                  </ul>
                </li>
                <li v-if="!timeline.length" class="pb-2 pl-6 text-[13px] text-ink-3">暂无时间线记录。</li>
              </ol>
              <form v-if="canManage" class="mt-4 flex items-end gap-3 border-t border-ink-hair pt-4" @submit.prevent="submitNote">
                <label class="form-field flex-1">
                  <span class="label">追加研判记录</span>
                  <input v-model="noteText" aria-label="追加研判记录" class="field" maxlength="1000" placeholder="写下证据核实与研判依据" />
                </label>
                <button type="submit" class="act-ghost" :disabled="busy || !noteText.trim()">添加记录</button>
              </form>
            </Panel>

            <Panel title="关联证据组" :icon="Layers" flush>
              <template #actions><span class="text-[12px] text-ink-3">{{ episodes.length }} 组 · 点击查看证据明细{{ canLabel ? '与标注' : '' }}</span></template>
              <table class="table">
                <thead>
                  <tr><th>时间窗起点</th><th>对端</th><th>方向 / 端口</th><th>类别 / 来源</th><th class="text-right">修订</th></tr>
                </thead>
                <tbody>
                  <tr v-for="ep in episodes" :key="ep.id" class="row-link" tabindex="0"
                    @click="pickedEpisode = ep" @keydown.enter="pickedEpisode = ep">
                    <td class="num text-ink-3">{{ fmtTime(ep.bucketStart) }}</td>
                    <td>
                      <IdText :value="ep.peerKey" :length="12" :copy="false" />
                    </td>
                    <td class="num text-ink-2">{{ ep.direction }} / {{ ep.servicePort }}</td>
                    <td>
                      <span class="block text-ink-2">{{ ep.family ? (guardFamilyLabel[ep.family] ?? ep.family) : '—' }}</span>
                      <span class="text-[12px] text-ink-3">{{ guardSourceLabel(ep.source, ep.ruleId) }}</span>
                    </td>
                    <td class="num text-right text-ink-3">{{ ep.revision }}</td>
                  </tr>
                  <tr v-if="!episodes.length"><td colspan="5" class="py-8 text-center text-ink-3">暂无关联证据组。</td></tr>
                </tbody>
              </table>
            </Panel>

            <!-- 关联处置动作（仅在持有 action.read 时显示） -->
            <Panel v-if="canReadAction" title="关联处置动作" :icon="ShieldBan" flush>
              <template #actions><span class="text-[12px] text-ink-3">期望与观测分列，制定不等于执行</span></template>
              <table class="table">
                <thead>
                  <tr><th>动作</th><th>模式</th><th>期望 → 观测</th><th class="text-right">租约截止</th></tr>
                </thead>
                <tbody>
                  <tr v-for="a in actions" :key="a.id">
                    <td><IdText :value="a.id" /></td>
                    <td class="text-ink-2">{{ guardActionModeLabel[a.mode] ?? a.mode }}</td>
                    <td class="whitespace-nowrap">
                      <span class="inline-flex items-center gap-2">
                        <Tag :tone="actionStateTone[a.desiredState]" :label="guardActionStateLabel[a.desiredState] ?? a.desiredState" />
                        <ArrowRight :size="13" :stroke-width="1.5" class="text-ink-4" aria-hidden="true" />
                        <Tag pill :tone="actionStateTone[a.observedState]" :label="guardActionStateLabel[a.observedState] ?? a.observedState" />
                      </span>
                    </td>
                    <td class="num text-right text-ink-3">{{ fmtTime(a.blockUntil) }}</td>
                  </tr>
                  <tr v-if="!actions.length"><td colspan="4" class="py-8 text-center text-ink-3">该事件尚未产生处置动作。</td></tr>
                </tbody>
              </table>
            </Panel>
          </div>

          <!-- 侧栏：处置资格与绑定目标、技术细节 -->
          <aside class="min-w-0 space-y-4 xl:sticky xl:top-20">
            <Panel title="处置资格" :icon="ev.actionable ? ShieldCheck : ShieldOff">
              <p class="mb-4 flex items-start gap-2.5 rounded px-3 py-2.5 text-[12.5px] leading-relaxed" :class="ev.actionable ? 'bg-ok-soft text-ink-2' : 'bg-paper-soft text-ink-2'">
                <span class="dot mt-[7px] shrink-0" :class="ev.actionable ? 'bg-ok' : 'bg-ink-4'" />{{ actionableReasonText }}
              </p>
              <dl class="kv">
                <div v-for="[k, v] in [
                  ['可否申请', ev.actionable ? '可申请' : '不可申请'],
                  ['原因码', ev.actionableReasonCode ?? '—'],
                  ['关联判定', String(ev.decisionIds?.length ?? 0)],
                ]" :key="k" class="grid-cols-[6rem_minmax(0,1fr)] text-[12.5px]">
                  <dt>{{ k }}</dt>
                  <dd class="num break-all">{{ v }}</dd>
                </div>
              </dl>
              <p v-if="canRequestAction" class="mt-3 text-[12px] leading-relaxed text-ink-3">申请只引用已登记的目标，不能手工输入地址或命令；须由他人批准。</p>
            </Panel>

            <details class="tech-details">
              <summary>技术细节</summary>
              <dl class="kv text-[12px]">
                <div v-for="[k, v] in [
                  ['事件 ID', ev.id],
                  ['事件键', ev.eventKey],
                  ['关联资产', ev.guardAssetId ?? '—'],
                  ['候选证据组', ev.actionEpisodeId ?? '—'],
                  ['稳定预算目标', ev.budgetTargetId ?? '—'],
                  ['目标引用', ev.targetRef ?? '—'],
                  ['决策策略', ev.policyId ?? '—'],
                  ['修订', String(ev.revision)],
                  ['创建时间', fmtTime(ev.createdAt)],
                  ['结案时间', fmtTime(ev.closedAt)],
                ]" :key="k" class="grid-cols-[6rem_minmax(0,1fr)]">
                  <dt>{{ k }}</dt>
                  <dd class="num break-all">{{ v }}</dd>
                </div>
              </dl>
            </details>
          </aside>
        </div>

        <!-- 指派负责人抽屉 -->
        <Drawer :open="assigning" title="指派负责人" :kicker="ev.eventKey" @close="assigning = false">
          <div class="space-y-6">
            <p class="text-[13px] text-ink-2">当前处理人：{{ who(ev.assigneeId) }}</p>
            <label class="form-field">
              <span class="label">可指派人员</span>
              <select v-model="assignForm.userId" aria-label="可指派人员" class="field">
                <option value="">— 请选择负责人 —</option>
                <option v-for="u in assignableUsers" :key="u.userKey" :value="u.userKey">
                  {{ u.displayName }} · {{ u.username }}
                </option>
              </select>
              <span class="text-[12px] text-ink-3">只列出能处理该资产事件的在职账号。</span>
            </label>
            <button v-if="session.user && assignableUsers.some((u) => u.username === session.user?.username)"
              type="button" class="link text-[12.5px]"
              @click="assignForm.userId = assignableUsers.find((u) => u.username === session.user?.username)?.userKey ?? ''">
              指派给我
            </button>
            <label class="form-field">
              <span class="label">指派说明（可选）</span>
              <textarea v-model="assignForm.reason" aria-label="指派说明" rows="3" maxlength="1000" class="field resize-none" placeholder="写入事件时间线与审计日志" />
            </label>
            <p v-if="assignForm.error" role="alert" class="text-[12.5px] text-threat">{{ assignForm.error }}</p>
          </div>
          <template #foot>
            <button v-if="ev.assigneeId" type="button" class="act-ghost" :disabled="busy" @click="submitAssign(true)">取消指派</button>
            <button type="button" class="act-ghost" @click="assigning = false">取消</button>
            <button type="button" class="act" :disabled="busy || !assignForm.userId" @click="submitAssign(false)">确认指派</button>
          </template>
        </Drawer>

        <!-- 发起人工处置申请抽屉 -->
        <Drawer :open="askingAction" title="发起人工处置申请" :kicker="ev.eventKey" @close="askingAction = false">
          <div class="space-y-6">
            <dl class="kv">
              <div v-for="[k, v] in [
                ['绑定证据组', ev.actionEpisodeId ?? '—'],
                ['目标引用', ev.targetRef ?? '—'],
                ['预算目标', ev.budgetTargetId ?? '—'],
                ['决策策略', ev.policyId ?? '—'],
              ]" :key="k" class="grid-cols-[6rem_minmax(0,1fr)] text-[13px]">
                <dt class="text-ink-3">{{ k }}</dt>
                <dd><IdText :value="v === '—' ? null : v" /></dd>
              </div>
            </dl>
            <p class="text-[12px] leading-relaxed text-ink-3">目标由后端按最新阻断候选绑定，不能手工输入地址、端口或命令；提交后待他人审批。</p>
            <label class="form-field">
              <span class="label">申请理由（必填）</span>
              <textarea v-model="actionForm.reason" aria-label="申请理由" rows="3" maxlength="1000" class="field resize-none" placeholder="说明触发人工阻断的研判依据" />
            </label>
            <p v-if="actionForm.error" role="alert" class="text-[12.5px] text-threat">{{ actionForm.error }}</p>
          </div>
          <template #foot>
            <button type="button" class="act-ghost" @click="askingAction = false">取消</button>
            <button type="button" class="act" :disabled="busy || !actionForm.reason.trim()" @click="submitActionRequest">提交处置申请</button>
          </template>
        </Drawer>

        <!-- 证据组详情与标注抽屉 -->
        <Drawer :open="!!pickedEpisode" :title="pickedEpisode ? `证据组 · ${pickedEpisode.direction} / ${pickedEpisode.servicePort}` : ''" @close="pickedEpisode = null">
          <template v-if="pickedEpisode">
            <dl class="kv">
              <div v-for="[k, v] in [
                ['对端', pickedEpisode.peerKey],
                ['证据组 ID', pickedEpisode.id],
                ['方向 / 端口', `${pickedEpisode.direction} / ${pickedEpisode.servicePort}`],
                ['类别', pickedEpisode.family ? (guardFamilyLabel[pickedEpisode.family] ?? pickedEpisode.family) : '—'],
                ['来源', guardSourceLabel(pickedEpisode.source, pickedEpisode.ruleId)],
                ['时间窗起点', fmtTime(pickedEpisode.bucketStart)],
                ['修订', String(pickedEpisode.revision)],
              ]" :key="k" class="grid-cols-[7rem_minmax(0,1fr)] text-[13px]">
                <dt class="text-ink-3">{{ k }}</dt>
                <dd class="num break-all">{{ v }}</dd>
              </div>
            </dl>
            <h3 class="section-title mt-8">证据明细</h3>
            <LoadState :loading="epEvidence.loading" :error="epEvidence.error" :empty="!epEvidence.items.length" empty-text="该证据组暂无明细。">
              <ul>
                <li v-for="x in epEvidence.items" :key="x.id" class="grid grid-cols-[5.5rem_1fr_auto] items-center gap-3 border-b border-ink-hair py-2.5 text-[12.5px]">
                  <span class="num text-ink-3">#{{ x.score == null ? '—' : Number(x.score).toFixed(3) }}</span>
                  <span>
                    <span class="flex items-center gap-1.5">观察 <IdText :value="x.observationId" :copy="false" /></span>
                    <span class="num text-[11.5px] text-ink-4">{{ guardSourceLabel(x.source, x.ruleId) }} · asOf {{ fmtTime(x.asOf) }}</span>
                  </span>
                  <button v-if="canLabel" type="button" class="link text-[12px]" @click="labelTarget = x.observationId">标注</button>
                </li>
              </ul>
            </LoadState>
            <LabelForm v-if="canLabel && labelTarget" :observation-id="labelTarget" :evidence-ref="`event:${ev.eventKey}`" auto-open />
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
