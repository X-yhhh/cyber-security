<script setup lang="ts">
/**
 * 告警人工标注抽屉（路线 B 阶段 7 人工抽检）。
 *
 * 打开时读取 GET /alerts/{id}/feedback 展示标注历史（含被驳回的，新在前）。
 * 满足以下条件才显示标注表单：具备 alert.feedback.label 权限、告警状态为 new / acknowledged、
 * 没有 pending / training_approved 的有效标注。前端判断只用于隐藏入口，
 * 是否可标注以后端为准（409 ALERT_NOT_LABELABLE / ALERT_ALREADY_LABELED 会以提示展示）。
 * 提交 POST /alerts/{id}/feedback { label, note } 成功后重新读取历史并发出 changed，
 * 由父组件重新读取告警列表（误报会使告警变为 false_positive，真报变为 acknowledged）。
 *
 * status 可不传（例如影子验证抽检样本不带告警状态），此时从 GET /alerts/{id} 读取当前状态。
 */
import { computed, ref, watch } from 'vue'
import Drawer from '@/components/Drawer.vue'
import Tag from '@/components/Tag.vue'
import LoadState from '@/components/LoadState.vue'
import { api } from '@/api/client'
import { can } from '@/api/session'
import { alertTypeLabel, feedbackLabel, feedbackReviewLabel, fmtTime, type AlertFeedbackView, type AlertView } from '@/api/types'
import { feedbackReviewTone, feedbackTone, statusTone } from '@/data/tones'
import { toast } from '@/composables/toast'
import { errText } from '@/composables/load'

const props = defineProps<{ open: boolean; alertId: number | null; alertKey: string; status?: string | null; alertType?: string | null }>()
const emit = defineEmits<{ close: []; changed: [] }>()

const history = ref<AlertFeedbackView[]>([])
const loading = ref(false)
const error = ref('')
/** 调用方未提供状态时从后端读取的当前告警状态。 */
const fetched = ref<{ status: string; alertType: string } | null>(null)
const choice = ref<'false_positive' | 'true_positive' | null>(null)
const note = ref('')
const busy = ref(false)
let seq = 0

/** 读取标注历史（及必要时的告警状态）；以请求序号丢弃切换告警后到达的旧响应。 */
async function load() {
  const id = props.alertId
  if (id == null) return
  const mine = ++seq
  loading.value = true
  error.value = ''
  try {
    const [list, alert] = await Promise.all([
      api.get<AlertFeedbackView[]>(`/alerts/${id}/feedback`),
      props.status ? Promise.resolve(null) : api.get<AlertView>(`/alerts/${id}`),
    ])
    if (mine !== seq) return
    history.value = list ?? []
    if (alert) fetched.value = { status: alert.status, alertType: alert.alertType }
  } catch (e) {
    if (mine === seq) error.value = errText(e)
  } finally {
    if (mine === seq) loading.value = false
  }
}

watch(() => [props.open, props.alertId] as const, ([open, id]) => {
  choice.value = null
  note.value = ''
  if (!open || id == null) { seq++; history.value = []; fetched.value = null; return }
  load()
}, { immediate: true })

const status = computed(() => props.status ?? fetched.value?.status ?? null)
const type = computed(() => props.alertType ?? fetched.value?.alertType ?? null)
/** 已有有效标注（待复核或已批准）时不接受新标注；被驳回的标注已失效。 */
const active = computed(() => history.value.find((f) => f.reviewStatus === 'pending' || f.reviewStatus === 'training_approved'))
const statusOpen = computed(() => status.value === 'new' || status.value === 'acknowledged')
const labelable = computed(() => can('alert.feedback.label') && !loading.value && !error.value && statusOpen.value && !active.value)
/** 不能标注时的说明；无标注权限时不显示原因，只保留只读历史。 */
const blocked = computed(() => {
  if (!can('alert.feedback.label') || loading.value || error.value) return ''
  if (active.value) return '该告警已有有效标注，复核驳回后才能重新标注。'
  if (status.value && !statusOpen.value) return `告警状态为 ${status.value}，已结案的告警不接受新标注。`
  return ''
})

const valid = computed(() => !!choice.value && !!note.value.trim() && note.value.trim().length <= 1000)

async function submit() {
  if (!valid.value || props.alertId == null) return
  busy.value = true
  try {
    await api.post<AlertFeedbackView>(`/alerts/${props.alertId}/feedback`, { label: choice.value, note: note.value.trim() })
    toast(`已标注为「${feedbackLabel[choice.value!]}」，等待第二人复核。`)
    choice.value = null
    note.value = ''
    // 标注会改变告警状态，重新读取状态与历史，不在本地推断
    fetched.value = null
    await load()
    emit('changed')
  } catch (e) {
    toast(errText(e), 'threat')
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <Drawer :open="open" :title="`告警标注 · ${alertKey}`" kicker="人工抽检" @close="emit('close')">
    <p class="num flex flex-wrap gap-x-6 gap-y-1 text-[12.5px] text-ink-3">
      <span>类型 {{ type ? alertTypeLabel[type] ?? type : '—' }}</span>
      <span class="inline-flex items-center gap-2">状态 <Tag v-if="status" :tone="statusTone[status]" :label="status" /><template v-else>—</template></span>
    </p>

    <h3 class="section-title mt-8">标注历史</h3>
    <LoadState :loading="loading" :error="error" :empty="!history.length" empty-text="该告警暂无人工标注。">
      <ul>
        <li v-for="f in history" :key="f.id" class="border-b border-ink-hair py-4 text-[13px]">
          <p class="flex items-center justify-between gap-4">
            <Tag :tone="feedbackTone[f.label]" :label="feedbackLabel[f.label] ?? f.label" />
            <Tag :tone="feedbackReviewTone[f.reviewStatus]" :label="feedbackReviewLabel[f.reviewStatus] ?? f.reviewStatus" />
          </p>
          <p class="mt-2 whitespace-pre-line leading-relaxed">{{ f.note }}</p>
          <p class="num mt-2 text-[12px] text-ink-3">标注 {{ f.reviewerName }} · {{ fmtTime(f.reviewedAt) }}</p>
          <p v-if="f.secondReviewedAt" class="mt-1 text-[12px] text-ink-3">
            复核 {{ f.secondReviewerName ?? '—' }} · <span class="num">{{ fmtTime(f.secondReviewedAt) }}</span>{{ f.secondReviewReason ? ' · ' + f.secondReviewReason : '' }}
          </p>
        </li>
      </ul>
    </LoadState>

    <p v-if="blocked" class="mt-8 text-[12.5px] text-ink-3">{{ blocked }}</p>

    <form v-if="labelable" id="alert-feedback-form" class="mt-12 space-y-8" @submit.prevent="submit">
      <fieldset>
        <legend class="label">标注</legend>
        <div class="mt-3 flex gap-8 text-[13.5px]">
          <label class="inline-flex items-center gap-2"><input v-model="choice" type="radio" name="feedback-label" value="false_positive" />误报</label>
          <label class="inline-flex items-center gap-2"><input v-model="choice" type="radio" name="feedback-label" value="true_positive" />真报</label>
        </div>
      </fieldset>
      <label class="form-field">
        <span class="label">研判说明</span>
        <textarea v-model="note" rows="4" maxlength="1000" required aria-describedby="alert-feedback-hint" class="field resize-none" />
        <span id="alert-feedback-hint" class="mt-2 block text-[12px] text-ink-3">写研判依据：时间、本机当时在做什么、服务/协议；不要写对端地址。</span>
      </label>
      <p class="text-[12px] leading-relaxed text-ink-3">标注误报后告警状态变为 false_positive，标注真报后变为 acknowledged。标注需第二人复核后才可能进入离线训练候选。</p>
    </form>

    <template v-if="labelable" #foot>
      <button type="button" class="act-ghost" @click="emit('close')">取消</button>
      <button type="submit" form="alert-feedback-form" class="act" :disabled="!valid || busy">提交标注</button>
    </template>
  </Drawer>
</template>
