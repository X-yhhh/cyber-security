<script setup lang="ts">
import { useActionError } from '@/composables/actionError'
/**
 * 决策策略详情抽屉（发布管理 `?tab=policies&id=`，待办中心的策略审核直达这里）。
 *
 * - 业务字段在前：模式、模型、评价计划、快照类型；四个攻击类别与规则策略逐条列出 autoEligible / modelAutoEligible。
 * - 「策略原文」把定义按 JSON 格式化显示，mode 与各类 autoEligible 所在行标出（允许自动的行着警示色）。
 * - 审核（policy.approve，草稿）：批准记为已审核、驳回记为已退役；起草人本人由后端拒绝（查询不返回起草人，入口照常显示）。
 * - 删除草稿（policy.draft）：只限本人起草、未被引用的草稿，否则 403 / 409 RESOURCE_IN_USE。
 * - 改名（policy.draft，任意状态）：只改显示名与备注（命名规范 P 编号），策略正文冻结不变。
 */
import { computed, reactive, ref, watch } from 'vue'
import { Pencil, Trash2 } from 'lucide-vue-next'
import Drawer from '@/components/Drawer.vue'
import Tag from '@/components/Tag.vue'
import IdText from '@/components/IdText.vue'
import LoadState from '@/components/LoadState.vue'
import { errText } from '@/composables/load'
import { toast } from '@/composables/toast'
import { can } from '@/api/session'
import { fmtTime } from '@/api/types'
import { releaseApi, type ReleasePolicy } from '@/api/v2/release'
import { policyReviewTone } from '@/data/tones'
import { capabilityName, ensureIndex, familyLabel, modeLabel, modelName, planName, policyStatusLabel, profileLabel, releaseErr, scopeLabel } from './shared'

const props = defineProps<{ id: string }>()
const emit = defineEmits<{ close: []; changed: [] }>()

type Mode = 'view' | 'rename' | 'approve' | 'reject' | 'delete'
const mode = ref<Mode>('view')
const policy = ref<ReleasePolicy | null>(null)
const loading = ref(false)
const error = ref('')
let seq = 0
async function load() {
  const mine = ++seq
  loading.value = !policy.value || policy.value.id !== props.id
  error.value = ''
  try {
    const p = await releaseApi.getPolicy(props.id)
    if (mine === seq) policy.value = p
    void ensureIndex('models'); void ensureIndex('plans'); void ensureIndex('capabilities')
  } catch (e) { if (mine === seq) { policy.value = null; error.value = errText(e) } } finally { if (mine === seq) loading.value = false }
}
watch(() => props.id, (id) => { mode.value = 'view'; if (id) void load(); else { seq++; policy.value = null } }, { immediate: true })

const def = computed(() => policy.value?.definition ?? null)
const draft = computed(() => policy.value?.status === 'draft')
const reviewable = computed(() => draft.value && can('policy.approve'))
const deletable = computed(() => draft.value && can('policy.draft'))
const autoFamilies = computed(() => def.value?.familyPolicies?.filter((f) => f.autoEligible).length ?? 0)

/** 原文逐行渲染：mode / autoEligible / modelAutoEligible 行标出，值为 true 或 mode=auto 时着警示色。 */
const lines = computed(() => {
  if (!def.value) return []
  return JSON.stringify(def.value, null, 2).split('\n').map((text) => {
    const m = /^\s*"(mode|autoEligible|modelAutoEligible)":\s*(.+?),?$/.exec(text)
    const hot = !!m && (m[2] === 'true' || m[2] === '"auto"')
    return { text, mark: !!m, hot }
  })
})
async function copy() {
  if (!def.value) return
  try {
    if (!navigator.clipboard) throw new Error('clipboard unavailable')
    await navigator.clipboard.writeText(JSON.stringify(def.value, null, 2))
    toast('已复制策略原文。')
  } catch { toast('无法访问剪贴板，请选中策略原文后手动复制。', 'warn') }
}

const busy = ref(false)
const reason = ref('')
const formError = useActionError()
const canRename = computed(() => can('policy.draft'))
const naming = reactive({ displayName: '', notes: '' })
function enter(m: Mode) {
  mode.value = m; reason.value = ''; formError.value = ''
  if (m === 'rename' && policy.value) Object.assign(naming, { displayName: policy.value.displayName ?? '', notes: policy.value.notes ?? '' })
}
function rename(p: ReleasePolicy) {
  const displayName = naming.displayName.trim(), notes = naming.notes.trim()
  if (displayName.length > 128) { formError.value = '显示名最多 128 个字符。'; return }
  const body: { displayName?: string | null; notes?: string | null } = {}
  if (displayName !== (p.displayName ?? '')) body.displayName = displayName || null
  if (notes !== (p.notes ?? '')) body.notes = notes || null
  if (!Object.keys(body).length) { formError.value = '没有需要保存的修改。'; return }
  busy.value = true
  formError.value = ''
  releaseApi.updatePolicy(p.id, p.revision, body)
    .then(async () => { toast('已保存策略名称。'); emit('changed'); void ensureIndex('policies', true); mode.value = 'view'; await load() })
    .catch((e: unknown) => { formError.value = releaseErr(e, 'policy') }).finally(() => { busy.value = false })
}
function confirm() {
  const p = policy.value
  if (!p) return
  if (mode.value === 'rename') return rename(p)
  if (mode.value !== 'delete' && !reason.value.trim()) { formError.value = '请填写理由，理由会写入审计。'; return }
  busy.value = true
  formError.value = ''
  const deleting = mode.value === 'delete'
  const call = deleting ? releaseApi.deletePolicy(p.id, p.revision) : releaseApi.reviewPolicy(p.id, p.revision, { decision: mode.value === 'approve' ? 'approve' : 'reject', reason: reason.value.trim() })
  const done = deleting ? '已删除草稿。' : mode.value === 'approve' ? '已审核；策略可用于申请发布组合，审核不等于激活。' : '已驳回，策略记为已退役。'
  call.then(async () => {
    toast(done)
    emit('changed')
    if (deleting) emit('close')
    else { mode.value = 'view'; await load() }
  }).catch((e: unknown) => { formError.value = releaseErr(e, 'policy') }).finally(() => { busy.value = false })
}
</script>

<template>
  <Drawer :open="!!id" :title="policy ? (policy.displayName || `${policy.policyKey} · ${policy.version}`) : '决策策略'" kicker="决策策略" @close="emit('close')">
    <LoadState :loading="loading" :error="error">
      <template v-if="policy && def">
        <template v-if="mode === 'view'">
          <p class="note mb-5" :class="def.mode === 'auto' ? 'note-warn' : ''">
            <template v-if="draft">草稿：须由起草人以外的审核人审核后，才能用于申请发布组合。</template>
            <template v-else-if="policy.status === 'reviewed'">已审核：可用于申请发布组合；审核不等于激活。</template>
            <template v-else>已退役：不能再用于新的发布组合。</template>
            <template v-if="def.mode === 'auto'">模式为「自动」：{{ autoFamilies }} 个类别允许自动路径，仍受能力等级、授权与预算约束。</template>
            <template v-else>模式为「只告警」：不会下发阻断命令。</template>
          </p>
          <dl class="kv">
            <div><dt>名称</dt><dd>
              <span :class="policy.displayName ? 'text-ink' : 'text-ink-4'">{{ policy.displayName || '未命名' }}</span>
              <button v-if="canRename" type="button" class="link ml-3 text-[12px]" @click="enter('rename')"><Pencil :size="12" :stroke-width="1.5" />改名</button>
              <p v-if="policy.notes" class="mt-1 text-[12px] text-ink-3">{{ policy.notes }}</p>
            </dd></div>
            <div><dt>状态</dt><dd><Tag pill :tone="policyReviewTone[policy.status]" :label="policyStatusLabel[policy.status] ?? policy.status" /></dd></div>
            <div><dt>模式</dt><dd><Tag :tone="def.mode === 'alert_only' ? 'mute' : 'warn'" :label="modeLabel[def.mode] ?? def.mode" /><span class="num ml-2 text-[11.5px] text-ink-4">mode = {{ def.mode }}</span></dd></div>
            <div><dt>模型</dt><dd>{{ modelName(policy.modelId) }}</dd></div>
            <div><dt>评价计划</dt><dd class="num">{{ planName(policy.planId) }}</dd></div>
            <div><dt>快照类型</dt><dd>{{ profileLabel[def.profile] ?? def.profile }}<span v-if="def.acceptedProfiles?.length" class="text-ink-3">（接受 {{ def.acceptedProfiles.map((x) => profileLabel[x] ?? x).join('、') }}）</span></dd></div>
            <div><dt>支持能力</dt><dd class="num">{{ def.supportedCapabilityIds.map(capabilityName).join('、') || '—' }}</dd></div>
            <div><dt>说明</dt><dd>{{ policy.notes || '—' }}</dd></div>
            <div><dt>登记</dt><dd class="num">{{ fmtTime(policy.createdAt) }}</dd></div>
          </dl>

          <h3 class="section-title mt-8">类别策略</h3>
          <ul class="divide-y divide-ink-hair rounded border border-ink-hair">
            <li v-for="f in def.familyPolicies" :key="f.family" class="flex items-center justify-between gap-3 px-3.5 py-2.5 text-[12.5px]">
              <span class="min-w-0">
                <span class="block text-ink">{{ familyLabel[f.family] ?? f.family }}</span>
                <span class="num block text-[11.5px] text-ink-4">{{ scopeLabel[f.scope] ?? f.scope }} · 阈值 {{ f.alertThreshold }} / {{ f.autoThreshold }} · 最少 {{ f.minDistinctFlows }} 条流</span>
              </span>
              <span class="flex shrink-0 flex-col items-end gap-1">
                <Tag :tone="f.autoEligible ? 'warn' : 'mute'" :label="f.autoEligible ? '允许自动' : '只告警'" />
                <span v-if="f.modelAutoEligible" class="text-[11.5px] text-warn">含模型来源</span>
              </span>
            </li>
          </ul>
          <p class="mt-2 text-[12px] text-ink-4">autoEligible 决定该类别能否走自动路径；modelAutoEligible 另允许模型来源（而非规则）触发自动。</p>

          <template v-if="def.rulePolicies?.length">
            <h3 class="section-title mt-8">规则策略</h3>
            <ul class="divide-y divide-ink-hair rounded border border-ink-hair">
              <li v-for="r in def.rulePolicies" :key="r.ruleId" class="flex items-center justify-between gap-3 px-3.5 py-2.5 text-[12.5px]">
                <span class="min-w-0">
                  <span class="block"><span class="num text-ink">{{ r.ruleId }}</span><span class="ml-2 text-ink-3">{{ familyLabel[r.family] ?? r.family }}</span></span>
                  <span class="num block truncate text-[11.5px] text-ink-4">{{ r.field }} {{ { gte: '≥', gt: '>', lte: '≤', lt: '<', eq: '=' }[r.operator] }} {{ r.threshold }}</span>
                </span>
                <Tag class="shrink-0" :tone="r.autoEligible ? 'warn' : 'mute'" :label="r.autoEligible ? '允许自动' : '只告警'" />
              </li>
            </ul>
          </template>

          <div class="mt-8 flex items-center justify-between">
            <h3 class="section-title mb-0">策略原文</h3>
            <button type="button" class="link text-[12px]" @click="copy">复制</button>
          </div>
          <p class="mb-2 mt-1 text-[12px] text-ink-3">左侧标线为 mode 与各类 autoEligible 所在行；着色表示允许自动。</p>
          <pre class="max-h-[22rem] overflow-auto rounded border border-ink-hair bg-paper-soft py-2 text-[11.5px] leading-[1.6]"><code><span v-for="(l, i) in lines" :key="i" class="block whitespace-pre border-l-2 px-3" :class="l.hot ? 'border-warn bg-warn-soft text-ink' : l.mark ? 'border-ink-4 text-ink' : 'border-transparent text-ink-2'"><span class="num">{{ l.text }}</span></span></code></pre>

          <details class="mt-7 text-[12.5px]">
            <summary class="cursor-pointer text-ink-3 hover:text-ink">技术细节</summary>
            <dl class="kv mt-2">
              <div><dt>策略 ID</dt><dd><IdText :value="policy.id" /></dd></div>
              <div><dt>策略键</dt><dd class="num break-all">{{ policy.policyKey }}</dd></div>
              <div><dt>契约版本</dt><dd class="num">{{ def.contractVersion }}</dd></div>
              <div><dt>定义摘要</dt><dd><IdText :value="policy.definitionSha256" :length="16" /></dd></div>
              <div><dt>保护集摘要</dt><dd><IdText :value="def.protectionSetSha256" :length="16" /></dd></div>
              <div><dt>评价计划摘要</dt><dd><IdText :value="def.evaluationPlanSha256" :length="16" /></dd></div>
              <div><dt>修订号</dt><dd class="num">{{ policy.revision }}</dd></div>
            </dl>
          </details>
          <button v-if="deletable" type="button" class="link mt-6 text-[12.5px] text-threat" @click="enter('delete')"><Trash2 :size="13" :stroke-width="1.5" />删除草稿</button>
        </template>

        <form v-else-if="mode === 'rename'" class="form" @submit.prevent="confirm()">
          <p class="note">按命名规范填写：<span class="num">P编号 · 用途</span>，例如「P5 · 真实主机只告警」；策略正文一变就用新编号。名称只用于界面显示，不改变冻结的策略正文、审核状态或引用它的组合，修改写入审计。</p>
          <label class="form-field"><span class="label">显示名</span><input v-model="naming.displayName" class="field" maxlength="128" :placeholder="`留空则显示策略键 ${policy.policyKey.slice(0, 8)}…`" /></label>
          <label class="form-field"><span class="label">备注</span><textarea v-model="naming.notes" class="field min-h-[5rem]" maxlength="1000" placeholder="来源、差异或用途" /></label>
        </form>

        <div v-else>
          <p class="note mb-5" :class="mode === 'delete' ? 'note-threat' : mode === 'reject' ? 'note-warn' : ''">
            <template v-if="mode === 'approve'">审核通过后策略记为已审核，可用于申请发布组合；审核不等于激活。起草人本人不能审核，后端会拒绝。</template>
            <template v-else-if="mode === 'reject'">驳回后策略记为已退役，起草人需要重新起草新版本。</template>
            <template v-else>只能删除你本人起草、未被引用的草稿，删除后无法恢复。被引用时会被拒绝（409 RESOURCE_IN_USE）。</template>
          </p>
          <label v-if="mode !== 'delete'" class="form-field"><span class="label">理由</span><textarea v-model="reason" rows="3" maxlength="1000" class="field resize-none" placeholder="写入审计" /></label>
        </div>
        <p v-if="formError" class="mt-4 text-[12.5px] text-threat" role="alert">{{ formError }}</p>
      </template>
    </LoadState>

    <template v-if="policy && (reviewable || mode !== 'view')" #foot>
      <template v-if="mode === 'view'">
        <button type="button" class="act-ghost" @click="enter('reject')">驳回</button>
        <button type="button" class="act" @click="enter('approve')">审核通过</button>
      </template>
      <template v-else>
        <button type="button" class="act-ghost" :disabled="busy" @click="enter('view')">返回</button>
        <button type="button" :class="mode === 'approve' || mode === 'rename' ? 'act' : 'act-danger'" :disabled="busy" @click="confirm">{{ mode === 'rename' ? '保存名称' : mode === 'approve' ? '确认审核通过' : mode === 'reject' ? '确认驳回' : '确认删除' }}</button>
      </template>
    </template>
  </Drawer>
</template>
