<script setup lang="ts">
/**
 * lab 会话资格抽屉（发布管理 `?tab=validation&record=lab&id=`，待办中心的 lab 资格审批直达这里）。
 *
 * 资格状态与运行状态分开显示；effectiveEligibility 由后端按到期与授权当前状态计算，前端不推断。
 * - 批准 / 驳回资格（authorization.approve，资格待批准）：登记人本人由后端拒绝（查询不返回登记人，入口照常显示）。
 * - 作废（automation.stop，未作废）：撤销会话资格，不影响已登记的事实与报告。
 * 会话本身不授予执行权限，也不断言规则清理；开始、中断、恢复、完成、事实追加与报告导入由 runner 执行。
 */
import { computed, ref, watch } from 'vue'
import { RouterLink } from 'vue-router'
import { ArrowUpRight, Ban } from 'lucide-vue-next'
import Drawer from '@/components/Drawer.vue'
import Tag from '@/components/Tag.vue'
import IdText from '@/components/IdText.vue'
import LoadState from '@/components/LoadState.vue'
import { errText } from '@/composables/load'
import { toast } from '@/composables/toast'
import { can } from '@/api/session'
import { fmtTime, guardLabEligibilityLabel, guardLabRunStatusLabel, type GuardLabRun } from '@/api/types'
import { releaseApi } from '@/api/v2/release'
import { labEligibilityTone, labRunTone } from '@/data/tones'
import { releaseErr, short } from './shared'

const props = defineProps<{ id: string }>()
const emit = defineEmits<{ close: []; changed: [] }>()

type Mode = 'view' | 'approve' | 'reject' | 'revoke'
const mode = ref<Mode>('view')
const run = ref<GuardLabRun | null>(null)
const loading = ref(false)
const error = ref('')
let seq = 0
async function load() {
  const mine = ++seq
  loading.value = !run.value || run.value.id !== props.id
  error.value = ''
  try { const r = await releaseApi.getLabRun(props.id); if (mine === seq) run.value = r }
  catch (e) { if (mine === seq) { run.value = null; error.value = errText(e) } }
  finally { if (mine === seq) loading.value = false }
}
watch(() => props.id, (id) => { mode.value = 'view'; if (id) void load(); else { seq++; run.value = null } }, { immediate: true })

const decidable = computed(() => run.value?.eligibilityStatus === 'pending' && can('authorization.approve'))
const revocable = computed(() => !!run.value && run.value.eligibilityStatus !== 'revoked' && can('automation.stop'))
const cleanupLabel: Record<string, string> = { not_asserted: '会话不断言清理', verified: '执行器已核验清理', pending: '待核验' }

const busy = ref(false)
const reason = ref('')
const formError = ref('')
function enter(m: Mode) { mode.value = m; reason.value = ''; formError.value = '' }
function confirm() {
  const r = run.value
  if (!r) return
  if (!reason.value.trim()) { formError.value = '请填写理由，理由会写入审计。'; return }
  busy.value = true
  formError.value = ''
  const call = mode.value === 'revoke'
    ? releaseApi.revokeLabRun(r.id, r.revision, reason.value.trim())
    : releaseApi.decideLabRun(r.id, r.revision, { decision: mode.value === 'approve' ? 'approve' : 'reject', reason: reason.value.trim() })
  const done = mode.value === 'revoke' ? '已作废会话资格。' : mode.value === 'approve' ? '已批准会话资格；会话推进由 runner 执行。' : '已驳回会话资格。'
  call.then(async () => { toast(done); emit('changed'); mode.value = 'view'; await load() })
    .catch((e: unknown) => { formError.value = releaseErr(e) })
    .finally(() => { busy.value = false })
}
</script>

<template>
  <Drawer :open="!!id" :title="run ? `lab 会话 ${short(run.id)}` : 'lab 会话'" kicker="验证记录 · lab 会话" @close="emit('close')">
    <LoadState :loading="loading" :error="error">
      <template v-if="run">
        <template v-if="mode === 'view'">
          <p class="note mb-5" :class="run.effectiveEligibility === 'blocked' || run.effectiveEligibility === 'revoked' ? 'note-warn' : ''">
            会话在网络隔离的 lab 资产上以 1 倍速运行，只记录事实，不授予执行权限。
            <template v-if="run.blockedReason">资格受阻：{{ run.blockedReason }}。</template>
          </p>
          <dl class="kv">
            <div><dt>资格</dt><dd><Tag :tone="labEligibilityTone[run.effectiveEligibility]" :label="guardLabEligibilityLabel[run.effectiveEligibility] ?? run.effectiveEligibility" />
              <span v-if="run.effectiveEligibility !== run.eligibilityStatus" class="ml-2 text-[12px] text-ink-3">登记状态：{{ guardLabEligibilityLabel[run.eligibilityStatus] ?? run.eligibilityStatus }}</span></dd></div>
            <div><dt>运行</dt><dd><Tag pill :tone="labRunTone[run.runStatus]" :label="guardLabRunStatusLabel[run.runStatus] ?? run.runStatus" /><span v-if="run.timedOut" class="ml-2 text-[12px] text-threat">已超时</span></dd></div>
            <div><dt>证据类别</dt><dd class="num">{{ run.evidenceKind }}</dd></div>
            <div><dt>发布组合</dt><dd><RouterLink v-if="run.bundleId" class="link num" :to="{ query: { tab: 'bundles', id: run.bundleId } }">{{ short(run.bundleId) }}</RouterLink><span v-else>—</span></dd></div>
            <div><dt>资产</dt><dd><RouterLink v-if="run.assetId" class="link num" :to="{ name: 'assets-list-detail', params: { id: run.assetId } }">{{ short(run.assetId) }}</RouterLink><span v-else>—</span></dd></div>
            <div><dt>有效期至</dt><dd class="num">{{ fmtTime(run.validUntil) }}</dd></div>
            <div><dt>开始 / 结束</dt><dd class="num">{{ fmtTime(run.startedAt) }} → {{ fmtTime(run.endedAt) }}</dd></div>
            <div><dt>规则清理</dt><dd>{{ cleanupLabel[run.cleanupStatus] ?? run.cleanupStatus }}</dd></div>
            <div><dt>执行权限</dt><dd>{{ run.executionAuthority ? '有' : '无（会话不授予执行权限）' }}</dd></div>
          </dl>
          <RouterLink class="act-ghost mt-6 w-full justify-center" :to="{ name: 'release-lab-detail', params: { id: run.id } }">查看会话详情（报告与事实）<ArrowUpRight :size="14" :stroke-width="1.5" /></RouterLink>
          <details class="mt-7 text-[12.5px]">
            <summary class="cursor-pointer text-ink-3 hover:text-ink">技术细节</summary>
            <dl class="kv mt-2">
              <div><dt>会话 ID</dt><dd><IdText :value="run.id" /></dd></div>
              <div><dt>会话摘要</dt><dd><IdText :value="run.sessionSha256" :length="16" /></dd></div>
              <div><dt>清单摘要</dt><dd><IdText :value="run.manifestSha256" :length="16" /></dd></div>
              <div><dt>修订号</dt><dd class="num">{{ run.revision }}</dd></div>
            </dl>
          </details>
          <button v-if="revocable" type="button" class="link mt-6 text-[12.5px] text-threat" @click="enter('revoke')"><Ban :size="13" :stroke-width="1.5" />作废会话资格</button>
        </template>

        <div v-else>
          <p class="note mb-5" :class="mode === 'revoke' ? 'note-threat' : mode === 'reject' ? 'note-warn' : ''">
            <template v-if="mode === 'approve'">批准后会话可由 runner 开始运行；批准不授予执行权限。登记人本人不能批准，后端会拒绝。</template>
            <template v-else-if="mode === 'reject'">驳回后会话不能开始运行。</template>
            <template v-else>作废后会话资格立即失效，运行中的会话不能继续推进；已登记的事实与报告保留。</template>
          </p>
          <label class="form-field"><span class="label">理由</span><textarea v-model="reason" rows="3" maxlength="1000" class="field resize-none" placeholder="写入审计" /></label>
        </div>
        <p v-if="formError" class="mt-4 text-[12.5px] text-threat" role="alert">{{ formError }}</p>
      </template>
    </LoadState>

    <template v-if="run && (decidable || mode !== 'view')" #foot>
      <template v-if="mode === 'view'">
        <button type="button" class="act-ghost" @click="enter('reject')">驳回</button>
        <button type="button" class="act" @click="enter('approve')">批准资格</button>
      </template>
      <template v-else>
        <button type="button" class="act-ghost" :disabled="busy" @click="enter('view')">返回</button>
        <button type="button" :class="mode === 'approve' ? 'act' : 'act-danger'" :disabled="busy" @click="confirm">{{ mode === 'approve' ? '确认批准' : mode === 'reject' ? '确认驳回' : '确认作废' }}</button>
      </template>
    </template>
  </Drawer>
</template>
