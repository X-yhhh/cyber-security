<script setup lang="ts">
/**
 * 采集配置详情抽屉（传感器与执行器页 `?tab=configs&id=`，待办中心的配置审批直达这里）。
 *
 * - 批准 / 驳回：authorization.approve，只对草稿或待批准配置；按 requestedBy 隐藏起草人本人的入口，
 *   历史归属为空时由后端判定，自批仍以 403 拒绝。批准时后端核验接口在有效授权内，批准后仍需代理验证。
 * - 删除草稿：sensor.manage，只限本人起草且未被引用的草稿（否则 403 / 409 RESOURCE_IN_USE）。
 * 抽屉内切换确认模式，不叠加抽屉；写后通知父页面重读。
 */
import { computed, ref, watch } from 'vue'
import { Trash2 } from 'lucide-vue-next'
import Drawer from '@/components/Drawer.vue'
import Tag from '@/components/Tag.vue'
import IdText from '@/components/IdText.vue'
import LoadState from '@/components/LoadState.vue'
import { errText } from '@/composables/load'
import { toast } from '@/composables/toast'
import { can, session } from '@/api/session'
import { fmtTime } from '@/api/types'
import { assetsApi, configStatusLabel, type SensorConfig } from '@/api/v2/assets'
import { configTone } from '@/data/tones'

const props = defineProps<{ id: string; assetLabel: (id: string | null | undefined) => string; sensorLabel: (id: string | null | undefined) => string }>()
const emit = defineEmits<{ close: []; changed: [] }>()

type Mode = 'view' | 'approve' | 'reject' | 'delete'
const mode = ref<Mode>('view')
const cfg = ref<SensorConfig | null>(null)
const loading = ref(false)
const error = ref('')
let seq = 0
async function load() {
  const mine = ++seq
  loading.value = !cfg.value || cfg.value.id !== props.id
  error.value = ''
  try {
    const c = await assetsApi.getConfig(props.id)
    if (mine === seq) cfg.value = c
  } catch (e) { if (mine === seq) { cfg.value = null; error.value = errText(e) } } finally { if (mine === seq) loading.value = false }
}
watch(() => props.id, (id) => { mode.value = 'view'; if (id) void load(); else { seq++; cfg.value = null } }, { immediate: true })

const mine = computed(() => {
  const by = cfg.value?.requestedBy
  return by !== undefined && by !== null && session.user != null && String(by) === String(session.user.id)
})
const unknownAuthor = computed(() => cfg.value?.requestedBy === undefined || cfg.value?.requestedBy === null)
const decidable = computed(() => !!cfg.value && ['draft', 'pending'].includes(cfg.value.status) && can('authorization.approve') && !mine.value)
const deletable = computed(() => !!cfg.value && cfg.value.status === 'draft' && can('sensor.manage') && (mine.value || unknownAuthor.value))

const reason = ref('')
const formError = ref('')
const busy = ref(false)
function enter(m: Mode) { mode.value = m; reason.value = ''; formError.value = '' }

function confirm() {
  const c = cfg.value
  if (!c) return
  if ((mode.value === 'approve' || mode.value === 'reject') && !reason.value.trim()) { formError.value = '请填写理由，理由会写入审计。'; return }
  busy.value = true
  const call = mode.value === 'delete' ? assetsApi.deleteConfig(c.id, c.revision) : assetsApi.decideConfig(c.id, c.revision, mode.value === 'approve' ? 'approve' : 'reject', reason.value.trim())
  const done = mode.value === 'delete' ? '已删除草稿。' : mode.value === 'approve' ? '已批准采集配置；仍需代理验证后生效。' : '已驳回采集配置。'
  const deleting = mode.value === 'delete'
  call.then(async () => {
    toast(done)
    emit('changed')
    if (deleting) emit('close')
    else { mode.value = 'view'; await load() }
  }).catch((e: unknown) => { formError.value = errText(e) }).finally(() => { busy.value = false })
}
const def = computed(() => cfg.value?.definition)
</script>

<template>
  <Drawer :open="!!id" :title="cfg ? `采集配置 · ${sensorLabel(cfg.sensorId)}` : '采集配置'" kicker="采集配置" @close="emit('close')">
    <LoadState :loading="loading" :error="error">
      <template v-if="cfg">
        <template v-if="mode === 'view'">
          <p class="note mb-5" :class="cfg.status === 'draft' || cfg.status === 'pending' ? '' : cfg.status === 'rejected' ? 'note-threat' : ''">
            <template v-if="cfg.status === 'draft' || cfg.status === 'pending'">等待起草人以外的审批人批准。批准时后端核验接口在资产有效授权内，批准后仍需代理验证才会生效。</template>
            <template v-else-if="cfg.status === 'active'">生效中。批准新的配置后，这一份会被替换。</template>
            <template v-else-if="cfg.status === 'retired'">已被更新的配置替换，只作记录。</template>
            <template v-else-if="cfg.status === 'rejected'">已驳回，不会下发给传感器。</template>
            <template v-else>配置状态：{{ configStatusLabel[cfg.status] ?? cfg.status }}。</template>
          </p>
          <dl class="kv">
            <div><dt>状态</dt><dd><Tag pill :tone="configTone[cfg.status]" :label="configStatusLabel[cfg.status] ?? cfg.status" /></dd></div>
            <div><dt>传感器</dt><dd>{{ sensorLabel(cfg.sensorId) }}</dd></div>
            <div><dt>资产</dt><dd>{{ assetLabel(cfg.assetId) }}</dd></div>
            <div><dt>采集接口</dt><dd class="num">{{ def?.interfaceIds?.join(', ') ?? '—' }}</dd></div>
            <div><dt>地址族</dt><dd class="num">{{ def?.addressFamily ?? '—' }}</dd></div>
            <div><dt>批量上限</dt><dd class="num">{{ def?.limits?.maxBatchSize ?? '—' }}</dd></div>
            <div><dt>健康版本</dt><dd class="num break-all">{{ def?.captureHealthVersion ?? '—' }}</dd></div>
            <div><dt>起草</dt><dd class="num">{{ fmtTime(cfg.createdAt) }}</dd></div>
            <div><dt>生效</dt><dd class="num">{{ fmtTime(cfg.activatedAt) }}</dd></div>
          </dl>
          <details class="mt-7 text-[12.5px]">
            <summary class="cursor-pointer text-ink-3 hover:text-ink">技术细节</summary>
            <dl class="kv mt-2">
              <div><dt>配置 ID</dt><dd><IdText :value="cfg.id" /></dd></div>
              <div><dt>配置版本</dt><dd><IdText :value="cfg.configVersion" /></dd></div>
              <div><dt>采集契约</dt><dd class="num">{{ def?.contractVersion ?? cfg.featureContractVersion ?? '—' }}</dd></div>
              <div><dt>采集域</dt><dd><IdText :value="def?.captureScopeId" /></dd></div>
              <div><dt>特征档案摘要</dt><dd><IdText :value="def?.profileSha256" :length="16" /></dd></div>
              <div><dt>构建摘要</dt><dd><IdText :value="def?.buildSha256" :length="16" /></dd></div>
              <div><dt>内容摘要</dt><dd><IdText :value="cfg.contentSha256" :length="16" /></dd></div>
              <div><dt>修订号</dt><dd class="num">{{ cfg.revision }}</dd></div>
            </dl>
          </details>
          <button v-if="deletable" type="button" class="link mt-6 text-[12.5px] text-threat" @click="enter('delete')"><Trash2 :size="13" :stroke-width="1.5" />删除草稿</button>
        </template>

        <div v-else>
          <p class="note mb-5" :class="mode === 'delete' ? 'note-threat' : mode === 'reject' ? 'note-warn' : ''">
            <template v-if="mode === 'approve'">批准后替换该传感器当前生效的配置；后端会核验接口在资产有效授权内，否则拒绝。批准后仍需代理验证。</template>
            <template v-else-if="mode === 'reject'">驳回后该草稿结束，起草人需要重新起草。</template>
            <template v-else>只能删除你本人起草、未被引用的草稿。删除后无法恢复。</template>
          </p>
          <label v-if="mode !== 'delete'" class="form-field"><span class="label">理由</span><textarea v-model="reason" rows="3" maxlength="1000" class="field resize-none" placeholder="写入审计" /></label>
        </div>
        <p v-if="formError" class="mt-4 text-[12.5px] text-threat" role="alert">{{ formError }}</p>
      </template>
    </LoadState>

    <template v-if="cfg && (decidable || mode !== 'view')" #foot>
      <template v-if="mode === 'view'">
        <button type="button" class="act-ghost" @click="enter('reject')">驳回</button>
        <button type="button" class="act" @click="enter('approve')">批准配置</button>
      </template>
      <template v-else>
        <button type="button" class="act-ghost" :disabled="busy" @click="enter('view')">返回</button>
        <button type="button" :class="mode === 'approve' ? 'act' : 'act-danger'" :disabled="busy" @click="confirm">{{ mode === 'approve' ? '确认批准' : mode === 'reject' ? '确认驳回' : '确认删除' }}</button>
      </template>
    </template>
  </Drawer>
</template>
