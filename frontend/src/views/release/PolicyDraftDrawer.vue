<script setup lang="ts">
import { useActionError } from '@/composables/actionError'
/**
 * 起草决策策略（policy.draft）：上传或粘贴策略 JSON，客户端按仓库 Schema 与静态不变量预校验，逐字段显示错误。
 *
 * 预校验不通过时不发送请求；通过后提交原文，模型归属、评价计划摘要、能力与签名仍由后端裁决。
 * 文件只在浏览器内读取，不上传到其他位置；错误信息不回显上传内容。
 */
import { computed, ref, watch } from 'vue'
import { CircleCheck, FileUp, TriangleAlert } from 'lucide-vue-next'
import Drawer from '@/components/Drawer.vue'
import Tag from '@/components/Tag.vue'
import { toast } from '@/composables/toast'
import { releaseApi, validateDecisionPolicy, type PolicyCheck } from '@/api/v2/release'
import { FAMILIES, familyLabel, modeLabel, releaseErr } from './shared'

const props = defineProps<{ open: boolean }>()
const emit = defineEmits<{ drafted: [id: string]; close: [] }>()

const MAX_BYTES = 256 * 1024
const text = ref('')
const fileName = ref('')
const check = ref<PolicyCheck | null>(null)
const error = useActionError()
const busy = ref(false)
watch(() => props.open, (v) => { if (v) { text.value = ''; fileName.value = ''; check.value = null; error.value = '' } })

let timer: ReturnType<typeof setTimeout> | undefined
watch(text, (v) => {
  clearTimeout(timer)
  if (!v.trim()) { check.value = null; return }
  timer = setTimeout(() => { check.value = validateDecisionPolicy(v) }, 250)
})

function pick(e: Event) {
  const input = e.target as HTMLInputElement
  const file = input.files?.[0]
  input.value = ''
  if (!file) return
  if (file.size > MAX_BYTES) { error.value = '策略文件不能超过 256 KB。'; return }
  error.value = ''
  fileName.value = file.name
  void file.text().then((t) => { text.value = t })
}

const policy = computed(() => (check.value?.valid ? check.value.policy : null))
const issues = computed(() => (check.value && !check.value.valid ? check.value.issues : []))

async function submit() {
  const result = validateDecisionPolicy(text.value)
  check.value = result
  if (!text.value.trim()) { error.value = '请上传或粘贴策略 JSON。'; return }
  if (!result.valid) { error.value = `预校验未通过（${result.issues.length} 处），请修正后再提交。`; return }
  error.value = ''
  busy.value = true
  try {
    const r = await releaseApi.draftPolicy(text.value)
    toast('已起草策略，等待他人审核。')
    emit('drafted', r.id)
  } catch (e) { error.value = releaseErr(e, 'policy') } finally { busy.value = false }
}
</script>

<template>
  <Drawer :open="open" title="起草决策策略" kicker="发布管理" @close="emit('close')">
    <div class="form">
      <p class="note">上传符合 host-guard/5.0.0-rc.4 的策略 JSON。提交前按契约 Schema 与静态不变量预校验；模型、评价计划与能力的归属由后端核验。</p>

      <div class="form-field">
        <span class="label">策略文件</span>
        <label class="flex cursor-pointer items-center gap-3 rounded border border-dashed border-ink-line px-4 py-3 text-[13px] transition-colors hover:border-ink-3">
          <FileUp :size="16" :stroke-width="1.5" class="text-ink-3" aria-hidden="true" />
          <span class="min-w-0 flex-1 truncate" :class="fileName ? 'text-ink' : 'text-ink-3'">{{ fileName || '选择 .json 文件，或在下方粘贴原文' }}</span>
          <span class="act-ghost act-sm">选择文件</span>
          <input type="file" accept=".json,application/json" class="sr-only" @change="pick" />
        </label>
      </div>

      <label class="form-field"><span class="label">策略原文</span>
        <textarea v-model="text" rows="12" spellcheck="false" class="field num resize-y text-[11.5px] leading-[1.55]" placeholder="{ &quot;contractVersion&quot;: &quot;host-guard/5.0.0-rc.4&quot;, … }" />
      </label>

      <section v-if="check" aria-live="polite">
        <div v-if="policy" class="rounded border border-ok/30 bg-ok-soft px-3.5 py-3 text-[12.5px]">
          <p class="flex items-center gap-2 text-ink"><CircleCheck :size="14" :stroke-width="1.5" class="text-ok" aria-hidden="true" />预校验通过</p>
          <dl class="mt-2 grid grid-cols-[5rem_minmax(0,1fr)] gap-x-3 gap-y-1 text-ink-2">
            <dt class="text-ink-3">版本</dt><dd class="num break-all">{{ policy.policyVersion }}</dd>
            <dt class="text-ink-3">模式</dt><dd><Tag :tone="policy.mode === 'alert_only' ? 'mute' : 'warn'" :label="modeLabel[policy.mode] ?? policy.mode" /></dd>
            <dt class="text-ink-3">允许自动</dt><dd>{{ FAMILIES.filter((f) => policy!.familyPolicies.find((x) => x.family === f)?.autoEligible).map((f) => familyLabel[f]).join('、') || '无（全部只告警）' }}</dd>
            <dt class="text-ink-3">支持能力</dt><dd class="num">{{ policy.supportedCapabilityIds.length }} 项</dd>
          </dl>
        </div>
        <div v-else class="rounded border border-threat/30 bg-threat-soft px-3.5 py-3 text-[12.5px]" role="alert">
          <p class="flex items-center gap-2 text-ink"><TriangleAlert :size="14" :stroke-width="1.5" class="text-threat" aria-hidden="true" />预校验发现 {{ issues.length }} 处问题，修正前不会提交</p>
          <ul class="mt-2 max-h-48 space-y-1.5 overflow-auto">
            <li v-for="(x, i) in issues.slice(0, 30)" :key="i" class="grid grid-cols-[minmax(0,9rem)_minmax(0,1fr)] gap-3">
              <span class="num truncate text-ink-2" :title="x.path || '/'">{{ x.path || '/' }}</span>
              <span class="text-ink-2">{{ x.message }}</span>
            </li>
          </ul>
          <p v-if="issues.length > 30" class="mt-2 text-ink-3">另有 {{ issues.length - 30 }} 处未显示。</p>
        </div>
      </section>
      <p v-if="error" class="text-[12.5px] text-threat" role="alert">{{ error }}</p>
    </div>
    <template #foot>
      <button type="button" class="act-ghost" @click="emit('close')">取消</button>
      <button type="button" class="act" :disabled="busy || (!!check && !check.valid)" @click="submit">提交草稿</button>
    </template>
  </Drawer>
</template>
