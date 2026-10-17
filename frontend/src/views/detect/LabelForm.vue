<script setup lang="ts">
import { useActionError } from '@/composables/actionError'
/**
 * 观察样本标注（POST /api/v2/feedback）：检测记录的观察与推理详情共用。调用方只在持有 `feedback.label` 时渲染。
 * 提交后为待复核（pending），由他人独立复核；复核通过也不进入在线训练。
 */
import { reactive, watch } from 'vue'
import { detectApi } from '@/api/v2/detect'
import { guardFeedbackLabel } from '@/api/types'
import { errText } from '@/composables/load'
import { toast } from '@/composables/toast'

/** `autoOpen`：从列表中点“标注”进入时直接展开表单。 */
const props = defineProps<{ observationId: string; evidenceRef: string; title?: string; autoOpen?: boolean }>()
const emit = defineEmits<{ submitted: [] }>()

const form = reactive({ open: false, label: 'attack', evidenceRef: '', busy: false, error: useActionError(), done: '' })
function reset() {
  form.open = Boolean(props.autoOpen)
  form.label = 'attack'
  form.evidenceRef = props.evidenceRef
  form.error = ''
  form.done = ''
}
watch(() => props.observationId, reset, { immediate: true })

async function submit() {
  if (!form.evidenceRef.trim()) {
    form.error = '请填写证据引用说明'
    return
  }
  form.busy = true
  form.error = ''
  form.done = ''
  try {
    await detectApi.createFeedback(props.observationId, form.label, form.evidenceRef.trim())
    form.done = '已提交标注，等待他人复核'
    toast('标注已提交，等待独立复核')
    emit('submitted')
  } catch (e) {
    form.error = errText(e)
  } finally {
    form.busy = false
  }
}
</script>

<template>
  <div class="mt-8 border-t border-ink-hair pt-6">
    <div class="flex items-center justify-between">
      <h3 class="section-title">样本标注</h3>
      <button v-if="!form.open" type="button" class="link text-[12.5px]" @click="form.open = true">{{ title ?? '标注此观察' }}</button>
    </div>
    <div v-if="form.open" class="mt-4 space-y-4 text-[13px]">
      <label class="form-field">
        <span class="label">标注结论</span>
        <select v-model="form.label" aria-label="标注结论" class="field">
          <option v-for="(lbl, k) in guardFeedbackLabel" :key="k" :value="k">{{ lbl }}</option>
        </select>
      </label>
      <label class="form-field">
        <span class="label">证据引用说明</span>
        <input v-model="form.evidenceRef" aria-label="证据引用说明" class="field" maxlength="1000" />
        <span class="text-[12px] text-ink-3">提交后为待复核，须由他人独立复核；复核通过也不会自动进入在线训练。</span>
      </label>
      <p v-if="form.error" role="alert" class="text-[12.5px] text-threat">{{ form.error }}</p>
      <p v-if="form.done" class="text-[12.5px] text-ok">{{ form.done }}</p>
      <div class="flex items-center gap-4">
        <button type="button" class="act" :disabled="form.busy" @click="submit">{{ form.busy ? '提交中…' : '提交标注' }}</button>
        <button type="button" class="link text-[12.5px]" @click="form.open = false">取消</button>
      </div>
    </div>
  </div>
</template>
