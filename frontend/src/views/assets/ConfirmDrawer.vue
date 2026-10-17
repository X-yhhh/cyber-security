<script setup lang="ts">
import { useActionError } from '@/composables/actionError'
/**
 * 二次确认抽屉（前端设计文档第 3.5 节第 8 条）：停用、退役、撤销、吊销、删除前写明影响，必要时填写写入审计的理由。
 *
 * - `reason`：required 必填、optional 可空、none 不显示理由框；关闭或重新打开时清空。
 * - 只负责确认，不发请求；调用方在 confirm 回调里提交并决定何时关闭。
 */
import { ref, watch } from 'vue'
import Drawer from '@/components/Drawer.vue'

const props = withDefaults(defineProps<{
  open: boolean; title: string; kicker?: string; note: string; tone?: 'warn' | 'threat' | 'plain'
  confirmLabel: string; danger?: boolean; reason?: 'required' | 'optional' | 'none'; reasonLabel?: string; busy?: boolean
}>(), { tone: 'warn', danger: false, reason: 'required', reasonLabel: '理由', busy: false })
const emit = defineEmits<{ confirm: [reason: string]; close: [] }>()

const text = ref('')
const error = useActionError()
watch(() => props.open, () => { text.value = ''; error.value = '' })

function submit() {
  const v = text.value.trim()
  if (props.reason === 'required' && !v) { error.value = '请填写理由，理由会写入审计。'; return }
  error.value = ''
  emit('confirm', v)
}
</script>

<template>
  <Drawer :open="open" :title="title" :kicker="kicker" @close="emit('close')">
    <p class="note mb-5" :class="tone === 'threat' ? 'note-threat' : tone === 'warn' ? 'note-warn' : ''">{{ note }}</p>
    <slot />
    <label v-if="reason !== 'none'" class="form-field mt-6"><span class="label">{{ reasonLabel }}<template v-if="reason === 'optional'">（可选）</template></span>
      <textarea v-model="text" rows="3" maxlength="1000" class="field resize-none" placeholder="写入审计" />
      <span v-if="error" class="form-hint text-threat" role="alert">{{ error }}</span>
    </label>
    <template #foot>
      <button type="button" class="act-ghost" @click="emit('close')">取消</button>
      <button type="button" :class="danger ? 'act-danger' : 'act'" :disabled="busy" @click="submit">{{ confirmLabel }}</button>
    </template>
  </Drawer>
</template>
