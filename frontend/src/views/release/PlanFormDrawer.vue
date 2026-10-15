<script setup lang="ts">
/**
 * 建立冻结评价计划（evaluation.run）：登记 P6 在读取测试集前冻结的计划原件。
 * 只提交原件引用与原字节 SHA-256；后端读取原件并核对阶段、评价口径、特征档案摘要与「未提前读取测试集」声明。
 * 旧的结构化登记仍由接口支持，但页面只提供冻结原件这一种方式。
 */
import { reactive, ref, watch } from 'vue'
import Drawer from '@/components/Drawer.vue'
import { toast } from '@/composables/toast'
import { isSha256, RELEASE_FIELDS, releaseApi } from '@/api/v2/release'
import { releaseErr } from './shared'

const props = defineProps<{ open: boolean }>()
const emit = defineEmits<{ created: [id: string]; close: [] }>()

const form = reactive({ planRef: '', planSha256: '' })
const error = ref('')
const busy = ref(false)
watch(() => props.open, (v) => { if (v) { Object.assign(form, { planRef: '', planSha256: '' }); error.value = '' } })

async function submit() {
  const path = form.planRef.trim(), sha = form.planSha256.trim().toLowerCase()
  if (!path || /^[a-z][a-z0-9+.-]*:\/\//i.test(path)) { error.value = '请填写计划原件在制品根内的相对路径（不接受 URL）。'; return }
  if (!isSha256(sha)) { error.value = 'SHA-256 须为 64 位小写十六进制。'; return }
  error.value = ''
  busy.value = true
  try {
    const f = RELEASE_FIELDS.plan
    const r = await releaseApi.registerEvaluationPlan({ [f.planRef]: path, [f.planSha256]: sha })
    toast('已建立冻结评价计划。')
    emit('created', r.id)
  } catch (e) { error.value = releaseErr(e) } finally { busy.value = false }
}
</script>

<template>
  <Drawer :open="open" title="建立冻结计划" kicker="验证记录 · 评价计划" @close="emit('close')">
    <form class="form" @submit.prevent="submit">
      <p class="note">冻结计划须在读取测试集之前登记。后端按原文件字节核对摘要，并检查阶段为 P6、评价口径与特征档案一致；内容不符时拒绝（EVALUATION_PLAN_MISMATCH）。</p>
      <label class="form-field"><span class="label">计划原件引用</span>
        <input v-model="form.planRef" class="field num" maxlength="512" placeholder="如 p6/evaluation-plan.json" autocomplete="off" />
        <span class="form-hint">受控制品根内的相对路径，原件不超过 1 MB。</span></label>
      <label class="form-field"><span class="label">原件 SHA-256</span>
        <input v-model="form.planSha256" class="field num" maxlength="64" placeholder="64 位小写十六进制" autocomplete="off" />
        <span class="form-hint">原文件字节摘要（不是规范化 JSON 摘要），策略与组合将以它绑定计划。</span></label>
      <p v-if="error" class="text-[12.5px] text-threat" role="alert">{{ error }}</p>
    </form>
    <template #foot>
      <button type="button" class="act-ghost" @click="emit('close')">取消</button>
      <button type="button" class="act" :disabled="busy" @click="submit">建立计划</button>
    </template>
  </Drawer>
</template>
