<script setup lang="ts">
/**
 * 模型与数据集的登记表单（model.manage / dataset.manage）。
 *
 * 只登记受控制品根内的 manifest 引用与原字节 SHA-256，不接受任意 URL；后端读取并核验 manifest 后写入台账。
 * 显示名与说明可选，登记后可编辑；manifest 内容不可修改，换版本须重新登记。提交与重读由父页面负责。
 */
import { reactive, ref, watch } from 'vue'
import Drawer from '@/components/Drawer.vue'
import { isSha256, RELEASE_FIELDS, type ManifestRegistration } from '@/api/v2/release'

const props = defineProps<{ open: boolean; kind: 'models' | 'datasets'; busy?: boolean }>()
const emit = defineEmits<{ submit: [body: ManifestRegistration]; close: [] }>()

const form = reactive({ manifestRef: '', manifestSha256: '', displayName: '', notes: '' })
const error = ref('')
watch(() => props.open, (v) => { if (v) { Object.assign(form, { manifestRef: '', manifestSha256: '', displayName: '', notes: '' }); error.value = '' } })

function submit() {
  const path = form.manifestRef.trim(), sha = form.manifestSha256.trim().toLowerCase()
  const displayName = form.displayName.trim(), notes = form.notes.trim()
  if (!path || path.length > 512) { error.value = '请填写 manifest 引用（受控制品根内的相对路径）。'; return }
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(path)) { error.value = 'manifest 引用是制品根内的相对路径，不接受 URL。'; return }
  if (!isSha256(sha)) { error.value = 'SHA-256 须为 64 位小写十六进制。'; return }
  if (displayName.length > 128) { error.value = '显示名最多 128 个字符。'; return }
  const f = RELEASE_FIELDS.manifest
  const body: ManifestRegistration = { [f.manifestRef]: path, [f.manifestSha256]: sha }
  if (displayName) body.displayName = displayName
  if (notes) body.notes = notes
  error.value = ''
  emit('submit', body)
}
</script>

<template>
  <Drawer :open="open" :title="kind === 'models' ? '登记模型' : '登记数据集'" kicker="模型与数据集" @close="emit('close')">
    <form class="form" @submit.prevent="submit">
      <label class="form-field"><span class="label">manifest 引用</span>
        <input v-model="form.manifestRef" class="field num" maxlength="512" autocomplete="off" :placeholder="kind === 'models' ? '如 models/unsw-binary/manifest.json' : '如 datasets/cic-2017/manifest.json'" />
        <span class="form-hint">受控制品根内的相对路径。后端按此读取 manifest，不从任意 URL 抓取。</span>
      </label>
      <label class="form-field"><span class="label">manifest SHA-256</span>
        <input v-model="form.manifestSha256" class="field num" maxlength="64" autocomplete="off" placeholder="64 位小写十六进制" />
        <span class="form-hint">原文件字节摘要，与读取到的内容不一致时拒绝登记。</span>
      </label>
      <label class="form-field"><span class="label">显示名（可选）</span>
        <input v-model="form.displayName" class="field" maxlength="128" placeholder="界面上显示的名称" />
      </label>
      <label class="form-field"><span class="label">说明（可选）</span>
        <textarea v-model="form.notes" rows="3" maxlength="1000" class="field resize-none" placeholder="来源、用途等" />
      </label>
      <p v-if="kind === 'models'" class="note">登记后模型只是候选（candidateOnly），状态为「待校验」；校验通过也不等于可以发布，须经发布组合的评价、封存与独立批准。</p>
      <p v-else class="note">数据集键与版本取自 manifest，登记后不可修改；数据集被评价计划引用后不能退役。</p>
      <p v-if="error" class="text-[12.5px] text-threat" role="alert">{{ error }}</p>
    </form>
    <template #foot>
      <button type="button" class="act-ghost" @click="emit('close')">取消</button>
      <button type="button" class="act" :disabled="busy" @click="submit">{{ kind === 'models' ? '登记模型' : '登记数据集' }}</button>
    </template>
  </Drawer>
</template>
