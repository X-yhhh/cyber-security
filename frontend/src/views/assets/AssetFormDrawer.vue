<script setup lang="ts">
import { useActionError } from '@/composables/actionError'
/**
 * 资产登记与资料编辑（asset.manage，接口设计第 2、3.2 节）。
 *
 * - 登记：资产键、平台、环境、责任人必填，显示名与说明可选；登记后这三项不可修改，登记不授予执行权。
 * - 编辑：显示名、说明、关键性、责任人；只提交改动过的字段，清空显示名或说明时显式传 null。
 * 提交与重读由父组件负责，本组件只校验字段并发出请求体。
 */
import { computed, reactive, watch } from 'vue'
import Drawer from '@/components/Drawer.vue'
import {
  ASSET_FIELDS, CRITICALITIES, criticalityLabel, platformLabel,
  type Asset, type AssetCreate, type AssetEnv, type AssetUpdate, type Criticality, type Platform,
} from '@/api/v2/assets'
import { guardAssetEnvLabel } from '@/api/types'

const props = defineProps<{ open: boolean; asset?: Asset | null; busy?: boolean }>()
const emit = defineEmits<{ create: [body: AssetCreate]; update: [body: AssetUpdate]; close: [] }>()

const editing = computed(() => !!props.asset)
const ENVS: readonly AssetEnv[] = ['research', 'lab', 'authorized']
const PLATFORMS: readonly Platform[] = ['macos', 'windows']
const form = reactive({ assetKey: '', platform: 'macos' as Platform, environment: 'lab' as AssetEnv, owner: '', displayName: '', notes: '', criticality: 'medium' as Criticality })
const error = useActionError()

watch(() => props.open, (v) => {
  if (!v) return
  error.value = ''
  const a = props.asset
  Object.assign(form, {
    assetKey: a?.assetKey ?? '', platform: (a?.labels?.platform as Platform) ?? 'macos', environment: (a?.environment as AssetEnv) ?? 'lab',
    owner: a?.owner ?? '', displayName: a?.displayName ?? '', notes: a?.notes ?? '', criticality: (a?.criticality as Criticality) ?? 'medium',
  })
}, { immediate: true })

function submit() {
  const displayName = form.displayName.trim(), notes = form.notes.trim(), owner = form.owner.trim()
  if (!owner) { error.value = '请填写责任人。'; return }
  if (displayName.length > 128) { error.value = '显示名最多 128 个字符。'; return }
  if (!editing.value) {
    const key = form.assetKey.trim()
    if (!key || key.length > 128) { error.value = '请填写资产键（最多 128 个字符）。'; return }
    const body: AssetCreate = { [ASSET_FIELDS.assetKey]: key, [ASSET_FIELDS.platform]: form.platform, [ASSET_FIELDS.environment]: form.environment, [ASSET_FIELDS.owner]: owner }
    if (displayName) body.displayName = displayName
    if (notes) body.notes = notes
    error.value = ''
    emit('create', body)
    return
  }
  const a = props.asset!
  const body: AssetUpdate = {}
  if (displayName !== (a.displayName ?? '')) body[ASSET_FIELDS.displayName] = displayName || null
  if (notes !== (a.notes ?? '')) body[ASSET_FIELDS.notes] = notes || null
  if (owner !== a.owner) body[ASSET_FIELDS.owner] = owner
  if (form.criticality !== a.criticality) body[ASSET_FIELDS.criticality] = form.criticality
  if (!Object.keys(body).length) { error.value = '没有需要保存的修改。'; return }
  error.value = ''
  emit('update', body)
}
</script>

<template>
  <Drawer :open="open" :title="editing ? '编辑资产资料' : '登记资产'" :kicker="editing ? (asset?.displayName || asset?.assetKey) : '资产与接入'" @close="emit('close')">
    <form class="form" @submit.prevent="submit">
      <template v-if="!editing">
        <label class="form-field"><span class="label">资产键</span>
          <input v-model="form.assetKey" class="field num" maxlength="128" placeholder="如 lab-mac-01" autocomplete="off" />
          <span class="form-hint">资产的唯一键。资产键、平台与环境登记后不可修改。</span>
        </label>
        <div class="grid grid-cols-2 gap-4">
          <label class="form-field"><span class="label">平台</span>
            <select v-model="form.platform" class="field"><option v-for="p in PLATFORMS" :key="p" :value="p">{{ platformLabel[p] }}</option></select>
          </label>
          <label class="form-field"><span class="label">环境</span>
            <select v-model="form.environment" class="field"><option v-for="e in ENVS" :key="e" :value="e">{{ guardAssetEnvLabel[e] }}</option></select>
          </label>
        </div>
      </template>
      <label class="form-field"><span class="label">显示名</span>
        <input v-model="form.displayName" class="field" maxlength="128" placeholder="界面上显示的名称，可留空" />
      </label>
      <div class="grid gap-4" :class="editing ? 'grid-cols-2' : ''">
        <label v-if="editing" class="form-field"><span class="label">关键性</span>
          <select v-model="form.criticality" class="field"><option v-for="c in CRITICALITIES" :key="c" :value="c">{{ criticalityLabel[c] }}</option></select>
        </label>
        <label class="form-field"><span class="label">责任人</span>
          <input v-model="form.owner" class="field" maxlength="128" placeholder="负责该主机的人员或小组" />
        </label>
      </div>
      <label class="form-field"><span class="label">说明</span>
        <textarea v-model="form.notes" rows="3" maxlength="1000" class="field resize-none" placeholder="用途、位置等，可留空" />
      </label>
      <p v-if="!editing" class="note">登记只建立台账，不授予观察或执行权；授权须另行申请并由他人批准。新资产的关键性默认为「中」，登记后可编辑。</p>
      <p v-if="error" class="text-[12.5px] text-threat" role="alert">{{ error }}</p>
    </form>
    <template #foot>
      <button type="button" class="act-ghost" @click="emit('close')">取消</button>
      <button type="button" class="act" :disabled="busy" @click="submit">{{ editing ? '保存资料' : '登记资产' }}</button>
    </template>
  </Drawer>
</template>
