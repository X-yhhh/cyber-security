<script setup lang="ts">
/**
 * 新建用户（iam.manage）：用户名、显示名与初始口令。新账号不带任何角色，绑定在用户抽屉里另行添加。
 * 口令只留在本组件内存中，关闭或重新打开即清空，不写入日志或本地存储。
 */
import { reactive, ref, watch } from 'vue'
import Drawer from '@/components/Drawer.vue'
import type { CreateUser } from '@/api/v2/iam'
import { passwordProblem } from './shared'

const props = defineProps<{ open: boolean; busy?: boolean }>()
const emit = defineEmits<{ create: [body: CreateUser]; close: [] }>()

const form = reactive({ username: '', displayName: '', password: '', confirm: '' })
const error = ref('')
watch(() => props.open, () => { Object.assign(form, { username: '', displayName: '', password: '', confirm: '' }); error.value = '' })

function submit() {
  const username = form.username.trim(), displayName = form.displayName.trim()
  if (!username || username.length > 64) { error.value = '请填写用户名（最多 64 个字符）。'; return }
  if (!displayName || displayName.length > 128) { error.value = '请填写显示名（最多 128 个字符）。'; return }
  const pw = passwordProblem(form.password, form.confirm)
  if (pw) { error.value = pw; return }
  error.value = ''
  emit('create', { username, displayName, password: form.password })
}
</script>

<template>
  <Drawer :open="open" title="新建用户" kicker="系统管理" @close="emit('close')">
    <form class="form" autocomplete="off" @submit.prevent="submit">
      <label class="form-field"><span class="label">用户名</span>
        <input v-model="form.username" class="field num" maxlength="64" placeholder="登录用，如 zhang.wei" autocomplete="off" />
        <span class="form-hint">登录名，系统内唯一。</span>
      </label>
      <label class="form-field"><span class="label">显示名</span>
        <input v-model="form.displayName" class="field" maxlength="128" placeholder="界面上显示的姓名" />
      </label>
      <div class="grid grid-cols-2 gap-4">
        <label class="form-field"><span class="label">初始口令</span>
          <input v-model="form.password" type="password" class="field" maxlength="128" autocomplete="new-password" />
        </label>
        <label class="form-field"><span class="label">再次输入</span>
          <input v-model="form.confirm" type="password" class="field" maxlength="128" autocomplete="new-password" />
        </label>
      </div>
      <p class="form-hint">至少 12 位。请通过线下渠道告知本人，并提醒其首次登录后在账户菜单中修改。</p>
      <p class="note">新账号没有任何角色，登录后只能看到待办中心。创建后可在用户详情中添加角色绑定。</p>
      <p v-if="error" class="text-[12.5px] text-threat" role="alert">{{ error }}</p>
    </form>
    <template #foot>
      <button type="button" class="act-ghost" @click="emit('close')">取消</button>
      <button type="button" class="act" :disabled="busy" @click="submit">新建用户</button>
    </template>
  </Drawer>
</template>
