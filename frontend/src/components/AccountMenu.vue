<script setup lang="ts">
import { useActionError } from '@/composables/actionError'
/**
 * 侧栏底部账户菜单：用户名、角色中文名、修改口令、退出（权限设计第 8 节“全局”行，登录即可）。
 * 修改口令通过 v2 会话模块提交幂等请求，成功后后端撤销本人全部会话，前端回到登录页。
 * 口令只在抽屉的本地状态中短暂存在，关闭即清空。
 * 长度、两次一致与“新旧不同”在抽屉内就地提示，满足前“修改”保持禁用；后端错误同时写入抽屉与系统警告弹窗。
 */
import { computed, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { KeyRound, LogOut } from 'lucide-vue-next'
import { changePassword, logout, session } from '@/api/session'
import { roleName } from '@/api/v2/roles'
import Drawer from '@/components/Drawer.vue'
import { toast } from '@/composables/toast'
import { errText } from '@/composables/load'

const router = useRouter()
const roles = computed(() => (session.user?.roles ?? []).map((key) => roleName(key)))

async function signOut() {
  await logout()
  router.push({ name: 'login' })
}

const changing = ref(false)
const secrets = ref({ current: '', next: '', confirm: '' })
const busy = ref(false)
watch(changing, (open) => { if (!open) secrets.value = { current: '', next: '', confirm: '' } }, { flush: 'sync' })
const failure = useActionError()
watch(changing, () => { failure.value = '' })
/** 与后端口令规则一致：12—128 个字符且 UTF-8 不超过 72 字节。 */
const problem = computed(() => {
  const f = secrets.value
  if (!f.current) return '请输入当前口令。'
  if (!f.next) return ''
  if (f.next.length < 12) return `新口令至少 12 个字符，当前 ${f.next.length} 个。`
  if (new TextEncoder().encode(f.next).length > 72) return '新口令过长：按 UTF-8 计不能超过 72 字节。'
  if (f.next === f.current) return '新口令不能与当前口令相同。'
  if (f.confirm && f.next !== f.confirm) return '两次输入的新口令不一致。'
  return ''
})
const ready = computed(() => !problem.value && !!secrets.value.next && secrets.value.next === secrets.value.confirm)
async function changeSecret() {
  if (!ready.value) return
  const f = secrets.value
  failure.value = ''
  busy.value = true
  try {
    await changePassword(f.current, f.next)
    secrets.value = { current: '', next: '', confirm: '' }
    changing.value = false
    toast('口令已修改，全部会话已失效，请重新登录。')
    router.push({ name: 'login' })
  } catch (e) { failure.value = errText(e) } finally { busy.value = false }
}
</script>

<template>
  <div class="border-t border-ink-hair pt-4 text-[12px]" aria-label="账户">
    <p class="text-ink">{{ session.user?.displayName }} · <span class="num">{{ session.user?.username }}</span></p>
    <p class="mt-1 text-ink-3">{{ roles.join(' · ') || '无角色' }}</p>
    <div class="mt-4 flex gap-5">
      <button type="button" class="link text-ink-3" @click="changing = true"><KeyRound :size="13" :stroke-width="1.5" /> 修改口令</button>
      <button type="button" class="link text-ink-3" @click="signOut"><LogOut :size="13" :stroke-width="1.5" /> 退出</button>
    </div>

    <Drawer :open="changing" title="修改口令" :kicker="session.user?.username" @close="changing = false">
      <div class="space-y-6">
        <label class="form-field"><span class="label">当前口令</span><input v-model="secrets.current" type="password" autocomplete="current-password" class="field" maxlength="128" /></label>
        <label class="form-field"><span class="label">新口令（≥ 12 个字符）</span><input v-model="secrets.next" type="password" autocomplete="new-password" class="field" maxlength="128" /></label>
        <label class="form-field"><span class="label">再次输入新口令</span><input v-model="secrets.confirm" type="password" autocomplete="new-password" class="field" maxlength="128" /></label>
        <p v-if="problem && (secrets.next || secrets.confirm)" class="note note-warn" role="status" data-password-problem>{{ problem }}</p>
        <p v-if="failure" class="note note-threat text-threat" role="alert" data-password-failure>{{ failure }}</p>
        <p class="text-[12.5px] leading-relaxed text-ink-3">修改成功后本人全部会话立即失效，需要用新口令重新登录。当前口令连续输错会按登录限速暂时锁定。</p>
      </div>
      <template #foot>
        <button type="button" class="act-ghost" @click="changing = false">取消</button>
        <button type="button" class="act" :disabled="busy || !ready" @click="changeSecret">修改</button>
      </template>
    </Drawer>
  </div>
</template>
