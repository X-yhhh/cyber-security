<script setup lang="ts">
/**
 * 控制台外壳：左侧文字导航（按功能模块），顶部仅保留面包屑与会话信息。
 * 不使用卡片化侧栏；当前模块由一条细线和墨色文字标识。
 * 会话信息来自 /auth/me，顶栏状态来自 /health/ready 与传感器列表（无权限时不显示）。
 * 左下角「修改口令」调用 POST /auth/password：成功后后端撤销本人全部会话，前端清空会话并回到登录页。
 */
import { computed, onMounted, ref, watch } from 'vue'
import { RouterLink, RouterView, useRoute, useRouter } from 'vue-router'
import { api, resetCsrf } from '@/api/client'
import { can, logout, session } from '@/api/session'
import type { SensorView } from '@/api/types'
import { KeyRound, LogOut } from 'lucide-vue-next'
import { modules } from '@/router'
import Drawer from '@/components/Drawer.vue'
import { toast } from '@/composables/toast'
import { errText } from '@/composables/load'

const route = useRoute()
const active = computed(() => (route.meta.parent as string | undefined) ?? (route.name as string))
const activeModule = computed(() => modules.find((m) => m.name === active.value))
const router = useRouter()
const ready = ref<boolean | null>(null)
const degraded = ref<SensorView[]>([])
onMounted(async () => {
  try { await api.get('/health/ready'); ready.value = true } catch { ready.value = false }
  if (can('sensor.read')) {
    try { degraded.value = (await api.get<SensorView[]>('/sensors')).filter((x) => x.status !== 'active') } catch { /* 忽略 */ }
  }
})
async function signOut() {
  await logout()
  router.push({ name: 'login' })
}
const index = computed(() => modules.findIndex((m) => m.name === active.value))

/** 自助改密：请求体字段名集中定义，口令只在本抽屉的本地状态中短暂存在。 */
const SELF_FIELDS = { current: 'currentPassword', next: 'newPassword' } as const
const changing = ref(false)
const secrets = ref({ current: '', next: '', confirm: '' })
const busy = ref(false)
watch(changing, (open) => { if (!open) secrets.value = { current: '', next: '', confirm: '' } }, { flush: 'sync' })
async function changeSecret() {
  const f = secrets.value
  if (f.next.length < 12) return toast('新口令至少 12 个字符。', 'warn')
  if (f.next !== f.confirm) return toast('两次输入的新口令不一致。', 'warn')
  busy.value = true
  try {
    await api.post('/auth/password', { [SELF_FIELDS.current]: f.current, [SELF_FIELDS.next]: f.next })
    secrets.value = { current: '', next: '', confirm: '' }
    changing.value = false
    session.user = null
    resetCsrf()
    toast('口令已修改，全部会话已失效，请重新登录。')
    router.push({ name: 'login' })
  } catch (e) { toast(errText(e), 'threat') } finally { busy.value = false }
}
</script>

<template>
  <div class="flex min-h-screen bg-paper">
    <aside class="sticky top-0 hidden h-screen w-60 shrink-0 flex-col border-r border-ink-hair px-8 py-8 md:flex">
      <RouterLink to="/" class="flex items-center gap-2.5">
        <span class="inline-flex h-4 w-4 items-center justify-center border border-ink"><span class="h-1 w-1 bg-signal" /></span>
        <span class="text-[13px] font-medium tracking-[0.2em]">SENTINEL</span>
      </RouterLink>

      <nav class="mt-16 flex-1" aria-label="功能模块">
        <ul class="space-y-1">
          <li v-for="(m, i) in modules" :key="m.name">
            <RouterLink
              :to="{ name: m.name }"
              class="group flex items-center gap-3 py-2 text-[13.5px] transition-colors duration-300"
              :class="active === m.name ? 'text-ink' : 'text-ink-3 hover:text-ink'"
              :aria-current="active === m.name ? 'page' : undefined"
            >
              <span class="h-px transition-all duration-500 ease-out" :class="active === m.name ? 'w-5 bg-signal' : 'w-2 bg-ink-line group-hover:w-3.5'" />
              <span class="num w-5 text-[10.5px] text-ink-4">{{ String(i + 1).padStart(2, '0') }}</span>
              {{ m.title }}
            </RouterLink>
          </li>
        </ul>
      </nav>

      <div class="border-t border-ink-hair pt-5 text-[12px]">
        <p class="text-ink">{{ session.user?.displayName }} · {{ session.user?.username }}</p>
        <p class="mt-1 text-ink-3">{{ session.user?.roles.join(' · ') || '无角色' }}</p>
        <div class="mt-4 flex gap-5">
          <button class="link text-ink-3" @click="changing = true"><KeyRound :size="13" :stroke-width="1.5" /> 修改口令</button>
          <button class="link text-ink-3" @click="signOut"><LogOut :size="13" :stroke-width="1.5" /> 退出</button>
        </div>
      </div>
    </aside>

    <div class="min-w-0 flex-1">
      <header class="sticky top-0 z-20 flex h-14 items-center justify-between border-b border-ink-hair bg-paper/85 px-6 backdrop-blur md:px-12">
        <div class="flex items-center gap-3 text-[12.5px]">
          <span class="num text-ink-4">{{ String(index + 1).padStart(2, '0') }}</span>
          <span class="text-ink-3">{{ activeModule?.en }}</span>
          <template v-if="route.meta.parent">
            <span class="text-ink-4">/</span>
            <span class="num text-ink">{{ route.params.id }}</span>
          </template>
        </div>
        <div class="flex items-center gap-6 text-[12px] text-ink-3">
          <span v-if="ready !== null" class="hidden items-center gap-2 md:flex"><span class="dot" :class="ready ? 'bg-ok' : 'bg-threat'" />{{ ready ? '控制面正常' : '数据库不可用' }}</span>
          <span v-for="x in degraded.slice(0, 2)" :key="x.id" class="hidden items-center gap-2 md:flex"><span class="dot bg-warn" />{{ x.agentKey }} {{ x.status }}</span>
        </div>
      </header>

      <main class="px-6 pb-24 pt-12 md:px-12 lg:px-16">
        <RouterView v-slot="{ Component, route: r }">
          <Transition name="page" mode="out-in">
            <component :is="Component" :key="r.fullPath" />
          </Transition>
        </RouterView>
      </main>
    </div>

    <Drawer :open="changing" title="修改口令" :kicker="session.user?.username" @close="changing = false">
      <div class="space-y-6">
        <label class="block"><span class="label">当前口令</span><input v-model="secrets.current" type="password" autocomplete="current-password" class="field mt-2" maxlength="128" /></label>
        <label class="block"><span class="label">新口令（≥ 12 个字符）</span><input v-model="secrets.next" type="password" autocomplete="new-password" class="field mt-2" maxlength="128" /></label>
        <label class="block"><span class="label">再次输入新口令</span><input v-model="secrets.confirm" type="password" autocomplete="new-password" class="field mt-2" maxlength="128" /></label>
        <p class="text-[12.5px] leading-relaxed text-ink-3">修改成功后本人全部会话立即失效，需要用新口令重新登录。当前口令连续输错会按登录限速暂时锁定。</p>
      </div>
      <template #foot>
        <button class="link text-[13px]" @click="changing = false">取消</button>
        <button class="act" :disabled="busy || !secrets.current || !secrets.next" @click="changeSecret">修改</button>
      </template>
    </Drawer>
  </div>
</template>
