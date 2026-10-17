<script setup lang="ts">
import { useActionError } from '@/composables/actionError'
/**
 * 登录。左侧复用首屏粒子场景的"边界"形态作为品牌延续，右侧是极简表单。
 * 通过 session.ts 提交到 /api/v2/auth/login 建立服务端会话；失败使用后端稳定且脱敏的消息
 * （不区分用户名不存在与密码错误），并附带 request-id 便于排查。
 */
import { onBeforeUnmount, onMounted, ref, shallowRef } from 'vue'
import { RouterLink, useRoute, useRouter } from 'vue-router'
import { login } from '@/api/session'
import { ApiError } from '@/api/client'
import { errText } from '@/composables/load'
import { ArrowLeft, ArrowRight } from 'lucide-vue-next'
import { ThreatScene } from '@/three/ThreatScene'

const router = useRouter()
const route = useRoute()
const requestId = ref('')
const canvas = ref<HTMLCanvasElement>()
const scene = shallowRef<ThreatScene>()
const username = ref('')
const password = ref('')
const error = useActionError()
const busy = ref(false)

let t = 0
let timer = 0
onMounted(() => {
  try {
    scene.value = new ThreatScene(canvas.value!, { centered: true })
    // 在"边界"与"感知"两个形态之间缓慢往复，暗示持续观测
    timer = window.setInterval(() => {
      t += 0.004
      scene.value?.setProgress((Math.sin(t) * 0.5 + 0.5) * 0.9)
    }, 16)
  } catch {
    /* WebGL 不可用时保留静态版式 */
  }
})
onBeforeUnmount(() => {
  clearInterval(timer)
  scene.value?.dispose()
})

async function submit() {
  error.value = ''
  requestId.value = ''
  if (!username.value.trim() || !password.value) {
    error.value = '请输入用户名和密码。'
    return
  }
  busy.value = true
  try {
    await login(username.value.trim(), password.value)
    password.value = ''
    const to = typeof route.query.redirect === 'string' && route.query.redirect.startsWith('/console') ? route.query.redirect : '/console'
    router.push(to)
  } catch (e) {
    error.value = e instanceof ApiError ? errText(e) : '登录失败，请稍后重试。'
    requestId.value = e instanceof ApiError ? e.requestId ?? '' : ''
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <main class="grid min-h-screen bg-paper lg:grid-cols-[1.15fr_1fr]">
    <section class="relative hidden overflow-hidden border-r border-ink-hair lg:block" aria-hidden="true">
      <canvas ref="canvas" class="absolute inset-0 h-full w-full" />
      <div class="absolute bottom-12 left-12 right-12 flex items-end justify-between">
        <p class="max-w-xs text-[13px] leading-relaxed text-ink-3">控制台会话仅在受控部署内有效。所有登录、失败与限速事件都会写入审计。</p>
        <span class="label">00 · Boundary</span>
      </div>
    </section>

    <section class="flex flex-col px-8 py-10 md:px-16">
      <RouterLink to="/" class="link self-start text-[13px] text-ink-3"><ArrowLeft :size="14" :stroke-width="1.5" /> 返回概览</RouterLink>

      <form class="my-auto w-full max-w-sm" novalidate @submit.prevent="submit">
        <p class="label mb-6">Sign in</p>
        <h1 class="text-[2.25rem] font-light leading-tight tracking-[-0.02em]">登录控制台</h1>
        <p class="mt-4 text-[14px] text-ink-3">使用分配给你的平台账号。</p>

        <div class="mt-14 space-y-8">
          <label class="block">
            <span class="label">用户名</span>
            <input v-model="username" class="field mt-2" autocomplete="username" autofocus />
          </label>
          <label class="block">
            <span class="label">密码</span>
            <input v-model="password" type="password" class="field mt-2" autocomplete="current-password" />
          </label>
        </div>

        <p class="mt-6 min-h-5 break-words text-[13px] text-threat" role="alert">{{ error }}</p>

        <button type="submit" class="act mt-4 w-full justify-between" :disabled="busy">
          {{ busy ? '正在验证…' : '登录' }}
          <ArrowRight :size="14" :stroke-width="1.5" />
        </button>
        <p class="mt-6 text-[12px] leading-relaxed text-ink-4">连续失败会触发持久限速。忘记密码请联系平台管理员。</p>
      </form>

      <p class="num text-[11px] text-ink-4">SENTINEL · {{ requestId ? `request-id ${requestId}` : 'request-id 在错误时显示' }}</p>
    </section>
  </main>
</template>
