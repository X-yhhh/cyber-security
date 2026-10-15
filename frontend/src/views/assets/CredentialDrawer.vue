<script setup lang="ts">
/**
 * 一次性机器凭据（任务单 F4 验收）：登记或轮换的响应里只出现这一次。
 *
 * 凭据只保存在父组件传入的 prop 中，本组件不写本地存储、不打印日志；父组件在 close 时必须把它置空，
 * 关闭后页面上不存在任何可以再次查看的入口，遗失只能再轮换。
 */
import { ref, watch } from 'vue'
import { Check, Copy, KeyRound } from 'lucide-vue-next'
import Drawer from '@/components/Drawer.vue'
import IdText from '@/components/IdText.vue'
import { toast } from '@/composables/toast'
import type { IssuedCredential } from '@/api/v2/assets'

const props = defineProps<{ issued: (IssuedCredential & { title: string; deviceKind: string }) | null }>()
const emit = defineEmits<{ close: [] }>()

const copied = ref(false)
const revealed = ref(false)
watch(() => props.issued, () => { copied.value = false; revealed.value = false })

async function copy() {
  if (!props.issued) return
  try {
    if (!navigator.clipboard) throw new Error('clipboard unavailable')
    await navigator.clipboard.writeText(props.issued.credential)
    copied.value = true
  } catch {
    revealed.value = true
    toast('无法访问剪贴板，请选中凭据后手动复制。', 'warn')
  }
}
const masked = (v: string) => `${v.slice(0, 10)}${'•'.repeat(24)}`
</script>

<template>
  <Drawer :open="!!issued" :title="issued?.title ?? ''" kicker="一次性机器凭据" @close="emit('close')">
    <template v-if="issued">
      <p class="note note-threat mb-5">凭据只在这里显示一次，关闭后无法再次查看。请立即写入{{ issued.deviceKind }}主机的安全存储；遗失只能轮换生成新凭据，旧凭据随之失效。</p>

      <div class="rounded border border-ink-line">
        <div class="flex items-center justify-between gap-3 border-b border-ink-hair px-4 py-2.5">
          <span class="flex items-center gap-2 text-[12.5px] text-ink-3"><KeyRound :size="14" :stroke-width="1.5" aria-hidden="true" />机器凭据</span>
          <span class="flex items-center gap-3">
            <button type="button" class="link text-[12.5px]" @click="revealed = !revealed">{{ revealed ? '隐藏' : '显示' }}</button>
            <button type="button" class="act-ghost act-sm" @click="copy">
              <Check v-if="copied" :size="13" :stroke-width="1.5" class="text-ok" /><Copy v-else :size="13" :stroke-width="1.5" />{{ copied ? '已复制' : '复制' }}
            </button>
          </span>
        </div>
        <p class="num select-all break-all px-4 py-3.5 text-[13px] leading-relaxed text-ink" data-credential>{{ revealed ? issued.credential : masked(issued.credential) }}</p>
      </div>

      <dl class="kv mt-5">
        <div><dt>设备</dt><dd><IdText :value="issued.id" /></dd></div>
        <div><dt>机器客户端</dt><dd><IdText :value="issued.clientId" /></dd></div>
        <div><dt>状态</dt><dd>{{ issued.status === 'pending' ? '待心跳确认' : issued.status === 'active' ? '有效' : issued.status }}</dd></div>
      </dl>
    </template>
    <template #foot>
      <button type="button" class="act" @click="emit('close')">我已保存，关闭</button>
    </template>
  </Drawer>
</template>
