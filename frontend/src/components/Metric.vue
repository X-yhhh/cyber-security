<script setup lang="ts">
/**
 * 指标：标签 + 大号数字 + 可选说明，放在面板内或面板网格中，不自带容器与分隔线（视觉基线 v2）。
 * 数字在进入视口时计数滚动；`prefers-reduced-motion` 或环境不支持 IntersectionObserver 时直接显示终值。
 * tone 只影响数字颜色。
 */
import { onBeforeUnmount, onMounted, ref, watch } from 'vue'

const props = defineProps<{ label: string; value: number; unit?: string; digits?: number; note?: string; tone?: 'threat' | 'signal' }>()
const shown = ref(0)
const el = ref<HTMLElement>()
let io: IntersectionObserver | undefined

onMounted(() => {
  const reduced = typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches
  if (reduced || typeof IntersectionObserver === 'undefined') return void (shown.value = props.value)
  io = new IntersectionObserver(([e]) => {
    if (!e.isIntersecting) return
    io?.disconnect()
    const t0 = performance.now()
    const tick = (t: number) => {
      const k = Math.min(1, (t - t0) / 1100)
      shown.value = props.value * (1 - Math.pow(1 - k, 4))
      if (k < 1) requestAnimationFrame(tick)
    }
    requestAnimationFrame(tick)
  })
  io.observe(el.value!)
})
onBeforeUnmount(() => io?.disconnect())
// 数据异步到达后直接更新到新值
watch(() => props.value, (v) => { shown.value = v })
</script>

<template>
  <div ref="el" class="min-w-0">
    <p class="label">{{ label }}</p>
    <p class="mt-2 flex items-baseline gap-1.5">
      <span class="num text-[1.75rem] font-light leading-none tracking-[-0.02em]" :class="tone === 'threat' ? 'text-threat' : tone === 'signal' ? 'text-signal' : 'text-ink'">
        {{ shown.toLocaleString('zh-CN', { minimumFractionDigits: digits ?? 0, maximumFractionDigits: digits ?? 0 }) }}
      </span>
      <span v-if="unit" class="text-[12.5px] text-ink-3">{{ unit }}</span>
    </p>
    <p v-if="note" class="mt-2 text-[12px] text-ink-3">{{ note }}</p>
  </div>
</template>
