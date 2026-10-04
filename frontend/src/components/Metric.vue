<script setup lang="ts">
/** 大号指标：数字按进入视口时计数滚动，无卡片容器，靠上边线分组。 */
import { onMounted, ref, watch } from 'vue'

const props = defineProps<{ label: string; value: number; unit?: string; digits?: number; note?: string; tone?: 'threat' | 'signal' }>()
const shown = ref(0)
const el = ref<HTMLElement>()

onMounted(() => {
  const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches
  const io = new IntersectionObserver(([e]) => {
    if (!e.isIntersecting) return
    io.disconnect()
    if (reduced) return void (shown.value = props.value)
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
// 数据异步到达后直接更新到新值
watch(() => props.value, (v) => { shown.value = v })
</script>

<template>
  <div ref="el" class="border-t border-ink pt-5">
    <p class="label">{{ label }}</p>
    <p class="mt-4 flex items-baseline gap-1.5">
      <span class="num text-[2.5rem] font-light leading-none tracking-[-0.03em]" :class="tone === 'threat' ? 'text-threat' : tone === 'signal' ? 'text-signal' : ''">
        {{ shown.toLocaleString('zh-CN', { minimumFractionDigits: digits ?? 0, maximumFractionDigits: digits ?? 0 }) }}
      </span>
      <span v-if="unit" class="text-[13px] text-ink-3">{{ unit }}</span>
    </p>
    <p v-if="note" class="mt-3 text-[12.5px] text-ink-3">{{ note }}</p>
  </div>
</template>
