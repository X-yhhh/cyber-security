<script setup lang="ts">
/** 404：未知地址。控制台内渲染在外壳中并给出返回工作台的入口；控制台外返回首页。 */
import { computed } from 'vue'
import { RouterLink, useRoute } from 'vue-router'
import { ArrowRight } from 'lucide-vue-next'

const route = useRoute()
const inConsole = computed(() => route.meta.shell === 'console')
</script>

<template>
  <section :class="inConsole ? 'max-w-xl py-10' : 'mx-auto flex min-h-screen max-w-xl flex-col justify-center px-6'" aria-labelledby="not-found-title">
    <p class="label mb-5 flex items-center gap-3"><span class="text-signal">404</span><span class="h-px w-6 bg-ink-line" />Not Found</p>
    <h1 id="not-found-title" class="text-[2.25rem] font-light leading-tight tracking-[-0.02em]">页面不存在</h1>
    <p class="mt-4 text-[14px] leading-relaxed text-ink-3">没有找到 <span class="num text-ink-2">{{ route.path }}</span>。地址可能已迁移到新的两级菜单，请从左侧菜单重新进入。</p>
    <RouterLink v-if="inConsole" :to="{ name: 'workbench' }" class="link mt-10 text-[13px]">返回工作台 <ArrowRight :size="14" :stroke-width="1.5" /></RouterLink>
    <RouterLink v-else to="/" class="link mt-10 text-[13px]">返回首页 <ArrowRight :size="14" :stroke-width="1.5" /></RouterLink>
  </section>
</template>
