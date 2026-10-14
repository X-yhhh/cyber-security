<script setup lang="ts">
/**
 * 403：当前会话的权限与该页 anyOf 无交集。守卫在加载目标组件之前改道到这里，
 * 因此目标页面不会挂载、也不会发出数据请求。只说明“无权访问”，不提示所需权限或对象状态。
 */
import { RouterLink, useRoute } from 'vue-router'
import { ArrowRight } from 'lucide-vue-next'

const route = useRoute()
</script>

<template>
  <section class="max-w-xl py-10" aria-labelledby="forbidden-title">
    <p class="label mb-5 flex items-center gap-3"><span class="text-threat">403</span><span class="h-px w-6 bg-ink-line" />Forbidden</p>
    <h1 id="forbidden-title" class="text-[2.25rem] font-light leading-tight tracking-[-0.02em]">无权访问此页面</h1>
    <p class="mt-4 text-[14px] leading-relaxed text-ink-3">当前身份没有访问 <span class="num text-ink-2">{{ route.path }}</span> 的权限。角色变更需要重新登录后生效；如需开通，请联系平台管理员。</p>
    <RouterLink :to="{ name: 'workbench' }" class="link mt-10 text-[13px]">返回工作台 <ArrowRight :size="14" :stroke-width="1.5" /></RouterLink>
  </section>
</template>
