<script setup lang="ts">
/** 模块页头：章节编号 + 标题 + 一句说明，右侧放唯一主操作。 */
defineProps<{ no: string; title: string; desc?: string }>()
</script>

<template>
  <div class="mb-14 flex flex-col gap-8 md:flex-row md:items-end md:justify-between">
    <div>
      <p class="label mb-5 flex items-center gap-3"><span class="text-signal">{{ no }}</span><span class="h-px w-6 bg-ink-line" /><slot name="kicker" /></p>
      <h1 class="text-[2.25rem] font-light leading-tight tracking-[-0.02em]">{{ title }}</h1>
      <p v-if="desc" class="mt-4 max-w-2xl text-[14px] leading-relaxed text-ink-3">{{ desc }}</p>
    </div>
    <div class="flex items-center gap-6"><slot /></div>
  </div>
</template>
