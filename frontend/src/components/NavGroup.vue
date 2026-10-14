<script setup lang="ts">
/**
 * 侧栏一级组：标题可折叠，展开时列出二级项。当前路由所在组由父组件强制展开。
 * 当前二级项用墨色实心底 + 白字标识，与登录按钮一致（前端设计文档第 3.2 节，视觉基线 v2）。
 */
import { computed } from 'vue'
import { RouterLink } from 'vue-router'
import { ChevronDown } from 'lucide-vue-next'
import { routeName, type MenuGroup } from '@/router/nav'

const props = defineProps<{ group: MenuGroup; open: boolean; activeItem?: string }>()
const emit = defineEmits<{ toggle: []; navigate: [] }>()
const listId = computed(() => `nav-group-${props.group.key}`)
</script>

<template>
  <li>
    <button
      type="button"
      class="flex w-full items-center justify-between rounded px-3 py-1.5 text-left text-[12px] text-ink-4 transition-colors hover:text-ink"
      :aria-expanded="open"
      :aria-controls="listId"
      @click="emit('toggle')"
    >
      <span>{{ group.title }}</span>
      <ChevronDown :size="13" :stroke-width="1.5" class="transition-transform duration-300" :class="open ? '' : '-rotate-90'" />
    </button>
    <ul v-show="open" :id="listId" class="mb-3 space-y-px">
      <li v-for="i in group.items" :key="i.key">
        <RouterLink
          :to="{ name: routeName(i) }"
          class="flex items-center gap-2.5 rounded px-3 py-1.5 text-[13.5px] transition-colors duration-200"
          :class="activeItem === i.key ? 'bg-ink font-medium text-paper' : 'text-ink-2 hover:bg-paper-soft hover:text-ink'"
          :aria-current="activeItem === i.key ? 'page' : undefined"
          @click="emit('navigate')"
        >
          <component :is="i.icon" :size="16" :stroke-width="1.5" class="shrink-0" :class="activeItem === i.key ? 'text-paper' : 'text-ink-3'" aria-hidden="true" />
          {{ i.title }}
        </RouterLink>
      </li>
    </ul>
  </li>
</template>
