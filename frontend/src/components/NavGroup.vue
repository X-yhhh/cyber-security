<script setup lang="ts">
/**
 * 侧栏一级组：标题可折叠，展开时列出二级项。当前路由所在组由父组件强制展开。
 * 当前二级项用一条钴蓝细线和墨色文字标识（沿用前端设计文档第 3 节视觉基线）。
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
      class="flex w-full items-center justify-between py-2 text-left text-[12px] tracking-[0.04em] text-ink-3 transition-colors hover:text-ink"
      :aria-expanded="open"
      :aria-controls="listId"
      @click="emit('toggle')"
    >
      <span>{{ group.title }}</span>
      <ChevronDown :size="13" :stroke-width="1.5" class="transition-transform duration-300" :class="open ? '' : '-rotate-90'" />
    </button>
    <ul v-show="open" :id="listId" class="mb-3 space-y-0.5">
      <li v-for="i in group.items" :key="i.key">
        <RouterLink
          :to="{ name: routeName(i) }"
          class="group flex items-center gap-3 py-1.5 text-[13.5px] transition-colors duration-300"
          :class="activeItem === i.key ? 'text-ink' : 'text-ink-3 hover:text-ink'"
          :aria-current="activeItem === i.key ? 'page' : undefined"
          @click="emit('navigate')"
        >
          <span class="h-px transition-all duration-500 ease-out" :class="activeItem === i.key ? 'w-5 bg-signal' : 'w-2 bg-ink-line group-hover:w-3.5'" />
          {{ i.title }}
        </RouterLink>
      </li>
    </ul>
  </li>
</template>
