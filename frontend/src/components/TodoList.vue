<script setup lang="ts">
/**
 * 待办列表（权限设计第 7.4 节、前端设计文档第 10.1 节，任务单 U0.7）：
 * 按「需要批准 → 需要研判 → 其他」分组，组标题带计数，每条显示对象、资产、时间与右侧进入按钮。
 *
 * - 组顺序固定为 approve、triage、other，与传入顺序无关；没有条目的组不显示。
 * - 计数以后端返回值为准（`count` 可大于本页条目数）；`truncated` 时写明“仅显示最近 N 条”。
 * - 条目没有 `to`（目标页未上线或无权访问）时不显示进入按钮，只列出事项。
 * - 本组件只负责展示，不判断权限、不发请求；数据由待办中心页面从 `GET /todos` 映射而来。
 */
import { computed } from 'vue'
import { RouterLink, type RouteLocationRaw } from 'vue-router'
import { ArrowRight } from 'lucide-vue-next'
import { fmtTime } from '@/api/types'

export type TodoGroupKey = 'approve' | 'triage' | 'other'
export interface TodoItem {
  id: string
  /** 对象，如「资产授权 · mac-01」。 */
  title: string
  /** 资产名称；能显示名称时不显示 UUID。 */
  asset?: string | null
  /** ISO 时间。 */
  at?: string | null
  to?: RouteLocationRaw
  /** 进入按钮文字，缺省为「进入」。 */
  action?: string
}
export interface TodoGroup { key: TodoGroupKey; count?: number; items: readonly TodoItem[] }

const props = withDefaults(defineProps<{ groups: readonly TodoGroup[]; truncated?: boolean; limit?: number; emptyText?: string }>(), {
  limit: 100,
  emptyText: '当前没有需要你处理的事项',
})

const ORDER: readonly TodoGroupKey[] = ['approve', 'triage', 'other']
const TITLE: Record<TodoGroupKey, string> = { approve: '需要批准', triage: '需要研判', other: '其他' }

const shown = computed(() => ORDER
  .map((key) => {
    const list = props.groups.filter((g) => g.key === key)
    const items = list.flatMap((g) => g.items)
    const count = list.reduce((n, g) => n + (g.count ?? g.items.length), 0)
    return { key, title: TITLE[key], count, items }
  })
  .filter((g) => g.items.length > 0 || g.count > 0))
</script>

<template>
  <p v-if="!shown.length" class="py-8 text-center text-[13px] text-ink-3" data-todo-empty>{{ emptyText }}</p>
  <div v-else class="space-y-6">
    <section v-for="g in shown" :key="g.key" :aria-label="`${g.title}（${g.count}）`" :data-todo-group="g.key">
      <h3 class="mb-1 flex items-center gap-2 text-[13px] font-medium text-ink">
        {{ g.title }}<span class="num rounded-full bg-paper-soft px-2 text-[11.5px] font-normal leading-5 text-ink-2">{{ g.count }}</span>
      </h3>
      <ul>
        <li v-for="t in g.items" :key="t.id" class="flex items-center gap-4 border-b border-ink-hair py-2.5 last:border-b-0">
          <div class="min-w-0 flex-1">
            <p class="truncate text-[13.5px] text-ink">{{ t.title }}</p>
            <p class="mt-0.5 flex flex-wrap gap-x-3 text-[12px] text-ink-3">
              <span v-if="t.asset">{{ t.asset }}</span>
              <span v-if="t.at" class="num">{{ fmtTime(t.at) }}</span>
            </p>
          </div>
          <RouterLink v-if="t.to" :to="t.to" class="act-ghost act-sm">{{ t.action ?? '进入' }}<ArrowRight :size="13" :stroke-width="1.5" /></RouterLink>
        </li>
      </ul>
    </section>
    <p v-if="truncated" class="text-[12px] text-ink-3">仅显示最近 {{ limit }} 条，计数以后端统计为准。</p>
  </div>
</template>
