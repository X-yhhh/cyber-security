<script setup lang="ts">
/**
 * 工作台（权限设计第 7.4 节）：登录后的统一入口，按卡片配置（cards.ts）渲染。
 *
 * - 卡片 anyOf 与会话权限无交集即不渲染；没有任何可见卡片时不请求汇总。
 * - 数字取自 GET /api/v2/summary（B2.5 契约）：没有权限的字段后端不返回，前端不补 0。
 * - 卡片行可点击，跳到对应列表并带上状态筛选；目标页尚未上线或无权访问时只显示数字。
 * F0 只搭框架，F2 负责完善卡片内容与定时刷新。
 */
import { computed, ref } from 'vue'
import PageHead from '@/components/PageHead.vue'
import LoadState from '@/components/LoadState.vue'
import SummaryCard from '@/components/SummaryCard.vue'
import { session } from '@/api/session'
import { fetchSummary, type WorkbenchSummary } from '@/api/v2/summary'
import { errText } from '@/composables/load'
import { allowed } from '@/router/nav'
import { cards, linker } from './cards'

const permissions = computed(() => session.user?.permissions ?? [])
const visible = computed(() => cards.filter((c) => allowed(c.anyOf, permissions.value)))
const link = computed(() => linker(permissions.value))

const summary = ref<WorkbenchSummary>({})
const loading = ref(visible.value.length > 0)
const error = ref('')
async function reload() {
  if (!visible.value.length) return
  loading.value = true
  error.value = ''
  try { summary.value = await fetchSummary() } catch (e) { error.value = errText(e) } finally { loading.value = false }
}
reload()
</script>

<template>
  <div>
    <PageHead title="工作台" desc="你权限范围内需要关注的事项。计数只覆盖你可见的资产范围，点击条目进入对应列表。">
      <template #kicker>Workbench</template>
    </PageHead>

    <p v-if="!visible.length" class="py-10 text-[13px] text-ink-3">当前身份没有可显示的工作台卡片，可从左侧菜单进入有权限的页面。</p>
    <LoadState v-else :loading="loading" :error="error">
      <div class="grid gap-x-12 gap-y-14 md:grid-cols-2 xl:grid-cols-3">
        <SummaryCard v-for="c in visible" :key="c.key" :title="c.title" :en="c.en" :lines="c.lines(summary, link)" :note="c.note?.(summary)" />
      </div>
    </LoadState>
  </div>
</template>
