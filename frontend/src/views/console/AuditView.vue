<script setup lang="ts">
/** 审计：追加式台账，只读，数据来自 GET /audit（服务端分页，按审计范围过滤）。本页筛选只作用于当前页。 */
import { computed, ref, watch } from 'vue'
import PageHead from '@/components/PageHead.vue'
import Tag from '@/components/Tag.vue'
import LoadState from '@/components/LoadState.vue'
import { api, type Page } from '@/api/client'
import { fmtTime, type AuditView } from '@/api/types'
import { useLoad } from '@/composables/load'

const page = ref(0)
const size = 50
const { data, loading, error, reload } = useLoad(() => api.get<Page<AuditView>>(`/api/v1/audit?page=${page.value}&size=${size}`), { totalElements: 0, page: 0, size, items: [] } as Page<AuditView>)
watch(page, reload)
const pages = computed(() => Math.max(1, Math.ceil(data.value.totalElements / size)))

const result = ref('all')
const q = ref('')
const outcomes = computed(() => ['all', ...new Set(data.value.items.map((a) => a.outcome))])
const rows = computed(() => data.value.items.filter((a) => (result.value === 'all' || a.outcome === result.value) && (!q.value || [a.action, a.resourceType, a.resourceId, a.actorType, a.requestId].join(' ').includes(q.value))))
const tone = (o: string) => (o === 'success' ? 'ok' : o === 'denied' ? 'warn' : o === 'failure' || o === 'failed' ? 'threat' : 'mute')
</script>

<template>
  <div>
    <PageHead no="07" title="审计" desc="登录、权限变更、数据接入、模型激活、审批与执行都会写入追加式台账。普通业务接口不能修改或删除这些记录。">
      <template #kicker>Audit</template>
    </PageHead>

    <div class="flex flex-wrap items-center justify-between gap-6">
      <div class="flex items-center gap-5 text-[13px]">
        <button v-for="k in outcomes" :key="k" class="transition-colors" :class="result === k ? 'text-ink underline decoration-1 underline-offset-[6px]' : 'text-ink-3 hover:text-ink'" @click="result = k">{{ k === 'all' ? '全部' : k }}</button>
      </div>
      <input v-model="q" class="field w-72" placeholder="动作、资源或 request ID" aria-label="搜索审计" />
    </div>

    <LoadState :loading="loading" :error="error" :empty="!data.items.length" empty-text="数据库中暂无你审计范围内的记录。">
      <table class="table mt-10">
        <thead><tr><th>时间</th><th>操作者</th><th>动作</th><th>资源</th><th>结果</th><th class="text-right">Request ID</th></tr></thead>
        <tbody>
          <tr v-for="a in rows" :key="a.id">
            <td class="num text-ink-3">{{ fmtTime(a.occurredAt) }}</td>
            <td class="text-ink-2">{{ a.actorType }}</td>
            <td class="num">{{ a.action }}</td>
            <td class="num text-ink-2">{{ a.resourceType }}{{ a.resourceId ? ' · ' + a.resourceId : '' }}</td>
            <td><Tag :tone="tone(a.outcome)" :label="a.outcome" /></td>
            <td class="num text-right text-[12px] text-ink-3">{{ a.requestId ?? '—' }}</td>
          </tr>
        </tbody>
      </table>
      <div class="mt-6 flex items-center justify-between text-[12.5px] text-ink-3">
        <span>共 {{ data.totalElements }} 条 · 第 {{ page + 1 }} / {{ pages }} 页</span>
        <span class="flex gap-6">
          <button class="link" :disabled="page === 0" @click="page--">上一页</button>
          <button class="link" :disabled="page + 1 >= pages" @click="page++">下一页</button>
        </span>
      </div>
    </LoadState>
    <p class="mt-6 text-[12px] text-ink-3">仅显示全部关联资源都在你审计范围内的记录。</p>
  </div>
</template>
