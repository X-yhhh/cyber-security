<script setup lang="ts">
/** 审计：追加式台账，只读。按结果筛选，展开查看 request ID。 */
import { computed, ref } from 'vue'
import PageHead from '@/components/PageHead.vue'
import Tag from '@/components/Tag.vue'
import { auditLog } from '@/data/demo'

const result = ref<'all' | 'success' | 'denied' | 'failed'>('all')
const q = ref('')
const rows = computed(() => auditLog.filter((a) => (result.value === 'all' || a.result === result.value) && (!q.value || (a.action + a.resource + a.actor + a.requestId).includes(q.value))))
const label = { all: '全部', success: '成功', denied: '拒绝', failed: '失败' }
</script>

<template>
  <div>
    <PageHead no="07" title="审计" desc="登录、权限变更、数据接入、模型激活、审批、执行与回滚都会写入追加式台账。普通业务接口不能修改或删除这些记录。">
      <template #kicker>Audit</template>
    </PageHead>

    <div class="flex flex-wrap items-center justify-between gap-6">
      <div class="flex items-center gap-5 text-[13px]">
        <button v-for="(l, k) in label" :key="k" class="transition-colors" :class="result === k ? 'text-ink underline decoration-1 underline-offset-[6px]' : 'text-ink-3 hover:text-ink'" @click="result = k">{{ l }}</button>
      </div>
      <input v-model="q" class="field w-72" placeholder="动作、资源、操作者或 request ID" aria-label="搜索审计" />
    </div>

    <table class="table mt-10">
      <thead><tr><th>时间</th><th>操作者</th><th>动作</th><th>资源</th><th>结果</th><th class="text-right">Request ID</th></tr></thead>
      <TransitionGroup tag="tbody" name="fade">
        <tr v-for="a in rows" :key="a.id">
          <td class="num text-ink-3">{{ a.time }}</td>
          <td class="text-ink-2">{{ a.actor }}</td>
          <td class="num">{{ a.action }}</td>
          <td class="num text-ink-2">{{ a.resource }}</td>
          <td><Tag :tone="a.result === 'success' ? 'ok' : a.result === 'denied' ? 'warn' : 'threat'" :label="label[a.result]" /></td>
          <td class="num text-right text-[12px] text-ink-3">{{ a.requestId }}</td>
        </tr>
      </TransitionGroup>
    </table>
    <p class="mt-6 text-[12px] text-ink-3">仅显示全部关联资源都在你审计范围内的记录。导出报告时执行脱敏。</p>
  </div>
</template>
