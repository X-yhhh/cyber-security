<script setup lang="ts">
/**
 * lab 验证与 G3（13）：lab 验证会话列表（GET /api/v2/lab-validation-runs）。
 *
 * - 资格状态（会话批准、到期、授权失效）与运行状态（registered → running → completed …）分开显示；
 *   effectiveEligibility 由后端按到期与授权当前状态计算，前端不自行推断；
 * - 会话本身不授予执行权限（executionAuthority 恒为 false），清理状态不由会话断言；
 * - 详情页读取签名 G3 报告与已登记的来源等级，lab_auto 只在 lab 资产有效。
 */
import { computed, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import PageHead from '@/components/PageHead.vue'
import Tag from '@/components/Tag.vue'
import LoadState from '@/components/LoadState.vue'
import CursorPager from '@/components/CursorPager.vue'
import { useCursor } from '@/composables/cursor'
import { guard } from '@/api/client'
import { can } from '@/api/session'
import { fmtTime, guardLabEligibilityLabel, guardLabRunStatusLabel, type GuardLabRun } from '@/api/types'
import { labEligibilityTone, labRunTone } from '@/data/tones'

const router = useRouter()
const allowed = can('evaluation.read')
const status = ref('')
const runs = useCursor<GuardLabRun>((cursor) => guard.read<{ items: GuardLabRun[]; nextCursor: string | null }>('lab-validation-runs', { cursor, status: status.value, limit: 50 }), allowed)
watch(status, () => { if (allowed) runs.reset() })

const statuses = Object.keys(guardLabRunStatusLabel)
const duration = (r: GuardLabRun) => {
  if (!r.startedAt || !r.endedAt) return '—'
  const s = Math.round((Date.parse(r.endedAt) - Date.parse(r.startedAt)) / 1000)
  return s >= 60 ? `${Math.floor(s / 60)} 分 ${s % 60} 秒` : `${s} 秒`
}
const open = (r: GuardLabRun) => router.push({ name: 'lab-detail', params: { id: r.id } })
const count = computed(() => runs.items.value.length)
</script>

<template>
  <div>
    <PageHead no="13" title="lab 验证与 G3" desc="网络隔离 lab 中的 1 倍速联合闭环会话。会话只记录事实，不授予执行权限；来源等级只来自已验签导入的 G3 报告，且 lab_auto 只对 lab 资产有效，不适用于真实主机。">
      <template #kicker>Lab validation</template>
    </PageHead>

    <p v-if="!allowed" class="py-10 text-[13px] text-ink-3">当前身份没有评价读取权限（evaluation.read），本页不显示数据。</p>
    <template v-else>
      <div class="mb-8 flex items-end gap-6 text-[13px]">
        <label class="w-40"><span class="label">运行状态</span>
          <select v-model="status" class="field mt-1">
            <option value="">全部</option>
            <option v-for="s in statuses" :key="s" :value="s">{{ guardLabRunStatusLabel[s] }}</option>
          </select>
        </label>
      </div>

      <LoadState :loading="runs.loading.value" :error="runs.error.value" :empty="!count" empty-text="数据库中暂无 lab 验证会话。">
        <table class="table">
          <thead><tr><th>会话</th><th>运行</th><th>资格</th><th>证据类别</th><th>发布组合</th><th>开始 / 时长</th><th class="text-right">有效期至</th></tr></thead>
          <tbody>
            <tr v-for="r in runs.items.value" :key="r.id" class="row-link" tabindex="0" @click="open(r)" @keydown.enter="open(r)">
              <td><span class="num block">{{ r.id.slice(0, 8) }}</span><span class="num text-[12px] text-ink-4">r{{ r.revision }}</span></td>
              <td><Tag :tone="labRunTone[r.runStatus]" :label="guardLabRunStatusLabel[r.runStatus] ?? r.runStatus" /><span v-if="r.timedOut" class="ml-2 text-[12px] text-threat">已超时</span></td>
              <td><Tag :tone="labEligibilityTone[r.effectiveEligibility]" :label="guardLabEligibilityLabel[r.effectiveEligibility] ?? r.effectiveEligibility" /><span v-if="r.blockedReason" class="num ml-2 text-[11.5px] text-ink-4">{{ r.blockedReason }}</span></td>
              <td class="num text-ink-2">{{ r.evidenceKind }}</td>
              <td class="num text-ink-3">{{ r.bundleId?.slice(0, 8) ?? '—' }}</td>
              <td><span class="num block text-ink-2">{{ fmtTime(r.startedAt) }}</span><span class="text-[12px] text-ink-4">{{ duration(r) }}</span></td>
              <td class="num text-right text-ink-3">{{ fmtTime(r.validUntil) }}</td>
            </tr>
          </tbody>
        </table>
      </LoadState>
      <CursorPager :count="count" :has-next="!!runs.next.value" :has-prev="!!runs.stack.value.length" :busy="runs.turning.value" label="lab 会话" @next="runs.forward()" @prev="runs.back()" />
    </template>
  </div>
</template>
