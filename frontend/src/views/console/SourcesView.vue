<script setup lang="ts">
/**
 * 数据源与回放：数据源 / 映射版本 / 接入批次汇总（/data-sources、/data-sources/ingest-summary），
 * 以及隔离靶场回放场景与最近运行（/replay-scenarios）。
 * 回放是重放已有数据，不生成或发起攻击流量；回放控制接口尚未实现，本页只读展示数据库记录。
 * 「影子验证」页签（仅 shadow.report.read）见 SourcesShadowPanel：只读汇总 + 人工标注 / 复核。
 */
import { computed, ref } from 'vue'
import PageHead from '@/components/PageHead.vue'
import Segmented from '@/components/Segmented.vue'
import Tag from '@/components/Tag.vue'
import LoadState from '@/components/LoadState.vue'
import SourcesShadowPanel from './SourcesShadowPanel.vue'
import { api, type Page } from '@/api/client'
import { can } from '@/api/session'
import { fmtTime, type DataSourceView, type IngestSummary, type ReplayScenarioView } from '@/api/types'
import { statusTone } from '@/data/tones'
import { optional, useLoad } from '@/composables/load'

const { data, loading, error } = useLoad(async () => {
  const [sources, summary, replay] = await Promise.all([
    can('source.read') ? api.get<Page<DataSourceView>>('/data-sources?size=100').then((p) => p.items) : [],
    can('ingest.batch.read') ? optional(api.get<IngestSummary[]>('/data-sources/ingest-summary'), []) : [],
    can('source.read') ? api.get<ReplayScenarioView[]>('/replay-scenarios') : [],
  ])
  return { sources, summary, replay }
}, { sources: [] as DataSourceView[], summary: [] as IngestSummary[], replay: [] as ReplayScenarioView[] })

const tab = ref<'sources' | 'replay' | 'shadow'>('sources')
const sum = computed(() => new Map(data.value.summary.map((s) => [s.dataSourceId, s])))
/** 影子验证页签只在具备 shadow.report.read 时出现；授权以后端为准。 */
const tabs = computed(() => [
  { value: 'sources' as const, label: '数据源', count: data.value.sources.length },
  { value: 'replay' as const, label: '回放', count: data.value.replay.length },
  ...(can('shadow.report.read') ? [{ value: 'shadow' as const, label: '影子验证' }] : []),
])
</script>

<template>
  <div>
    <PageHead no="06" title="数据源与回放" desc="字段映射经版本化审批后才用于接入；不满足模型契约的记录会被拒绝或转人工，不会静默补值。">
      <template #kicker>Sources</template>
    </PageHead>

    <Segmented v-model="tab" :options="tabs" />

    <LoadState :loading="loading" :error="error">
    <Transition name="fade" mode="out-in">
      <table v-if="tab === 'sources'" key="s" class="table mt-10">
        <thead><tr><th>数据源</th><th>类型</th><th>环境 / 模式</th><th>映射版本</th><th>批次 · 接收 / 拒绝</th><th class="text-right">最后成功</th></tr></thead>
        <tbody>
          <tr v-for="d in data.sources" :key="d.id">
            <td><span class="block num">{{ d.sourceKey }}</span><span class="num text-[12px] text-ink-3">#{{ d.id }} · <Tag :tone="statusTone[d.status]" :label="d.status" /></span></td>
            <td class="text-ink-2">{{ d.sourceType }}</td>
            <td class="num text-ink-2">{{ d.environment }} · {{ d.schemaVersion }}</td>
            <td><template v-if="sum.get(d.id)?.mappingVersion"><span class="num mr-3 text-[12.5px]">{{ sum.get(d.id)!.mappingVersion }}</span><Tag :tone="statusTone[sum.get(d.id)!.mappingStatus ?? '']" :label="sum.get(d.id)!.mappingStatus ?? ''" /></template><span v-else class="text-ink-3">—</span></td>
            <td class="num">
              <template v-if="sum.get(d.id)">{{ sum.get(d.id)!.batches }} · {{ sum.get(d.id)!.accepted.toLocaleString() }} <span class="text-ink-4">/</span> <span :class="sum.get(d.id)!.rejected ? 'text-warn' : 'text-ink-3'">{{ sum.get(d.id)!.rejected.toLocaleString() }}</span></template>
              <span v-else class="text-ink-3">—</span>
            </td>
            <td class="num text-right text-ink-3">{{ fmtTime(d.lastSuccessAt) }}</td>
          </tr>
          <tr v-if="!data.sources.length"><td colspan="6" class="py-16 text-center text-ink-3">数据库中暂无授权范围内的数据源。</td></tr>
        </tbody>
      </table>

      <SourcesShadowPanel v-else-if="tab === 'shadow'" key="h" :sources="data.sources" />

      <div v-else key="r" class="mt-10">
        <table class="table">
          <thead><tr><th>场景</th><th>数据集</th><th>安全配置</th><th>最近运行</th><th>进度</th><th class="text-right">状态</th></tr></thead>
          <tbody>
            <tr v-for="s in data.replay" :key="s.id">
              <td><span class="block">{{ s.name }}</span><span class="num text-[12px] text-ink-3">{{ s.scenarioKey }} · {{ s.environment }}</span></td>
              <td class="num text-[12.5px] text-ink-2">{{ s.datasetRef }}</td>
              <td class="text-ink-2">{{ s.safetyProfile }}</td>
              <td class="num text-[12.5px] text-ink-2">
                <template v-if="s.lastRunKey">{{ s.lastRunKey }} · {{ s.lastRunSpeed }}x<br /><span class="text-ink-3">{{ fmtTime(s.lastRunStartedAt) }} — {{ fmtTime(s.lastRunFinishedAt) }}</span></template>
                <span v-else class="text-ink-3">未运行</span>
              </td>
              <td class="num">{{ s.lastRunProgress == null ? '—' : Number(s.lastRunProgress).toFixed(1) + '%' }}</td>
              <td class="text-right"><Tag :tone="statusTone[s.lastRunStatus ?? s.status]" :label="s.lastRunStatus ?? s.status" /></td>
            </tr>
            <tr v-if="!data.replay.length"><td colspan="6" class="py-16 text-center text-ink-3">数据库中暂无回放场景。</td></tr>
          </tbody>
        </table>
        <p class="mt-8 max-w-2xl text-[12px] leading-relaxed text-ink-3">回放产生的事件标记为演练数据，与实网事件隔离展示。靶场外网隔离由部署网络控制保证，不以此页面选项代替。回放启停接口尚未实现。</p>
      </div>
    </Transition>
    </LoadState>
  </div>
</template>
