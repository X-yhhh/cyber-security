<script setup lang="ts">
/**
 * F3 路由接线载体：复用现有通用组件读取模型/数据集，避免 ready 路由悬空。
 * 正式页面的版式、详情与增删改查表单由后续页面工作接续；本组件不宣称 F3 页面已验收。
 */
import { computed, ref, watch } from 'vue'
import { BrainCircuit } from 'lucide-vue-next'
import { can } from '@/api/session'
import { releaseApi, type ReleaseDataset, type ReleaseModel } from '@/api/v2/release'
import { useCursor } from '@/composables/cursor'
import { queryString, useQueryState } from '@/composables/query'
import { fmtTime } from '@/api/types'
import { statusTone } from '@/data/tones'
import PageHead from '@/components/PageHead.vue'
import SectionTabs from '@/components/SectionTabs.vue'
import Panel from '@/components/Panel.vue'
import LoadState from '@/components/LoadState.vue'
import CursorPager from '@/components/CursorPager.vue'
import Tag from '@/components/Tag.vue'

type Tab = 'models' | 'datasets'
const tab = ref<Tab>('models')
useQueryState({ tab: { state: tab, default: 'models' as Tab, parse: (value) => queryString(value) === 'datasets' ? 'datasets' : 'models' } })
const allowed = can('resource.read')
const models = useCursor<ReleaseModel>((cursor) => releaseApi.listModels({ cursor }), false)
const datasets = useCursor<ReleaseDataset>((cursor) => releaseApi.listDatasets({ cursor }), false)
const active = computed(() => tab.value === 'models' ? models : datasets)
watch(tab, () => { if (allowed) active.value.reset() }, { immediate: true })
const label = computed(() => tab.value === 'models' ? '模型' : '数据集')
const status = (row: ReleaseModel | ReleaseDataset) => 'validationStatus' in row ? row.validationStatus : row.status
const statusLabels: Record<string, string> = { pending: '待校验', validated: '已校验', failed: '校验失败', active: '启用', retired: '已退役' }
const name = (row: ReleaseModel | ReleaseDataset) => row.displayName || ('modelKey' in row ? row.modelKey : row.datasetKey)
</script>

<template>
  <div>
    <PageHead title="模型与数据集" desc="模型保持候选状态，校验结果与发布资格分别记录。" />
    <SectionTabs v-model="tab" class="mb-4" label="模型与数据集" :options="[{ value: 'models', label: '模型' }, { value: 'datasets', label: '数据集' }]" />
    <p v-if="!allowed" class="panel p-5 text-[13px] text-ink-3">当前身份没有读取模型与数据集的权限。</p>
    <Panel v-else :title="label" :icon="BrainCircuit" flush>
      <LoadState :loading="active.loading.value" :error="active.error.value" :empty="!active.items.value.length" :empty-text="`你可见范围内暂无${label}。`">
        <table class="table">
          <thead><tr><th>名称</th><th>版本</th><th>状态</th><th>登记时间</th></tr></thead>
          <tbody>
            <tr v-for="row in active.items.value" :key="row.id">
              <td>{{ name(row) }}</td><td class="num">{{ row.version }}</td>
              <td><Tag :tone="statusTone[status(row)]" :label="statusLabels[status(row)] ?? status(row)" /></td>
              <td class="num">{{ fmtTime(row.createdAt) }}</td>
            </tr>
          </tbody>
        </table>
      </LoadState>
      <template #foot>
        <CursorPager :count="active.items.value.length" :has-next="!!active.next.value" :has-prev="!!active.stack.value.length" :busy="active.turning.value" :label="label" @next="active.forward()" @prev="active.back()" />
      </template>
    </Panel>
  </div>
</template>
