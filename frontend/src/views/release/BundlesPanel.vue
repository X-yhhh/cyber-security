<script setup lang="ts">
/**
 * 发布管理 · 发布组合分段：组合台账（`q` 按组合键前缀、状态由后端筛选）+ 侧栏环境构成与发布口径。
 * 行点击打开组合详情抽屉（`id`）；页头「申请发布组合」经 defineExpose 的 create 打开申请表单。
 * 本分段只读取组合与模型名称，不读取策略与评价集合；策略、报告与绑定在打开详情时再读取。
 */
import { computed, ref, watch } from 'vue'
import { Layers, PackageCheck, Scale, Search } from 'lucide-vue-next'
import Panel from '@/components/Panel.vue'
import Tag from '@/components/Tag.vue'
import IdText from '@/components/IdText.vue'
import DistBar from '@/components/DistBar.vue'
import LoadState from '@/components/LoadState.vue'
import CursorPager from '@/components/CursorPager.vue'
import { tally } from '@/components/viz'
import { useCursor } from '@/composables/cursor'
import { fmtTime } from '@/api/types'
import { releaseApi, type BundleStatus, type ReleaseBundle } from '@/api/v2/release'
import { bundleTone } from '@/data/tones'
import BundleDrawer from './BundleDrawer.vue'
import BundleFormDrawer from './BundleFormDrawer.vue'
import { bundleStatusLabel, ensureIndex, envLabel, isObject, modelName } from './shared'

const q = defineModel<string>('q', { required: true })
const status = defineModel<string>('status', { required: true })
const openId = defineModel<string>('id', { required: true })

const bundles = useCursor<ReleaseBundle>((cursor) => releaseApi.listBundles({ q: q.value || undefined, status: (status.value || undefined) as BundleStatus | undefined, cursor }), false)
watch([q, status], () => bundles.reset(), { immediate: true })
void ensureIndex('models')

const qDraft = ref(q.value)
watch(q, (v) => { if (v !== qDraft.value.trim()) qDraft.value = v })
let typing: ReturnType<typeof setTimeout> | undefined
watch(qDraft, (v) => { clearTimeout(typing); typing = setTimeout(() => { q.value = v.trim().slice(0, 128) }, 350) })

const STATUSES = Object.keys(bundleStatusLabel)
const filtered = computed(() => !!(q.value || status.value))
function clearFilters() { q.value = ''; qDraft.value = ''; status.value = '' }
const emptyText = computed(() => (filtered.value ? '当前筛选条件下没有发布组合。' : '你可见范围内还没有发布组合。'))
const capabilityCount = (b: ReleaseBundle) => (isObject(b.subject) && Array.isArray(b.subject.capabilityIds) ? b.subject.capabilityIds.length : null)
const envComposition = computed(() => tally(bundles.items.value, (b) => b.environment, (k) => envLabel[k] ?? k, (k) => (k === 'authorized' ? 'ok' : k === 'lab' ? 'warn' : 'mute')))

const formOpen = ref(false)
defineExpose({ create: () => { formOpen.value = true } })
function created(id: string) {
  formOpen.value = false
  bundles.reset()
  openId.value = id
}
</script>

<template>
  <div class="grid items-start gap-5 xl:grid-cols-[minmax(0,1fr)_18rem]">
    <Panel title="发布组合" :icon="PackageCheck" flush>
      <template #actions><span class="text-[12px] text-ink-3">最近申请在前</span></template>
      <template #toolbar>
        <div class="toolbar w-full" role="search">
          <label class="toolbar-field"><Search :size="14" :stroke-width="1.5" aria-hidden="true" />
            <input v-model="qDraft" type="search" class="field !w-52" maxlength="128" placeholder="按组合键前缀搜索" aria-label="搜索发布组合" />
          </label>
          <label class="toolbar-field"><span>状态</span>
            <select v-model="status" class="field" aria-label="组合状态">
              <option value="">全部状态</option>
              <option v-for="s in STATUSES" :key="s" :value="s">{{ bundleStatusLabel[s] }}</option>
            </select>
          </label>
          <button v-if="filtered" type="button" class="link ml-auto text-[12.5px]" @click="clearFilters">清除筛选</button>
        </div>
      </template>

      <LoadState :loading="bundles.loading.value" :error="bundles.error.value" :empty="!bundles.items.value.length" :empty-text="emptyText">
        <table class="table min-w-[780px]">
          <thead><tr><th>组合（模型）</th><th>环境</th><th>能力</th><th>封存清单</th><th>状态</th><th class="text-right">最近更新</th></tr></thead>
          <tbody>
            <tr v-for="b in bundles.items.value" :key="b.id" class="row-link" tabindex="0" :aria-current="openId === b.id ? 'true' : undefined" @click="openId = b.id" @keydown.enter="openId = b.id">
              <td class="max-w-[18rem]">
                <span class="block truncate font-medium text-ink">{{ modelName(b.modelId) }}</span>
                <span class="flex items-center gap-1.5 text-[11.5px] text-ink-4">组合 <IdText :value="b.bundleKey" :copy="false" /><span class="num">· v{{ b.version }}</span></span>
              </td>
              <td class="whitespace-nowrap text-ink-2">{{ envLabel[b.environment] ?? b.environment }}</td>
              <td class="num whitespace-nowrap text-ink-2">{{ capabilityCount(b) ?? '—' }}</td>
              <td class="whitespace-nowrap text-[12.5px]" :class="b.sealedManifestSha256 ? 'text-ink-2' : 'text-ink-4'">{{ b.sealedManifestSha256 ? '已封存' : '未封存' }}</td>
              <td class="whitespace-nowrap"><Tag pill :tone="bundleTone[b.status]" :label="bundleStatusLabel[b.status] ?? b.status" /></td>
              <td class="num whitespace-nowrap text-right text-ink-3">{{ fmtTime(b.updatedAt ?? b.createdAt) }}</td>
            </tr>
          </tbody>
        </table>
      </LoadState>
      <template #foot>
        <CursorPager :count="bundles.items.value.length" :has-next="!!bundles.next.value" :has-prev="!!bundles.stack.value.length"
          :busy="bundles.turning.value" label="发布组合" @next="bundles.forward()" @prev="bundles.back()" />
      </template>
    </Panel>

    <aside class="space-y-4 xl:sticky xl:top-20">
      <Panel title="环境构成" :icon="Layers" :desc="`按当前页 ${bundles.items.value.length} 个组合统计`">
        <DistBar :segments="envComposition" empty-text="当前页没有发布组合" />
      </Panel>
      <Panel title="发布口径" :icon="Scale">
        <ul class="space-y-2.5 text-[12.5px] leading-relaxed text-ink-3">
          <li><span class="text-ink">组合不可变。</span>仅改阈值也要申请新组合，不能沿用旧组合的评价成绩。</li>
          <li><span class="text-ink">封存须含一次最终评价。</span>非研究环境且非只告警时，另需平台与灰度报告。</li>
          <li><span class="text-ink">批准与激活分开。</span>批准由申请人以外的人完成，激活按资产与有效授权逐个核验。</li>
          <li><span class="text-ink">报告不反向写入组合。</span>封存清单只引用报告摘要。</li>
        </ul>
      </Panel>
    </aside>

    <BundleDrawer :id="openId" @close="openId = ''" @changed="bundles.reset()" />
    <BundleFormDrawer :open="formOpen" @created="created" @close="formOpen = false" />
  </div>
</template>
