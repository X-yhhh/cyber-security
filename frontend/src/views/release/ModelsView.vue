<script setup lang="ts">
/**
 * 模型与数据集（模型与发布 / Models，前端设计文档第 10.10 节，任务单 F3）。
 *
 * 分段「模型 · 数据集」；分段、`q`（后端按显示名或键前缀搜索）、状态与打开的对象（`id`）同步到 URL，
 * 待办中心的待校验模型（`?tab=models&id=`）直接打开详情抽屉。只读取当前分段的集合。
 * - 模型登记后恒为候选（candidateOnly）：校验只改变校验状态，发布资格来自发布组合的评价、封存与独立批准。
 * - 写操作：登记、编辑资料、退役（model.manage / dataset.manage），发起校验（model.validate，配置固定 host-guard-onnx-v1）。
 * - 读数带的「待校验模型」来自汇总接口（全量、按权限裁剪），其余按当前页统计并写明。
 */
import { computed, ref, watch } from 'vue'
import { Archive, BrainCircuit, CircleCheck, CircleX, Database, FlaskConical, Layers, Plus, Route, Search } from 'lucide-vue-next'
import PageHead from '@/components/PageHead.vue'
import Panel from '@/components/Panel.vue'
import Segmented from '@/components/Segmented.vue'
import StatBand from '@/components/StatBand.vue'
import Tag from '@/components/Tag.vue'
import DistBar from '@/components/DistBar.vue'
import LoadState from '@/components/LoadState.vue'
import CursorPager from '@/components/CursorPager.vue'
import { countIf, tally } from '@/components/viz'
import { useCursor } from '@/composables/cursor'
import { queryString, useQueryState } from '@/composables/query'
import { useSummary } from '@/composables/summary'
import { toast } from '@/composables/toast'
import { can } from '@/api/session'
import { fmtTime } from '@/api/types'
import { isUuid } from '@/api/v2/detect'
import { releaseApi, type ManifestRegistration, type ReleaseDataset, type ReleaseModel } from '@/api/v2/release'
import { catalogTone } from '@/data/tones'
import CatalogDrawer from './CatalogDrawer.vue'
import ManifestFormDrawer from './ManifestFormDrawer.vue'
import { datasetStatusLabel, isObject, modelStatusLabel, modelTitle, profileLabel, releaseErr } from './shared'

type Tab = 'models' | 'datasets'
const STATUS: Record<Tab, readonly string[]> = { models: ['pending', 'validated', 'failed', 'retired'], datasets: ['active', 'retired'] }
const tab = ref<Tab>('models')
const q = ref('')
const qDraft = ref('')
const status = ref('')
const openId = ref('')
const tabOf = (v: unknown): Tab => (queryString(v as string) === 'datasets' ? 'datasets' : 'models')
useQueryState({
  tab: { state: tab, default: 'models' as Tab, parse: tabOf },
  q: { state: q, default: '', parse: (v) => queryString(v).trim().slice(0, 128) },
  status: { state: status, default: '', parse: (v, query) => (STATUS[tabOf(query.tab)].includes(queryString(v)) ? queryString(v) : '') },
  id: { state: openId, default: '', parse: (v) => (isUuid(queryString(v)) ? queryString(v).trim() : '') },
}, () => { qDraft.value = q.value })

/** 用户切换分段时清空本分段的筛选与打开的对象；外部链接同时带来的参数由 useQueryState 一次回填，不经过这里。 */
const tabModel = computed({
  get: () => tab.value,
  set: (v: Tab) => { if (v === tab.value) return; tab.value = v; q.value = ''; qDraft.value = ''; status.value = ''; openId.value = '' },
})

const allowed = can('resource.read')
const lists = {
  models: useCursor<ReleaseModel>((cursor) => releaseApi.listModels({ q: q.value || undefined, status: (status.value || undefined) as ReleaseModel['validationStatus'] | undefined, cursor }), false),
  datasets: useCursor<ReleaseDataset>((cursor) => releaseApi.listDatasets({ q: q.value || undefined, status: (status.value || undefined) as ReleaseDataset['status'] | undefined, cursor }), false),
}
const models = computed(() => lists.models.items.value)
const datasets = computed(() => lists.datasets.items.value)
const active = computed(() => lists[tab.value])
watch([tab, q, status], () => { if (allowed) active.value.reset() }, { immediate: true })

let typing: ReturnType<typeof setTimeout> | undefined
watch(qDraft, (v) => { clearTimeout(typing); typing = setTimeout(() => { q.value = v.trim().slice(0, 128) }, 350) })

/* ---------------- 读数带与侧栏 ---------------- */
const summary = useSummary()
const pageHint = computed(() => `按当前页 ${active.value.items.value.length} 条统计`)
const stats = computed(() => {
  const loaded = !active.value.loading.value
  if (tab.value === 'datasets') {
    const items = datasets.value
    return [
      { key: 'page', label: '当前页数据集', value: loaded ? items.length : undefined, icon: Database, hint: lists.datasets.next.value ? '还有下一页' : '已到末页' },
      { key: 'active', label: '启用', value: loaded ? countIf(items, (d) => d.status === 'active') : undefined, icon: CircleCheck, tone: 'ok' as const, hint: '按当前页统计' },
      { key: 'retired', label: '已退役', value: loaded ? countIf(items, (d) => d.status === 'retired') : undefined, icon: Archive, hint: '按当前页统计' },
    ]
  }
  const items = models.value
  return [
    { key: 'page', label: '当前页模型', value: loaded ? items.length : undefined, icon: BrainCircuit, hint: lists.models.next.value ? '还有下一页' : '已到末页' },
    { key: 'pending', label: '待校验模型', value: summary.data.modelsPendingValidation, icon: FlaskConical, tone: 'signal' as const, hint: '你可见范围内全部' },
    { key: 'validated', label: '已校验', value: loaded ? countIf(items, (m) => m.validationStatus === 'validated') : undefined, icon: CircleCheck, tone: 'ok' as const, hint: '按当前页统计' },
    { key: 'failed', label: '校验失败', value: loaded ? countIf(items, (m) => m.validationStatus === 'failed') : undefined, icon: CircleX, tone: 'threat' as const, hint: '按当前页统计' },
  ]
})
const statusLabel = (s: string) => (tab.value === 'models' ? modelStatusLabel : datasetStatusLabel)[s] ?? s
const composition = computed(() => (tab.value === 'models'
  ? tally(models.value, (m) => m.validationStatus, statusLabel, (k) => catalogTone[k])
  : tally(datasets.value, (d) => d.status, statusLabel, (k) => catalogTone[k])))

const filtered = computed(() => !!(q.value || status.value))
function clearFilters() { q.value = ''; qDraft.value = ''; status.value = '' }
const label = computed(() => (tab.value === 'models' ? '模型' : '数据集'))
const emptyText = computed(() => (filtered.value ? '当前筛选条件下没有记录。' : `你可见范围内还没有登记${label.value}。`))

/** manifest 中的算法与快照类型，表格只显示摘要。 */
const algorithm = (m: ReleaseModel) => (isObject(m.manifest) && typeof m.manifest.algorithm === 'string' ? m.manifest.algorithm : '—')
const profiles = (m: ReleaseModel) => (isObject(m.manifest) && Array.isArray(m.manifest.profiles) ? m.manifest.profiles.map((p) => profileLabel[String(p)] ?? String(p)).join('、') : '—')

/* ---------------- 抽屉与登记 ---------------- */
const open = (id: string) => { openId.value = id }
const formOpen = ref(false)
const busy = ref(false)
const manageable = computed(() => can(tab.value === 'models' ? 'model.manage' : 'dataset.manage'))
async function register(body: ManifestRegistration) {
  busy.value = true
  const kind = tab.value
  try {
    const r = kind === 'models' ? await releaseApi.registerModel(body) : await releaseApi.registerDataset(body)
    formOpen.value = false
    toast(kind === 'models' ? '已登记模型候选，状态为待校验。' : '已登记数据集。')
    active.value.reset()
    openId.value = r.id
  } catch (e) { toast(releaseErr(e), 'threat') } finally { busy.value = false }
}

const flow = computed(() => (tab.value === 'models'
  ? [
      { t: '登记 manifest', d: '模型以候选（candidateOnly）入库，状态为待校验。' },
      { t: '校验', d: '按 host-guard-onnx-v1 核对制品与特征契约；失败的模型不能进入组合。' },
      { t: '进入发布组合', d: '与已审核策略、评价计划、能力组成不可变组合，导入报告并封存。' },
      { t: '独立批准与激活', d: '由申请人以外的批准人批准，再按资产与有效授权激活。' },
    ]
  : [
      { t: '登记 manifest', d: '数据集键与版本取自 manifest，登记后不可修改。' },
      { t: '被评价计划引用', d: '结构化评价计划按 ID 引用启用中的数据集。' },
      { t: '退役', d: '仍被引用时退役会被拒绝（409）。' },
    ]))
</script>

<template>
  <div>
    <PageHead title="模型与数据集" desc="模型与数据集台账。登记与校验都不授予发布资格。">
      <button v-if="manageable" type="button" class="act" @click="formOpen = true"><Plus :size="15" :stroke-width="1.5" />{{ tab === 'models' ? '登记模型' : '登记数据集' }}</button>
    </PageHead>

    <p v-if="!allowed" class="panel px-5 py-10 text-center text-[13px] text-ink-3">当前身份没有读取模型与数据集的权限。</p>
    <template v-else>
      <StatBand class="mb-5" :label="`${label}概览`" :stats="stats" />
      <Segmented v-model="tabModel" :options="[{ value: 'models', label: '模型' }, { value: 'datasets', label: '数据集' }]" />

      <div class="mt-4 grid items-start gap-5 xl:grid-cols-[minmax(0,1fr)_18rem]">
        <Panel :title="tab === 'models' ? '模型台账' : '数据集台账'" :icon="tab === 'models' ? BrainCircuit : Database" flush>
          <template #actions><span class="text-[12px] text-ink-3">最近登记在前</span></template>
          <template #toolbar>
            <div class="toolbar w-full" role="search">
              <label class="toolbar-field"><Search :size="14" :stroke-width="1.5" aria-hidden="true" />
                <input v-model="qDraft" type="search" class="field !w-56" maxlength="128" :placeholder="tab === 'models' ? '按显示名或模型键搜索' : '按显示名或数据集键搜索'" :aria-label="`搜索${label}`" />
              </label>
              <span class="toolbar-sep" aria-hidden="true" />
              <div class="chips" role="group" :aria-label="`${label}状态`">
                <button type="button" class="chip" :aria-pressed="status === ''" @click="status = ''">全部状态</button>
                <button v-for="s in STATUS[tab]" :key="s" type="button" class="chip" :aria-pressed="status === s" @click="status = status === s ? '' : s">{{ statusLabel(s) }}</button>
              </div>
              <button v-if="filtered" type="button" class="link ml-auto text-[12.5px]" @click="clearFilters">清除筛选</button>
            </div>
          </template>

          <LoadState :loading="active.loading.value" :error="active.error.value" :empty="!active.items.value.length" :empty-text="emptyText">
            <table v-if="tab === 'models'" class="table min-w-[760px]">
              <thead><tr><th>模型</th><th>版本</th><th>算法</th><th>快照类型</th><th>校验状态</th><th class="text-right">最近更新</th></tr></thead>
              <tbody>
                <tr v-for="m in models" :key="m.id" class="row-link" tabindex="0" :aria-current="openId === m.id ? 'true' : undefined" @click="open(m.id)" @keydown.enter="open(m.id)">
                  <td class="max-w-[18rem]">
                    <span class="block truncate font-medium text-ink">{{ modelTitle(m) }}</span>
                    <span v-if="m.displayName" class="num block truncate text-[11.5px] text-ink-4">{{ m.modelKey }}</span>
                  </td>
                  <td class="num whitespace-nowrap text-ink-2">{{ m.version }}</td>
                  <td class="num whitespace-nowrap text-ink-2">{{ algorithm(m) }}</td>
                  <td class="whitespace-nowrap text-ink-2">{{ profiles(m) }}</td>
                  <td class="whitespace-nowrap"><Tag pill :tone="catalogTone[m.validationStatus]" :label="statusLabel(m.validationStatus)" /></td>
                  <td class="num whitespace-nowrap text-right text-ink-3">{{ fmtTime(m.updatedAt ?? m.createdAt) }}</td>
                </tr>
              </tbody>
            </table>
            <table v-else class="table min-w-[720px]">
              <thead><tr><th>数据集</th><th>版本</th><th>说明</th><th>状态</th><th class="text-right">最近更新</th></tr></thead>
              <tbody>
                <tr v-for="d in datasets" :key="d.id" class="row-link" tabindex="0" :aria-current="openId === d.id ? 'true' : undefined" @click="open(d.id)" @keydown.enter="open(d.id)">
                  <td class="max-w-[18rem]">
                    <span class="block truncate font-medium text-ink">{{ d.displayName || d.datasetKey }}</span>
                    <span v-if="d.displayName" class="num block truncate text-[11.5px] text-ink-4">{{ d.datasetKey }}</span>
                  </td>
                  <td class="num whitespace-nowrap text-ink-2">{{ d.version }}</td>
                  <td class="max-w-[16rem] truncate text-ink-3">{{ d.notes || '—' }}</td>
                  <td class="whitespace-nowrap"><Tag pill :tone="catalogTone[d.status]" :label="statusLabel(d.status)" /></td>
                  <td class="num whitespace-nowrap text-right text-ink-3">{{ fmtTime(d.updatedAt ?? d.createdAt) }}</td>
                </tr>
              </tbody>
            </table>
          </LoadState>
          <template #foot>
            <CursorPager :count="active.items.value.length" :has-next="!!active.next.value" :has-prev="!!active.stack.value.length"
              :busy="active.turning.value" :label="label" @next="active.forward()" @prev="active.back()" />
          </template>
        </Panel>

        <aside class="space-y-4 xl:sticky xl:top-20">
          <Panel :title="tab === 'models' ? '校验状态构成' : '状态构成'" :icon="Layers" :desc="pageHint">
            <DistBar :segments="composition" :empty-text="`当前页没有${label}`" />
          </Panel>
          <Panel :title="tab === 'models' ? '从登记到发布' : '数据集的用途'" :icon="Route">
            <ol class="space-y-3 text-[12.5px] leading-relaxed">
              <li v-for="(s, i) in flow" :key="s.t" class="grid grid-cols-[1.25rem_minmax(0,1fr)] gap-2">
                <span class="num mt-px inline-flex h-5 w-5 items-center justify-center rounded-full border border-ink-line text-[11px] text-ink-2">{{ i + 1 }}</span>
                <span><span class="text-ink">{{ s.t }}</span><span class="block text-ink-3">{{ s.d }}</span></span>
              </li>
            </ol>
          </Panel>
        </aside>
      </div>
    </template>

    <CatalogDrawer :kind="tab" :id="openId" @close="openId = ''" @changed="active.reset()" />
    <ManifestFormDrawer :open="formOpen" :kind="tab" :busy="busy" @submit="register" @close="formOpen = false" />
  </div>
</template>
