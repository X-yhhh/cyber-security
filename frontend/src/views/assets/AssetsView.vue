<script setup lang="ts">
/**
 * 资产（资产与接入 / Assets，前端设计文档第 10.7 节，任务单 F4）。
 *
 * 数据：GET /api/v2/assets（status、q 由后端筛选并绑定游标）；环境筛选只作用于已加载的当前页，并在旁边写明。
 * - 筛选（q、status、env）同步到 URL；行可点击或回车进入详情整页 /console/assets/list/:id。
 * - 待办中心的授权条目带 `?assetId=&tab=authorizations&id=` 进入本页，这里直接改道到该资产详情的授权分段。
 * - 登记资产需 asset.manage；登记不授予执行权，授权须另行申请并由他人批准。
 */
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { Activity, CirclePause, Layers, Plus, Server, ShieldCheck, Archive, Search } from 'lucide-vue-next'
import PageHead from '@/components/PageHead.vue'
import Panel from '@/components/Panel.vue'
import StatBand from '@/components/StatBand.vue'
import Tag from '@/components/Tag.vue'
import DistBar from '@/components/DistBar.vue'
import LoadState from '@/components/LoadState.vue'
import CursorPager from '@/components/CursorPager.vue'
import { countIf, tally } from '@/components/viz'
import { useCursor } from '@/composables/cursor'
import { errText } from '@/composables/load'
import { queryString, useQueryState } from '@/composables/query'
import { useSummary } from '@/composables/summary'
import { toast } from '@/composables/toast'
import { can } from '@/api/session'
import { fmtTime, guardAssetEnvLabel } from '@/api/types'
import { isUuid } from '@/api/v2/detect'
import {
  assetPlatform, assetsApi, assetStatusLabel, assetTitle, CRITICALITIES, criticalityLabel, platformLabel,
  type Asset, type AssetCreate,
} from '@/api/v2/assets'
import { assetStatusTone, criticalityTone } from '@/data/tones'
import AssetFormDrawer from './AssetFormDrawer.vue'

const route = useRoute()
const router = useRouter()

/* 待办跳转：/console/assets/list?assetId=…&tab=authorizations&id=… → 资产详情的对应分段 */
const jumpAsset = queryString(route.query.assetId)
if (isUuid(jumpAsset)) {
  const rest = Object.fromEntries(Object.entries(route.query).filter(([k]) => k !== 'assetId'))
  void router.replace({ path: `/console/assets/list/${encodeURIComponent(jumpAsset.trim())}`, query: rest, hash: route.hash })
}

const STATUSES = ['active', 'disabled', 'retired'] as const
const ENVS = ['research', 'lab', 'authorized'] as const
type Env = (typeof ENVS)[number]
const status = ref('')
const env = ref<Env | ''>('')
const q = ref('')
const qDraft = ref('')
useQueryState({
  q: { state: q, default: '', parse: (v) => queryString(v).trim().slice(0, 128) },
  status: { state: status, default: '', parse: (v) => ((STATUSES as readonly string[]).includes(queryString(v)) ? queryString(v) : '') },
  env: { state: env, default: '', parse: (v) => ((ENVS as readonly string[]).includes(queryString(v)) ? queryString(v) as Env : '') },
}, () => { qDraft.value = q.value })

const assets = useCursor<Asset>((cursor) => assetsApi.listAssets({ status: status.value || undefined, q: q.value || undefined, cursor }))
watch([status, q], () => assets.reset())

/** 搜索框输入停顿 350ms 后提交；后端按显示名或资产键前缀匹配。 */
let typing: ReturnType<typeof setTimeout> | undefined
watch(qDraft, (v) => {
  clearTimeout(typing)
  typing = setTimeout(() => { q.value = v.trim().slice(0, 128) }, 350)
})

const shown = computed(() => (env.value ? assets.items.value.filter((a) => a.environment === env.value) : assets.items.value))
const envLabel = (e: string) => guardAssetEnvLabel[e] ?? e
const envCount = (e: Env) => countIf(assets.items.value, (a) => a.environment === e)
const pageHint = computed(() => `按当前页 ${assets.items.value.length} 个资产统计`)
const envComposition = computed(() => tally(assets.items.value, (a) => a.environment, envLabel, (k) => (k === 'authorized' ? 'ok' : k === 'lab' ? 'warn' : 'mute')))
const critComposition = computed(() => CRITICALITIES.slice().reverse().map((c) => ({ key: c, label: criticalityLabel[c], value: countIf(assets.items.value, (a) => a.criticality === c), tone: criticalityTone[c] })).filter((s) => s.value > 0))

const summary = useSummary()
const stats = computed(() => {
  const loaded = !assets.loading.value
  const items = assets.items.value
  return [
    { key: 'page', label: '当前页资产', value: loaded ? items.length : undefined, icon: Server, hint: assets.next.value ? '还有下一页' : '已到末页' },
    { key: 'active', label: '运行中', value: loaded ? countIf(items, (a) => a.status === 'active') : undefined, icon: Activity, tone: 'ok' as const, hint: '按当前页统计' },
    { key: 'disabled', label: '已停用 · 新命令暂停', value: loaded ? countIf(items, (a) => a.status === 'disabled') : undefined, icon: CirclePause, tone: 'warn' as const, hint: '按当前页统计' },
    { key: 'auth', label: '待我批准的授权', value: summary.data.pendingApprovals?.authorizations, icon: ShieldCheck, tone: 'signal' as const, hint: '你可见范围内，排除本人申请', to: { name: 'workbench' } },
  ]
})
const filtered = computed(() => !!(status.value || q.value || env.value))
const emptyText = computed(() => (filtered.value ? '当前筛选条件下没有资产。' : '你的范围内还没有登记资产。'))
function clearFilters() { status.value = ''; env.value = ''; q.value = ''; qDraft.value = '' }

const open = (a: Asset) => router.push({ name: 'assets-list-detail', params: { id: a.id } })

/** 关键性刻度：四格，按等级点亮。 */
const critLevel = (c: string) => Math.max(0, CRITICALITIES.indexOf(c as (typeof CRITICALITIES)[number])) + 1
const critBar: Record<string, string> = { low: 'bg-ink-4', medium: 'bg-ink-3', high: 'bg-warn', critical: 'bg-threat' }

/* 登记 */
const formOpen = ref(false)
const busy = ref(false)
async function create(body: AssetCreate) {
  busy.value = true
  try {
    const r = await assetsApi.createAsset(body)
    formOpen.value = false
    toast('已登记资产。登记不授予执行权，请在详情中申请授权。')
    void router.push({ name: 'assets-list-detail', params: { id: r.id } })
  } catch (e) { toast(errText(e), 'threat') } finally { busy.value = false }
}
</script>

<template>
  <div>
    <PageHead title="资产" desc="已登记的主机资产。停用会暂停该资产的新命令，退役后不能再启用。">
      <button v-if="can('asset.manage')" type="button" class="act" @click="formOpen = true"><Plus :size="15" :stroke-width="1.5" />登记资产</button>
    </PageHead>

    <StatBand class="mb-5" label="资产概览" :stats="stats" />

    <div class="grid items-start gap-5 xl:grid-cols-[minmax(0,1fr)_18rem]">
      <Panel title="资产台账" :icon="Server" flush>
        <template #actions><span class="text-[12px] text-ink-3">最近登记在前</span></template>
        <template #toolbar>
          <div class="toolbar w-full" role="search">
            <label class="toolbar-field"><Search :size="14" :stroke-width="1.5" aria-hidden="true" />
              <input v-model="qDraft" type="search" class="field !w-56" maxlength="128" placeholder="按显示名或资产键搜索" aria-label="搜索资产" />
            </label>
            <label class="toolbar-field"><span>状态</span>
              <select v-model="status" class="field" aria-label="资产状态">
                <option value="">全部状态</option>
                <option v-for="s in STATUSES" :key="s" :value="s">{{ assetStatusLabel[s] }}</option>
              </select>
            </label>
            <span class="toolbar-sep" aria-hidden="true" />
            <div class="chips" role="group" aria-label="环境（当前页）">
              <button type="button" class="chip" :aria-pressed="env === ''" @click="env = ''">全部环境</button>
              <button v-for="e in ENVS" :key="e" type="button" class="chip" :aria-pressed="env === e" @click="env = env === e ? '' : e">
                {{ envLabel(e) }}<span class="num ml-1 opacity-70">{{ envCount(e) }}</span>
              </button>
            </div>
            <span class="toolbar-end text-[12px] text-ink-4">环境按当前页筛选</span>
            <button v-if="filtered" type="button" class="link text-[12.5px]" @click="clearFilters">清除筛选</button>
          </div>
        </template>

        <LoadState :loading="assets.loading.value" :error="assets.error.value" :empty="!shown.length" :empty-text="emptyText">
          <table class="table min-w-[760px]">
            <thead>
              <tr><th>资产</th><th>环境</th><th>平台</th><th>关键性</th><th>责任人</th><th>状态</th><th class="text-right">最近更新</th></tr>
            </thead>
            <tbody>
              <tr v-for="a in shown" :key="a.id" class="row-link" tabindex="0" @click="open(a)" @keydown.enter="open(a)">
                <td class="max-w-[18rem]">
                  <span class="block truncate font-medium text-ink">{{ assetTitle(a) }}</span>
                  <span v-if="a.displayName" class="num block truncate text-[11.5px] text-ink-4">{{ a.assetKey }}</span>
                </td>
                <td class="whitespace-nowrap text-ink-2">{{ envLabel(a.environment) }}</td>
                <td class="whitespace-nowrap text-ink-2">{{ platformLabel[assetPlatform(a) ?? ''] ?? assetPlatform(a) ?? '—' }}</td>
                <td class="whitespace-nowrap">
                  <span class="inline-flex items-center gap-2" :title="`关键性：${criticalityLabel[a.criticality] ?? a.criticality}`">
                    <span class="inline-flex gap-0.5" aria-hidden="true">
                      <span v-for="n in 4" :key="n" class="h-2.5 w-1.5 rounded-[1px]" :class="n <= critLevel(a.criticality) ? critBar[a.criticality] ?? 'bg-ink-3' : 'bg-ink-hair'" />
                    </span>
                    <span class="text-[12.5px] text-ink-2">{{ criticalityLabel[a.criticality] ?? a.criticality }}</span>
                  </span>
                </td>
                <td class="max-w-[10rem] truncate text-ink-2">{{ a.owner || '—' }}</td>
                <td class="whitespace-nowrap"><Tag pill :tone="assetStatusTone[a.status]" :label="assetStatusLabel[a.status] ?? a.status" /></td>
                <td class="num whitespace-nowrap text-right text-ink-3">{{ fmtTime(a.updatedAt ?? a.createdAt) }}</td>
              </tr>
            </tbody>
          </table>
        </LoadState>
        <template #foot>
          <CursorPager :count="assets.items.value.length" :has-next="!!assets.next.value" :has-prev="!!assets.stack.value.length"
            :busy="assets.turning.value" label="资产" @next="assets.forward()" @prev="assets.back()" />
        </template>
      </Panel>

      <aside class="space-y-4 xl:sticky xl:top-20">
        <Panel title="环境构成" :icon="Layers" :desc="pageHint">
          <DistBar :segments="envComposition" empty-text="当前页没有资产" />
        </Panel>
        <Panel title="关键性" :icon="Activity" :desc="pageHint">
          <DistBar :segments="critComposition" empty-text="当前页没有资产" />
        </Panel>
        <Panel title="状态与影响" :icon="Archive">
          <ul class="space-y-3 text-[12.5px] leading-relaxed">
            <li class="flex gap-2.5"><span class="dot mt-[7px] bg-ok" /><span><span class="text-ink">运行中</span><span class="block text-ink-3">可接收观察；有效授权与活动发布下才会下发命令。</span></span></li>
            <li class="flex gap-2.5"><span class="dot mt-[7px] bg-warn" /><span><span class="text-ink">已停用</span><span class="block text-ink-3">新命令暂停，活动发布绑定同时暂停；可重新启用。</span></span></li>
            <li class="flex gap-2.5"><span class="dot mt-[7px] bg-ink-4" /><span><span class="text-ink">已退役</span><span class="block text-ink-3">终态，新命令暂停，不能再启用。</span></span></li>
          </ul>
        </Panel>
      </aside>
    </div>

    <AssetFormDrawer :open="formOpen" :busy="busy" @create="create" @close="formOpen = false" />
  </div>
</template>
