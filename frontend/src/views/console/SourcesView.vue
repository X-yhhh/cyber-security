<script setup lang="ts">
/**
 * 数据源与回放：数据源 / 映射版本 / 接入批次汇总（/data-sources、/data-sources/ingest-summary），
 * 以及隔离靶场回放场景与最近运行（/replay-scenarios）。
 * 回放是重放已有数据，不生成或发起攻击流量；回放控制接口尚未实现，本页只读展示数据库记录。
 * 「影子验证」页签（仅 shadow.report.read）见 SourcesShadowPanel：只读汇总 + 人工标注 / 复核。
 * 数据源详情抽屉（开发路线 §4.1）：登记、修改环境/模式版本/状态（active ↔ disabled，→ retired 为终态），
 * 映射版本登记、他人批准或驳回、退役。停用数据源或退役映射后新批次被拒绝，历史批次与记录保留。
 */
import { computed, ref, watch } from 'vue'
import PageHead from '@/components/PageHead.vue'
import Segmented from '@/components/Segmented.vue'
import Tag from '@/components/Tag.vue'
import Drawer from '@/components/Drawer.vue'
import LoadState from '@/components/LoadState.vue'
import SourcesShadowPanel from './SourcesShadowPanel.vue'
import { api, type Page } from '@/api/client'
import { can, session } from '@/api/session'
import { fmtTime, lifecycleStatusLabel, type DataSourceView, type IngestSummary, type MappingView, type ReplayScenarioView } from '@/api/types'
import { statusTone } from '@/data/tones'
import { toast } from '@/composables/toast'
import { errText, optional, useLoad } from '@/composables/load'

const { data, loading, error, reload } = useLoad(async () => {
  const [sources, summary, replay] = await Promise.all([
    can('source.read') ? api.get<Page<DataSourceView>>('/api/v1/data-sources?size=100').then((p) => p.items) : [],
    can('ingest.batch.read') ? optional(api.get<IngestSummary[]>('/api/v1/data-sources/ingest-summary'), []) : [],
    can('source.read') ? api.get<ReplayScenarioView[]>('/api/v1/replay-scenarios') : [],
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

const label = (v: string) => lifecycleStatusLabel[v] ?? v
const busy = ref(false)
async function act(fn: () => Promise<unknown>, done: string, after?: () => Promise<void> | void) {
  busy.value = true
  try {
    await fn()
    toast(done)
    await reload()
    await after?.()
  } catch (e) { toast(errText(e), 'threat') } finally { busy.value = false }
}

// 数据源详情
const picked = ref<DataSourceView | null>(null)
const mappings = ref<MappingView[]>([])
const mapError = ref('')
const form = ref({ environment: '', schemaVersion: '', status: 'active' })
const reason = ref('')
let mappingRequest = 0
async function loadMappings() {
  const request = ++mappingRequest
  const id = picked.value?.id
  mappings.value = []
  mapError.value = ''
  if (!picked.value) return
  try {
    const result = await api.get<MappingView[]>(`/api/v1/data-sources/${id}/mappings`)
    if (request === mappingRequest && picked.value?.id === id) mappings.value = result
  } catch (e) { if (request === mappingRequest && picked.value?.id === id) mapError.value = errText(e) }
}
watch(picked, (d) => {
  if (d) form.value = { environment: d.environment, schemaVersion: d.schemaVersion, status: d.status }
  reason.value = ''
  mapping.value = false
  loadMappings()
})
const statusOptions = computed(() => picked.value?.status === 'retired' ? ['retired'] : ['active', 'disabled', 'retired'])
const refreshPicked = async () => {
  const id = picked.value?.id
  picked.value = id == null ? null : data.value.sources.find((d) => d.id === id) ?? null
  await loadMappings()
}
const saveSource = () => act(() => api.put(`/api/v1/data-sources/${picked.value!.id}`, form.value), '数据源已更新。', refreshPicked)
const mine = (m: MappingView) => m.requestedBy != null && m.requestedBy === session.user?.id
const approve = (m: MappingView) => act(() => api.post(`/api/v1/data-sources/${picked.value!.id}/mappings/${m.id}/approve`), '映射已批准，可用于接入。', loadMappings)
function decide(m: MappingView, path: 'reject' | 'retire') {
  if (!reason.value.trim()) return toast('请先填写理由。', 'warn')
  return act(() => api.post(`/api/v1/data-sources/${picked.value!.id}/mappings/${m.id}/${path}`, { reason: reason.value.trim() }),
    path === 'reject' ? '映射已驳回。' : '映射已退役；使用该版本的新批次将被拒绝。', loadMappings)
}

const mapping = ref(false)
const mapForm = ref({ mappingVersion: '', featureContractVersion: 'unsw-nb15-flow-v4', sourceSchema: '{}', mapping: '{}' })
function registerMapping() {
  let sourceSchema: unknown, mappingJson: unknown
  try { sourceSchema = JSON.parse(mapForm.value.sourceSchema); mappingJson = JSON.parse(mapForm.value.mapping) } catch { return toast('模式与映射须为 JSON 对象。', 'warn') }
  const contract = mapForm.value.featureContractVersion.trim()
  return act(() => api.post(`/api/v1/data-sources/${picked.value!.id}/mappings`, {
    mappingVersion: mapForm.value.mappingVersion.trim(), sourceSchema, mapping: mappingJson, ...(contract ? { featureContractVersion: contract } : {}),
  }), '映射版本已登记，须由其他管理员批准。', async () => { mapping.value = false; await loadMappings() })
}

const creating = ref(false)
const newSource = ref({ sourceKey: '', sourceType: 'sensor', environment: 'lab', schemaVersion: 'v1' })
const createSource = () => act(() => api.post('/api/v1/data-sources', { ...newSource.value, sourceKey: newSource.value.sourceKey.trim() }), '数据源已登记。',
  () => { creating.value = false; newSource.value = { sourceKey: '', sourceType: 'sensor', environment: 'lab', schemaVersion: 'v1' } })
</script>

<template>
  <div>
    <PageHead no="06" title="数据源与回放" desc="字段映射经版本化审批后才用于接入；不满足模型契约的记录会被拒绝或转人工，不会静默补值。">
      <template #kicker>Sources</template>
    </PageHead>

    <Segmented v-model="tab" :options="tabs" />

    <LoadState :loading="loading" :error="error">
    <Transition name="fade" mode="out-in">
      <section v-if="tab === 'sources'" key="s" class="mt-10">
      <div v-if="can('source.manage')" class="mb-6 flex justify-end"><button class="act-ghost" @click="creating = true">登记数据源</button></div>
      <table class="table">
        <thead><tr><th>数据源</th><th>类型</th><th>环境 / 模式</th><th>映射版本</th><th>批次 · 接收 / 拒绝</th><th class="text-right">最后成功</th></tr></thead>
        <tbody>
          <tr v-for="d in data.sources" :key="d.id" class="row-link" tabindex="0" @click="picked = d" @keydown.enter="picked = d">
            <td><span class="block num">{{ d.sourceKey }}</span><span class="num text-[12px] text-ink-3">#{{ d.id }} · <Tag :tone="statusTone[d.status]" :label="label(d.status)" /></span></td>
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
      </section>

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

    <Drawer :open="!!picked" :title="picked?.sourceKey ?? ''" :kicker="picked ? `SOURCE #${picked.id} · ${picked.sourceType}` : ''" @close="picked = null">
      <template v-if="picked">
        <dl class="border-t border-ink">
          <div v-for="[k, v] in [['状态', label(picked.status)], ['最后成功接入', fmtTime(picked.lastSuccessAt)]]" :key="k" class="grid grid-cols-[7rem_1fr] border-b border-ink-hair py-3 text-[13px]">
            <dt class="text-ink-3">{{ k }}</dt><dd class="num">{{ v }}</dd>
          </div>
        </dl>
        <div v-if="can('source.manage') && picked.status !== 'retired'" class="mt-8 grid grid-cols-3 gap-4">
          <label class="block"><span class="label">环境</span><input v-model="form.environment" class="field mt-2" maxlength="32" /></label>
          <label class="block"><span class="label">模式版本</span><input v-model="form.schemaVersion" class="field mt-2 num" maxlength="64" /></label>
          <label class="block"><span class="label">状态</span><select v-model="form.status" class="field mt-2"><option v-for="o in statusOptions" :key="o" :value="o">{{ label(o) }}</option></select></label>
          <button class="link col-span-3 justify-self-start text-[12.5px]" :disabled="busy" @click="saveSource">保存数据源</button>
          <p v-if="form.status !== 'active'" class="col-span-3 text-[12px] text-warn">停用或退役后，该数据源的新批次会被拒绝；退役为终态。</p>
        </div>

        <div class="mb-4 mt-12 flex items-center justify-between">
          <h3 class="label">映射版本</h3>
          <button v-if="can('source.manage') && picked.status === 'active'" class="link text-[12.5px]" @click="mapping = true">登记新版本</button>
        </div>
        <p v-if="mapError" class="text-[13px] text-threat">{{ mapError }}</p>
        <ol v-else class="border-l border-ink-hair">
          <li v-for="m in mappings" :key="m.id" class="relative pb-6 pl-6">
            <span class="absolute -left-[3px] top-2 h-[5px] w-[5px]" :class="m.status === 'approved' ? 'bg-ok' : 'bg-ink-4'" />
            <p class="flex items-center gap-3 text-[13px]"><span class="num">{{ m.mappingVersion }}</span><Tag :tone="statusTone[m.status]" :label="label(m.status)" /></p>
            <p class="num mt-1 text-[12px] text-ink-3">{{ m.featureContractVersion ?? '未绑定契约' }} · 登记 #{{ m.requestedBy ?? '—' }} · 批准 #{{ m.approvedBy ?? '—' }} · {{ fmtTime(m.createdAt) }}</p>
            <p v-if="m.decisionReason" class="mt-1 text-[12px] text-ink-3">{{ m.status === 'retired' ? '退役' : '驳回' }}理由：{{ m.decisionReason }}</p>
            <div v-if="can('source.mapping.approve')" class="mt-2 flex gap-5">
              <template v-if="['draft', 'pending'].includes(m.status) && !mine(m)">
                <button class="link text-[12.5px]" :disabled="busy" @click="approve(m)">批准</button>
                <button class="link text-[12.5px]" :disabled="busy" @click="decide(m, 'reject')">驳回</button>
              </template>
              <span v-else-if="['draft', 'pending'].includes(m.status) && mine(m)" class="text-[12px] text-ink-3">待其他管理员审批</span>
              <button v-if="m.status === 'approved'" class="link text-[12.5px]" :disabled="busy" @click="decide(m, 'retire')">退役</button>
            </div>
          </li>
          <li v-if="!mappings.length" class="pl-6 text-[13px] text-ink-3">暂无映射版本。</li>
        </ol>
        <label v-if="can('source.mapping.approve') && mappings.some((m) => ['draft', 'pending', 'approved'].includes(m.status))" class="mt-4 block">
          <span class="label">驳回 / 退役理由</span><input v-model="reason" class="field mt-2" maxlength="1000" placeholder="写入审计" />
        </label>
        <p class="mt-8 text-[12px] leading-relaxed text-ink-3">映射版本不可原地修改；登记人不能批准或驳回本人登记的版本。接入只使用已批准的映射。</p>
      </template>
    </Drawer>

    <Drawer :open="mapping" title="登记映射版本" :kicker="picked?.sourceKey" @close="mapping = false">
      <div class="space-y-6">
        <label class="block"><span class="label">映射版本</span><input v-model="mapForm.mappingVersion" class="field mt-2 num" maxlength="64" /></label>
        <label class="block"><span class="label">特征契约（留空表示不绑定）</span><input v-model="mapForm.featureContractVersion" class="field mt-2 num" maxlength="64" /></label>
        <label class="block"><span class="label">来源字段模式（JSON 对象）</span><textarea v-model="mapForm.sourceSchema" rows="3" class="field mt-2 h-auto resize-none py-2 num" /></label>
        <label class="block"><span class="label">字段映射（JSON 对象）</span><textarea v-model="mapForm.mapping" rows="3" class="field mt-2 h-auto resize-none py-2 num" /></label>
      </div>
      <template #foot>
        <button class="link text-[13px]" @click="mapping = false">取消</button>
        <button class="act" :disabled="busy || !mapForm.mappingVersion.trim()" @click="registerMapping">登记</button>
      </template>
    </Drawer>

    <Drawer :open="creating" title="登记数据源" kicker="SOURCE" @close="creating = false">
      <div class="space-y-6">
        <label class="block"><span class="label">数据源标识</span><input v-model="newSource.sourceKey" class="field mt-2 num" maxlength="128" placeholder="3-128 位字母、数字、. _ -" /></label>
        <label class="block"><span class="label">类型</span><select v-model="newSource.sourceType" class="field mt-2"><option value="sensor">sensor</option><option value="connector">connector</option><option value="replay">replay（回放）</option></select></label>
        <label class="block"><span class="label">环境</span><input v-model="newSource.environment" class="field mt-2" maxlength="32" /></label>
        <label class="block"><span class="label">模式版本</span><input v-model="newSource.schemaVersion" class="field mt-2 num" maxlength="64" /></label>
        <p class="text-[12.5px] text-ink-3">只有全局平台管理员可以登记数据源；类型登记后不可修改。</p>
      </div>
      <template #foot>
        <button class="link text-[13px]" @click="creating = false">取消</button>
        <button class="act" :disabled="busy || !newSource.sourceKey.trim()" @click="createSource">登记</button>
      </template>
    </Drawer>
  </div>
</template>
