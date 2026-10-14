<script setup lang="ts">
/**
 * 观测与推理（威胁检测 / Observations）：host-guard v5 接入链路的前半段问题排查视图。
 *
 * 读 `/api/v2` 的 observation-batches / observations / detections / evidence-episodes，
 * 四个分段按「批次受理 → 单条观察 → 推理结论 → 证据归并」的因果顺序排列。
 *
 * 关键口径（docs/功能模块设计.md §3.1、§3.2；权限设计 §8）：
 * - 202 只表示持久化受理，**不代表检测或阻断已完成**，因此批次状态与推理状态分开显示；
 * - 不成功的推理不带攻击概率，score 为 null 时显示为「—」而不是 0；
 * - episode 按 (asset, sensor, boot, peerKey, keyEpoch, direction, transport, servicePort, family, bundle)
 *   与固定 30 秒桶归并、按 parentConnectionId 去重；同一主机其他 peer 不升级本 episode；
 * - 具备 `feedback.label` 权限时，可对观察快照提交标注反馈（pending 复核，不自动训练）。
 */
import { computed, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import PageHead from '@/components/PageHead.vue'
import Segmented from '@/components/Segmented.vue'
import Tag from '@/components/Tag.vue'
import Drawer from '@/components/Drawer.vue'
import LoadState from '@/components/LoadState.vue'
import CursorPager from '@/components/CursorPager.vue'
import FamilyScores from '@/components/FamilyScores.vue'
import { errText } from '@/composables/load'
import { useCursor } from '@/composables/cursor'
import { guard } from '@/api/client'
import { detectApi } from '@/api/v2/detect'
import { can } from '@/api/session'
import { toast } from '@/composables/toast'
import {
  fmtTime, guardFamilyLabel, guardFeedbackLabel, guardInferenceStatusLabel, guardSourceLabel,
  type GuardAsset, type GuardDetection, type GuardEpisode,
  type GuardEpisodeEvidence, type GuardObservation, type GuardObservationBatch,
} from '@/api/types'
import { inferenceTone } from '@/data/tones'

type View = 'batches' | 'observations' | 'detections' | 'episodes'
const route = useRoute()
const router = useRouter()
const view = ref<View>('batches')
const assetFilter = ref(typeof route.query.assetId === 'string' ? route.query.assetId : '')

/** 资产用于把 UUID 翻译成可读标识并提供筛选；无权限时保持为空，不显示占位假值。 */
const assets = ref<GuardAsset[]>([])
void (async () => {
  if (!can('resource.read')) return
  try { assets.value = (await guard.list<GuardAsset>('assets', { limit: 200 })).items } catch { /* 翻译失败不影响本页主列表 */ }
})()
const assetKey = (id: string | null) => assets.value.find((a) => a.id === id)?.assetKey ?? null
const assetLabel = (id: string | null) => (id ? (assetKey(id) ?? id.slice(0, 8)) : '—')

const queryFor = (cursor?: string) => ({
  assetId: assetFilter.value || undefined,
  cursor,
  limit: 50,
})

const batches = useCursor<GuardObservationBatch>((cursor) => detectApi.listBatches(queryFor(cursor)))
const observations = useCursor<GuardObservation>((cursor) => detectApi.listObservations(queryFor(cursor)))
const detections = useCursor<GuardDetection>((cursor) => detectApi.listDetections(queryFor(cursor)))
const episodes = useCursor<GuardEpisode>((cursor) => detectApi.listEpisodes(queryFor(cursor)))

watch(assetFilter, (a) => {
  void router.replace({ query: a ? { assetId: a } : {} })
  batches.reset()
  observations.reset()
  detections.reset()
  episodes.reset()
})

const active = computed(() => (view.value === 'batches' ? batches : view.value === 'observations' ? observations : view.value === 'detections' ? detections : episodes))

const counts = ref({ batches: 0, detections: 0, episodes: 0 })
watch([batches.items, detections.items, episodes.items], () => {
  counts.value = { batches: batches.items.value.length, detections: detections.items.value.length, episodes: episodes.items.value.length }
})

const views = computed(() => [
  { value: 'batches' as const, label: '观察批次', count: counts.value.batches },
  { value: 'observations' as const, label: '观察记录' },
  { value: 'detections' as const, label: '推理结论', count: counts.value.detections },
  { value: 'episodes' as const, label: '证据迹', count: counts.value.episodes },
])

/** 批次受理结果是局部接收：accepted / rejected / duplicate 三态并存，拒绝明细另附。 */
const rejectionCount = (b: GuardObservationBatch) => {
  const r = b.result
  if (!r || typeof r !== 'object') return null
  const o = r as Record<string, unknown>
  return typeof o.rejectedCount === 'number' ? o.rejectedCount : null
}
const acceptedCount = (b: GuardObservationBatch) => {
  const r = b.result
  if (!r || typeof r !== 'object') return null
  const o = r as Record<string, unknown>
  return typeof o.acceptedCount === 'number' ? o.acceptedCount : null
}

const pickedBatch = ref<GuardObservationBatch | null>(null)
const pickedObservation = ref<GuardObservation | null>(null)
const pickedDetection = ref<GuardDetection | null>(null)
const pickedEpisode = ref<GuardEpisode | null>(null)

/** 证据迹的证据明细按需读取（子资源最多 200 条），不在列表阶段预取。 */
const evidence = ref<{ loading: boolean; error: string; items: GuardEpisodeEvidence[] }>({ loading: false, error: '', items: [] })
watch(pickedEpisode, async (e) => {
  if (!e) { evidence.value = { loading: false, error: '', items: [] }; return }
  evidence.value = { loading: true, error: '', items: [] }
  try {
    const r = await detectApi.listEpisodeEvidence(e.id)
    evidence.value = { loading: false, error: '', items: r.items }
  } catch (err) {
    evidence.value = { loading: false, error: errText(err), items: [] }
  }
})

const payloadEntries = (v: unknown): [string, string][] => {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return []
  return Object.entries(v as Record<string, unknown>).map(([k, val]) => [k, typeof val === 'object' && val !== null ? JSON.stringify(val) : String(val)])
}

/** 标注反馈（POST /api/v2/feedback）：仅 feedback.label 可见。 */
const canLabel = computed(() => can('feedback.label'))
const labelForm = reactive({ open: false, observationId: '', label: 'attack', evidenceRef: '', busy: false, error: '', done: '' })

function openLabelFor(observationId: string, defaultRef?: string) {
  labelForm.observationId = observationId
  labelForm.label = 'attack'
  labelForm.evidenceRef = defaultRef ?? `obs:${observationId}`
  labelForm.error = ''
  labelForm.done = ''
  labelForm.open = true
}

async function submitLabel() {
  if (!labelForm.observationId || !labelForm.evidenceRef.trim()) {
    labelForm.error = '请填写证据引用说明'
    return
  }
  labelForm.busy = true
  labelForm.error = ''
  labelForm.done = ''
  try {
    await detectApi.createFeedback(
      labelForm.observationId,
      labelForm.label,
      labelForm.evidenceRef.trim(),
    )
    labelForm.done = '已提交标注（待复核，不自动进入在线训练）'
    toast('标注已提交，等待独立复核')
    observations.reset()
  } catch (err) {
    labelForm.error = errText(err)
  } finally {
    labelForm.busy = false
  }
}
</script>

<template>
  <div>
    <PageHead title="观测与推理" desc="采集身份提交的观察批次、单条因果快照、模型推理结论与目标级证据归并。批次返回 202 仅表示持久化受理，不代表检测或阻断已完成；推理状态需单独读取。只显示全部来源都在你授权范围内的记录。">
      <template #kicker>Observations &amp; Inference</template>
      <label v-if="assets.length" class="w-48 text-[13px]">
        <span class="label">资产筛选</span>
        <select v-model="assetFilter" aria-label="资产筛选" class="field mt-1">
          <option value="">全部授权资产</option>
          <option v-for="a in assets" :key="a.id" :value="a.id">{{ a.assetKey }}</option>
        </select>
      </label>
    </PageHead>

    <Segmented v-model="view" :options="views" />

    <div class="mt-10">
      <LoadState :loading="active.loading.value" :error="active.error.value" :empty="!active.items.value.length" empty-text="数据库中暂无你授权范围内的观测或推理记录。">
      <Transition name="fade" mode="out-in">
        <!-- 观察批次：受理结果三态并存，缺口未恢复期间相应上下文不得用于自动动作 -->
        <table v-if="view === 'batches'" key="b" class="table">
          <thead><tr><th>受理</th><th>批次</th><th>资产</th><th>序号</th><th>接受 / 拒绝</th><th class="text-right">接收时间</th></tr></thead>
          <tbody>
            <tr v-for="b in batches.items.value" :key="b.id" class="row-link" tabindex="0" @click="pickedBatch = b" @keydown.enter="pickedBatch = b">
              <td><span class="num text-[13px]">{{ acceptedCount(b) ?? '—' }}</span><span v-if="rejectionCount(b)" class="num ml-1 text-[12px] text-threat">/ {{ rejectionCount(b) }}</span></td>
              <td><span class="num block">{{ b.id.slice(0, 8) }}</span><span class="num text-[12px] text-ink-3">boot {{ b.bootId.slice(0, 8) }}</span></td>
              <td class="num text-ink-2">{{ assetLabel(b.assetId) }}</td>
              <td class="num text-ink-2">{{ b.sequenceNo }}</td>
              <td class="num text-ink-2">{{ acceptedCount(b) ?? '—' }} / {{ rejectionCount(b) ?? '—' }}</td>
              <td class="num text-right text-ink-3">{{ fmtTime(b.createdAt) }}</td>
            </tr>
          </tbody>
        </table>

        <!-- 单条观察：快照只含 asOf 之前的报文，lastPacketAt 与 asOf 分开 -->
        <table v-else-if="view === 'observations'" key="o" class="table">
          <thead><tr><th>快照</th><th>流</th><th>对象</th><th>方向 / 服务</th><th>Profile</th><th class="text-right">asOf</th></tr></thead>
          <tbody>
            <tr v-for="o in observations.items.value" :key="o.id" class="row-link" tabindex="0" @click="pickedObservation = o; labelForm.open = false" @keydown.enter="pickedObservation = o; labelForm.open = false">
              <td class="num text-ink-2">#{{ o.snapshotIndex ?? '—' }}</td>
              <td><span class="num block">{{ o.flowId.slice(0, 12) }}</span><span class="num text-[12px] text-ink-3">{{ o.keyEpoch ? `epoch ${o.keyEpoch}` : o.flowId }}</span></td>
              <td><span class="num block">{{ o.peerKey ?? '—' }}</span><span class="num text-[12px] text-ink-3">{{ assetLabel(o.assetId) }}</span></td>
              <td class="text-ink-2">{{ o.direction ?? '—' }} / {{ o.servicePort ?? '—' }}</td>
              <td class="num text-ink-3">{{ o.profile ?? '—' }}</td>
              <td class="num text-right text-ink-3">{{ fmtTime(o.asOf) }}</td>
            </tr>
          </tbody>
        </table>

        <!-- 推理结论：失败与不适用不带攻击概率 -->
        <table v-else-if="view === 'detections'" key="d" class="table">
          <thead><tr><th>分数</th><th>结论</th><th>家族</th><th>四类分数</th><th>资产</th><th class="text-right">完成</th></tr></thead>
          <tbody>
            <tr v-for="d in detections.items.value" :key="d.id" class="row-link" tabindex="0" @click="pickedDetection = d; labelForm.open = false" @keydown.enter="pickedDetection = d; labelForm.open = false">
              <td class="num w-20 text-[1.25rem] font-light" :class="(d.score ?? 0) >= 0.9 ? 'text-threat' : ''">{{ d.score == null ? '—' : Number(d.score).toFixed(3) }}</td>
              <td><Tag :tone="inferenceTone[d.status]" :label="guardInferenceStatusLabel[d.status] ?? d.status" /><span v-if="d.errorCode" class="num ml-2 text-[12px] text-threat">{{ d.errorCode }}</span></td>
              <td class="text-ink-2">{{ d.family ? (guardFamilyLabel[d.family] ?? d.family) : '—' }}</td>
              <td><FamilyScores :scores="d.familyScores" compact /></td>
              <td class="num text-ink-2">{{ assetLabel(d.assetId) }}</td>
              <td class="num text-right text-ink-3">{{ fmtTime(d.completedAt) }}</td>
            </tr>
          </tbody>
        </table>

        <!-- 证据迹：按 30 秒桶归并，revision 随证据追加递增 -->
        <table v-else key="e" class="table">
          <thead><tr><th>桶起点</th><th>对象</th><th>方向 / 服务</th><th>家族</th><th>来源</th><th>修订</th><th class="text-right">资产</th></tr></thead>
          <tbody>
            <tr v-for="e in episodes.items.value" :key="e.id" class="row-link" tabindex="0" @click="pickedEpisode = e; labelForm.open = false" @keydown.enter="pickedEpisode = e; labelForm.open = false">
              <td class="num text-ink-2">{{ fmtTime(e.bucketStart) }}</td>
              <td><span class="num block">{{ e.peerKey }}</span><span class="num text-[12px] text-ink-3">{{ e.id.slice(0, 8) }}</span></td>
              <td class="num text-ink-2">{{ e.direction }} / {{ e.servicePort }}</td>
              <td class="text-ink-3">{{ e.family ? (guardFamilyLabel[e.family] ?? e.family) : '—' }}</td>
              <td><span class="block text-ink-2">{{ guardSourceLabel(e.source, e.ruleId) }}</span><span class="num text-[12px] text-ink-4">{{ e.scope ?? '—' }}</span></td>
              <td class="num text-ink-3">r{{ e.revision }}</td>
              <td class="num text-right text-ink-2">{{ assetLabel(e.assetId) }}</td>
            </tr>
          </tbody>
        </table>
      </Transition>
      </LoadState>

      <CursorPager :count="active.items.value.length" :has-next="!!active.next.value" :has-prev="!!active.stack.value.length"
        :busy="active.turning.value" :label="String(view)" @next="active.forward()" @prev="active.back()" />
    </div>

    <!-- 批次详情 -->
    <Drawer :open="!!pickedBatch" :title="pickedBatch ? `批次 ${pickedBatch.id.slice(0, 8)}` : ''" kicker="OBSERVATION BATCH" @close="pickedBatch = null">
      <template v-if="pickedBatch">
        <p class="mb-8 border-l-2 border-signal py-1 pl-4 text-[12.5px] leading-relaxed text-ink-2">202 表示批次已持久化受理，检测、处置与阻断都尚未完成。允许部分接收：拒绝明细由后端按 observationId 逐条返回。</p>
        <dl class="border-t border-ink">
          <div v-for="[k, v] in [
            ['资产', assetLabel(pickedBatch.assetId)],
            ['采集身份', pickedBatch.sensorId],
            ['bootId', pickedBatch.bootId],
            ['序号', String(pickedBatch.sequenceNo)],
            ['配置版本', pickedBatch.configId ?? '—'],
            ['请求摘要', pickedBatch.requestSha256],
            ['接收时间', fmtTime(pickedBatch.createdAt)],
          ]" :key="k" class="grid grid-cols-[7rem_1fr] border-b border-ink-hair py-3 text-[13px]">
            <dt class="text-ink-3">{{ k }}</dt><dd class="num break-all">{{ v }}</dd>
          </div>
        </dl>
        <h3 class="label mb-4 mt-10">受理结果</h3>
        <dl class="border-t border-ink">
          <div v-for="[k, v] in payloadEntries(pickedBatch.result)" :key="k" class="grid grid-cols-[9rem_1fr] border-b border-ink-hair py-2.5 text-[12.5px]">
            <dt class="num text-ink-3">{{ k }}</dt><dd class="num break-all">{{ v }}</dd>
          </div>
          <p v-if="!payloadEntries(pickedBatch.result).length" class="py-3 text-[12.5px] text-ink-3">未保存受理明细。</p>
        </dl>
      </template>
    </Drawer>

    <!-- 观察记录详情 -->
    <Drawer :open="!!pickedObservation" :title="pickedObservation ? `观察 ${pickedObservation.id.slice(0, 8)}` : ''" kicker="OBSERVATION" @close="pickedObservation = null">
      <template v-if="pickedObservation">
        <p class="mb-8 border-l-2 border-ink-line py-1 pl-4 text-[12.5px] leading-relaxed text-ink-2">快照只包含 asOf 之前的报文，不读取未来包与最终时长；父流标识用于近重复归并，同一 parent 的续段不重复计数。</p>
        <dl class="border-t border-ink">
          <div v-for="[k, v] in [
            ['资产', assetLabel(pickedObservation.assetId)],
            ['批次', pickedObservation.batchId],
            ['采集身份', pickedObservation.sensorId],
            ['捕获域', pickedObservation.captureScopeId ?? '—'],
            ['流标识', pickedObservation.flowId],
            ['父流', pickedObservation.parentConnectionId ?? '—'],
            ['快照序', pickedObservation.snapshotIndex == null ? '—' : String(pickedObservation.snapshotIndex)],
            ['Profile', pickedObservation.profile ?? '—'],
            ['asOf', fmtTime(pickedObservation.asOf)],
            ['末包', fmtTime(pickedObservation.lastPacketAt)],
            ['对端键', pickedObservation.peerKey ?? '—'],
            ['keyEpoch', pickedObservation.keyEpoch ?? '—'],
            ['方向', pickedObservation.direction ?? '—'],
            ['传输', pickedObservation.transport ?? '—'],
            ['服务端口', pickedObservation.servicePort == null ? '—' : String(pickedObservation.servicePort)],
            ['环境', pickedObservation.environment ?? '—'],
            ['内容哈希', pickedObservation.contentSha256],
            ['写入时间', fmtTime(pickedObservation.createdAt)],
          ]" :key="k" class="grid grid-cols-[7rem_1fr] border-b border-ink-hair py-3 text-[13px]">
            <dt class="text-ink-3">{{ k }}</dt><dd class="num break-all">{{ v }}</dd>
          </div>
        </dl>
        <h3 class="label mb-4 mt-10">特征与上下文</h3>
        <dl class="border-t border-ink">
          <div v-for="[k, v] in payloadEntries(pickedObservation.payload)" :key="k" class="grid grid-cols-[10rem_1fr] border-b border-ink-hair py-2.5 text-[12.5px]">
            <dt class="num text-ink-3">{{ k }}</dt><dd class="num break-all">{{ v }}</dd>
          </div>
          <p v-if="!payloadEntries(pickedObservation.payload).length" class="py-3 text-[12.5px] text-ink-3">该记录未保存特征载荷。</p>
        </dl>

        <div v-if="canLabel" class="mt-10 border-t border-ink pt-6">
          <div class="flex items-center justify-between">
            <h3 class="label">样本标注反馈</h3>
            <button v-if="!labelForm.open" type="button" class="link text-[12.5px]" @click="openLabelFor(pickedObservation.id, `sha256:${pickedObservation.contentSha256.slice(0, 16)}`)">标注此观察</button>
          </div>
          <div v-if="labelForm.open" class="mt-4 space-y-4 text-[13px]">
            <label class="block">
              <span class="label">标注结论</span>
              <select v-model="labelForm.label" aria-label="标注结论" class="field mt-1">
                <option v-for="(lbl, k) in guardFeedbackLabel" :key="k" :value="k">{{ lbl }}（{{ k }}）</option>
              </select>
            </label>
            <label class="block">
              <span class="label">证据引用说明</span>
              <input v-model="labelForm.evidenceRef" aria-label="证据引用说明" class="field mt-1" placeholder="例如 sha256 或研判依据摘要" />
            </label>
            <p v-if="labelForm.error" role="alert" class="text-[12.5px] text-threat">{{ labelForm.error }}</p>
            <p v-if="labelForm.done" class="text-[12.5px] text-ok">{{ labelForm.done }}</p>
            <div class="flex items-center gap-4">
              <button type="button" class="act" :disabled="labelForm.busy" @click="submitLabel">{{ labelForm.busy ? '提交中…' : '提交标注' }}</button>
              <button type="button" class="link text-[12.5px]" @click="labelForm.open = false">取消</button>
            </div>
          </div>
        </div>

        <p class="mt-6 text-[12.5px] leading-relaxed text-ink-3">原始地址与稳定目标 token 不在接口中返回，模型输入也不含 ID、原始地址和标签辅助字段。</p>
      </template>
    </Drawer>

    <!-- 推理详情 -->
    <Drawer :open="!!pickedDetection" :title="pickedDetection ? `推理 ${pickedDetection.id.slice(0, 8)}` : ''" kicker="INFERENCE" @close="pickedDetection = null">
      <template v-if="pickedDetection">
        <p class="mb-8 border-l-2 py-1 pl-4 text-[12.5px] leading-relaxed text-ink-2" :class="pickedDetection.status === 'succeeded' ? 'border-ok' : 'border-threat'">
          {{ pickedDetection.status === 'succeeded' ? '推理成功，分数为模型输出；分数本身不决定放行或隔离，判定由策略与发布组合完成。' : '推理未成功，不携带攻击概率；缺失数据不会被当作低风险。' }}
        </p>
        <dl class="border-t border-ink">
          <div v-for="[k, v] in [
            ['状态', guardInferenceStatusLabel[pickedDetection.status] ?? pickedDetection.status],
            ['分数', pickedDetection.score == null ? '—' : Number(pickedDetection.score).toFixed(4)],
            ['家族', pickedDetection.family ?? '—'],
            ['适用性', pickedDetection.applicability ?? '—'],
            ['资产', assetLabel(pickedDetection.assetId)],
            ['观察记录', pickedDetection.observationId],
            ['模型', pickedDetection.modelId ?? '—'],
            ['模型清单哈希', pickedDetection.manifestSha256 ?? '—'],
            ['错误码', pickedDetection.errorCode ?? '—'],
            ['完成时间', fmtTime(pickedDetection.completedAt)],
            ['写入时间', fmtTime(pickedDetection.createdAt)],
          ]" :key="k" class="grid grid-cols-[7rem_1fr] border-b border-ink-hair py-3 text-[13px]">
            <dt class="text-ink-3">{{ k }}</dt><dd class="num break-all">{{ v }}</dd>
          </div>
        </dl>
        <h3 class="label mb-4 mt-10">四类分数</h3>
        <FamilyScores :scores="pickedDetection.familyScores" />

        <div v-if="canLabel && pickedDetection.observationId" class="mt-10 border-t border-ink pt-6">
          <div class="flex items-center justify-between">
            <h3 class="label">样本标注反馈</h3>
            <button v-if="!labelForm.open" type="button" class="link text-[12.5px]" @click="openLabelFor(pickedDetection.observationId, `det:${pickedDetection.id.slice(0, 8)}`)">标注关联观察</button>
          </div>
          <div v-if="labelForm.open" class="mt-4 space-y-4 text-[13px]">
            <label class="block">
              <span class="label">标注结论</span>
              <select v-model="labelForm.label" aria-label="标注结论" class="field mt-1">
                <option v-for="(lbl, k) in guardFeedbackLabel" :key="k" :value="k">{{ lbl }}（{{ k }}）</option>
              </select>
            </label>
            <label class="block">
              <span class="label">证据引用说明</span>
              <input v-model="labelForm.evidenceRef" aria-label="证据引用说明" class="field mt-1" />
            </label>
            <p v-if="labelForm.error" role="alert" class="text-[12.5px] text-threat">{{ labelForm.error }}</p>
            <p v-if="labelForm.done" class="text-[12.5px] text-ok">{{ labelForm.done }}</p>
            <div class="flex items-center gap-4">
              <button type="button" class="act" :disabled="labelForm.busy" @click="submitLabel">{{ labelForm.busy ? '提交中…' : '提交标注' }}</button>
              <button type="button" class="link text-[12.5px]" @click="labelForm.open = false">取消</button>
            </div>
          </div>
        </div>
      </template>
    </Drawer>

    <!-- 证据迹详情 -->
    <Drawer :open="!!pickedEpisode" :title="pickedEpisode ? `证据迹 ${pickedEpisode.id.slice(0, 8)}` : ''" kicker="EVIDENCE EPISODE" @close="pickedEpisode = null">
      <template v-if="pickedEpisode">
        <dl class="border-t border-ink">
          <div v-for="[k, v] in [
            ['资产', assetLabel(pickedEpisode.assetId)],
            ['采集身份', pickedEpisode.sensorId],
            ['bootId', pickedEpisode.bootId],
            ['对端键', pickedEpisode.peerKey],
            ['keyEpoch', pickedEpisode.keyEpoch ?? '—'],
            ['方向 / 传输', `${pickedEpisode.direction} / ${pickedEpisode.transport}`],
            ['服务端口', String(pickedEpisode.servicePort)],
            ['家族', pickedEpisode.family ? (guardFamilyLabel[pickedEpisode.family] ?? pickedEpisode.family) : '—'],
            ['来源', guardSourceLabel(pickedEpisode.source, pickedEpisode.ruleId)],
            ['作用域', pickedEpisode.scope ?? '—'],
            ['发布组合', pickedEpisode.bundleId ?? '—'],
            ['桶起点', fmtTime(pickedEpisode.bucketStart)],
            ['修订', String(pickedEpisode.revision)],
          ]" :key="k" class="grid grid-cols-[7rem_1fr] border-b border-ink-hair py-3 text-[13px]">
            <dt class="text-ink-3">{{ k }}</dt><dd class="num break-all">{{ v }}</dd>
          </div>
        </dl>
        <h3 class="label mb-4 mt-10">证据明细</h3>
        <LoadState :loading="evidence.loading" :error="evidence.error" :empty="!evidence.items.length" empty-text="该证据迹暂无关联证据。">
          <ul class="border-t border-ink">
            <li v-for="x in evidence.items" :key="x.id" class="grid grid-cols-[6rem_1fr_auto] items-center gap-3 border-b border-ink-hair py-2.5 text-[12.5px]">
              <span class="num text-ink-3">#{{ x.score == null ? '—' : Number(x.score).toFixed(3) }}</span>
              <span><span class="block">观察 {{ x.observationId.slice(0, 8) }}<template v-if="x.parentConnectionId"> · 父流 {{ x.parentConnectionId.slice(0, 8) }}</template></span><span class="num text-[11.5px] text-ink-4">{{ guardSourceLabel(x.source, x.ruleId) }}<template v-if="x.source === 'rule'"> · {{ x.ruleMatched ? '命中' : '未命中' }}</template> · asOf {{ fmtTime(x.asOf) }}</span></span>
              <button v-if="canLabel" type="button" class="link text-[12px]" @click="openLabelFor(x.observationId, `ep:${pickedEpisode.id.slice(0, 8)}`)" >标注</button>
            </li>
          </ul>
        </LoadState>
        <div v-if="canLabel && labelForm.open" class="mt-6 border-t border-ink pt-4 space-y-4 text-[13px]">
          <p class="num text-[12px] text-ink-3">观察 {{ labelForm.observationId }}</p>
          <label class="block">
            <span class="label">标注结论</span>
            <select v-model="labelForm.label" aria-label="标注结论" class="field mt-1">
              <option v-for="(lbl, k) in guardFeedbackLabel" :key="k" :value="k">{{ lbl }}（{{ k }}）</option>
            </select>
          </label>
          <label class="block">
            <span class="label">证据引用说明</span>
            <input v-model="labelForm.evidenceRef" aria-label="证据引用说明" class="field mt-1" />
          </label>
          <p v-if="labelForm.error" role="alert" class="text-[12.5px] text-threat">{{ labelForm.error }}</p>
          <p v-if="labelForm.done" class="text-[12.5px] text-ok">{{ labelForm.done }}</p>
          <div class="flex items-center gap-4">
            <button type="button" class="act" :disabled="labelForm.busy" @click="submitLabel">{{ labelForm.busy ? '提交中…' : '提交标注' }}</button>
            <button type="button" class="link text-[12.5px]" @click="labelForm.open = false">取消</button>
          </div>
        </div>
        <p class="mt-6 text-[12.5px] leading-relaxed text-ink-3">同一主机其他 peer 不会升级本证据迹；案件可合并多个证据迹，但动作仍绑定单一证据与目标。</p>
      </template>
    </Drawer>
  </div>
</template>
