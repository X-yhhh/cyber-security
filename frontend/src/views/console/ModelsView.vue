<script setup lang="ts">
/**
 * 模型治理：版本与发布、漂移与反馈、离线训练三段。
 * 版本与 manifest 来自 /models（按 model_registry 范围过滤），发布记录与部署来自各自台账。
 * 页面提供制品校验、发布申请、发布审批与本机激活四个命令，全部由后端校验门禁与职责分离；
 * 漂移只展示观察结果，不自动改阈值或权重。
 * 阶段 2：非活动版本可退役（POST /models/{id}/retire，事实与制品保留）；活动部署可回退到同模型键最近的已批准历史部署
 * （POST /model-deployments/rollback，带 expectedCurrentModelId 并二次确认）。活动部署、待审申请、已退役与无可回退版本均为 409。
 */
import { computed, ref, watch } from 'vue'
import PageHead from '@/components/PageHead.vue'
import Segmented from '@/components/Segmented.vue'
import Tag from '@/components/Tag.vue'
import LoadState from '@/components/LoadState.vue'
import { api, type Page } from '@/api/client'
import { can, session } from '@/api/session'
import { fmtTime, modelStageLabel, type DeploymentView, type DriftView, type FeedbackView, type ModelView, type ReleaseView, type TrainingJobView } from '@/api/types'
import { statusTone } from '@/data/tones'
import { toast } from '@/composables/toast'
import { errText, useLoad } from '@/composables/load'

const { data, loading, error, reload } = useLoad(async () => {
  if (!can('model.validation.read')) throw new Error('当前身份没有模型治理查看权限（model.validation.read），平台管理员与模型治理按职责分离。')
  const [models, deployments, drift, feedback, jobs] = await Promise.all([
    api.get<Page<ModelView>>('/api/v1/models?size=100').then((p) => p.items),
    api.get<DeploymentView[]>('/api/v1/model-deployments'),
    api.get<DriftView[]>('/api/v1/model-drift-windows'),
    api.get<FeedbackView[]>('/api/v1/feedback-samples'),
    api.get<TrainingJobView[]>('/api/v1/training-jobs'),
  ])
  return { models, deployments, drift, feedback, jobs }
}, { models: [] as ModelView[], deployments: [] as DeploymentView[], drift: [] as DriftView[], feedback: [] as FeedbackView[], jobs: [] as TrainingJobView[] })

const tab = ref<'versions' | 'drift' | 'training'>('versions')
const selId = ref<number | null>(null)
watch(() => data.value.models, (l) => { if (l.length && !l.some((x) => x.id === selId.value)) selId.value = l[0].id })
const m = computed(() => data.value.models.find((x) => x.id === selId.value))
const deployment = computed(() => data.value.deployments.find((d) => d.modelVersionId === m.value?.id && d.status === 'active'))

const releases = ref<ReleaseView[]>([])
watch(m, async (x) => {
  releases.value = []
  if (x) try { releases.value = await api.get<ReleaseView[]>(`/api/v1/models/${x.id}/release-requests`) } catch { /* 无权限时留空 */ }
})
const pendingRelease = computed(() => releases.value.find((r) => r.reviewStatus === 'pending'))

// manifest 中的评估指标；缺失字段显示为 —，不补值
type Obj = Record<string, unknown>
const man = computed(() => (m.value?.manifest ?? {}) as Obj)
const holdout = computed(() => ((man.value.evaluation as Obj | undefined)?.holdout ?? {}) as Obj)
const metric = (k: string) => (typeof holdout.value[k] === 'number' ? (holdout.value[k] as number).toFixed(4) : '—')
const pick = (path: string) => path.split('.').reduce<unknown>((o, k) => (o && typeof o === 'object' ? (o as Obj)[k] : undefined), man.value)
const str = (path: string) => { const v = pick(path); return v == null ? '—' : typeof v === 'object' ? JSON.stringify(v) : String(v) }
const featureCount = computed(() => {
  const f = pick('feature_contract.features') ?? pick('feature_contract.feature_order')
  return Array.isArray(f) ? f.length : null
})

// 命令：每个按钮只在具备对应权限时出现，门禁与职责分离由后端判定
const busy = ref(false)
const reason = ref('')
async function run(label: string, fn: () => Promise<unknown>) {
  if (!reason.value.trim() && label !== '制品校验') return toast('请先填写操作理由。', 'warn')
  busy.value = true
  try {
    await fn()
    toast(`${label}已提交并写入审计。`)
    reason.value = ''
    await reload()
    if (m.value) releases.value = await api.get<ReleaseView[]>(`/api/v1/models/${m.value.id}/release-requests`).catch(() => [])
  } catch (e) { toast(errText(e), 'threat') } finally { busy.value = false }
}
const validate = () => run('制品校验', () => api.post(`/api/v1/models/${m.value!.id}/validate`))
const requestRelease = () => run('发布申请', () => api.post(`/api/v1/models/${m.value!.id}/release-requests`, { reason: reason.value.trim() }))
const decideRelease = (ok: boolean) => run(ok ? '发布批准' : '发布驳回', () => api.post(`/api/v1/model-release-requests/${pendingRelease.value!.id}/decision`, { decision: ok ? 'approve' : 'reject', reason: reason.value.trim() }))
const activate = () => run('本机激活', () => api.put('/api/v1/model-deployments/active', { modelVersionId: m.value!.id, reason: reason.value.trim() }))
const retire = () => run('版本退役', () => api.post(`/api/v1/models/${m.value!.id}/retire`, { reason: reason.value.trim() }))
// 回退需二次确认：第一次点击只展开确认区，确认时以当前活动版本作为 expectedCurrentModelId
const confirmingRollback = ref(false)
watch(m, () => { confirmingRollback.value = false })
function askRollback() {
  if (!reason.value.trim()) return toast('请先填写操作理由。', 'warn')
  confirmingRollback.value = true
}
const rollback = () => run('部署回退', async () => {
  confirmingRollback.value = false
  await api.post('/api/v1/model-deployments/rollback', { expectedCurrentModelId: m.value!.id, reason: reason.value.trim() })
})
const stages = ['candidate', 'validated', 'approved']
const stageIdx = computed(() => (deployment.value ? 3 : stages.indexOf(m.value?.approvalStatus ?? '')))
const allowed = computed(() => ({
  validate: can('model.candidate.validate') && m.value?.approvalStatus === 'candidate',
  request: can('model.release.request') && m.value?.approvalStatus === 'validated' && !pendingRelease.value,
  decide: can('model.release.approve') && !!pendingRelease.value && pendingRelease.value.requester !== session.user?.username,
  activate: can('model.deployment.activate') && m.value?.approvalStatus === 'approved' && !deployment.value,
  retire: can('model.candidate.manage') && !!m.value && m.value.approvalStatus !== 'retired' && !deployment.value && !pendingRelease.value,
  rollback: can('model.deployment.activate') && !!deployment.value && deployment.value.environment === 'local',
}))
</script>

<template>
  <div>
    <PageHead no="04" title="模型治理" desc="在线检测期间权重保持冻结。再训练在 Windows 离线环境执行，经校验、独立审批后才能激活。">
      <template #kicker>Models</template>
    </PageHead>

    <Segmented v-model="tab" :options="[{ value: 'versions', label: '版本与发布', count: data.models.length }, { value: 'drift', label: '漂移与反馈', count: data.drift.length }, { value: 'training', label: '离线训练', count: data.jobs.length }]" />

    <LoadState :loading="loading" :error="error">
      <Transition name="fade" mode="out-in">
        <div v-if="tab === 'versions'" key="v" class="mt-10">
          <p v-if="!data.models.length" class="py-16 text-center text-ink-3">当前授权范围内没有已登记的模型版本。</p>
          <div v-else class="grid gap-16 lg:grid-cols-[18rem_1fr]">
            <ul class="border-t border-ink">
              <li v-for="x in data.models" :key="x.id">
                <button class="w-full border-b border-ink-hair py-4 text-left transition-colors" :class="x.id === selId ? 'text-ink' : 'text-ink-3 hover:text-ink'" @click="selId = x.id">
                  <span class="num block text-[13.5px]">{{ x.modelKey }} · {{ x.version }}</span>
                  <span class="mt-1 flex items-center justify-between text-[12px]">
                    <span>{{ x.taskType }}</span>
                    <Tag :tone="data.deployments.some((d) => d.modelVersionId === x.id && d.status === 'active') ? 'ok' : statusTone[x.approvalStatus]" :label="data.deployments.some((d) => d.modelVersionId === x.id && d.status === 'active') ? '活动' : modelStageLabel[x.approvalStatus] ?? x.approvalStatus" />
                  </span>
                </button>
              </li>
            </ul>
            <section v-if="m" :key="m.id">
              <p class="label">{{ m.taskType }}</p>
              <h2 class="num mt-3 text-[1.75rem] font-light tracking-[-0.02em]">{{ m.modelKey }} · {{ m.version }}</h2>

              <ol class="mt-12 grid grid-cols-4">
                <li v-for="(s, i) in ['候选', '已校验', '已批准', '活动']" :key="s" class="relative pt-5">
                  <span class="absolute left-0 right-0 top-0 h-px" :class="i <= stageIdx ? 'bg-ink' : 'bg-ink-line'" />
                  <span class="absolute left-0 top-[-3px] h-[7px] w-[7px]" :class="i < stageIdx ? 'bg-ink' : i === stageIdx ? 'bg-signal' : 'border border-ink-line bg-paper'" />
                  <span class="text-[12.5px]" :class="i <= stageIdx ? 'text-ink' : 'text-ink-4'">{{ s }}</span>
                </li>
              </ol>

              <div class="mt-14 grid grid-cols-2 gap-x-10 gap-y-10 md:grid-cols-4">
                <div v-for="k in ['pr_auc', 'mcc', 'fpr', 'fnr']" :key="k" class="border-t border-ink pt-4">
                  <p class="label">{{ k.toUpperCase().replace('_', '-') }}</p>
                  <p class="num mt-3 text-[1.75rem] font-light">{{ metric(k) }}</p>
                </div>
              </div>
              <p class="mt-4 text-[12px] text-ink-3">指标取自 manifest 中锁定测试集评估（{{ str('evaluation.holdout.rows') }} 行）。DoS 类识别不等于通用 DDoS 防护。</p>

              <div class="mt-14 grid gap-14 xl:grid-cols-2">
                <div>
                  <h3 class="label mb-4">Manifest</h3>
                  <dl class="border-t border-ink">
                    <div v-for="[k, v] in [['运行时', `onnxruntime ${str('runtime.onnxruntime')} · ${str('runtime.execution_provider')}`], ['特征契约', `${m.featureContractVersion}${featureCount ? ' · ' + featureCount + ' 项' : ''}`], ['切分指纹', str('dataset.split_fingerprint')], ['阈值', `${str('decision.threshold')} · 不可调`], ['制品', m.artifactRef], ['SHA-256', m.artifactSha256], ['登记', fmtTime(m.createdAt)]]" :key="k" class="grid grid-cols-[6.5rem_1fr] border-b border-ink-hair py-3 text-[13px]">
                      <dt class="text-ink-3">{{ k }}</dt><dd class="num break-all">{{ v }}</dd>
                    </div>
                  </dl>
                </div>
                <div>
                  <h3 class="label mb-4">发布记录</h3>
                  <ul class="border-t border-ink">
                    <li v-for="r in releases" :key="r.id" class="border-b border-ink-hair py-3 text-[13px]">
                      <p class="flex justify-between"><span>{{ r.requester ?? '—' }} → {{ r.approver ?? '待审批' }}</span><Tag :tone="statusTone[r.reviewStatus]" :label="r.reviewStatus" /></p>
                      <p class="mt-1 text-[12px] text-ink-3">{{ r.requestReason ?? '—' }}</p>
                      <p v-if="r.decisionReason" class="mt-1 text-[12px] text-ink-3">决定：{{ r.decisionReason }} · {{ fmtTime(r.reviewedAt) }}</p>
                    </li>
                    <li v-if="!releases.length" class="py-6 text-[13px] text-ink-3">暂无发布申请。</li>
                  </ul>
                  <p v-if="deployment" class="mt-6 text-[12.5px] text-ink-2">本机部署：{{ deployment.runtimeType }} · {{ deployment.mode }} · 激活于 {{ fmtTime(deployment.activatedAt) }}</p>
                </div>
              </div>

              <div v-if="allowed.validate || allowed.request || allowed.decide || allowed.activate || allowed.retire || allowed.rollback" class="mt-14 border-t border-ink pt-6">
                <label class="block"><span class="label">操作理由</span><textarea v-model="reason" rows="2" maxlength="1000" class="field mt-2 h-auto resize-none py-2" /></label>
                <div class="mt-6 flex flex-wrap gap-6">
                  <button v-if="allowed.validate" class="act" :disabled="busy" @click="validate">提交制品校验</button>
                  <button v-if="allowed.request" class="act" :disabled="busy" @click="requestRelease">申请发布审批</button>
                  <template v-if="allowed.decide"><button class="link text-[13px]" :disabled="busy" @click="decideRelease(false)">驳回发布</button><button class="act" :disabled="busy" @click="decideRelease(true)">批准发布</button></template>
                  <button v-if="allowed.activate" class="act" :disabled="busy" @click="activate">激活为本机部署</button>
                  <button v-if="allowed.rollback && !confirmingRollback" class="act-ghost" :disabled="busy" @click="askRollback">回退到上一已批准版本</button>
                  <button v-if="allowed.retire" class="act-ghost" :disabled="busy" @click="retire">退役此版本</button>
                </div>
                <div v-if="allowed.rollback && confirmingRollback" class="mt-6 border-l-2 border-threat py-1 pl-4" role="alertdialog" aria-label="确认回退">
                  <p class="text-[12.5px] leading-relaxed text-ink-2">将停用当前本机部署 <span class="num">{{ m.modelKey }} · {{ m.version }}</span>，改为激活同模型键最近的已批准历史部署；目标制品会重新校验，失败时不改变运行模型。</p>
                  <div class="mt-4 flex gap-6">
                    <button class="link text-[13px]" :disabled="busy" @click="confirmingRollback = false">取消</button>
                    <button class="act" :disabled="busy" @click="rollback">确认回退</button>
                  </div>
                </div>
                <p v-if="allowed.retire" class="mt-4 text-[12px] text-ink-3">退役只改变版本状态，制品引用与审批事实保留；退役版本不可再发布或激活。</p>
              </div>
            </section>
          </div>
        </div>

        <div v-else-if="tab === 'drift'" key="d" class="mt-10">
          <h2 class="mb-6 text-[15px]">漂移窗口</h2>
          <table class="table">
            <thead><tr><th>窗口</th><th>模型</th><th>数据源</th><th>质量拒绝率</th><th>状态</th></tr></thead>
            <tbody>
              <tr v-for="w in data.drift" :key="w.id">
                <td class="num">{{ fmtTime(w.windowStart) }} — {{ fmtTime(w.windowEnd, false) }}</td>
                <td class="num text-ink-2">{{ w.modelKey }} · {{ w.version }}</td>
                <td class="num text-ink-2">#{{ w.dataSourceId }}</td>
                <td class="num">{{ w.qualityRejectRate == null ? '—' : (Number(w.qualityRejectRate) * 100).toFixed(2) + '%' }}</td>
                <td><Tag :tone="w.driftStatus === 'normal' ? 'ok' : 'warn'" :label="w.driftStatus" /></td>
              </tr>
              <tr v-if="!data.drift.length"><td colspan="5" class="py-12 text-center text-ink-3">数据库中暂无漂移统计窗口。</td></tr>
            </tbody>
          </table>
          <p class="mt-4 text-[12px] text-ink-3">漂移统计由离线/在线窗口汇总写入；超出阈值仅创建观察告警，需人工判断是否由采集降级导致。</p>

          <h2 class="mb-6 mt-20 text-[15px]">人工反馈样本</h2>
          <table class="table">
            <thead><tr><th>样本</th><th>来源告警</th><th>标签</th><th>依据</th><th>复核人</th><th>训练资格</th></tr></thead>
            <tbody>
              <tr v-for="f in data.feedback" :key="f.id">
                <td class="num">#{{ f.id }}</td><td class="num text-ink-2">{{ f.alertKey ?? '—' }}</td><td class="num">{{ f.label }}</td>
                <td class="text-ink-2">{{ f.labelSource }}</td><td class="text-ink-2">{{ f.reviewer ?? '—' }}</td>
                <td><Tag :tone="f.trainingEligible ? 'ok' : 'mute'" :label="f.trainingEligible ? '可用' : '不纳入'" /></td>
              </tr>
              <tr v-if="!data.feedback.length"><td colspan="6" class="py-12 text-center text-ink-3">数据库中暂无人工反馈样本。</td></tr>
            </tbody>
          </table>
          <p class="mt-4 text-[12px] text-ink-3">告警本身不作为真值；不使用伪标签，不做在线增量拟合。</p>
        </div>

        <div v-else key="t" class="mt-10">
          <table class="table">
            <thead><tr><th>任务</th><th>数据集版本</th><th>训练主机</th><th>申请人</th><th>产出</th><th>状态</th></tr></thead>
            <tbody>
              <tr v-for="j in data.jobs" :key="j.id">
                <td><span class="num block">{{ j.jobKey }}</span><span class="text-[12px] text-ink-3">{{ fmtTime(j.startedAt) }} — {{ fmtTime(j.finishedAt) }}</span></td>
                <td class="text-ink-2">{{ j.datasetVersion }}</td><td class="num text-ink-2">{{ j.trainHostRef ?? '—' }}</td><td class="text-ink-2">{{ j.requester }}</td>
                <td class="num text-ink-2">{{ j.resultManifestRef ?? j.failureReason ?? '—' }}</td>
                <td><Tag :tone="statusTone[j.status]" :label="j.status" /></td>
              </tr>
              <tr v-if="!data.jobs.length"><td colspan="6" class="py-12 text-center text-ink-3">数据库中暂无离线训练任务登记。</td></tr>
            </tbody>
          </table>
          <p class="mt-6 max-w-2xl text-[12.5px] leading-relaxed text-ink-3">训练在 Windows CUDA 离线环境执行，平台只登记任务与导入结果。训练输出始终是候选版本，不直接修改活动部署。</p>
        </div>
      </Transition>
    </LoadState>
  </div>
</template>
