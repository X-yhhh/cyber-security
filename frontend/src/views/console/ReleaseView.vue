<script setup lang="ts">
/**
 * 策略与发布（10）：v5 的决策策略、发布组合、能力登记与评价台账。
 *
 * 读 `/api/v2` 的 decision-policies / release-bundles / capabilities / evaluation-plans / evaluations，
 * 五个分段对应「策略起草 → 组合冻结 → 评价封存 → 审批激活 → 能力等级」。
 *
 * 关键口径（docs/功能模块设计.md §3.3）：
 * - 策略 draft → reviewed → retired，draft 不能进入活动发布组合；
 * - 发布组合 candidate → evaluated → approved → active → suspended/retired，**审批与激活分开**；
 * - 仅改阈值也要新发布组合，不能复用旧权重的历史成绩；
 * - 报告不反向写入被评估的 subject，避免哈希循环；评估失败保留 candidate 与失败报告，不伪造 evaluated；
 * - 能力等级 research / alert_only / lab_auto / authorized_auto 按平台分别取得，不能复制另一平台成绩。
 *
 * 写操作全部带 Idempotency-Key；审批类另带 If-Match: <revision>。
 * 前端只按权限隐藏入口，职责分离（自批 403）与状态迁移一律以后端判定为准。
 */
import { computed, ref, watch } from 'vue'
import PageHead from '@/components/PageHead.vue'
import Segmented from '@/components/Segmented.vue'
import Tag from '@/components/Tag.vue'
import Drawer from '@/components/Drawer.vue'
import LoadState from '@/components/LoadState.vue'
import CursorPager from '@/components/CursorPager.vue'
import { errText } from '@/composables/load'
import { guard } from '@/api/client'
import { can } from '@/api/session'
import {
  fmtTime, guardBundleStatusLabel, guardCapabilityLevelLabel,
  type GuardCapability, type GuardDecisionPolicy, type GuardEvaluation, type GuardEvaluationPlan,
  type GuardModel, type GuardReleaseBundle,
} from '@/api/types'
import { bundleTone, capabilityTone, policyReviewTone, statusTone } from '@/data/tones'
import { toast } from '@/composables/toast'

type View = 'policies' | 'bundles' | 'capabilities' | 'evaluations'
/** 两级菜单（FE-9）按二级项指定初始分段；F1—F4 拆分本页后删除。 */
const props = defineProps<{ segment?: View }>()
const view = ref<View>(props.segment ?? 'policies')

/** v2 列表为游标分页且不返回总数；游标栈支持回退一页。 */
function useCursor<T>(load: (cursor?: string) => Promise<{ items: T[]; nextCursor: string | null }>) {
  const items = ref([]) as { value: T[] }
  const next = ref<string | null>(null)
  const loading = ref(true)
  const error = ref('')
  const stack = ref<string[]>([])
  const turning = ref(false)
  let seq = 0
  async function go(cursor?: string) {
    const mine = ++seq
    loading.value = true
    error.value = ''
    try {
      const page = await load(cursor)
      if (mine !== seq) return
      items.value = page.items
      next.value = page.nextCursor
    } catch (e) {
      if (mine !== seq) return
      error.value = errText(e)
      items.value = []
      next.value = null
    } finally { if (mine === seq) loading.value = false }
  }
  async function forward() {
    if (!next.value) return
    turning.value = true
    try { const c = next.value; await go(c); stack.value.push(c) } finally { turning.value = false }
  }
  async function back() {
    if (!stack.value.length) return
    turning.value = true
    try { stack.value.pop(); await go(stack.value[stack.value.length - 1]) } finally { turning.value = false }
  }
  function refresh() { seq++; stack.value = []; void go() }
  void go()
  return { items, next, loading, error, stack, turning, forward, back, refresh }
}

const policies = useCursor<GuardDecisionPolicy>((cursor) => guard.list<GuardDecisionPolicy>('decision-policies', { cursor, limit: 50 }))
const bundles = useCursor<GuardReleaseBundle>((cursor) => guard.list<GuardReleaseBundle>('release-bundles', { cursor, limit: 50 }))
const capabilities = useCursor<GuardCapability>((cursor) => guard.list<GuardCapability>('capabilities', { cursor, limit: 50 }))
const evaluations = useCursor<GuardEvaluation>((cursor) => guard.list<GuardEvaluation>('evaluations', { cursor, limit: 50 }))
/** 评价计划数量少且需按 id 翻译，一次性读取用于详情引用。 */
const plans = ref<GuardEvaluationPlan[]>([])
const models = ref<GuardModel[]>([])
void (async () => {
  try {
    if (can('evaluation.read')) plans.value = (await guard.list<GuardEvaluationPlan>('evaluation-plans', { limit: 200 })).items
    if (can('resource.read')) models.value = (await guard.list<GuardModel>('models', { limit: 200 })).items
  } catch { /* 翻译失败不影响主列表 */ }
})()
const planLabel = (id: string | null) => (id ? plans.value.find((p) => p.id === id)?.planKey ?? id.slice(0, 8) : '—')
const modelLabel = (id: string | null) => (id ? models.value.find((m) => m.id === id)?.modelKey ?? id.slice(0, 8) : '—')

const active = computed(() => (view.value === 'policies' ? policies : view.value === 'bundles' ? bundles : view.value === 'capabilities' ? capabilities : evaluations))
const views = computed(() => [
  { value: 'policies' as const, label: '决策策略', count: policies.items.value.length },
  { value: 'bundles' as const, label: '发布组合', count: bundles.items.value.length },
  { value: 'capabilities' as const, label: '能力登记', count: capabilities.items.value.length },
  { value: 'evaluations' as const, label: '评价运行', count: evaluations.items.value.length },
])

const busy = ref(false)
const reason = ref('')
const pickedPolicy = ref<GuardDecisionPolicy | null>(null)
const pickedBundle = ref<GuardReleaseBundle | null>(null)
const pickedCapability = ref<GuardCapability | null>(null)
const pickedEvaluation = ref<GuardEvaluation | null>(null)
watch([pickedPolicy, pickedBundle, pickedCapability], () => { reason.value = '' })

const entries = (v: unknown): [string, string][] => {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return []
  return Object.entries(v as Record<string, unknown>).map(([k, val]) => [k, typeof val === 'object' && val !== null ? JSON.stringify(val) : String(val)])
}

/** 策略复核对：draft 才可复核；同一主体批准由后端拒绝（APPROVAL_SEPARATION_REQUIRED）。 */
const canReviewPolicy = computed(() => can('policy.approve') && pickedPolicy.value?.status === 'draft')
const reviewPolicy = (decision: 'approve' | 'reject') => act(
  () => guard.op('decision-policies', pickedPolicy.value!.id, 'reviews', { decision, reason: reason.value.trim() }, pickedPolicy.value!.revision),
  decision === 'approve' ? '已复核；策略进入 reviewed，仍不自动激活。' : '已驳回，策略记为 retired。',
  () => { pickedPolicy.value = null; policies.refresh() },
)

/** 发布组合：candidate 才可导入报告与封存；evaluated 且有封存清单才可批准。 */
const canImport = computed(() => can('evaluation.run') && pickedBundle.value?.status === 'candidate')
const canSeal = computed(() => can('bundle.request') && pickedBundle.value?.status === 'candidate')
const canDecideBundle = computed(() => can('bundle.approve') && pickedBundle.value?.status === 'evaluated' && !!pickedBundle.value.sealedManifestSha256)
const canActivate = computed(() => can('bundle.approve') && pickedBundle.value?.status === 'approved')
const canSuspend = computed(() => can('automation.stop') && ['active', 'approved'].includes(pickedBundle.value?.status ?? ''))

const importForm = ref({ reportRef: '', sha256: '', runnerIdentity: '' })
const sealForm = ref({ evaluationIds: '' })
const activateForm = ref({ assetIds: '', authorizationIds: '' })

async function act(fn: () => Promise<unknown>, done: string, after?: () => void) {
  busy.value = true
  try {
    await fn()
    toast(done)
    after?.()
  } catch (e) { toast(errText(e), 'threat') } finally { busy.value = false }
}

const importReport = () => {
  if (!importForm.value.reportRef.trim() || !importForm.value.sha256.trim() || !importForm.value.runnerIdentity.trim()) return toast('报告引用、哈希与签发身份都必填。', 'warn')
  void act(() => guard.op('release-bundles', pickedBundle.value!.id, 'imports', { ...importForm.value }), '报告已登记；上传不等于内容真实，仍需计划一致性与签发身份核验。', () => { pickedBundle.value = null; bundles.refresh() })
}
const seal = () => {
  const ids = sealForm.value.evaluationIds.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean)
  if (!ids.length) return toast('至少选择一个评价运行。', 'warn')
  if (!ids.some((id) => evaluations.items.value.find((e) => e.id === id && e.runKind === 'final'))) return toast('封存必须包含一次 final 评价运行。', 'warn')
  void act(() => guard.op('release-bundles', pickedBundle.value!.id, 'sealings', { evaluationIds: ids }, pickedBundle.value!.revision), '已封存；组合进入 evaluated。', () => { pickedBundle.value = null; bundles.refresh() })
}
const decideBundle = (decision: 'approve' | 'reject') => {
  if (!reason.value.trim()) return toast('请填写理由。', 'warn')
  void act(() => guard.op('release-bundles', pickedBundle.value!.id, 'decisions', { decision, reason: reason.value.trim() }, pickedBundle.value!.revision), decision === 'approve' ? '已批准；激活需另行按资产执行。' : '已驳回。', () => { pickedBundle.value = null; bundles.refresh() })
}
const activate = () => {
  const assets = activateForm.value.assetIds.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean)
  const auths = activateForm.value.authorizationIds.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean)
  if (!assets.length || assets.length !== auths.length) return toast('资产与授权必须一一对应且数量相同。', 'warn')
  void act(() => guard.op('release-bundles', pickedBundle.value!.id, 'activations', { assetIds: assets, authorizationIds: auths }, pickedBundle.value!.revision), '已受理激活；逐个资产核验范围，不代表立即生效。', () => { pickedBundle.value = null; bundles.refresh() })
}
const suspend = () => {
  if (!reason.value.trim()) return toast('请填写停用理由。', 'warn')
  void act(() => guard.op('release-bundles', pickedBundle.value!.id, 'suspensions', { reason: reason.value.trim(), revokeExisting: true }, pickedBundle.value!.revision), '已受理停用；立即停新命令，现有规则的清理状态另行查询。', () => { pickedBundle.value = null; bundles.refresh() })
}
</script>

<template>
  <div>
    <PageHead no="10" title="策略与发布" desc="决策策略、冻结发布组合、平台能力等级与评价运行台账。发布组合是不可变组合，审批与激活分开：仅改阈值也要新组合，不能复用旧权重的历史成绩。只显示在你范围内的对象。">
      <template #kicker>Release</template>
    </PageHead>

    <Segmented v-model="view" :options="views" />

    <div class="mt-10">
      <LoadState :loading="active.loading.value" :error="active.error.value" :empty="!active.items.value.length">
      <Transition name="fade" mode="out-in">
        <table v-if="view === 'policies'" key="p" class="table">
          <thead><tr><th>策略</th><th>版本</th><th>状态</th><th>模型</th><th>评价计划</th><th class="text-right">登记</th></tr></thead>
          <tbody>
            <tr v-for="p in policies.items.value" :key="p.id" class="row-link" tabindex="0" @click="pickedPolicy = p" @keydown.enter="pickedPolicy = p">
              <td><span class="num block">{{ p.policyKey }}</span><span class="num text-[12px] text-ink-3">{{ p.id.slice(0, 8) }}</span></td>
              <td class="num text-ink-2">{{ p.version }}</td>
              <td><Tag :tone="policyReviewTone[p.status]" :label="p.status" /></td>
              <td class="num text-ink-2">{{ modelLabel(p.modelId) }}</td>
              <td class="num text-ink-3">{{ planLabel(p.planId) }}</td>
              <td class="num text-right text-ink-3">{{ fmtTime(p.createdAt) }}</td>
            </tr>
          </tbody>
        </table>

        <table v-else-if="view === 'bundles'" key="b" class="table">
          <thead><tr><th>组合</th><th>版本</th><th>状态</th><th>环境</th><th>模型 / 策略</th><th class="text-right">登记</th></tr></thead>
          <tbody>
            <tr v-for="b in bundles.items.value" :key="b.id" class="row-link" tabindex="0" @click="pickedBundle = b" @keydown.enter="pickedBundle = b">
              <td><span class="num block">{{ b.bundleKey }}</span><span class="num text-[12px] text-ink-3">{{ b.subjectSha256.slice(0, 12) }}…</span></td>
              <td class="num text-ink-2">{{ b.version }}</td>
              <td><Tag :tone="bundleTone[b.status]" :label="guardBundleStatusLabel[b.status] ?? b.status" /></td>
              <td class="num text-ink-3">{{ b.environment }}</td>
              <td class="num text-ink-2">{{ modelLabel(b.modelId) }} / {{ b.policyId.slice(0, 8) }}</td>
              <td class="num text-right text-ink-3">{{ fmtTime(b.createdAt) }}</td>
            </tr>
          </tbody>
        </table>

        <table v-else-if="view === 'capabilities'" key="c" class="table">
          <thead><tr><th>能力</th><th>版本</th><th>等级</th><th>平台</th><th>登记</th></tr></thead>
          <tbody>
            <tr v-for="c in capabilities.items.value" :key="c.id" class="row-link" tabindex="0" @click="pickedCapability = c" @keydown.enter="pickedCapability = c">
              <td class="num">{{ c.capabilityKey }}</td>
              <td class="num text-ink-2">{{ c.version }}</td>
              <td><Tag :tone="capabilityTone[c.level]" :label="guardCapabilityLevelLabel[c.level] ?? c.level" /></td>
              <td class="num text-ink-3">{{ c.platform }}</td>
              <td class="num text-ink-3">{{ fmtTime(c.createdAt) }}</td>
            </tr>
          </tbody>
        </table>

        <table v-else key="e" class="table">
          <thead><tr><th>运行类型</th><th>状态</th><th>组合</th><th>签发身份</th><th>报告</th><th class="text-right">登记</th></tr></thead>
          <tbody>
            <tr v-for="e in evaluations.items.value" :key="e.id" class="row-link" tabindex="0" @click="pickedEvaluation = e" @keydown.enter="pickedEvaluation = e">
              <td><span class="block text-ink-2">{{ e.runKind }}</span><span class="num text-[12px] text-ink-3">{{ planLabel(e.planId) }}</span></td>
              <td><Tag :tone="statusTone[e.status]" :label="e.status" /></td>
              <td class="num text-ink-3">{{ e.bundleId ? e.bundleId.slice(0, 8) : '—' }}</td>
              <td class="num text-ink-3">{{ e.runnerIdentity }}</td>
              <td class="num text-ink-3">{{ e.reportRef ? e.reportRef.slice(0, 20) : '—' }}</td>
              <td class="num text-right text-ink-3">{{ fmtTime(e.createdAt) }}</td>
            </tr>
          </tbody>
        </table>
      </Transition>
      </LoadState>

      <CursorPager :count="active.items.value.length" :has-next="!!active.next.value" :has-prev="!!active.stack.value.length"
        :busy="active.turning.value" :label="String(view)" @next="active.forward()" @prev="active.back()" />
    </div>

    <!-- 决策策略详情与复核 -->
    <Drawer :open="!!pickedPolicy" :title="pickedPolicy ? `${pickedPolicy.policyKey} ${pickedPolicy.version}` : ''" kicker="DECISION POLICY" @close="pickedPolicy = null">
      <template v-if="pickedPolicy">
        <p class="mb-8 border-l-2 border-ink-line py-1 pl-4 text-[12.5px] leading-relaxed text-ink-2">策略为 draft 时不能进入活动发布组合；复核通过后记为 reviewed，仍不自动激活。修改阈值也要生成新策略版本并重新组合，不改旧清单冒充已验证。</p>
        <dl class="border-t border-ink">
          <div v-for="[k, v] in [
            ['状态', pickedPolicy.status],
            ['版本', pickedPolicy.version],
            ['模型', modelLabel(pickedPolicy.modelId)],
            ['评价计划', planLabel(pickedPolicy.planId)],
            ['定义哈希', pickedPolicy.definitionSha256],
            ['修订', String(pickedPolicy.revision)],
            ['登记', fmtTime(pickedPolicy.createdAt)],
          ]" :key="k" class="grid grid-cols-[8rem_1fr] border-b border-ink-hair py-3 text-[13px]">
            <dt class="text-ink-3">{{ k }}</dt><dd class="num break-all">{{ v }}</dd>
          </div>
        </dl>
        <h3 class="label mb-4 mt-10">策略定义</h3>
        <dl class="border-t border-ink">
          <div v-for="[k, v] in entries(pickedPolicy.definition)" :key="k" class="grid grid-cols-[10rem_1fr] border-b border-ink-hair py-2.5 text-[12.5px]">
            <dt class="num text-ink-3">{{ k }}</dt><dd class="num break-all">{{ v }}</dd>
          </div>
          <p v-if="!entries(pickedPolicy.definition).length" class="py-3 text-[12.5px] text-ink-3">未保存策略定义。</p>
        </dl>
        <label v-if="canReviewPolicy" class="mt-10 block"><span class="label">复核理由</span><textarea v-model="reason" rows="3" maxlength="1000" class="field mt-2 h-auto resize-none py-2" placeholder="写入审计" /></label>
      </template>
      <template v-if="canReviewPolicy" #foot>
        <button class="link text-[13px]" :disabled="busy" @click="reviewPolicy('reject')">驳回</button>
        <button class="act" :disabled="busy" @click="reviewPolicy('approve')">复核通过</button>
      </template>
    </Drawer>

    <!-- 发布组合详情与全生命周期操作 -->
    <Drawer :open="!!pickedBundle" :title="pickedBundle ? `${pickedBundle.bundleKey} ${pickedBundle.version}` : ''" kicker="RELEASE BUNDLE" @close="pickedBundle = null">
      <template v-if="pickedBundle">
        <p class="mb-8 border-l-2 py-1 pl-4 text-[12.5px] leading-relaxed text-ink-2" :class="pickedBundle.status === 'active' ? 'border-ok' : 'border-ink-line'">
          candidate → evaluated → approved → active，审批与激活分开。评估失败会保留 candidate 与失败报告，不伪造 evaluated；报告完成后才封存发布清单，报告不反向写入被评估的 subject。
        </p>
        <dl class="border-t border-ink">
          <div v-for="[k, v] in [
            ['状态', guardBundleStatusLabel[pickedBundle.status] ?? pickedBundle.status],
            ['环境', pickedBundle.environment],
            ['模型', modelLabel(pickedBundle.modelId)],
            ['策略', pickedBundle.policyId],
            ['评价计划', planLabel(pickedBundle.planId)],
            ['subject 哈希', pickedBundle.subjectSha256],
            ['封存清单哈希', pickedBundle.sealedManifestSha256 ?? '未封存'],
            ['修订', String(pickedBundle.revision)],
            ['登记', fmtTime(pickedBundle.createdAt)],
          ]" :key="k" class="grid grid-cols-[8rem_1fr] border-b border-ink-hair py-3 text-[13px]">
            <dt class="text-ink-3">{{ k }}</dt><dd class="num break-all">{{ v }}</dd>
          </div>
        </dl>
        <h3 class="label mb-4 mt-10">subject 绑定</h3>
        <dl class="border-t border-ink">
          <div v-for="[k, v] in entries(pickedBundle.subject)" :key="k" class="grid grid-cols-[10rem_1fr] border-b border-ink-hair py-2.5 text-[12.5px]">
            <dt class="num text-ink-3">{{ k }}</dt><dd class="num break-all">{{ v }}</dd>
          </div>
          <p v-if="!entries(pickedBundle.subject).length" class="py-3 text-[12.5px] text-ink-3">未保存 subject 内容。</p>
        </dl>

        <section v-if="canImport" class="mt-10 space-y-4 border-t border-ink pt-6">
          <h3 class="label">登记评价报告</h3>
          <label class="block"><span class="label">报告引用</span><input v-model="importForm.reportRef" class="field num mt-2" placeholder="受控产物引用" /></label>
          <label class="block"><span class="label">SHA-256</span><input v-model="importForm.sha256" class="field num mt-2" placeholder="64 位小写十六进制" /></label>
          <label class="block"><span class="label">签发身份</span><input v-model="importForm.runnerIdentity" class="field num mt-2" /></label>
          <p class="text-[12px] leading-relaxed text-ink-3">只登记受控对象，不从任意 URL 抓取；报告上传不等于内容真实，仍须核验来源、哈希与计划一致性。</p>
        </section>

        <section v-if="canSeal" class="mt-10 space-y-4 border-t border-ink pt-6">
          <h3 class="label">封存发布清单</h3>
          <label class="block"><span class="label">评价运行 ID（逗号或换行分隔）</span><textarea v-model="sealForm.evaluationIds" rows="3" class="field num mt-2 h-auto resize-none py-2 text-[12px]" /></label>
          <p class="text-[12px] leading-relaxed text-ink-3">必须含一次 final 运行；非 research 环境另需 platform 与 canary。封存成功才进入 evaluated。</p>
        </section>

        <section v-if="canActivate" class="mt-10 space-y-4 border-t border-ink pt-6">
          <h3 class="label">按资产激活</h3>
          <label class="block"><span class="label">资产 ID</span><textarea v-model="activateForm.assetIds" rows="2" class="field num mt-2 h-auto resize-none py-2 text-[12px]" /></label>
          <label class="block"><span class="label">授权 ID（与资产一一对应）</span><textarea v-model="activateForm.authorizationIds" rows="2" class="field num mt-2 h-auto resize-none py-2 text-[12px]" /></label>
          <p class="text-[12px] leading-relaxed text-ink-3">激活逐个资产核验范围；授权在执行时仍须有效，任一不明确即 fail-closed。</p>
        </section>

        <label v-if="canDecideBundle || canSuspend" class="mt-10 block"><span class="label">理由</span><textarea v-model="reason" rows="3" maxlength="1000" class="field mt-2 h-auto resize-none py-2" placeholder="写入审计" /></label>
      </template>
      <template v-if="canImport || canSeal || canDecideBundle || canActivate || canSuspend" #foot>
        <button v-if="canImport" class="link text-[13px]" :disabled="busy" @click="importReport">登记报告</button>
        <button v-if="canSeal" class="link text-[13px]" :disabled="busy" @click="seal">封存</button>
        <button v-if="canSuspend" class="link text-[13px] text-threat" :disabled="busy" @click="suspend">停用并清理</button>
        <template v-if="canDecideBundle">
          <button class="link text-[13px]" :disabled="busy" @click="decideBundle('reject')">驳回</button>
          <button class="act" :disabled="busy" @click="decideBundle('approve')">批准</button>
        </template>
        <button v-if="canActivate" class="act" :disabled="busy" @click="activate">激活</button>
      </template>
    </Drawer>

    <!-- 能力详情 -->
    <Drawer :open="!!pickedCapability" :title="pickedCapability ? pickedCapability.capabilityKey : ''" kicker="CAPABILITY" @close="pickedCapability = null">
      <template v-if="pickedCapability">
        <p class="mb-8 border-l-2 py-1 pl-4 text-[12.5px] leading-relaxed text-ink-2" :class="pickedCapability.level === 'research' ? 'border-ink-line' : 'border-warn'">
          等级按 (平台, 适配器, 地址族, 协议, 方向, 家族, 特征 profile) 分别取得，不能复制另一平台成绩。声明能力必须有对应证据，未实现的 v5 能力不按已部署描述。
        </p>
        <dl class="border-t border-ink">
          <div v-for="[k, v] in [
            ['等级', guardCapabilityLevelLabel[pickedCapability.level] ?? pickedCapability.level],
            ['平台', pickedCapability.platform],
            ['版本', pickedCapability.version],
            ['登记', fmtTime(pickedCapability.createdAt)],
          ]" :key="k" class="grid grid-cols-[8rem_1fr] border-b border-ink-hair py-3 text-[13px]">
            <dt class="text-ink-3">{{ k }}</dt><dd class="num break-all">{{ v }}</dd>
          </div>
        </dl>
        <h3 class="label mb-4 mt-10">能力证据</h3>
        <dl class="border-t border-ink">
          <div v-for="[k, v] in entries(pickedCapability.payload)" :key="k" class="grid grid-cols-[10rem_1fr] border-b border-ink-hair py-2.5 text-[12.5px]">
            <dt class="num text-ink-3">{{ k }}</dt><dd class="num break-all">{{ v }}</dd>
          </div>
          <p v-if="!entries(pickedCapability.payload).length" class="py-3 text-[12.5px] text-ink-3">未保存能力载荷。</p>
        </dl>
      </template>
    </Drawer>

    <!-- 评价运行详情 -->
    <Drawer :open="!!pickedEvaluation" :title="pickedEvaluation ? `评价运行 ${pickedEvaluation.id.slice(0, 8)}` : ''" kicker="EVALUATION RUN" @close="pickedEvaluation = null">
      <template v-if="pickedEvaluation">
        <dl class="border-t border-ink">
          <div v-for="[k, v] in [
            ['运行类型', pickedEvaluation.runKind],
            ['状态', pickedEvaluation.status],
            ['评价计划', planLabel(pickedEvaluation.planId)],
            ['发布组合', pickedEvaluation.bundleId ?? '—'],
            ['签发身份', pickedEvaluation.runnerIdentity],
            ['报告引用', pickedEvaluation.reportRef ?? '—'],
            ['报告哈希', pickedEvaluation.reportSha256 ?? '—'],
            ['登记', fmtTime(pickedEvaluation.createdAt)],
          ]" :key="k" class="grid grid-cols-[8rem_1fr] border-b border-ink-hair py-3 text-[13px]">
            <dt class="text-ink-3">{{ k }}</dt><dd class="num break-all">{{ v }}</dd>
          </div>
        </dl>
        <h3 class="label mb-4 mt-10">运行载荷</h3>
        <dl class="border-t border-ink">
          <div v-for="[k, v] in entries(pickedEvaluation.payload)" :key="k" class="grid grid-cols-[10rem_1fr] border-b border-ink-hair py-2.5 text-[12.5px]">
            <dt class="num text-ink-3">{{ k }}</dt><dd class="num break-all">{{ v }}</dd>
          </div>
          <p v-if="!entries(pickedEvaluation.payload).length" class="py-3 text-[12.5px] text-ink-3">未保存运行载荷。</p>
        </dl>
        <p class="mt-6 text-[12.5px] leading-relaxed text-ink-3">报告按角色、行为与来源给出样本量、独立组与区间，不只看合并均值。点估计不等于真实精确率已被证明。</p>
      </template>
    </Drawer>
  </div>
</template>
