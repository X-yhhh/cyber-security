<script setup lang="ts">
/**
 * 验证记录只读抽屉：评价运行、评价计划、研究回放（发布管理 `?tab=validation&record=…&id=`）。
 * 评价运行的报告原文只摘出结论与局限（limitations 原样列出，不改写）；引用、摘要与原文收进「技术细节」。
 */
import { computed, ref, watch } from 'vue'
import { RouterLink } from 'vue-router'
import Drawer from '@/components/Drawer.vue'
import Tag from '@/components/Tag.vue'
import IdText from '@/components/IdText.vue'
import LoadState from '@/components/LoadState.vue'
import { errText } from '@/composables/load'
import { fmtTime } from '@/api/types'
import { releaseApi, type Evaluation, type EvaluationPlan, type ReplayRun } from '@/api/v2/release'
import { evaluationTone, replayTone } from '@/data/tones'
import { ensureIndex, evaluationStatusLabel, isObject, modelName, planName, policyName, replayStatusLabel, runKindLabel, short } from './shared'

const props = defineProps<{ kind: 'evaluations' | 'plans' | 'replays'; id: string }>()
const emit = defineEmits<{ close: [] }>()

const row = ref<Evaluation | EvaluationPlan | ReplayRun | null>(null)
const loading = ref(false)
const error = ref('')
let seq = 0
watch(() => [props.kind, props.id] as const, async ([kind, id]) => {
  const mine = ++seq
  if (!id) { row.value = null; return }
  loading.value = true
  error.value = ''
  try {
    const r = kind === 'evaluations' ? await releaseApi.getEvaluation(id) : kind === 'plans' ? await releaseApi.getEvaluationPlan(id) : await releaseApi.getReplayRun(id)
    if (mine === seq) row.value = r
    void ensureIndex('plans')
  } catch (e) { if (mine === seq) { row.value = null; error.value = errText(e) } } finally { if (mine === seq) loading.value = false }
}, { immediate: true })

const evaluation = computed(() => (props.kind === 'evaluations' ? row.value as Evaluation | null : null))
const plan = computed(() => (props.kind === 'plans' ? row.value as EvaluationPlan | null : null))
const replay = computed(() => (props.kind === 'replays' ? row.value as ReplayRun | null : null))
const payload = computed(() => (row.value && isObject((row.value as { payload?: unknown }).payload) ? (row.value as { payload: Record<string, unknown> }).payload : {}))
const limitations = computed(() => (Array.isArray(payload.value.limitations) ? payload.value.limitations.map(String) : []))
const scalars = computed(() => Object.entries(payload.value).filter(([, v]) => v !== null && typeof v !== 'object').slice(0, 10).map(([k, v]) => [k, String(v)] as [string, string]))
const frozen = computed(() => (payload.value.kind === 'p6-frozen' && isObject(payload.value.plan) ? payload.value.plan : null))
const title = computed(() => {
  if (evaluation.value) return `评价运行 · ${runKindLabel[evaluation.value.runKind] ?? evaluation.value.runKind}`
  if (plan.value) return plan.value.planKey
  if (replay.value) return `研究回放 ${short(replay.value.id)}`
  return { evaluations: '评价运行', plans: '评价计划', replays: '研究回放' }[props.kind]
})
const raw = computed(() => JSON.stringify(payload.value, null, 2))
</script>

<template>
  <Drawer :open="!!id" :title="title" :kicker="`验证记录 · ${{ evaluations: '评价运行', plans: '评价计划', replays: '研究回放' }[kind]}`" @close="emit('close')">
    <LoadState :loading="loading" :error="error">
      <template v-if="evaluation">
        <p class="note mb-5" :class="evaluation.status === 'failed' ? 'note-threat' : ''">由签名报告登记；结果以报告的 passed 为准。点估计不等于真实精确率已被证明。</p>
        <dl class="kv">
          <div><dt>结果</dt><dd><Tag :tone="evaluationTone[evaluation.status]" :label="evaluationStatusLabel[evaluation.status] ?? evaluation.status" /></dd></div>
          <div><dt>运行类型</dt><dd>{{ runKindLabel[evaluation.runKind] ?? evaluation.runKind }}</dd></div>
          <div><dt>评价计划</dt><dd class="num">{{ planName(evaluation.planId) }}</dd></div>
          <div><dt>发布组合</dt><dd><RouterLink v-if="evaluation.bundleId" class="link num" :to="{ query: { tab: 'bundles', id: evaluation.bundleId } }">{{ short(evaluation.bundleId) }}</RouterLink><span v-else>—</span></dd></div>
          <div><dt>签发身份</dt><dd class="num break-all">{{ evaluation.runnerIdentity }}</dd></div>
          <div><dt>登记</dt><dd class="num">{{ fmtTime(evaluation.createdAt) }}</dd></div>
        </dl>
        <template v-if="limitations.length">
          <h3 class="section-title mt-8">局限（报告原文）</h3>
          <ul class="list-disc space-y-1 pl-5 text-[12.5px] text-ink-2"><li v-for="(l, i) in limitations" :key="i">{{ l }}</li></ul>
        </template>
      </template>

      <template v-else-if="plan">
        <p class="note mb-5">{{ frozen ? '冻结原件：按原文件字节摘要登记，读取测试集前冻结，不接受内联改写。' : '结构化登记：由字段生成计划摘要（兼容旧登记方式）。' }}</p>
        <dl class="kv">
          <div><dt>计划键</dt><dd class="num break-all">{{ plan.planKey }}</dd></div>
          <div><dt>版本</dt><dd class="num">{{ plan.version }}</dd></div>
          <div><dt>登记方式</dt><dd>{{ frozen ? '冻结原件' : '结构化' }}</dd></div>
          <div v-if="frozen && typeof payload.planRef === 'string'"><dt>原件引用</dt><dd class="num break-all">{{ payload.planRef }}</dd></div>
          <div><dt>登记</dt><dd class="num">{{ fmtTime(plan.createdAt) }}</dd></div>
        </dl>
      </template>

      <template v-else-if="replay">
        <p class="note mb-5">研究回放固定 1 倍速，只在研究环境运行，不包含任何真实目标；开始、完成与失败由 runner 登记。</p>
        <dl class="kv">
          <div><dt>状态</dt><dd><Tag pill :tone="replayTone[replay.status]" :label="replayStatusLabel[replay.status] ?? replay.status" /></dd></div>
          <div><dt>模型</dt><dd>{{ modelName(replay.modelId) }}</dd></div>
          <div><dt>策略</dt><dd>{{ policyName(replay.policyId) }}</dd></div>
          <div><dt>研究组合</dt><dd><RouterLink class="link num" :to="{ query: { tab: 'bundles', id: replay.bundleId } }">{{ short(replay.bundleId) }}</RouterLink></dd></div>
          <div><dt>倍速</dt><dd class="num">{{ replay.speed }}×（固定）</dd></div>
          <div><dt>登记</dt><dd class="num">{{ fmtTime(replay.createdAt) }}</dd></div>
        </dl>
      </template>

      <details v-if="row" class="mt-7 text-[12.5px]">
        <summary class="cursor-pointer text-ink-3 hover:text-ink">技术细节</summary>
        <dl class="kv mt-2">
          <div><dt>ID</dt><dd><IdText :value="row.id" /></dd></div>
          <template v-if="evaluation">
            <div><dt>报告引用</dt><dd class="num break-all">{{ evaluation.reportRef ?? '—' }}</dd></div>
            <div><dt>报告摘要</dt><dd><IdText :value="evaluation.reportSha256" :length="16" /></dd></div>
          </template>
          <div v-if="plan"><dt>计划摘要</dt><dd><IdText :value="plan.planSha256" :length="16" /></dd></div>
          <template v-if="replay">
            <div><dt>场景</dt><dd><IdText :value="replay.scenarioId" /></dd></div>
            <div><dt>场景摘要</dt><dd><IdText :value="replay.scenarioSha256" :length="16" /></dd></div>
            <div><dt>内容摘要</dt><dd><IdText :value="replay.contentSha256" :length="16" /></dd></div>
          </template>
          <div v-for="[k, v] in scalars" :key="k"><dt class="num">{{ k }}</dt><dd class="num break-all">{{ v }}</dd></div>
        </dl>
        <pre v-if="raw !== '{}'" class="mt-3 max-h-64 overflow-auto rounded border border-ink-hair bg-paper-soft p-3 text-[11px] leading-[1.55]"><code class="num">{{ raw }}</code></pre>
      </details>
    </LoadState>
  </Drawer>
</template>
