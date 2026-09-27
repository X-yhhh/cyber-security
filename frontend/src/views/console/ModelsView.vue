<script setup lang="ts">
/**
 * 模型治理：版本（发布流水线）、漂移与反馈、离线训练三段。
 * 发布必须逐级经过 候选 → 已校验 → 影子 → 已批准 → 活动，不允许跳级；
 * 漂移只产生观察告警，不自动改阈值或权重。
 */
import { computed, reactive, ref } from 'vue'
import PageHead from '@/components/PageHead.vue'
import Segmented from '@/components/Segmented.vue'
import Tag from '@/components/Tag.vue'
import { driftWindows, feedback, models as seed, releaseStages, stageLabel, trainingJobs } from '@/data/demo'
import { toast } from '@/composables/toast'
import { vReveal } from '@/composables/reveal'

const list = reactive(structuredClone(seed))
const tab = ref<'versions' | 'drift' | 'training'>('versions')
const sel = ref(list[0].version)
const m = computed(() => list.find((x) => x.version === sel.value)!)
const stageIdx = computed(() => releaseStages.indexOf(m.value.stage))

const nextAction = computed(() => {
  switch (m.value.stage) {
    case 'candidate': return { label: '提交制品校验', perm: 'model.candidate.validate' }
    case 'validated': return { label: '开始影子验证', perm: 'model.shadow' }
    case 'shadow': return { label: '申请发布审批', perm: 'model.release.request' }
    case 'approved': return { label: '激活为本机部署', perm: 'model.deployment.activate' }
    default: return null
  }
})

function advance() {
  const cur = m.value
  const i = releaseStages.indexOf(cur.stage)
  if (cur.stage === 'candidate') cur.checks.forEach((c) => { c.ok = true; c.note = '通过' })
  if (i < releaseStages.length - 1) {
    if (releaseStages[i + 1] === 'active') list.forEach((x) => { if (x.stage === 'active') x.stage = 'retired' })
    cur.stage = releaseStages[i + 1]
    toast(`${cur.version} → ${stageLabel[cur.stage]}（本地演示，已记录审计）`)
  }
}

const maxPsi = Math.max(...driftWindows.map((w) => w.psi))
</script>

<template>
  <div>
    <PageHead no="04" title="模型治理" desc="在线检测期间权重保持冻结。再训练在 Windows 离线环境执行，经校验、影子验证与独立审批后才能激活。">
      <template #kicker>Models</template>
    </PageHead>

    <Segmented v-model="tab" :options="[{ value: 'versions', label: '版本与发布', count: list.length }, { value: 'drift', label: '漂移与反馈' }, { value: 'training', label: '离线训练', count: trainingJobs.length }]" />

    <Transition name="fade" mode="out-in">
      <div v-if="tab === 'versions'" key="v" class="mt-10 grid gap-16 lg:grid-cols-[18rem_1fr]">
        <ul class="border-t border-ink">
          <li v-for="x in list" :key="x.version">
            <button class="w-full border-b border-ink-hair py-4 text-left transition-colors" :class="sel === x.version ? 'text-ink' : 'text-ink-3 hover:text-ink'" @click="sel = x.version">
              <span class="flex items-center gap-3"><span class="h-px transition-all duration-500" :class="sel === x.version ? 'w-4 bg-signal' : 'w-0'" /><span class="num text-[13px]">{{ x.version }}</span></span>
              <span class="mt-1.5 flex items-center justify-between pl-0 text-[12px]" :class="sel === x.version ? 'pl-7' : ''">
                <span>{{ x.task }}</span><Tag :tone="x.stage === 'active' ? 'ok' : x.stage === 'candidate' ? 'mute' : 'signal'" :label="stageLabel[x.stage]" />
              </span>
            </button>
          </li>
        </ul>

        <Transition name="page" mode="out-in">
          <section :key="m.version">
            <div class="flex flex-wrap items-end justify-between gap-6">
              <div>
                <p class="label">{{ m.task }}</p>
                <h2 class="num mt-3 text-[1.75rem] font-light tracking-[-0.02em]">{{ m.version }}</h2>
              </div>
              <button v-if="nextAction" class="act" @click="advance">{{ nextAction.label }}</button>
            </div>

            <!-- 发布流水线 -->
            <ol class="mt-12 grid grid-cols-5">
              <li v-for="(s, i) in releaseStages" :key="s" class="relative pt-5">
                <span class="absolute left-0 right-0 top-0 h-px" :class="i <= stageIdx ? 'bg-ink' : 'bg-ink-line'" />
                <span class="absolute left-0 top-[-3px] h-[7px] w-[7px] transition-colors duration-500" :class="i < stageIdx ? 'bg-ink' : i === stageIdx ? 'bg-signal' : 'border border-ink-line bg-paper'" />
                <span class="text-[12.5px]" :class="i <= stageIdx ? 'text-ink' : 'text-ink-4'">{{ stageLabel[s] }}</span>
              </li>
            </ol>

            <div class="mt-14 grid grid-cols-2 gap-x-10 gap-y-10 md:grid-cols-4">
              <div v-for="k in m.metrics" :key="k.name" class="border-t border-ink pt-4">
                <p class="label">{{ k.name }}</p>
                <p class="num mt-3 text-[1.75rem] font-light">{{ k.value }}</p>
              </div>
            </div>
            <p class="mt-4 text-[12px] text-ink-3">指标来自锁定测试集的一次性最终评估。DoS 类识别仅代表该数据条件下的分类结果，不等于通用 DDoS 防护。</p>

            <div class="mt-14 grid gap-14 xl:grid-cols-2">
              <div>
                <h3 class="label mb-4">Manifest</h3>
                <dl class="border-t border-ink">
                  <div v-for="[k, v] in [['运行时', m.runtime], ['数据 / 切分', m.dataset], ['特征', `${m.features} 项 · 顺序与单位固定`], ['阈值策略', m.threshold], ['登记', m.registeredAt]]" :key="k" class="grid grid-cols-[6.5rem_1fr] border-b border-ink-hair py-3 text-[13px]">
                    <dt class="text-ink-3">{{ k }}</dt><dd>{{ v }}</dd>
                  </div>
                  <div class="grid grid-cols-[6.5rem_1fr] border-b border-ink-hair py-3 text-[13px]">
                    <dt class="text-ink-3">SHA-256</dt><dd class="num break-all text-[11.5px] text-ink-2">{{ m.sha256 }}</dd>
                  </div>
                </dl>
              </div>
              <div>
                <h3 class="label mb-4">制品校验</h3>
                <ul class="border-t border-ink">
                  <li v-for="c in m.checks" :key="c.name" class="flex items-center justify-between border-b border-ink-hair py-3 text-[13px]">
                    <span><span class="block">{{ c.name }}</span><span class="text-[12px] text-ink-3">{{ c.note }}</span></span>
                    <Tag :tone="c.ok === null ? 'mute' : c.ok ? 'ok' : 'threat'" :label="c.ok === null ? '待校验' : c.ok ? '通过' : '失败'" />
                  </li>
                </ul>
                <p class="mt-4 text-[12px] text-ink-3">校验失败的制品不可激活；不加载来源不明的 pickle / joblib。</p>
              </div>
            </div>
          </section>
        </Transition>
      </div>

      <div v-else-if="tab === 'drift'" key="d" class="mt-10">
        <section v-reveal>
          <div class="mb-6 flex items-baseline justify-between">
            <h2 class="text-[15px]">特征分布偏移 PSI · 24 小时</h2>
            <span class="text-[12px] text-ink-3">阈值 0.10 · 超出仅创建观察告警</span>
          </div>
          <div class="relative flex h-44 items-end gap-1.5 border-b border-ink">
            <span class="absolute inset-x-0 border-t border-dashed border-warn" :style="{ bottom: (0.1 / maxPsi) * 100 + '%' }" />
            <div v-for="w in driftWindows" :key="w.window" class="group relative flex-1">
              <div class="w-full origin-bottom transition-colors duration-300" :class="w.psi > 0.1 ? 'bg-warn' : 'bg-ink-line group-hover:bg-ink'" :style="{ height: (w.psi / maxPsi) * 176 + 'px' }" />
              <span class="num pointer-events-none absolute -top-6 left-1/2 -translate-x-1/2 whitespace-nowrap text-[10.5px] opacity-0 transition-opacity group-hover:opacity-100">{{ w.psi }}</span>
            </div>
          </div>
          <div class="num mt-3 flex justify-between text-[10.5px] text-ink-4"><span>00:00</span><span>12:00</span><span>23:00</span></div>
        </section>

        <div class="mt-16 grid grid-cols-3 gap-10">
          <div class="border-t border-ink pt-4"><p class="label">质量拒绝率峰值</p><p class="num mt-3 text-[1.75rem] font-light">{{ Math.max(...driftWindows.map((w) => w.rejectRate)) }}%</p></div>
          <div class="border-t border-ink pt-4"><p class="label">传感器丢弃率峰值</p><p class="num mt-3 text-[1.75rem] font-light text-warn">{{ Math.max(...driftWindows.map((w) => w.dropRate)) }}%</p></div>
          <div class="border-t border-ink pt-4"><p class="label">人工误报反馈</p><p class="num mt-3 text-[1.75rem] font-light">{{ driftWindows.reduce((s, w) => s + w.fpFeedback, 0) }}</p></div>
        </div>
        <p class="mt-4 text-[12px] text-ink-3">16:00–19:00 偏移与 SNS-WIN-01 丢弃率同步上升，更可能是采集降级而非真实分布变化，需人工判断。</p>

        <h2 class="mb-6 mt-20 text-[15px]">人工反馈样本</h2>
        <table class="table">
          <thead><tr><th>样本</th><th>来源告警</th><th>标签</th><th>依据</th><th>复核人</th><th>训练资格</th></tr></thead>
          <tbody>
            <tr v-for="f in feedback" :key="f.id">
              <td class="num">{{ f.id }}</td><td class="num text-ink-2">{{ f.alertId }}</td><td class="num">{{ f.label }}</td>
              <td class="text-ink-2">{{ f.basis }}</td><td class="text-ink-2">{{ f.reviewer }}</td>
              <td><Tag :tone="f.eligible === null ? 'signal' : f.eligible ? 'ok' : 'mute'" :label="f.eligible === null ? '待审查' : f.eligible ? '可用' : '不纳入'" /></td>
            </tr>
          </tbody>
        </table>
        <p class="mt-4 text-[12px] text-ink-3">告警本身不作为真值；不使用伪标签，不做在线增量拟合。</p>
      </div>

      <div v-else key="t" class="mt-10">
        <table class="table">
          <thead><tr><th>任务</th><th>数据集版本</th><th>申请人</th><th>审批人</th><th>产出</th><th>状态</th></tr></thead>
          <tbody>
            <tr v-for="j in trainingJobs" :key="j.id">
              <td><span class="num block">{{ j.id }}</span><span class="text-[12px] text-ink-3">{{ j.createdAt }}</span></td>
              <td class="text-ink-2">{{ j.dataset }}</td><td class="text-ink-2">{{ j.requester }}</td><td class="text-ink-2">{{ j.approver ?? '—' }}</td>
              <td class="num text-ink-2">{{ j.output ?? '—' }}</td>
              <td><Tag :tone="j.status === 'completed' ? 'ok' : j.status === 'failed' ? 'threat' : 'signal'" :label="{ requested: '待审批', approved: '已批准', queued: '排队', running: '运行中', completed: '完成', failed: '失败', cancelled: '取消' }[j.status]" /></td>
            </tr>
          </tbody>
        </table>
        <p class="mt-6 max-w-2xl text-[12.5px] leading-relaxed text-ink-3">训练在 Windows CUDA 离线环境执行，平台只登记任务与导入结果。训练输出始终是候选版本，不直接修改活动部署；候选失败不影响当前活动模型。</p>
      </div>
    </Transition>
  </div>
</template>
