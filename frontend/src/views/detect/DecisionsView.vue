<script setup lang="ts">
/**
 * 判定与来源（威胁检测 / Decisions）：按「来源 × 类别」查看后端决策事实（GET /api/v2/decisions）。
 *
 * 口径（docs/检测与处置契约.md 第 8 节、T1—T9）：
 * - 每条判定只走一条「类别 / 来源 / 规则编号」路径；模型来源与每条规则分别计数，互不借证据；
 * - 判定值为 observe / alert / block_candidate，reasonCode 是自动门的首个拒绝原因，
 *   告警是否出现与是否可自动是两件事：alert + 原因码表示「已告警、未进入自动」；
 * - 列表与矩阵只统计**已加载的最近若干条**判定（后端不提供聚合），页面明确标注样本量，
 *   不外推为全量比例；资格以 lab 验证页登记的来源等级为准，本页不推断「可自动」。
 */
import { computed, ref } from 'vue'
import { RouterLink } from 'vue-router'
import PageHead from '@/components/PageHead.vue'
import Segmented from '@/components/Segmented.vue'
import Tag from '@/components/Tag.vue'
import Drawer from '@/components/Drawer.vue'
import LoadState from '@/components/LoadState.vue'
import { errText } from '@/composables/load'
import { guard } from '@/api/client'
import { can } from '@/api/session'
import {
  fmtTime, GUARD_FAMILIES, guardDecisionLabel, guardFamilyLabel, guardReasonLabel, guardSourceKey, guardSourceLabel,
  type GuardDecision, type GuardDecisionEvidence,
} from '@/api/types'
import { decisionTone } from '@/data/tones'

const PAGE = 200
const allowed = can('detection.read')

/** 样本按页追加：每次再读 200 条更早的判定，矩阵与列表随样本扩大同步更新。 */
const rows = ref<GuardDecision[]>([])
const next = ref<string | null>(null)
const loading = ref(allowed)
const more = ref(false)
const error = ref('')
async function load(cursor?: string) {
  error.value = ''
  try {
    const page = await guard.list<GuardDecision>('decisions', { cursor, limit: PAGE })
    rows.value = cursor ? [...rows.value, ...page.items] : page.items
    next.value = page.nextCursor
  } catch (e) {
    error.value = errText(e)
  } finally {
    loading.value = false
    more.value = false
  }
}
if (allowed) void load()
function loadMore() {
  if (!next.value || more.value) return
  more.value = true
  void load(next.value)
}

const ev = (d: GuardDecision) => (d.evidence && typeof d.evidence === 'object' ? d.evidence : {}) as GuardDecisionEvidence
const familyOf = (d: GuardDecision) => ev(d).family ?? ''
const sourceOf = (d: GuardDecision) => guardSourceKey(ev(d).source, ev(d).ruleId)

/** 矩阵列：模型在前，规则按编号排序；只列样本中出现过的来源。 */
const sources = computed(() => {
  const keys = new Set(rows.value.map(sourceOf))
  keys.add('model')
  return [...keys].sort((a, b) => (a === 'model' ? -1 : b === 'model' ? 1 : a.localeCompare(b)))
})
interface Cell { total: number; alert: number; candidate: number; reasons: [string, number][] }
const matrix = computed(() => {
  const m = new Map<string, Cell>()
  for (const d of rows.value) {
    const key = `${familyOf(d)}|${sourceOf(d)}`
    const c = m.get(key) ?? { total: 0, alert: 0, candidate: 0, reasons: [] }
    c.total++
    if (d.decision === 'alert') c.alert++
    if (d.decision === 'block_candidate') c.candidate++
    if (d.reasonCode && d.decision !== 'observe') {
      const hit = c.reasons.find((r) => r[0] === d.reasonCode)
      if (hit) hit[1]++
      else c.reasons.push([d.reasonCode, 1])
    }
    m.set(key, c)
  }
  for (const c of m.values()) c.reasons.sort((a, b) => b[1] - a[1])
  return m
})
const cell = (family: string, source: string) => matrix.value.get(`${family}|${source}`)
const span = computed(() => {
  const times = rows.value.map((d) => d.decidedAt ?? d.createdAt).filter(Boolean).sort()
  return times.length ? { from: times[0], to: times[times.length - 1] } : null
})

type View = 'matrix' | 'list'
const view = ref<View>('matrix')
const views = computed(() => [
  { value: 'matrix' as const, label: '来源 × 类别' },
  { value: 'list' as const, label: '判定列表', count: filtered.value.length },
])

/** 列表筛选只作用于已加载样本；点矩阵单元格即带入类别与来源。 */
const decisionFilter = ref<'all' | 'alert' | 'block_candidate' | 'observe'>('all')
const familyFilter = ref('')
const sourceFilter = ref('')
const filtered = computed(() => rows.value.filter((d) =>
  (decisionFilter.value === 'all' || d.decision === decisionFilter.value)
  && (!familyFilter.value || familyOf(d) === familyFilter.value)
  && (!sourceFilter.value || sourceOf(d) === sourceFilter.value)))
const shown = computed(() => filtered.value.slice(0, 200))
function drill(family: string, source: string) {
  familyFilter.value = family
  sourceFilter.value = source
  decisionFilter.value = 'all'
  view.value = 'list'
}
function clearFilters() {
  decisionFilter.value = 'all'
  familyFilter.value = ''
  sourceFilter.value = ''
}

const picked = ref<GuardDecision | null>(null)
const pickedEv = computed(() => (picked.value ? ev(picked.value) : null))
const reasonText = (code: string | null | undefined) => (code ? `${guardReasonLabel[code] ?? code}` : '—')
</script>

<template>
  <div>
    <PageHead title="判定与来源" desc="按「来源 × 类别」查看判定：模型与每条规则各自形成判定，互不借用证据。告警与自动处置是两回事——带原因码的告警表示已告警、未进入自动封禁。来源能否自动以 lab 验证登记的等级为准，且 lab_auto 只在 lab 资产有效。">
      <template #kicker>Decisions &amp; Sources</template>
    </PageHead>

    <p v-if="!allowed" class="py-10 text-[13px] text-ink-3">当前身份没有判定读取权限（detection.read），本页不显示数据。</p>
    <template v-else>
      <Segmented v-model="view" :options="views" />

      <p class="num mt-6 flex flex-wrap items-center gap-x-6 gap-y-2 text-[12.5px] text-ink-3">
        <span>已加载最近 {{ rows.length }} 条判定<template v-if="span">（{{ fmtTime(span.from) }} — {{ fmtTime(span.to) }}）</template></span>
        <span>{{ next ? '还有更早的判定' : '已到最早一条' }}</span>
        <button type="button" class="link text-[12.5px]" :disabled="!next || more || loading" @click="loadMore">{{ more ? '读取中…' : `再加载 ${PAGE} 条` }}</button>
      </p>

      <div class="mt-8">
        <LoadState :loading="loading" :error="error" :empty="!rows.length" empty-text="数据库中暂无你授权范围内的判定记录。">
          <Transition name="fade" mode="out-in">
            <!-- 来源 × 类别：只统计已加载样本，点击单元格查看对应判定 -->
            <div v-if="view === 'matrix'" key="m">
              <div class="overflow-x-auto">
              <table class="table min-w-[640px]">
                <thead>
                  <tr><th>类别</th><th v-for="s in sources" :key="s" class="whitespace-nowrap normal-case">{{ guardSourceLabel(s) }}</th></tr>
                </thead>
                <tbody>
                  <tr v-for="f in GUARD_FAMILIES" :key="f">
                    <td class="text-ink">{{ guardFamilyLabel[f] }}<span class="num block text-[11.5px] text-ink-4">{{ f }}</span></td>
                    <td v-for="s in sources" :key="s">
                      <button v-if="cell(f, s)" type="button" class="group block w-full text-left" :aria-label="`查看${guardFamilyLabel[f]}·${guardSourceLabel(s)}的判定`" @click="drill(f, s)">
                        <span class="num block whitespace-nowrap text-[13px]">
                          <span :class="cell(f, s)!.alert ? 'text-warn' : 'text-ink-4'">告警 {{ cell(f, s)!.alert }}</span>
                          <span class="mx-1.5 text-ink-4">·</span>
                          <span :class="cell(f, s)!.candidate ? 'text-threat' : 'text-ink-4'">候选 {{ cell(f, s)!.candidate }}</span>
                        </span>
                        <span class="num block text-[11.5px] text-ink-3">共 {{ cell(f, s)!.total }} 条<template v-if="cell(f, s)!.reasons.length"> · 主要原因 {{ reasonText(cell(f, s)!.reasons[0][0]) }}</template></span>
                        <span class="text-[11.5px] text-ink-4 group-hover:text-signal">查看 →</span>
                      </button>
                      <span v-else class="num text-ink-4">—</span>
                    </td>
                  </tr>
                </tbody>
              </table>
              </div>
              <p class="mt-6 max-w-3xl text-[12.5px] leading-relaxed text-ink-3">
                「候选」为通过全部自动门的阻断候选，是否实际执行另见受控响应；「告警」若带原因码，说明在该门被拒绝而只告警。
                各来源的自动等级见 <RouterLink to="/console/release/lab" class="link">lab 验证与 G3</RouterLink>。
              </p>
            </div>

            <!-- 判定列表：筛选只作用于已加载样本 -->
            <div v-else key="l">
              <div class="mb-6 flex flex-wrap items-end gap-6 text-[13px]">
                <label class="w-36"><span class="label">判定</span>
                  <select v-model="decisionFilter" class="field mt-1">
                    <option value="all">全部</option><option value="alert">告警</option><option value="block_candidate">阻断候选</option><option value="observe">观察</option>
                  </select>
                </label>
                <label class="w-36"><span class="label">类别</span>
                  <select v-model="familyFilter" class="field mt-1">
                    <option value="">全部</option><option v-for="f in GUARD_FAMILIES" :key="f" :value="f">{{ guardFamilyLabel[f] }}</option>
                  </select>
                </label>
                <label class="w-44"><span class="label">来源</span>
                  <select v-model="sourceFilter" class="field mt-1">
                    <option value="">全部</option><option v-for="s in sources" :key="s" :value="s">{{ guardSourceLabel(s) }}</option>
                  </select>
                </label>
                <button type="button" class="link text-[12.5px] text-ink-3" @click="clearFilters">清除筛选</button>
                <span class="num text-[12.5px] text-ink-3">符合 {{ filtered.length }} 条<template v-if="filtered.length > shown.length">，显示前 {{ shown.length }} 条</template></span>
              </div>
              <p v-if="!filtered.length" class="py-10 text-[13px] text-ink-3">已加载样本中没有符合条件的判定。</p>
              <div v-else class="overflow-x-auto">
              <table class="table min-w-[760px]">
                <thead><tr><th>判定</th><th>类别</th><th>来源</th><th>原因</th><th>作用域</th><th class="text-right">判定时间</th></tr></thead>
                <tbody>
                  <tr v-for="d in shown" :key="d.id" class="row-link" tabindex="0" @click="picked = d" @keydown.enter="picked = d">
                    <td><Tag :tone="decisionTone[d.decision]" :label="guardDecisionLabel[d.decision] ?? d.decision" /></td>
                    <td class="text-ink-2">{{ guardFamilyLabel[familyOf(d)] ?? (familyOf(d) || '—') }}</td>
                    <td class="text-ink-2">{{ guardSourceLabel(ev(d).source, ev(d).ruleId) }}</td>
                    <td><span class="block text-ink-2">{{ reasonText(d.reasonCode) }}</span><span v-if="ev(d).detailCode" class="num text-[11.5px] text-ink-4">{{ ev(d).detailCode }}</span></td>
                    <td class="num text-ink-3">{{ ev(d).scope ?? '—' }}</td>
                    <td class="num text-right text-ink-3">{{ fmtTime(d.decidedAt ?? d.createdAt) }}</td>
                  </tr>
                </tbody>
              </table>
              </div>
            </div>
          </Transition>
        </LoadState>
      </div>
    </template>

    <Drawer :open="!!picked" :title="picked ? `判定 ${picked.id.slice(0, 8)}` : ''" kicker="DECISION" @close="picked = null">
      <template v-if="picked && pickedEv">
        <p class="mb-8 border-l-2 py-1 pl-4 text-[12.5px] leading-relaxed text-ink-2" :class="picked.decision === 'block_candidate' ? 'border-threat' : picked.decision === 'alert' ? 'border-warn' : 'border-ink-line'">
          <template v-if="picked.decision === 'block_candidate'">通过全部自动门的阻断候选；是否实际下发与生效以受控响应中的动作和回执为准。</template>
          <template v-else-if="picked.decision === 'alert'">已告警。{{ picked.reasonCode ? `自动门在「${reasonText(picked.reasonCode)}」处拒绝，因此不会自动封禁。` : '' }}</template>
          <template v-else>未达告警阈值，只作观察记录。</template>
        </p>
        <dl class="border-t border-ink">
          <div v-for="[k, v] in [
            ['判定', guardDecisionLabel[picked.decision] ?? picked.decision],
            ['原因码', picked.reasonCode ? `${reasonText(picked.reasonCode)}（${picked.reasonCode}）` : '—'],
            ['细分原因', pickedEv.detailCode ?? '—'],
            ['类别', guardFamilyLabel[pickedEv.family ?? ''] ?? pickedEv.family ?? '—'],
            ['来源', guardSourceLabel(pickedEv.source, pickedEv.ruleId)],
            ['作用域', pickedEv.scope ?? '—'],
            ['环境', pickedEv.environment ?? '—'],
            ['发布组合', pickedEv.bundleId ?? '—'],
            ['匹配能力', pickedEv.capabilityId ?? '无（该环境没有匹配的执行能力）'],
            ['授权', pickedEv.authorizationId ? `${pickedEv.authorizationId} · r${pickedEv.authorizationRevision ?? '—'}` : '—'],
            ['预算目标', pickedEv.budgetTargetId ?? '—'],
            ['证据迹', picked.episodeId],
            ['证据摘要', picked.evidenceSha256 ?? '—'],
            ['判定协议', picked.decisionContractVersion ?? '—'],
            ['判定时间', fmtTime(picked.decidedAt)],
          ]" :key="k" class="grid grid-cols-[7rem_1fr] border-b border-ink-hair py-3 text-[13px]">
            <dt class="text-ink-3">{{ k }}</dt><dd class="num break-all">{{ v }}</dd>
          </div>
        </dl>
        <h3 class="label mb-4 mt-10">选用证据（{{ pickedEv.selectedObservations?.length ?? 0 }}）</h3>
        <ul class="border-t border-ink">
          <li v-for="o in pickedEv.selectedObservations ?? []" :key="o.observationId" class="grid grid-cols-[1fr_auto] gap-3 border-b border-ink-hair py-2.5 text-[12.5px]">
            <span><span class="num block">观察 {{ o.observationId.slice(0, 8) }}<template v-if="o.parentConnectionId"> · 父流 {{ o.parentConnectionId.slice(0, 8) }}</template></span>
              <span class="text-[11.5px] text-ink-4">{{ guardFamilyLabel[o.family ?? ''] ?? o.family ?? '—' }} · {{ guardSourceLabel(o.source, o.ruleId) }}<template v-if="o.observationId === pickedEv.triggerObservationId"> · 触发观察</template></span></span>
            <span class="num text-ink-3">{{ fmtTime(o.asOf) }}</span>
          </li>
          <li v-if="!pickedEv.selectedObservations?.length" class="py-3 text-[12.5px] text-ink-3">该判定未选用证据。</li>
        </ul>
        <p class="mt-6 text-[12.5px] leading-relaxed text-ink-3">证据为判定时冻结的不可变摘要；目标绑定只显示引用，不返回真实地址与稳定目标 token。</p>
      </template>
    </Drawer>
  </div>
</template>
