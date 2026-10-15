<script setup lang="ts">
/**
 * 发布管理 · 决策策略分段：策略台账（`q` 按显示名或策略键前缀、状态由后端筛选）。
 * 每行显示模式（只告警 / 自动）与四个攻击类别的自动资格格子，行点击打开详情抽屉（`id`）。
 * 页头「起草策略」经 defineExpose 的 create 打开上传表单；草稿须由起草人以外的人审核，审核不等于激活。
 */
import { computed, ref, watch } from 'vue'
import { FileJson2, Search } from 'lucide-vue-next'
import Panel from '@/components/Panel.vue'
import Tag from '@/components/Tag.vue'
import LoadState from '@/components/LoadState.vue'
import CursorPager from '@/components/CursorPager.vue'
import { useCursor } from '@/composables/cursor'
import { fmtTime } from '@/api/types'
import { releaseApi, type PolicyStatus, type ReleasePolicy } from '@/api/v2/release'
import { policyReviewTone } from '@/data/tones'
import PolicyDrawer from './PolicyDrawer.vue'
import PolicyDraftDrawer from './PolicyDraftDrawer.vue'
import { ensureIndex, FAMILIES, familyLabel, modeLabel, modelName, policyStatusLabel, policyTitle } from './shared'

const q = defineModel<string>('q', { required: true })
const status = defineModel<string>('status', { required: true })
const openId = defineModel<string>('id', { required: true })

const policies = useCursor<ReleasePolicy>((cursor) => releaseApi.listPolicies({ q: q.value || undefined, status: (status.value || undefined) as PolicyStatus | undefined, cursor }), false)
watch([q, status], () => policies.reset(), { immediate: true })
void ensureIndex('models')

const qDraft = ref(q.value)
watch(q, (v) => { if (v !== qDraft.value.trim()) qDraft.value = v })
let typing: ReturnType<typeof setTimeout> | undefined
watch(qDraft, (v) => { clearTimeout(typing); typing = setTimeout(() => { q.value = v.trim().slice(0, 128) }, 350) })

const STATUSES = Object.keys(policyStatusLabel)
const filtered = computed(() => !!(q.value || status.value))
function clearFilters() { q.value = ''; qDraft.value = ''; status.value = '' }
const emptyText = computed(() => (filtered.value ? '当前筛选条件下没有决策策略。' : '你可见范围内还没有决策策略。'))

/** 类别自动资格：实心 = 允许自动路径（autoEligible），带点 = 另允许模型来源自动，空心 = 只告警。 */
const familyCell = (p: ReleasePolicy, f: string) => p.definition?.familyPolicies?.find((x) => x.family === f)
const mode = (p: ReleasePolicy) => p.definition?.mode ?? null

const draftOpen = ref(false)
defineExpose({ create: () => { draftOpen.value = true } })
function drafted(id: string) {
  draftOpen.value = false
  policies.reset()
  openId.value = id
}
</script>

<template>
  <div>
    <Panel title="决策策略" :icon="FileJson2" flush>
      <template #actions>
        <span class="hidden items-center gap-3 text-[12px] text-ink-3 md:flex" aria-hidden="true">
          <span class="inline-flex items-center gap-1.5"><span class="h-2.5 w-2.5 rounded-[2px] bg-ink" />允许自动</span>
          <span class="inline-flex items-center gap-1.5"><span class="h-2.5 w-2.5 rounded-[2px] border border-ink-3" />只告警</span>
        </span>
      </template>
      <template #toolbar>
        <div class="toolbar w-full" role="search">
          <label class="toolbar-field"><Search :size="14" :stroke-width="1.5" aria-hidden="true" />
            <input v-model="qDraft" type="search" class="field !w-56" maxlength="128" placeholder="按显示名或策略键搜索" aria-label="搜索决策策略" />
          </label>
          <span class="toolbar-sep" aria-hidden="true" />
          <div class="chips" role="group" aria-label="策略状态">
            <button type="button" class="chip" :aria-pressed="status === ''" @click="status = ''">全部状态</button>
            <button v-for="s in STATUSES" :key="s" type="button" class="chip" :aria-pressed="status === s" @click="status = status === s ? '' : s">{{ policyStatusLabel[s] }}</button>
          </div>
          <button v-if="filtered" type="button" class="link ml-auto text-[12.5px]" @click="clearFilters">清除筛选</button>
        </div>
      </template>

      <LoadState :loading="policies.loading.value" :error="policies.error.value" :empty="!policies.items.value.length" :empty-text="emptyText">
        <table class="table min-w-[860px]">
          <thead><tr><th>策略</th><th>模式</th><th>类别自动资格</th><th>模型</th><th>状态</th><th class="text-right">最近更新</th></tr></thead>
          <tbody>
            <tr v-for="p in policies.items.value" :key="p.id" class="row-link" tabindex="0" :aria-current="openId === p.id ? 'true' : undefined" @click="openId = p.id" @keydown.enter="openId = p.id">
              <td class="max-w-[16rem]">
                <span class="block truncate font-medium text-ink">{{ policyTitle(p) }}</span>
                <span class="num block truncate text-[11.5px] text-ink-4">{{ p.version }}</span>
              </td>
              <td class="whitespace-nowrap"><Tag v-if="mode(p)" :tone="mode(p) === 'alert_only' ? 'mute' : 'warn'" :label="modeLabel[mode(p)!] ?? mode(p)!" /><span v-else class="text-ink-4">—</span></td>
              <td class="whitespace-nowrap">
                <span class="inline-flex gap-1">
                  <span v-for="f in FAMILIES" :key="f" class="relative inline-flex h-4 w-4 items-center justify-center rounded-[3px] border"
                    :class="familyCell(p, f)?.autoEligible ? 'border-ink bg-ink' : 'border-ink-3 bg-paper'"
                    :title="`${familyLabel[f]}：${familyCell(p, f)?.autoEligible ? (familyCell(p, f)?.modelAutoEligible ? '允许自动（含模型来源）' : '允许自动（仅规则来源）') : '只告警'}`">
                    <span v-if="familyCell(p, f)?.modelAutoEligible" class="h-1 w-1 rounded-full bg-paper" />
                  </span>
                </span>
                <span class="sr-only">{{ FAMILIES.map((f) => `${familyLabel[f]}${familyCell(p, f)?.autoEligible ? '允许自动' : '只告警'}`).join('，') }}</span>
              </td>
              <td class="max-w-[12rem] truncate text-ink-2">{{ modelName(p.modelId) }}</td>
              <td class="whitespace-nowrap"><Tag pill :tone="policyReviewTone[p.status]" :label="policyStatusLabel[p.status] ?? p.status" /></td>
              <td class="num whitespace-nowrap text-right text-ink-3">{{ fmtTime(p.updatedAt ?? p.createdAt) }}</td>
            </tr>
          </tbody>
        </table>
      </LoadState>
      <template #foot>
        <CursorPager :count="policies.items.value.length" :has-next="!!policies.next.value" :has-prev="!!policies.stack.value.length"
          :busy="policies.turning.value" label="决策策略" @next="policies.forward()" @prev="policies.back()" />
      </template>
    </Panel>
    <p class="mt-3 text-[12px] text-ink-3">格子依次为{{ FAMILIES.map((f) => familyLabel[f]).join('、') }}；带白点表示模型来源也可自动。审核通过不等于激活，策略须进入发布组合并经批准。</p>

    <PolicyDrawer :id="openId" @close="openId = ''" @changed="policies.reset()" />
    <PolicyDraftDrawer :open="draftOpen" @drafted="drafted" @close="draftOpen = false" />
  </div>
</template>
