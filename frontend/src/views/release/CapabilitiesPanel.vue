<script setup lang="ts">
/**
 * 发布管理 · 能力分段：能力登记台账（`q` 按能力键前缀，后端无状态筛选）+ 侧栏当前页等级构成与等级口径。
 * 等级按（平台、适配器、地址族、协议、方向、类别、快照类型）分别取得，不复制另一平台成绩；
 * lab_auto 一律显示「lab 自动（仅 lab）」，只对 lab 资产有效。行点击打开详情抽屉（`id`），页头「登记能力」打开登记表单。
 */
import { computed, ref, watch } from 'vue'
import { BadgeCheck, Layers, Search, ShieldHalf } from 'lucide-vue-next'
import Panel from '@/components/Panel.vue'
import Tag from '@/components/Tag.vue'
import DistBar from '@/components/DistBar.vue'
import LoadState from '@/components/LoadState.vue'
import CursorPager from '@/components/CursorPager.vue'
import { tally } from '@/components/viz'
import { useCursor } from '@/composables/cursor'
import { fmtTime } from '@/api/types'
import { releaseApi, type ReleaseCapability } from '@/api/v2/release'
import { capabilityTone } from '@/data/tones'
import CapabilityDrawer from './CapabilityDrawer.vue'
import CapabilityFormDrawer from './CapabilityFormDrawer.vue'
import { capabilityFacts, familyLabel, levelLabel, profileLabel, scopeLabel } from './shared'

const q = defineModel<string>('q', { required: true })
const openId = defineModel<string>('id', { required: true })

const caps = useCursor<ReleaseCapability>((cursor) => releaseApi.listCapabilities({ q: q.value || undefined, cursor }), false)
watch(q, () => caps.reset(), { immediate: true })

const qDraft = ref(q.value)
watch(q, (v) => { if (v !== qDraft.value.trim()) qDraft.value = v })
let typing: ReturnType<typeof setTimeout> | undefined
watch(qDraft, (v) => { clearTimeout(typing); typing = setTimeout(() => { q.value = v.trim().slice(0, 128) }, 350) })

const LEVELS = ['research', 'alert_only', 'lab_auto', 'authorized_auto']
const composition = computed(() => tally(caps.items.value, (c) => c.level, (k) => levelLabel[k] ?? k, (k) => capabilityTone[k]))
const platformLabel: Record<string, string> = { macos: 'macOS', windows: 'Windows' }
const directionLabel: Record<string, string> = { inbound: '入站', outbound: '出站' }

const formOpen = ref(false)
defineExpose({ create: () => { formOpen.value = true } })
function created(id: string) {
  formOpen.value = false
  caps.reset()
  openId.value = id
}
</script>

<template>
  <div class="grid items-start gap-5 xl:grid-cols-[minmax(0,1fr)_18rem]">
    <Panel title="能力登记" :icon="BadgeCheck" flush>
      <template #actions><span class="text-[12px] text-ink-3">最近登记在前</span></template>
      <template #toolbar>
        <div class="toolbar w-full" role="search">
          <label class="toolbar-field"><Search :size="14" :stroke-width="1.5" aria-hidden="true" />
            <input v-model="qDraft" type="search" class="field !w-56" maxlength="128" placeholder="按能力键前缀搜索" aria-label="搜索能力" />
          </label>
          <button v-if="q" type="button" class="link ml-auto text-[12.5px]" @click="q = ''; qDraft = ''">清除搜索</button>
        </div>
      </template>

      <LoadState :loading="caps.loading.value" :error="caps.error.value" :empty="!caps.items.value.length" :empty-text="q ? '没有匹配的能力。' : '你可见范围内还没有登记能力。'">
        <table class="table min-w-[820px]">
          <thead><tr><th>能力</th><th>平台 / 适配器</th><th>类别 · 快照</th><th>方向 · 范围</th><th>等级</th><th class="text-right">登记</th></tr></thead>
          <tbody>
            <tr v-for="c in caps.items.value" :key="c.id" class="row-link" tabindex="0" :aria-current="openId === c.id ? 'true' : undefined" @click="openId = c.id" @keydown.enter="openId = c.id">
              <td class="max-w-[14rem]"><span class="num block truncate text-ink">{{ c.capabilityKey }}</span><span class="num text-[11.5px] text-ink-4">v{{ c.version }}</span></td>
              <td class="whitespace-nowrap"><span class="text-ink-2">{{ platformLabel[c.platform] ?? c.platform }}</span><span class="num ml-2 text-[11.5px] text-ink-4">{{ capabilityFacts(c).adapterVersion ?? '' }}</span></td>
              <td class="whitespace-nowrap text-ink-2">{{ familyLabel[capabilityFacts(c).family ?? ''] ?? capabilityFacts(c).family ?? '—' }}<span class="ml-1.5 text-[11.5px] text-ink-4">{{ profileLabel[capabilityFacts(c).profile ?? ''] ?? '' }}</span></td>
              <td class="whitespace-nowrap text-ink-2">{{ directionLabel[capabilityFacts(c).direction ?? ''] ?? '—' }}<span class="ml-1.5 text-[11.5px] text-ink-4">{{ scopeLabel[c.scope] ?? c.scope }}</span></td>
              <td class="whitespace-nowrap"><Tag :tone="capabilityTone[c.level]" :label="levelLabel[c.level] ?? c.level" /></td>
              <td class="num whitespace-nowrap text-right text-ink-3">{{ fmtTime(c.createdAt) }}</td>
            </tr>
          </tbody>
        </table>
      </LoadState>
      <template #foot>
        <CursorPager :count="caps.items.value.length" :has-next="!!caps.next.value" :has-prev="!!caps.stack.value.length"
          :busy="caps.turning.value" label="能力" @next="caps.forward()" @prev="caps.back()" />
      </template>
    </Panel>

    <aside class="space-y-4 xl:sticky xl:top-20">
      <Panel title="等级构成" :icon="Layers" :desc="`按当前页 ${caps.items.value.length} 项统计`">
        <DistBar :segments="composition" empty-text="当前页没有能力" />
      </Panel>
      <Panel title="等级口径" :icon="ShieldHalf">
        <ul class="space-y-2.5 text-[12.5px] leading-relaxed">
          <li v-for="l in LEVELS" :key="l" class="grid grid-cols-[7.25rem_minmax(0,1fr)] items-start gap-2">
            <Tag :tone="capabilityTone[l]" :label="levelLabel[l]" />
            <span class="text-ink-3">{{ { research: '只用于研究回放，不需要平台报告。', alert_only: '只告警，不下发阻断命令。', lab_auto: '只对 lab 资产有效，不适用于真实主机。', authorized_auto: '授权资产上可自动执行，需签名平台报告。' }[l] }}</span>
          </li>
        </ul>
        <p class="mt-3 border-t border-ink-hair pt-3 text-[12px] text-ink-4">等级按平台分别取得，不能复制另一平台的成绩。</p>
      </Panel>
    </aside>

    <CapabilityDrawer :id="openId" @close="openId = ''" />
    <CapabilityFormDrawer :open="formOpen" @created="created" @close="formOpen = false" />
  </div>
</template>
