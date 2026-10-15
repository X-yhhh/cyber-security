<script setup lang="ts">
/**
 * 能力详情抽屉（只读，发布管理 `?tab=capabilities&id=`）。能力登记后不可修改或删除，需要变化时登记新版本。
 * 业务字段在前（等级、平台、适配器、类别、方向、范围、行为范围、时延上限）；证据引用、签发身份与摘要收进「技术细节」。
 */
import { computed, ref, watch } from 'vue'
import Drawer from '@/components/Drawer.vue'
import Tag from '@/components/Tag.vue'
import IdText from '@/components/IdText.vue'
import LoadState from '@/components/LoadState.vue'
import { errText } from '@/composables/load'
import { fmtTime } from '@/api/types'
import { releaseApi, type ReleaseCapability } from '@/api/v2/release'
import { capabilityTone } from '@/data/tones'
import { capabilityFacts, familyLabel, isObject, levelLabel, profileLabel, scopeLabel } from './shared'

const props = defineProps<{ id: string }>()
const emit = defineEmits<{ close: [] }>()

const cap = ref<ReleaseCapability | null>(null)
const loading = ref(false)
const error = ref('')
let seq = 0
watch(() => props.id, async (id) => {
  const mine = ++seq
  if (!id) { cap.value = null; return }
  loading.value = true
  error.value = ''
  try { const c = await releaseApi.getCapability(id); if (mine === seq) cap.value = c }
  catch (e) { if (mine === seq) { cap.value = null; error.value = errText(e) } }
  finally { if (mine === seq) loading.value = false }
}, { immediate: true })

const facts = computed(() => (cap.value ? capabilityFacts(cap.value) : null))
const evidence = computed(() => {
  const p = cap.value && isObject(cap.value.payload) ? cap.value.payload : {}
  return ['evidenceRef', 'evidenceSha256', 'runnerIdentity', 'exemptionEvidenceRef'].filter((k) => typeof p[k] === 'string').map((k) => [k, String(p[k])] as [string, string])
})
const note = computed(() => {
  switch (cap.value?.level) {
    case 'lab_auto': return 'lab 自动（仅 lab）：只对 lab 资产有效，不适用于真实主机；真实主机按当前决定只告警。'
    case 'authorized_auto': return '授权自动：在已授权资产上可自动执行，仍受授权范围、预算与保护集约束。'
    case 'alert_only': return '只告警：不下发阻断命令。'
    default: return '研究：只用于研究回放，不具备执行资格。'
  }
})
</script>

<template>
  <Drawer :open="!!id" :title="cap ? cap.capabilityKey : '能力'" kicker="能力" @close="emit('close')">
    <LoadState :loading="loading" :error="error">
      <template v-if="cap && facts">
        <p class="note mb-5" :class="cap.level === 'lab_auto' ? 'note-warn' : ''">{{ note }}</p>
        <dl class="kv">
          <div><dt>等级</dt><dd><Tag :tone="capabilityTone[cap.level]" :label="levelLabel[cap.level] ?? cap.level" /></dd></div>
          <div><dt>版本</dt><dd class="num">{{ cap.version }}</dd></div>
          <div><dt>平台</dt><dd>{{ cap.platform === 'macos' ? 'macOS' : cap.platform === 'windows' ? 'Windows' : cap.platform }}<span class="num ml-2 text-[12px] text-ink-3">{{ facts.adapterVersion }}</span></dd></div>
          <div><dt>攻击类别</dt><dd>{{ familyLabel[facts.family ?? ''] ?? facts.family ?? '—' }}</dd></div>
          <div><dt>快照类型</dt><dd>{{ profileLabel[facts.profile ?? ''] ?? facts.profile ?? '—' }}</dd></div>
          <div><dt>协议</dt><dd class="num">{{ [facts.addressFamily, facts.transport].filter(Boolean).join(' / ') || '—' }}</dd></div>
          <div><dt>方向</dt><dd>{{ { inbound: '入站', outbound: '出站' }[facts.direction ?? ''] ?? facts.direction ?? '—' }}</dd></div>
          <div><dt>执行范围</dt><dd>{{ scopeLabel[cap.scope] ?? cap.scope }}</dd></div>
          <div><dt>行为范围</dt><dd>
            <span v-if="facts.behaviorScope.length" class="flex flex-wrap gap-1.5"><span v-for="b in facts.behaviorScope" :key="b" class="num rounded border border-ink-hair px-1.5 py-0.5 text-[11.5px] text-ink-2">{{ b }}</span></span>
            <span v-else class="text-ink-4">—</span>
          </dd></div>
          <div><dt>时延上限</dt><dd class="num">{{ facts.maxMs === null ? '—' : `${facts.maxMs} ms` }}</dd></div>
          <div><dt>登记</dt><dd class="num">{{ fmtTime(cap.createdAt) }}</dd></div>
        </dl>
        <details class="mt-7 text-[12.5px]">
          <summary class="cursor-pointer text-ink-3 hover:text-ink">技术细节</summary>
          <dl class="kv mt-2">
            <div><dt>能力 ID</dt><dd><IdText :value="cap.id" /></dd></div>
            <div v-for="[k, v] in evidence" :key="k"><dt class="num">{{ k }}</dt><dd class="num break-all">{{ v }}</dd></div>
            <div v-if="cap.protectionSetSha256"><dt>保护集摘要</dt><dd><IdText :value="cap.protectionSetSha256" :length="16" /></dd></div>
            <div v-if="cap.exemptionEvidenceSha256"><dt>豁免报告摘要</dt><dd><IdText :value="cap.exemptionEvidenceSha256" :length="16" /></dd></div>
          </dl>
        </details>
        <p class="mt-6 text-[12px] text-ink-3">能力登记后不可修改或删除；变化时登记新版本，并重新申请发布组合。</p>
      </template>
    </LoadState>
  </Drawer>
</template>
