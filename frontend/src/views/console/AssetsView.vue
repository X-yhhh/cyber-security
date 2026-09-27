<script setup lang="ts">
/**
 * 资产与传感器：资产台账与授权记录（/assets、/assets/{id}/authorizations）；
 * 传感器心跳与最近健康窗口（/sensors）。授权审批调用后端命令，申请人不能审批本人申请由后端强制。
 */
import { ref, watch } from 'vue'
import PageHead from '@/components/PageHead.vue'
import Segmented from '@/components/Segmented.vue'
import Tag from '@/components/Tag.vue'
import Drawer from '@/components/Drawer.vue'
import LoadState from '@/components/LoadState.vue'
import { api, type Page } from '@/api/client'
import { can, session } from '@/api/session'
import { fmtTime, type AssetView, type AuthorizationView, type SensorView } from '@/api/types'
import { statusTone } from '@/data/tones'
import { toast } from '@/composables/toast'
import { errText, useLoad } from '@/composables/load'

const { data, loading, error } = useLoad(async () => {
  const [assets, sensors] = await Promise.all([
    can('asset.read') ? api.get<Page<AssetView>>('/assets?size=100').then((p) => p.items) : [],
    can('sensor.read') ? api.get<SensorView[]>('/sensors') : [],
  ])
  return { assets, sensors }
}, { assets: [] as AssetView[], sensors: [] as SensorView[] })

const tab = ref<'assets' | 'sensors'>('assets')
const picked = ref<AssetView | null>(null)
const auths = ref<AuthorizationView[]>([])
const authError = ref('')
async function loadAuths() {
  auths.value = []
  authError.value = ''
  if (!picked.value || !can('asset.authorization.read')) return
  try { auths.value = await api.get<AuthorizationView[]>(`/assets/${picked.value.id}/authorizations`) } catch (e) { authError.value = errText(e) }
}
watch(picked, loadAuths)
const envLabel = (e: string) => (e === 'range' ? '隔离靶场' : e === 'production' ? '授权实网' : e)

async function approve(a: AuthorizationView) {
  try {
    await api.post(`/assets/${a.assetId}/authorizations/${a.id}/approve`)
    toast('授权已批准并写入审计。')
    await loadAuths()
  } catch (e) { toast(errText(e), 'threat') }
}
</script>

<template>
  <div>
    <PageHead no="05" title="资产与传感器" desc="处置只能引用已登记资产。靶场与实网分区标记；授权过期或资产停用后，相关动作一律被拒绝。">
      <template #kicker>Assets</template>
    </PageHead>

    <Segmented v-model="tab" :options="[{ value: 'assets', label: '资产', count: data.assets.length }, { value: 'sensors', label: '传感器', count: data.sensors.length }]" />

    <LoadState :loading="loading" :error="error">
    <Transition name="fade" mode="out-in">
      <table v-if="tab === 'assets'" key="a" class="table mt-10">
        <thead><tr><th>资产</th><th>类型</th><th>环境</th><th>关键性</th><th>负责人</th><th class="text-right">状态</th></tr></thead>
        <tbody>
          <tr v-for="a in data.assets" :key="a.id" class="row-link" tabindex="0" @click="picked = a" @keydown.enter="picked = a">
            <td><span class="block num">{{ a.assetKey }}</span><span class="num text-[12px] text-ink-3">#{{ a.id }}</span></td>
            <td class="text-ink-2">{{ a.assetType }}</td>
            <td><span class="text-[12.5px]" :class="a.environment === 'range' ? 'text-warn' : 'text-ink-2'">{{ envLabel(a.environment) }}</span></td>
            <td class="text-ink-2">{{ a.criticality }}</td>
            <td class="text-ink-2">{{ a.owner }}</td>
            <td class="text-right"><Tag :tone="statusTone[a.status]" :label="a.status" /></td>
          </tr>
          <tr v-if="!data.assets.length"><td colspan="6" class="py-16 text-center text-ink-3">数据库中暂无授权范围内的登记资产。</td></tr>
        </tbody>
      </table>

      <div v-else key="s" class="mt-10">
        <p v-if="!data.sensors.length" class="py-16 text-center text-ink-3">数据库中暂无登记传感器。</p>
        <div class="grid gap-x-12 gap-y-16 lg:grid-cols-3">
          <section v-for="s in data.sensors" :key="s.id" class="border-t border-ink pt-5">
            <div class="flex items-start justify-between">
              <div>
                <p class="text-[15px] num">{{ s.assetKey }}</p>
                <p class="num mt-1 text-[12px] text-ink-3">{{ s.agentKey }} · {{ s.platform }} · v{{ s.agentVersion }}</p>
              </div>
              <Tag :tone="statusTone[s.status]" :label="s.status" />
            </div>
            <dl class="mt-8 grid grid-cols-2 gap-y-6">
              <div v-for="[k, v] in [['观察流', s.flowsSeen], ['输出流', s.flowsEmitted], ['丢弃', s.flowsDropped], ['最大队列', s.queueDepthMax]] as [string, number | null][]" :key="k">
                <dt class="label">{{ k }}</dt><dd class="num mt-1.5 text-[1.25rem] font-light">{{ v == null ? '—' : Number(v).toLocaleString() }}</dd>
              </div>
            </dl>
            <p class="num mt-6 text-[12px] text-ink-3">心跳 {{ fmtTime(s.lastHeartbeatAt) }} · 窗口截至 {{ fmtTime(s.healthWindowEnd) }}</p>
            <p class="num mt-1 text-[12px] text-ink-3">配置 {{ s.configVersion ?? '—' }} · 流窗口 {{ s.flowWindowSeconds ?? '—' }}s</p>
          </section>
        </div>
        <p class="mt-10 text-[12px] text-ink-3">传感器只观测所在主机的可见流量，不代表全网覆盖。</p>
      </div>
    </Transition>
    </LoadState>

    <Drawer :open="!!picked" :title="picked?.assetKey ?? ''" :kicker="picked ? `ASSET #${picked.id}` : ''" @close="picked = null">
      <template v-if="picked">
        <dl class="border-t border-ink">
          <div v-for="[k, v] in [['类型', picked.assetType], ['环境', picked.environment === 'range' ? '隔离靶场（外联隔离由网络层保证）' : envLabel(picked.environment)], ['关键性', picked.criticality], ['负责人', picked.owner], ['状态', picked.status]]" :key="k" class="grid grid-cols-[6rem_1fr] border-b border-ink-hair py-3 text-[13px]">
            <dt class="text-ink-3">{{ k }}</dt><dd class="num">{{ v }}</dd>
          </div>
        </dl>
        <h3 class="label mb-4 mt-12">授权记录</h3>
        <p v-if="!can('asset.authorization.read')" class="text-[13px] text-ink-3">当前身份无权查看授权记录。</p>
        <p v-else-if="authError" class="text-[13px] text-threat">{{ authError }}</p>
        <ol v-else class="border-l border-ink-hair">
          <li v-for="a in auths" :key="a.id" class="relative pb-6 pl-6">
            <span class="absolute -left-[3px] top-2 h-[5px] w-[5px]" :class="a.status === 'active' ? 'bg-ok' : 'bg-ink-4'" />
            <p class="flex items-center gap-3 text-[13px]"><Tag :tone="statusTone[a.status]" :label="a.status" /> 申请 {{ a.requestedBy ?? '—' }} · 批准 {{ a.approvedBy ?? '—' }}</p>
            <p class="num mt-1 text-[12px] text-ink-3">{{ fmtTime(a.validFrom) }} — {{ fmtTime(a.validUntil) }} · {{ a.authorizationRef }}</p>
            <button v-if="a.status === 'pending' && can('asset.authorization.approve') && a.requestedBy !== session.user?.username" class="link mt-2 text-[12.5px]" @click="approve(a)">批准该授权</button>
          </li>
          <li v-if="!auths.length" class="pl-6 text-[13px] text-ink-3">暂无授权记录。</li>
        </ol>
        <p class="mt-8 text-[12px] leading-relaxed text-ink-3">授权证明原文保存在受控密钥系统，业务库仅保存引用。申请人不能批准本人提交的授权。</p>
      </template>
    </Drawer>
  </div>
</template>
