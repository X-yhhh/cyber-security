<script setup lang="ts">
/** 资产与传感器：资产登记与授权状态；传感器健康。授权申请与审批由不同人完成。 */
import { ref } from 'vue'
import PageHead from '@/components/PageHead.vue'
import Segmented from '@/components/Segmented.vue'
import Tag from '@/components/Tag.vue'
import Drawer from '@/components/Drawer.vue'
import { assetName, assets, sensors, type Asset } from '@/data/demo'

const tab = ref<'assets' | 'sensors'>('assets')
const picked = ref<Asset | null>(null)
const authTone = { approved: 'ok', pending: 'signal', expired: 'threat' } as const
const authLabel = { approved: '有效', pending: '待审批', expired: '已过期' }
</script>

<template>
  <div>
    <PageHead no="05" title="资产与传感器" desc="处置只能引用已登记资产。靶场与实网分区标记；授权过期或资产停用后，相关自动动作一律被拒绝。">
      <template #kicker>Assets</template>
    </PageHead>

    <Segmented v-model="tab" :options="[{ value: 'assets', label: '资产', count: assets.length }, { value: 'sensors', label: '传感器', count: sensors.length }]" />

    <Transition name="fade" mode="out-in">
      <table v-if="tab === 'assets'" key="a" class="table mt-10">
        <thead><tr><th>资产</th><th>系统</th><th>环境</th><th>关键性</th><th>负责人</th><th>授权</th><th class="text-right">有效期</th></tr></thead>
        <tbody>
          <tr v-for="a in assets" :key="a.id" class="row-link" tabindex="0" @click="picked = a" @keydown.enter="picked = a">
            <td><span class="block">{{ a.name }}</span><span class="num text-[12px] text-ink-3">{{ a.id }} · {{ a.address }}</span></td>
            <td class="text-ink-2">{{ a.os }}</td>
            <td><span class="text-[12.5px]" :class="a.env === 'range' ? 'text-warn' : 'text-ink-2'">{{ a.env === 'range' ? '隔离靶场' : '授权实网' }}</span></td>
            <td class="text-ink-2">{{ a.criticality }}</td>
            <td class="text-ink-2">{{ a.owner }}</td>
            <td><Tag :tone="authTone[a.authorization.status]" :label="authLabel[a.authorization.status]" /></td>
            <td class="num text-right text-ink-3">{{ a.authorization.from }} — {{ a.authorization.to }}</td>
          </tr>
        </tbody>
      </table>

      <div v-else key="s" class="mt-10 grid gap-x-12 gap-y-16 lg:grid-cols-3">
        <section v-for="s in sensors" :key="s.id" class="border-t border-ink pt-5">
          <div class="flex items-start justify-between">
            <div>
              <p class="text-[15px]">{{ assetName(s.assetId) }}</p>
              <p class="num mt-1 text-[12px] text-ink-3">{{ s.id }} · v{{ s.version }}</p>
            </div>
            <Tag :tone="s.status === 'online' ? 'ok' : s.status === 'degraded' ? 'warn' : 'mute'" :label="s.status === 'online' ? '在线' : s.status === 'degraded' ? '保护降级' : '失联'" />
          </div>
          <dl class="mt-8 grid grid-cols-2 gap-y-6">
            <div><dt class="label">接收</dt><dd class="num mt-1.5 text-[1.25rem] font-light">{{ s.accepted.toLocaleString() }}</dd></div>
            <div><dt class="label">丢弃</dt><dd class="num mt-1.5 text-[1.25rem] font-light" :class="s.dropped > 1000 ? 'text-warn' : ''">{{ s.dropped.toLocaleString() }}</dd></div>
            <div><dt class="label">队列深度</dt><dd class="num mt-1.5 text-[1.25rem] font-light">{{ s.queue }}</dd></div>
            <div><dt class="label">特征错误</dt><dd class="num mt-1.5 text-[1.25rem] font-light" :class="s.featureErrors ? 'text-threat' : ''">{{ s.featureErrors }}</dd></div>
          </dl>
          <div class="mt-8 space-y-3">
            <div v-for="[k, v, max, unit] in [['CPU', s.cpu, 50, '%'], ['内存', s.mem, 512, 'MB']] as const" :key="k">
              <p class="flex justify-between text-[12px] text-ink-3"><span>{{ k }}</span><span class="num">{{ v }} {{ unit }}</span></p>
              <div class="mt-1.5 h-px bg-ink-hair"><div class="h-px bg-ink transition-all duration-1000 ease-out" :style="{ width: Math.min(100, (v / max) * 100) + '%' }" /></div>
            </div>
          </div>
          <p class="mt-6 text-[12px] text-ink-3">最后心跳 {{ s.lastHeartbeat }} · 仅观测本机可见流量</p>
        </section>
      </div>
    </Transition>

    <Drawer :open="!!picked" :title="picked?.name ?? ''" :kicker="picked?.id" @close="picked = null">
      <template v-if="picked">
        <dl class="border-t border-ink">
          <div v-for="[k, v] in [['地址', picked.address], ['系统', picked.os], ['环境', picked.env === 'range' ? '隔离靶场（外联隔离由网络层保证）' : '授权实网'], ['关键性', picked.criticality], ['负责人', picked.owner]]" :key="k" class="grid grid-cols-[6rem_1fr] border-b border-ink-hair py-3 text-[13px]">
            <dt class="text-ink-3">{{ k }}</dt><dd class="num">{{ v }}</dd>
          </div>
        </dl>
        <h3 class="label mb-4 mt-12">授权记录</h3>
        <ol class="border-l border-ink-hair">
          <li class="relative pb-6 pl-6"><span class="absolute -left-[3px] top-2 h-[5px] w-[5px] bg-ink" /><p class="text-[13px]">申请 · {{ picked.authorization.requestedBy }}</p><p class="num text-[12px] text-ink-3">{{ picked.authorization.from }} — {{ picked.authorization.to }} · 证明引用 vault://auth/{{ picked.id.toLowerCase() }}</p></li>
          <li class="relative pl-6"><span class="absolute -left-[3px] top-2 h-[5px] w-[5px]" :class="picked.authorization.status === 'approved' ? 'bg-ok' : 'bg-ink-4'" /><p class="text-[13px]">{{ picked.authorization.status === 'approved' ? '批准 · platform_admin' : picked.authorization.status === 'pending' ? '等待独立审批' : '已过期，相关动作将被拒绝' }}</p></li>
        </ol>
        <p class="mt-8 text-[12px] leading-relaxed text-ink-3">授权证明原文保存在受控密钥系统，业务库仅保存引用。申请人不能批准本人提交的授权。</p>
      </template>
    </Drawer>
  </div>
</template>
