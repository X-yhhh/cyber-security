<script setup lang="ts">
/**
 * 数据源与回放：数据源 / 映射版本，以及隔离靶场的回放运行。
 * 回放是重放已有数据，不生成或发起攻击流量；运行控制仅本地演示。
 */
import { computed, onBeforeUnmount, reactive, ref } from 'vue'
import PageHead from '@/components/PageHead.vue'
import Segmented from '@/components/Segmented.vue'
import Tag from '@/components/Tag.vue'
import { dataSources, replayScenarios } from '@/data/demo'

const tab = ref<'sources' | 'replay'>('sources')

// 回放运行：演示进度推进与暂停/继续/终止
const run = reactive({ scenario: replayScenarios[0].id, state: 'idle' as 'idle' | 'running' | 'paused' | 'done' | 'stopped', done: 0, alerts: 0 })
const scn = computed(() => replayScenarios.find((s) => s.id === run.scenario)!)
let timer = 0
function start() {
  run.done = 0
  run.alerts = 0
  run.state = 'running'
  tick()
}
function tick() {
  clearInterval(timer)
  timer = window.setInterval(() => {
    if (run.state !== 'running') return
    run.done = Math.min(scn.value.rows, run.done + Math.ceil(scn.value.rows / 120))
    run.alerts += Math.random() < 0.3 ? 1 : 0
    if (run.done >= scn.value.rows) {
      run.state = 'done'
      clearInterval(timer)
    }
  }, 60)
}
onBeforeUnmount(() => clearInterval(timer))
const pct = computed(() => (run.done / scn.value.rows) * 100)
</script>

<template>
  <div>
    <PageHead no="06" title="数据源与回放" desc="字段映射经版本化审批后才用于接入；不满足模型契约的记录会被拒绝或转人工，不会静默补值。">
      <template #kicker>Sources</template>
    </PageHead>

    <Segmented v-model="tab" :options="[{ value: 'sources', label: '数据源', count: dataSources.length }, { value: 'replay', label: '回放', count: replayScenarios.length }]" />

    <Transition name="fade" mode="out-in">
      <table v-if="tab === 'sources'" key="s" class="table mt-10">
        <thead><tr><th>数据源</th><th>类型</th><th>模式</th><th>映射版本</th><th>接收 / 拒绝</th><th class="text-right">最后成功</th></tr></thead>
        <tbody>
          <tr v-for="d in dataSources" :key="d.id">
            <td><span class="block">{{ d.name }}</span><span class="num text-[12px] text-ink-3">{{ d.id }}</span></td>
            <td class="text-ink-2">{{ d.kind }}</td>
            <td class="num text-ink-2">{{ d.schema }}</td>
            <td><span class="num mr-3 text-[12.5px]">{{ d.mapping.version }}</span><Tag :tone="d.mapping.status === 'approved' ? 'ok' : 'mute'" :label="d.mapping.status === 'approved' ? '已批准' : '草稿'" /></td>
            <td class="num">
              {{ d.accepted.toLocaleString() }} <span class="text-ink-4">/</span> <span :class="d.rejected ? 'text-threat' : 'text-ink-3'">{{ d.rejected.toLocaleString() }}</span>
              <div class="mt-2 h-px w-32 bg-ink-hair"><div class="h-px bg-threat" :style="{ width: d.accepted ? Math.max(1, (d.rejected / (d.accepted + d.rejected)) * 100 * 20) + '%' : '0' }" /></div>
            </td>
            <td class="num text-right text-ink-3">{{ d.lastSuccess }}</td>
          </tr>
        </tbody>
      </table>

      <div v-else key="r" class="mt-10 grid gap-16 lg:grid-cols-[1fr_1.2fr]">
        <ul class="border-t border-ink">
          <li v-for="s in replayScenarios" :key="s.id">
            <label class="flex cursor-pointer items-start gap-4 border-b border-ink-hair py-5">
              <input v-model="run.scenario" type="radio" :value="s.id" class="mt-1.5 accent-ink" :disabled="run.state === 'running' || run.state === 'paused'" />
              <span>
                <span class="block text-[14px]">{{ s.name }}</span>
                <span class="num mt-1 block text-[12px] text-ink-3">{{ s.id }} · {{ s.rows.toLocaleString() }} 条 · {{ s.rate }}</span>
                <span class="mt-1 block text-[12px] text-ink-3">{{ s.range }}</span>
              </span>
            </label>
          </li>
        </ul>

        <section class="border-t border-ink pt-6">
          <div class="flex items-baseline justify-between">
            <p class="label">RUN · {{ scn.id }}</p>
            <Tag :tone="run.state === 'running' ? 'signal' : run.state === 'done' ? 'ok' : run.state === 'stopped' ? 'threat' : 'mute'" :label="{ idle: '未开始', running: '运行中', paused: '已暂停', done: '已完成', stopped: '已终止' }[run.state]" />
          </div>
          <p class="num mt-8 text-[4rem] font-extralight leading-none tracking-[-0.04em]">{{ pct.toFixed(0) }}<span class="text-[1.25rem] text-ink-3">%</span></p>
          <div class="mt-8 h-px bg-ink-hair"><div class="h-px bg-ink transition-[width] duration-100" :style="{ width: pct + '%' }" /></div>
          <dl class="mt-8 grid grid-cols-3 gap-6 text-[13px]">
            <div><dt class="label">已回放</dt><dd class="num mt-1.5">{{ run.done.toLocaleString() }}</dd></div>
            <div><dt class="label">演练告警</dt><dd class="num mt-1.5">{{ run.alerts }}</dd></div>
            <div><dt class="label">模型版本</dt><dd class="num mt-1.5 text-[12px]">2026.09.0</dd></div>
          </dl>
          <div class="mt-10 flex items-center gap-8">
            <button v-if="run.state === 'idle' || run.state === 'done' || run.state === 'stopped'" class="act" @click="start">开始回放</button>
            <template v-else>
              <button class="act-ghost" @click="run.state = run.state === 'running' ? 'paused' : 'running'">{{ run.state === 'running' ? '暂停' : '继续' }}</button>
              <button class="link text-[13px] text-threat" @click="run.state = 'stopped'">终止</button>
            </template>
          </div>
          <p class="mt-8 text-[12px] leading-relaxed text-ink-3">回放产生的事件标记为演练数据，与实网事件隔离展示。靶场外网隔离由部署网络控制保证，不以此页面选项代替。</p>
        </section>
      </div>
    </Transition>
  </div>
</template>
