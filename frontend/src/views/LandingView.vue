<script setup lang="ts">
/**
 * 首屏：滚动叙事。
 * 固定画布上的粒子主体随滚动在 8 个章节形态之间变形（最后一章为控制台入口）；
 * 每章文字按与当前进度的距离淡入淡出、错位移动，版式左右交替，
 * 3D 主体的整体位移与之呼应（姿态表见 ThreatScene POSES）。
 */
import { computed, onBeforeUnmount, onMounted, ref, shallowRef } from 'vue'
import { RouterLink } from 'vue-router'
import { ArrowRight, ArrowDown } from 'lucide-vue-next'
import { ThreatScene } from '@/three/ThreatScene'

interface Chapter {
  no: string
  key: string
  title: string
  body: string
  side: 'left' | 'right'
  readout: { k: string; v: string; tone?: 'signal' | 'threat' }[]
}

const chapters: Chapter[] = [
  {
    no: '00', key: 'Boundary', side: 'left',
    title: '只在被授权的边界之内，\n看见流量。',
    body: '面向已登记主机的流量威胁研判与受控响应平台。检测、研判、处置和审计沿同一条证据链进行。',
    readout: [{ k: '覆盖', v: '2 台已授权主机' }, { k: '模式', v: '被动观测' }, { k: '主动扫描', v: '不提供' }],
  },
  {
    no: '01', key: 'Sense', side: 'right',
    title: '每个传感器，\n只看见本机。',
    body: 'Mac 与 Windows 上的软件传感器形成有界流记录与时间窗统计。两台终端不等于整个内网，全网可见只来自已授权的镜像或流导出。',
    readout: [{ k: 'SNS-MAC-01', v: '在线', tone: 'signal' }, { k: 'SNS-WIN-01', v: '降级 · 丢弃 2.2%', tone: 'threat' }, { k: '逐包上传', v: '否' }],
  },
  {
    no: '02', key: 'Contract', side: 'left',
    title: '不满足契约的记录，\n不进入模型。',
    body: '字段、类型、单位与映射版本逐项校验。记录被分为可推理、待人工与拒绝三类，缺失的值不会被悄悄补上。',
    readout: [{ k: '特征契约', v: 'flow.v2 · 42 项' }, { k: '可推理', v: '98.1%' }, { k: '拒绝', v: '1.9%', tone: 'threat' }],
  },
  {
    no: '03', key: 'Infer', side: 'right',
    title: '冻结的权重，\n与确定性规则互证。',
    body: '在线期间模型权重保持冻结，只做推理与漂移观测。版本不符或推理超时显式失败，不会无提示切换模型。',
    readout: [{ k: '活动模型', v: 'unsw-binary-2026.09.0' }, { k: '运行时', v: 'ONNX · CPU' }, { k: 'p95', v: '3.1 ms' }],
  },
  {
    no: '04', key: 'Correlate', side: 'left',
    title: '告警归并为事件，\n风险有据可查。',
    body: '按资产、时间窗与对端把告警归并成事件。风险分由模型分数、独立证据、资产关键性、频度和数据可信度组成，每一项都可展开。',
    readout: [{ k: 'EVT-1042', v: '风险 86', tone: 'threat' }, { k: '关联告警', v: '14' }, { k: '独立证据', v: 'rule/rate-v3' }],
  },
  {
    no: '05', key: 'Respond', side: 'right',
    title: '阻断是窄的、限时的，\n并且可以撤回。',
    body: '只对登记资产追加带 TTL 的主机防火墙规则，不覆盖既有规则、不接管默认策略。策略外或高影响动作交由不同于申请人的审批员决定。',
    readout: [{ k: 'ACT-314', v: '待审批', tone: 'signal' }, { k: '目标', v: '198.51.100.23 · TCP/445' }, { k: 'TTL', v: '30 min' }],
  },
  {
    no: '06', key: 'Audit', side: 'left',
    title: '每一步，\n都留下追加式证据。',
    body: '登录、授权变化、模型激活、审批、执行与回滚写入不可改写的审计台账，并与 request ID 关联。',
    readout: [{ k: '今日审计', v: '1,284 条' }, { k: '拒绝记录', v: '37', tone: 'threat' }, { k: '可改写', v: '否' }],
  },
]

const canvas = ref<HTMLCanvasElement>()
const scene = shallowRef<ThreatScene>()
const progress = ref(0)
const webgl = ref(true)
let raf = 0

/** 最后一章（控制台入口）不在 chapters 中，它有自己的版式 */
const endIndex = chapters.length
const workspaces = ['态势', '告警与事件', '受控响应', '模型治理', '资产与传感器', '数据源与回放', '审计', '身份与角色']

const current = computed(() => Math.round(progress.value))

function onScroll() {
  cancelAnimationFrame(raf)
  raf = requestAnimationFrame(() => {
    const p = window.scrollY / window.innerHeight
    progress.value = Math.min(p, endIndex)
    scene.value?.setProgress(progress.value)
  })
}

function onPointer(e: PointerEvent) {
  if (e.pointerType !== 'mouse') return
  scene.value?.setPointer((e.clientX / innerWidth) * 2 - 1, -(e.clientY / innerHeight) * 2 + 1)
}
const onLeave = () => scene.value?.setPointer(null)

/** 章节文字的滚动联动样式：离当前进度越远越透明，并沿滚动方向错位 */
function textStyle(i: number) {
  const d = progress.value - i
  const o = Math.max(0, 1 - Math.abs(d) * 1.8)
  return { opacity: o, transform: `translate3d(0, ${-d * 60}px, 0)`, visibility: o < 0.01 ? 'hidden' : 'visible' } as const
}
function readoutStyle(i: number) {
  const d = progress.value - i
  const o = Math.max(0, 1 - Math.abs(d) * 2.4)
  return { opacity: o, transform: `translate3d(0, ${-d * 24}px, 0)` }
}

/** 结尾章的模块列表逐项错开进入，与粒子八段环的成形节奏对应 */
function itemStyle(i: number) {
  const d = endIndex - progress.value
  const o = Math.min(1, Math.max(0, 1 - (d * 2.2 - i * 0.06) * 1.4))
  return { opacity: o, transform: `translate3d(0, ${(1 - o) * 14}px, 0)` }
}

function go(i: number) {
  window.scrollTo({ top: i * window.innerHeight, behavior: 'smooth' })
}

onMounted(() => {
  try {
    scene.value = new ThreatScene(canvas.value!)
  } catch {
    webgl.value = false
  }
  onScroll()
  window.addEventListener('scroll', onScroll, { passive: true })
  window.addEventListener('pointermove', onPointer, { passive: true })
  document.addEventListener('pointerleave', onLeave)
})

onBeforeUnmount(() => {
  cancelAnimationFrame(raf)
  window.removeEventListener('scroll', onScroll)
  window.removeEventListener('pointermove', onPointer)
  document.removeEventListener('pointerleave', onLeave)
  scene.value?.dispose()
})

</script>

<template>
  <div class="relative bg-paper text-ink">
    <canvas ref="canvas" class="pointer-events-none fixed inset-0 h-screen w-full" aria-hidden="true" />
    <div v-if="!webgl" class="fixed inset-0 flex items-center justify-end pr-[12vw]" aria-hidden="true">
      <div class="h-[46vmin] w-[46vmin] rounded-full border border-ink-line" />
    </div>

    <!-- 顶栏 -->
    <header class="fixed inset-x-0 top-0 z-30 flex h-16 items-center justify-between px-6 md:px-12">
      <RouterLink to="/" class="flex items-center gap-2.5" @click="go(0)">
        <span class="relative inline-flex h-4 w-4 items-center justify-center border border-ink">
          <span class="h-1 w-1 bg-signal" />
        </span>
        <span class="text-[13px] font-medium tracking-[0.2em]">SENTINEL</span>
      </RouterLink>
      <nav class="flex items-center gap-8 text-[13px]">
        <span class="label hidden md:inline">授权主机 · 被动观测 · 受控响应</span>
        <RouterLink to="/login" class="link">登录控制台 <ArrowRight :size="14" :stroke-width="1.5" /></RouterLink>
      </nav>
    </header>

    <!-- 章节文字：固定层，由滚动进度驱动 -->
    <div class="pointer-events-none fixed inset-0 z-10">
      <section
        v-for="(c, i) in chapters"
        :key="c.no"
        class="absolute inset-0 flex items-center px-6 md:px-12 lg:px-[12vw]"
        :class="c.side === 'right' ? 'lg:justify-end' : ''"
        :style="textStyle(i)"
        :aria-hidden="current !== i"
      >
        <div class="max-w-[30rem] lg:max-w-[34rem]" :class="current === i ? 'pointer-events-auto' : ''">
          <p class="label mb-8 flex items-center gap-3">
            <span class="text-signal">{{ c.no }}</span><span class="h-px w-8 bg-ink-line" />{{ c.key }}
          </p>
          <h1 v-if="i === 0" class="whitespace-pre-line text-[clamp(2.25rem,4.6vw,4.25rem)] font-light leading-[1.12] tracking-[-0.02em]">{{ c.title }}</h1>
          <h2 v-else class="whitespace-pre-line text-[clamp(2rem,3.8vw,3.5rem)] font-light leading-[1.15] tracking-[-0.02em]">{{ c.title }}</h2>
          <p class="mt-8 max-w-[26rem] text-[15px] leading-[1.9] text-ink-2">{{ c.body }}</p>
          <div v-if="i === 0" class="mt-12 flex items-center gap-8">
            <RouterLink to="/login" class="act">进入控制台 <ArrowRight :size="14" :stroke-width="1.5" /></RouterLink>
            <button class="link text-[13px]" @click="go(1)">了解它如何工作 <ArrowDown :size="14" :stroke-width="1.5" /></button>
          </div>
        </div>
      </section>
    </div>

    <!-- 读数：与章节同步的现场数据，放在主体对侧下方 -->
    <div class="pointer-events-none fixed bottom-10 right-6 z-10 hidden w-72 md:right-12 md:block">
      <div class="relative h-[108px]">
        <dl v-for="(c, i) in chapters" :key="c.no" class="absolute inset-x-0 bottom-0 border-t border-ink" :style="readoutStyle(i)">
          <div v-for="r in c.readout" :key="r.k" class="flex items-baseline justify-between border-b border-ink-hair py-2">
            <dt class="label">{{ r.k }}</dt>
            <dd class="num text-[12px]" :class="r.tone === 'threat' ? 'text-threat' : r.tone === 'signal' ? 'text-signal' : 'text-ink'">{{ r.v }}</dd>
          </div>
        </dl>
      </div>
    </div>

    <!-- 滚动提示 -->
    <div class="pointer-events-none fixed bottom-10 left-1/2 z-10 -translate-x-1/2 transition-opacity duration-700" :style="{ opacity: progress < 0.15 ? 1 : 0 }">
      <div class="scroll-cue h-12 w-px bg-ink-line" />
    </div>

    <!-- 结尾章：与前面章节同一套滚动联动，粒子收束为八段环 -->
    <div class="pointer-events-none fixed inset-0 z-10">
      <section
        class="absolute inset-0 flex items-center px-6 md:px-12 lg:px-[12vw]"
        :style="textStyle(endIndex)"
        :aria-hidden="current !== endIndex"
      >
        <div class="max-w-[30rem] lg:max-w-[34rem]" :class="current === endIndex ? 'pointer-events-auto' : ''">
          <p class="label mb-8 flex items-center gap-3">
            <span class="text-signal">07</span><span class="h-px w-8 bg-ink-line" />Console
          </p>
          <h2 class="text-[clamp(2rem,3.8vw,3.5rem)] font-light leading-[1.15] tracking-[-0.02em]">同一条证据链，<br />八个工作区。</h2>
          <p class="mt-8 max-w-[26rem] text-[15px] leading-[1.9] text-ink-2">按功能模块组织，不按页面堆叠。每个角色只看见自己被授予范围内的资产、数据源与模型。</p>
          <ol class="mt-10 grid max-w-[26rem] grid-cols-2 gap-x-10 border-t border-ink">
            <li
              v-for="(m, i) in workspaces"
              :key="m"
              class="flex items-baseline gap-4 border-b border-ink-hair py-3"
              :style="itemStyle(i)"
            >
              <span class="num w-5 text-[10.5px] text-ink-4">{{ String(i + 1).padStart(2, '0') }}</span>
              <span class="text-[13.5px]">{{ m }}</span>
            </li>
          </ol>
          <RouterLink to="/login" class="act mt-10">登录控制台 <ArrowRight :size="14" :stroke-width="1.5" /></RouterLink>
        </div>
      </section>
    </div>

    <!-- 结尾声明：随最后一章淡入，占据读数的位置 -->
    <div
      class="pointer-events-none fixed inset-x-0 bottom-0 z-10 px-6 pb-8 md:px-12 lg:px-[12vw]"
      :style="readoutStyle(endIndex)"
    >
      <div class="flex flex-col justify-between gap-3 border-t border-ink-hair pt-5 text-[12px] text-ink-3 md:flex-row">
        <span>仅处理公开基准数据、预制回放与明确授权的被动遥测。不扫描、不注入流量、不攻击第三方。</span>
        <span class="num">SENTINEL · 2026</span>
      </div>
    </div>

    <!-- 滚动轨道：每章一屏，最后一章停在轨道末端 -->
    <div :style="{ height: `${(endIndex + 1) * 100}vh` }" aria-hidden="true" />
  </div>
</template>

<style scoped>
.scroll-cue { position: relative; overflow: hidden; }
.scroll-cue::after {
  content: '';
  position: absolute; left: 0; top: -40%;
  width: 1px; height: 40%;
  background: #14161A;
  animation: cue 2.2s cubic-bezier(.65,0,.35,1) infinite;
}
@keyframes cue { to { top: 100%; } }
</style>
