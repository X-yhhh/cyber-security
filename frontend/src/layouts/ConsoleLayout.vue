<script setup lang="ts">
/**
 * 控制台外壳（权限设计第 7 节，FE-9）：
 * - 左侧两级菜单由 nav.ts 生成并按会话权限过滤；一级组可折叠，折叠状态存 localStorage，
 *   进入某组的页面时该组自动展开；无可见二级项的组整组隐藏。
 * - 顶栏面包屑为“一级 / 二级 / 详情 ID”；待办中心与其他二级项一样挂在「态势」组下。
 * - 宽度小于 768 时侧栏改为左侧抽屉，由顶栏菜单按钮打开；抽屉内 Tab 焦点循环、Escape 关闭，关闭后焦点回到菜单按钮。
 * - 左下角账户菜单：用户名、角色中文名、修改口令、退出。
 * 顶栏只保留后端就绪探针（/health/ready，无需权限）；采集与执行健康见「传感器与执行器」页。
 * 视觉基线 v2：页面、侧栏与面板同为白底，以 1px 细边框分隔；当前菜单项为墨色实心。
 */
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { RouterLink, RouterView, useRoute } from 'vue-router'
import { Menu, X } from 'lucide-vue-next'
import { api } from '@/api/client'
import { session } from '@/api/session'
import { groupOf, itemOf, routeName, visibleMenu } from '@/router/nav'
import NavGroup from '@/components/NavGroup.vue'
import AccountMenu from '@/components/AccountMenu.vue'

const route = useRoute()
const menu = computed(() => visibleMenu(session.user?.permissions))
const activeGroup = computed(() => route.meta.group)
const activeItem = computed(() => route.meta.item)

/** 面包屑：一级 / 二级 / 详情 ID；旧页面只显示标题。 */
const crumbs = computed(() => {
  const g = groupOf(activeGroup.value)
  const i = itemOf(activeGroup.value, activeItem.value)
  const out: { label: string; to?: { name: string }; mono?: boolean }[] = []
  if (g && i && g.key !== i.key) out.push({ label: g.title }, { label: i.title, to: route.meta.detail ? { name: routeName(i) } : undefined })
  else if (i) out.push({ label: i.title })
  else out.push({ label: String(route.meta.title ?? '') })
  const id = route.meta.detail ? route.params[route.meta.detail] : undefined
  if (id) out.push({ label: String(id), mono: true })
  return out
})

/* 折叠状态：记录被折叠的一级组键。 */
const STORE = 'sentinel.nav.collapsed'
function readCollapsed(): Set<string> {
  try {
    const v: unknown = JSON.parse(localStorage.getItem(STORE) ?? '[]')
    return new Set(Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [])
  } catch { return new Set() }
}
const collapsed = ref(readCollapsed())
function persist() {
  try { localStorage.setItem(STORE, JSON.stringify([...collapsed.value])) } catch { /* 存储不可用时只在本次会话内生效 */ }
}
function toggle(key: string) {
  const next = new Set(collapsed.value)
  if (next.has(key)) next.delete(key)
  else next.add(key)
  collapsed.value = next
  persist()
}
watch(activeGroup, (g) => {
  if (g && collapsed.value.has(g)) toggle(g)
}, { immediate: true })

/* 移动端抽屉。 */
const drawerOpen = ref(false)
const drawer = ref<HTMLElement>()
const menuButton = ref<HTMLButtonElement>()
function focusables() {
  return Array.from(drawer.value?.querySelectorAll<HTMLElement>('a[href], button:not([disabled]), [tabindex="0"]') ?? [])
}
function onKey(e: KeyboardEvent) {
  if (!drawerOpen.value) return
  if (e.key === 'Escape') {
    e.preventDefault()
    drawerOpen.value = false
  } else if (e.key === 'Tab') {
    const list = focusables()
    const first = list[0], last = list[list.length - 1]
    if (!first) return void e.preventDefault()
    const inside = drawer.value?.contains(document.activeElement)
    if (e.shiftKey && (!inside || document.activeElement === first)) { e.preventDefault(); last.focus() }
    else if (!e.shiftKey && (!inside || document.activeElement === last)) { e.preventDefault(); first.focus() }
  }
}
watch(drawerOpen, (open) => {
  if (open) nextTick(() => focusables()[0]?.focus())
  else menuButton.value?.focus()
})
watch(() => route.fullPath, () => { drawerOpen.value = false })
onMounted(() => document.addEventListener('keydown', onKey))
onBeforeUnmount(() => document.removeEventListener('keydown', onKey))

const ready = ref<boolean | null>(null)
onMounted(async () => {
  try { await api.get('/health/ready'); ready.value = true } catch { ready.value = false }
})
</script>

<template>
  <div class="flex min-h-screen bg-paper">
    <aside class="sticky top-0 hidden h-screen w-60 shrink-0 flex-col border-r border-ink-hair bg-paper px-4 py-6 md:flex">
      <RouterLink to="/" class="flex items-center gap-2.5 px-3">
        <span class="inline-flex h-4 w-4 items-center justify-center border border-ink"><span class="h-1 w-1 bg-signal" /></span>
        <span class="text-[13px] font-medium tracking-[0.2em]">SENTINEL</span>
      </RouterLink>
      <nav class="mt-8 flex-1 overflow-y-auto" aria-label="功能菜单">
        <ul class="space-y-1">
          <NavGroup v-for="g in menu" :key="g.key" :group="g" :open="!collapsed.has(g.key)" :active-item="activeGroup === g.key ? activeItem : undefined" @toggle="toggle(g.key)" />
        </ul>
      </nav>
      <AccountMenu class="mx-3 mt-4" />
    </aside>

    <Transition name="fade">
      <div v-if="drawerOpen" class="fixed inset-0 z-40 bg-ink/10 md:hidden" @click="drawerOpen = false" />
    </Transition>
    <aside
      v-if="drawerOpen"
      id="console-drawer"
      ref="drawer"
      class="fixed inset-y-0 left-0 z-50 flex w-72 max-w-[85vw] flex-col border-r border-ink-line bg-paper px-4 py-6 shadow-panel md:hidden"
      role="dialog"
      aria-modal="true"
      aria-label="功能菜单"
    >
      <div class="flex items-center justify-between px-3">
        <span class="text-[13px] font-medium tracking-[0.2em]">SENTINEL</span>
        <button type="button" class="p-1 text-ink-3 hover:text-ink" aria-label="关闭菜单" @click="drawerOpen = false"><X :size="18" :stroke-width="1.5" /></button>
      </div>
      <nav class="mt-6 flex-1 overflow-y-auto" aria-label="功能菜单（抽屉）">
        <ul class="space-y-1">
          <NavGroup v-for="g in menu" :key="g.key" :group="g" :open="!collapsed.has(g.key)" :active-item="activeGroup === g.key ? activeItem : undefined" @toggle="toggle(g.key)" @navigate="drawerOpen = false" />
        </ul>
      </nav>
      <AccountMenu class="mx-3 mt-4" />
    </aside>

    <div class="min-w-0 flex-1">
      <header class="sticky top-0 z-20 flex h-14 items-center justify-between border-b border-ink-hair bg-paper/90 px-6 backdrop-blur md:px-10">
        <div class="flex min-w-0 items-center gap-3 text-[12.5px]">
          <button
            ref="menuButton"
            type="button"
            class="-ml-1 p-1 text-ink-2 hover:text-ink md:hidden"
            aria-label="打开菜单"
            aria-controls="console-drawer"
            :aria-expanded="drawerOpen"
            @click="drawerOpen = true"
          ><Menu :size="18" :stroke-width="1.5" /></button>
          <nav aria-label="面包屑" class="min-w-0">
            <ol class="flex items-center gap-3 truncate">
              <li v-for="(c, i) in crumbs" :key="i" class="flex items-center gap-3">
                <span v-if="i > 0" class="text-ink-4" aria-hidden="true">/</span>
                <RouterLink v-if="c.to" :to="c.to" class="text-ink-3 hover:text-ink">{{ c.label }}</RouterLink>
                <span v-else :class="[i === crumbs.length - 1 ? 'text-ink' : 'text-ink-3', c.mono ? 'num' : '']" :aria-current="i === crumbs.length - 1 ? 'page' : undefined">{{ c.label }}</span>
              </li>
            </ol>
          </nav>
        </div>
        <div class="flex items-center gap-6 text-[12px] text-ink-3">
          <span v-if="ready !== null" class="hidden items-center gap-2 md:flex"><span class="dot" :class="ready ? 'bg-ok' : 'bg-threat'" />{{ ready ? '控制面正常' : '数据库不可用' }}</span>
        </div>
      </header>

      <main class="mx-auto max-w-[1440px] px-6 pb-20 pt-8 md:px-10">
        <RouterView v-slot="{ Component, route: r }">
          <Transition name="page" mode="out-in">
            <component :is="Component" :key="r.fullPath" />
          </Transition>
        </RouterView>
      </main>
    </div>
  </div>
</template>
