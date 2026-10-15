import { setUnauthorizedHandler } from '@/api/client'
import { session } from '@/api/session'
import { createRouter, createWebHistory, type RouteLocation, type RouteRecordRaw, type RouterHistory } from 'vue-router'
import { installGuards } from './guards'
import { details, nav, routeName, type GroupKey } from './nav'
import { toRelease } from './release'

declare module 'vue-router' {
  interface RouteMeta {
    title?: string
    shell?: 'console'
    /** 与会话权限有交集才放行；缺省或空数组表示登录即可。 */
    anyOf?: readonly string[]
    group?: GroupKey
    item?: string
    /** 详情页的 ID 参数名，用于面包屑第三段。 */
    detail?: string
  }
}

const shell = 'console' as const

/** 二级菜单路由：只注册 ready 的项（权限设计第 7.2 节）。 */
const navRoutes: RouteRecordRaw[] = nav
  .filter((i) => i.ready && i.component)
  .map((i) => ({
    path: i.path,
    name: routeName(i),
    component: i.component!,
    props: i.segment ? { segment: i.segment } : false,
    meta: { title: i.title, shell, anyOf: i.anyOf, group: i.group, item: i.key },
  }))

/** 详情整页随所属二级项注册，沿用其 anyOf。 */
const detailRoutes: RouteRecordRaw[] = details.flatMap((d) => {
  const parent = nav.find((i) => i.group === d.group && i.key === d.item)
  if (!parent?.ready || !d.component) return []
  return [{ path: d.path, name: d.name, component: d.component, meta: { title: d.title, shell, anyOf: d.anyOf ?? parent.anyOf, group: d.group, item: d.item, detail: 'id' } }]
})

/** 旧检测地址保留有效分段、筛选和锚点；无效或重复的分段回落到原页面对应段。 */
const toRecords = (fallback: 'observations' | 'decisions') => (to: RouteLocation) => {
  const selected = to.query.tab
  const tab = typeof selected === 'string' && ['batches', 'observations', 'detections', 'decisions'].includes(selected) ? selected : fallback
  return { path: '/console/detect/records', query: { ...to.query, tab }, hash: to.hash }
}

/** 迁入新位置的 09—14 旧地址与 Q10 被合并的地址保留重定向一个版本；保留旧路由名，页面内既有链接无需改动。 */
const movedRoutes: RouteRecordRaw[] = [
  // F1R：观测与推理、判定与来源合并为检测记录（09—14 旧地址与 U0 过渡行地址）。
  { path: 'observation', name: 'observation', redirect: toRecords('observations') },
  { path: 'decisions', name: 'decisions', redirect: toRecords('decisions') },
  { path: 'detect/observations', redirect: toRecords('observations') },
  { path: 'detect/decisions', redirect: toRecords('decisions') },
  { path: 'release', name: 'release', redirect: toRelease('bundles') },
  { path: 'release/evaluations', name: 'release-evaluations', redirect: toRelease('validation', 'evaluations') },
  { path: 'release/policies', name: 'release-policies', redirect: toRelease('policies') },
  { path: 'release/lab', name: 'release-lab', redirect: toRelease('validation', 'lab') },
  { path: 'execution', name: 'execution', redirect: '/console/response/actions' },
  { path: 'lab', name: 'lab', redirect: toRelease('validation', 'lab') },
  { path: 'lab/:id', name: 'lab-detail', redirect: (to) => ({ path: `/console/release/lab/${encodeURIComponent(String(to.params.id))}`, query: to.query, hash: to.hash }) },
  // F4：运行健康并入传感器与执行器的健康窗口分段，授权并入资产详情。
  { path: 'health', name: 'health', redirect: '/console/assets/agents' },
  { path: 'ops/health', redirect: '/console/assets/agents' },
  { path: 'assets/authorizations', redirect: '/console/assets/list' },
  // F2：目标预算并入处置记录，预算占用改在动作详情中只读显示。
  { path: 'response/budgets', redirect: '/console/response/actions' },
  // Q10 菜单骨架（任务单 U0.9）：审计日志移到系统管理组，旧地址重定向一个版本。
  { path: 'ops/audit', redirect: '/console/system/audit' },
]

/** v1 页面不进菜单，地址暂时保留，到 C1 删除（权限设计第 9.3 节）。 */
const legacyRoutes: RouteRecordRaw[] = [
  { path: 'overview', name: 'overview', component: () => import('@/views/console/OverviewView.vue'), meta: { title: '态势', shell } },
  { path: 'events', name: 'events', component: () => import('@/views/console/EventsView.vue'), meta: { title: '告警与事件', shell } },
  { path: 'events/:id', name: 'event-detail', component: () => import('@/views/console/EventDetailView.vue'), meta: { title: '事件详情', shell, detail: 'id' } },
  { path: 'response', name: 'response', component: () => import('@/views/console/ResponseView.vue'), meta: { title: '受控响应', shell } },
  { path: 'models', name: 'models', component: () => import('@/views/console/ModelsView.vue'), meta: { title: '模型治理', shell } },
  { path: 'assets', name: 'assets', component: () => import('@/views/console/AssetsView.vue'), meta: { title: '资产与传感器', shell } },
  { path: 'sources', name: 'sources', component: () => import('@/views/console/SourcesView.vue'), meta: { title: '数据源与回放', shell } },
  { path: 'audit', name: 'audit', component: () => import('@/views/console/AuditView.vue'), meta: { title: '审计', shell } },
  { path: 'iam', name: 'iam', component: () => import('@/views/console/IamView.vue'), meta: { title: '身份与角色', shell } },
]

const NotFound = () => import('@/views/system/NotFoundView.vue')

export const routes: RouteRecordRaw[] = [
  { path: '/', name: 'landing', component: () => import('@/views/LandingView.vue'), meta: { title: '概览' } },
  { path: '/login', name: 'login', component: () => import('@/views/LoginView.vue'), meta: { title: '登录' } },
  {
    path: '/console',
    component: () => import('@/layouts/ConsoleLayout.vue'),
    meta: { shell },
    children: [
      // 空路径由守卫按权限改道到默认落地页（landingRoute），组件不会被挂载。
      { path: '', name: 'console-home', component: NotFound, meta: { title: '控制台', shell } },
      ...navRoutes,
      ...detailRoutes,
      ...movedRoutes,
      ...legacyRoutes,
      // 未知地址 404；守卫把无权限地址按名称改道到 403，两者同模式，按地址匹配时 404 在前。
      { path: ':pathMatch(.*)*', name: 'console-not-found', component: NotFound, meta: { title: '页面不存在', shell } },
      { path: ':pathMatch(.*)*', name: 'console-forbidden', component: () => import('@/views/system/ForbiddenView.vue'), meta: { title: '无权访问', shell } },
    ],
  },
  { path: '/:pathMatch(.*)*', name: 'not-found', component: NotFound, meta: { title: '页面不存在' } },
]

export function createAppRouter(history: RouterHistory = createWebHistory()) {
  // F0R.2：历史导航优先恢复已保存位置；同页查询串变化保持滚动，不影响跨页回顶。
  const router = createRouter({ history, routes, scrollBehavior: (to, from, saved) => saved ?? (to.path === from.path ? false : { top: 0 }) })
  installGuards(router)
  return router
}

export const router = createAppRouter()

setUnauthorizedHandler(() => {
  session.user = null
  if (router.currentRoute.value.name !== 'login') router.push({ name: 'login', query: { redirect: router.currentRoute.value.fullPath } })
})
