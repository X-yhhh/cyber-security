import { loadSession, session } from '@/api/session'
import { setUnauthorizedHandler } from '@/api/client'
import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router'

/**
 * 路由按功能模块划分（docs/功能模块设计.md §2），不再细拆子页面：
 * 同一模块内的子视图用页内分段切换，详情用抽屉或独立详情页。
 */
export const modules = [
  { path: 'overview', name: 'overview', title: '态势', en: 'Overview', component: () => import('@/views/console/OverviewView.vue') },
  { path: 'events', name: 'events', title: '告警与事件', en: 'Detection', component: () => import('@/views/console/EventsView.vue') },
  { path: 'response', name: 'response', title: '受控响应', en: 'Response', component: () => import('@/views/console/ResponseView.vue') },
  { path: 'models', name: 'models', title: '模型治理', en: 'Models', component: () => import('@/views/console/ModelsView.vue') },
  { path: 'assets', name: 'assets', title: '资产与传感器', en: 'Assets', component: () => import('@/views/console/AssetsView.vue') },
  { path: 'sources', name: 'sources', title: '数据源与回放', en: 'Sources', component: () => import('@/views/console/SourcesView.vue') },
  { path: 'audit', name: 'audit', title: '审计', en: 'Audit', component: () => import('@/views/console/AuditView.vue') },
  { path: 'iam', name: 'iam', title: '身份与角色', en: 'Identity', component: () => import('@/views/console/IamView.vue') },
  // host-guard v5（P4）新增：观测与推理、策略与发布、执行与预算三条 v2 链路。
  { path: 'observation', name: 'observation', title: '观测与目标', en: 'Observation', component: () => import('@/views/console/ObservationView.vue') },
  { path: 'release', name: 'release', title: '策略与发布', en: 'Release', component: () => import('@/views/console/ReleaseView.vue') },
  { path: 'execution', name: 'execution', title: '执行与预算', en: 'Execution', component: () => import('@/views/console/ExecutionView.vue') },
  // 演示最小集（FE-1—FE-3）：来源 × 类别判定、lab 验证与 G3 报告、健康与审计，全部只读。
  { path: 'decisions', name: 'decisions', title: '判定与来源', en: 'Decisions', component: () => import('@/views/console/DecisionsView.vue') },
  { path: 'lab', name: 'lab', title: 'lab 验证与 G3', en: 'Lab', component: () => import('@/views/console/LabView.vue') },
  { path: 'health', name: 'health', title: '健康与审计', en: 'Health', component: () => import('@/views/console/HealthView.vue') },
] as const

const routes: RouteRecordRaw[] = [
  { path: '/', name: 'landing', component: () => import('@/views/LandingView.vue'), meta: { title: '概览' } },
  { path: '/login', name: 'login', component: () => import('@/views/LoginView.vue'), meta: { title: '登录' } },
  {
    path: '/console',
    component: () => import('@/layouts/ConsoleLayout.vue'),
    meta: { shell: 'console' },
    redirect: { name: 'overview' },
    children: [
      ...modules.map((m) => ({ path: m.path, name: m.name, component: m.component, meta: { title: m.title, shell: 'console' } })),
      { path: 'events/:id', name: 'event-detail', component: () => import('@/views/console/EventDetailView.vue'), meta: { title: '事件详情', shell: 'console', parent: 'events' } },
      { path: 'lab/:id', name: 'lab-detail', component: () => import('@/views/console/LabRunDetailView.vue'), meta: { title: 'lab 会话详情', shell: 'console', parent: 'lab' } },
    ],
  },
  { path: '/:pathMatch(.*)*', redirect: '/' },
]

export const router = createRouter({
  history: createWebHistory(),
  routes,
  scrollBehavior: (_to, _from, saved) => saved ?? { top: 0 },
})

/** 控制台路由要求有效会话；会话以 /auth/me 为准，首次进入时加载一次。 */
router.beforeEach(async (to) => {
  if (to.matched.some((r) => r.meta.shell === 'console')) {
    if (!session.checked || !session.user) await loadSession()
    if (!session.user) return { name: 'login', query: { redirect: to.fullPath } }
  }
})

setUnauthorizedHandler(() => {
  session.user = null
  if (router.currentRoute.value.name !== 'login') router.push({ name: 'login', query: { redirect: router.currentRoute.value.fullPath } })
})

router.afterEach((to) => {
  document.title = `${to.meta.title ?? ''} · Sentinel`
})
