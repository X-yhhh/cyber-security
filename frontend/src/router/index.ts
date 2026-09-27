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
    ],
  },
  { path: '/:pathMatch(.*)*', redirect: '/' },
]

export const router = createRouter({
  history: createWebHistory(),
  routes,
  scrollBehavior: (_to, _from, saved) => saved ?? { top: 0 },
})

router.afterEach((to) => {
  document.title = `${to.meta.title ?? ''} · Sentinel`
})
