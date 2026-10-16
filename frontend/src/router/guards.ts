import type { RouteLocationNormalized, RouteLocationRaw, Router } from 'vue-router'
import { loadSession, session } from '@/api/session'
import { allowed, landingRoute } from './nav'

/**
 * 控制台守卫（权限设计第 7.1 节）：
 * 1. 未登录跳登录页；
 * 2. 路由 `meta.anyOf` 与会话权限无交集时，原地址渲染 403 页：在解析懒加载组件之前改道，
 *    目标页面组件不会被加载或挂载，也就不会发出任何数据请求。
 * 3. `/console` 空路径按权限改道到默认落地页（实时态势或待办中心）。
 * 前端判定只用于隐藏入口，授权始终以后端为准。
 */
export async function consoleGuard(to: RouteLocationNormalized): Promise<RouteLocationRaw | undefined> {
  if (!to.matched.some((r) => r.meta.shell === 'console')) return
  if (!session.checked || !session.user) await loadSession()
  if (!session.user) return { name: 'login', query: { redirect: to.fullPath } }
  if (to.name === 'console-home') return { name: landingRoute(session.user.permissions), replace: true }
  if (to.name === 'console-forbidden' || allowed(to.meta.anyOf, session.user.permissions)) return
  // 用同模式的兜底路由按名称改道，地址栏保持原地址，刷新后会重新判定。
  return { name: 'console-forbidden', params: { pathMatch: to.path.split('/').filter(Boolean).slice(1) }, query: to.query, hash: to.hash, replace: true }
}

export function installGuards(router: Router) {
  router.beforeEach(consoleGuard)
  router.afterEach((to) => {
    document.title = `${to.meta.title ?? ''} · Sentinel`
    // 首屏沿用 v1 版式，样式表按此属性锁定首屏的主操作形状与标签样式；交互色与控制台同为墨色（前端设计文档第 3 节）。
    document.documentElement.dataset.surface = to.name === 'landing' ? 'landing' : 'console'
  })
}
