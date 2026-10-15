/**
 * 控制台菜单的唯一配置（权限设计第 7 节，rbac-v2；Q10 后为 6 组 13 行）。
 *
 * - 一级组只是分组标题；二级项是独立路由 `/console/<group>/<item>`，路由由本文件生成。
 * - `anyOf` 与会话 `permissions` 有交集才显示该项，路由守卫用同一份 `anyOf` 判定 403。
 * - 13 行正式入口均已 ready；菜单与路由继续使用同一个 ready 判定。
 * - 前端过滤只用于隐藏入口，授权始终以后端为准。
 */
import type { Component } from 'vue'
import type { RouteComponent } from 'vue-router'
import {
  Activity, BrainCircuit, ListTodo, MessageSquareWarning, PackageCheck, RadioTower,
  ScanSearch, ScrollText, Server, ShieldAlert, ShieldBan, UserCog, Users,
} from 'lucide-vue-next'

/** 人工权限键（权限设计第 4.1 节，25 个）。 */
export type Permission =
  | 'resource.read' | 'detection.read' | 'event.manage' | 'feedback.label' | 'feedback.review'
  | 'action.read' | 'action.request' | 'action.revoke' | 'automation.stop'
  | 'authorization.request' | 'authorization.approve' | 'asset.manage' | 'sensor.manage'
  | 'dataset.manage' | 'model.manage' | 'model.validate' | 'evaluation.read' | 'evaluation.run'
  | 'policy.draft' | 'policy.approve' | 'bundle.request' | 'bundle.approve' | 'audit.read' | 'ops.read' | 'iam.manage'

type Loader = () => Promise<RouteComponent | { default: RouteComponent }>

/** 一级组（权限设计第 7.2 节，Q10 的 6 组）。 */
export type GroupKey = 'overview' | 'detect' | 'response' | 'release' | 'assets' | 'system'

export interface NavGroupDef { key: GroupKey; title: string; en: string }

export interface NavItem {
  group: GroupKey
  key: string
  title: string
  en: string
  /** 完整路由路径。 */
  path: string
  /** 空数组表示登录即可。 */
  anyOf: readonly Permission[]
  component: Loader | null
  ready: boolean
  /** 侧栏与页头使用的线性图标（lucide）。 */
  icon: Component
}

/** 详情整页（权限设计第 7.2 节）；随所属二级项一起注册，沿用其 `anyOf`。 */
export interface NavDetail { group: GroupKey; item: string; name: string; path: string; title: string; component: Loader; anyOf?: readonly Permission[] }

export const groups: readonly NavGroupDef[] = [
  { key: 'overview', title: '态势', en: 'Overview' },
  { key: 'detect', title: '威胁检测', en: 'Detection' },
  { key: 'response', title: '响应处置', en: 'Response' },
  { key: 'release', title: '模型与发布', en: 'Release' },
  { key: 'assets', title: '资产与接入', en: 'Assets' },
  { key: 'system', title: '系统管理', en: 'System' },
]

const Events = () => import('@/views/detect/EventsView.vue')
const Feedback = () => import('@/views/detect/FeedbackView.vue')

/** 13 行正式菜单逐项对应权限设计第 7.2 节；所有入口均已接线。 */
export const nav: readonly NavItem[] = [
  { group: 'overview', key: 'live', title: '实时态势', en: 'Live', path: '/console/overview/live', anyOf: ['detection.read', 'action.read', 'ops.read'], component: () => import('@/views/overview/LiveView.vue'), ready: true, icon: Activity },
  { group: 'overview', key: 'workbench', title: '待办中心', en: 'To-dos', path: '/console/workbench', anyOf: [], component: () => import('@/views/workbench/WorkbenchView.vue'), ready: true, icon: ListTodo },
  { group: 'detect', key: 'events', title: '事件研判', en: 'Events', path: '/console/detect/events', anyOf: ['detection.read'], component: Events, ready: true, icon: ShieldAlert },
  { group: 'detect', key: 'records', title: '检测记录', en: 'Records', path: '/console/detect/records', anyOf: ['detection.read'], component: () => import('@/views/detect/RecordsView.vue'), ready: true, icon: ScanSearch },
  { group: 'detect', key: 'feedback', title: '误报反馈', en: 'Feedback', path: '/console/detect/feedback', anyOf: ['feedback.label', 'feedback.review'], component: Feedback, ready: true, icon: MessageSquareWarning },
  { group: 'response', key: 'actions', title: '处置记录', en: 'Actions', path: '/console/response/actions', anyOf: ['action.read'], component: () => import('@/views/response/ActionsView.vue'), ready: true, icon: ShieldBan },
  { group: 'release', key: 'models', title: '模型与数据集', en: 'Models', path: '/console/release/models', anyOf: ['model.manage', 'model.validate', 'dataset.manage', 'bundle.request', 'bundle.approve', 'evaluation.read'], component: () => import('@/views/release/ModelsView.vue'), ready: true, icon: BrainCircuit },
  { group: 'release', key: 'bundles', title: '发布管理', en: 'Bundles', path: '/console/release/bundles', anyOf: ['bundle.request', 'bundle.approve', 'policy.draft', 'policy.approve', 'automation.stop', 'evaluation.read'], component: () => import('@/views/release/BundlesView.vue'), ready: true, icon: PackageCheck },
  { group: 'assets', key: 'list', title: '资产', en: 'Assets', path: '/console/assets/list', anyOf: ['asset.manage', 'authorization.request', 'authorization.approve', 'sensor.manage', 'audit.read'], component: () => import('@/views/assets/AssetsView.vue'), ready: true, icon: Server },
  { group: 'assets', key: 'agents', title: '传感器与执行器', en: 'Agents', path: '/console/assets/agents', anyOf: ['sensor.manage', 'authorization.approve', 'ops.read'], component: () => import('@/views/assets/AgentsView.vue'), ready: true, icon: RadioTower },
  { group: 'system', key: 'users', title: '用户管理', en: 'Users', path: '/console/system/users', anyOf: ['iam.manage'], component: () => import('@/views/system/UsersView.vue'), ready: true, icon: Users },
  { group: 'system', key: 'roles', title: '角色管理', en: 'Roles', path: '/console/system/roles', anyOf: ['iam.manage', 'audit.read'], component: () => import('@/views/system/RolesView.vue'), ready: true, icon: UserCog },
  { group: 'system', key: 'audit', title: '审计日志', en: 'Audit', path: '/console/system/audit', anyOf: ['audit.read'], component: () => import('@/views/system/AuditView.vue'), ready: true, icon: ScrollText },
]

export const details: readonly NavDetail[] = [
  { group: 'detect', item: 'events', name: 'detect-events-detail', path: '/console/detect/events/:id', title: '事件详情', component: () => import('@/views/detect/EventDetailView.vue') },
  { group: 'release', item: 'bundles', name: 'release-lab-detail', path: '/console/release/lab/:id', title: 'lab 会话详情', component: () => import('@/views/release/LabRunDetailView.vue'), anyOf: ['evaluation.read'] },
  { group: 'assets', item: 'list', name: 'assets-list-detail', path: '/console/assets/list/:id', title: '资产详情', component: () => import('@/views/assets/AssetDetailView.vue') },
]

/** 路由名：待办中心为 `workbench`，其余为 `<group>-<key>`。 */
export const routeName = (i: Pick<NavItem, 'group' | 'key'>) => (i.key === 'workbench' ? 'workbench' : `${i.group}-${i.key}`)

/** `anyOf` 为空表示登录即可；否则与权限集合有交集才放行。 */
export function allowed(anyOf: readonly string[] | undefined, permissions: readonly string[] | undefined): boolean {
  if (!anyOf || anyOf.length === 0) return true
  if (!permissions) return false
  return anyOf.some((p) => permissions.includes(p))
}

export interface MenuGroup extends NavGroupDef { items: NavItem[] }

/** 当前会话可见的两级菜单：只含 ready 且有权限的项，无可见项的组整组隐藏。 */
export function visibleMenu(permissions: readonly string[] | undefined, items: readonly NavItem[] = nav): MenuGroup[] {
  return groups
    .map((g) => ({ ...g, items: items.filter((i) => i.group === g.key && i.ready && allowed(i.anyOf, permissions)) }))
    .filter((g) => g.items.length > 0)
}

/**
 * 登录后的默认落地页（权限设计第 7.1 节，任务单 F6）：持有 detection.read 或 ops.read 且实时态势已上线时进入实时态势，
 * 其余进入待办中心。`/console` 空路径与登录跳转共用这一规则。
 */
export function landingRoute(permissions: readonly string[] | undefined): string {
  const live = nav.find((i) => i.group === 'overview' && i.key === 'live')
  return live?.ready && allowed(['detection.read', 'ops.read'], permissions) ? routeName(live) : 'workbench'
}

export const groupOf = (key: string | undefined) => groups.find((g) => g.key === key)
export const itemOf = (group: string | undefined, key: string | undefined) => nav.find((i) => i.group === group && i.key === key)
