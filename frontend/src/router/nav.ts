/**
 * 控制台菜单的唯一配置（权限设计第 7 节，rbac-v2）。
 *
 * - 一级组只是分组标题；二级项是独立路由 `/console/<group>/<item>`，路由由本文件生成。
 * - `anyOf` 与会话 `permissions` 有交集才显示该项，路由守卫用同一份 `anyOf` 判定 403。
 * - `ready=false` 的项既不显示也不注册路由；F1—F5 完成页面后只改自己那一行。
 * - 前端过滤只用于隐藏入口，授权始终以后端为准。
 */
import type { RouteComponent } from 'vue-router'

/** 人工权限键（权限设计第 4.1 节，25 个）。 */
export type Permission =
  | 'resource.read' | 'detection.read' | 'event.manage' | 'feedback.label' | 'feedback.review'
  | 'action.read' | 'action.request' | 'action.revoke' | 'automation.stop'
  | 'authorization.request' | 'authorization.approve' | 'asset.manage' | 'sensor.manage'
  | 'dataset.manage' | 'model.manage' | 'model.validate' | 'evaluation.read' | 'evaluation.run'
  | 'policy.draft' | 'policy.approve' | 'bundle.request' | 'bundle.approve' | 'audit.read' | 'ops.read' | 'iam.manage'

type Loader = () => Promise<RouteComponent | { default: RouteComponent }>

export type GroupKey = 'workbench' | 'detect' | 'response' | 'release' | 'assets' | 'ops' | 'system'

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
  /** 复用旧页面期间，打开该页时默认选中的分段；F1—F4 迁移后删除。 */
  segment?: string
}

/** 详情整页（权限设计第 7.2 节）；随所属二级项一起注册，沿用其 `anyOf`。 */
export interface NavDetail { group: GroupKey; item: string; name: string; path: string; title: string; component: Loader }

export const groups: readonly NavGroupDef[] = [
  { key: 'workbench', title: '工作台', en: 'Workbench' },
  { key: 'detect', title: '威胁检测', en: 'Detection' },
  { key: 'response', title: '受控响应', en: 'Response' },
  { key: 'release', title: '模型与发布', en: 'Release' },
  { key: 'assets', title: '资产与采集', en: 'Assets' },
  { key: 'ops', title: '运行与审计', en: 'Operations' },
  { key: 'system', title: '系统管理', en: 'System' },
]

const Observation = () => import('@/views/console/ObservationView.vue')
const Decisions = () => import('@/views/console/DecisionsView.vue')
const Release = () => import('@/views/console/ReleaseView.vue')
const Execution = () => import('@/views/console/ExecutionView.vue')
const Lab = () => import('@/views/console/LabView.vue')
const Health = () => import('@/views/console/HealthView.vue')

/* 每项一行；F1—F5 只改自己负责的行。 */
export const nav: readonly NavItem[] = [
  { group: 'workbench', key: 'workbench', title: '工作台', en: 'Workbench', path: '/console/workbench', anyOf: [], component: () => import('@/views/workbench/WorkbenchView.vue'), ready: true },
  { group: 'detect', key: 'observations', title: '观测与推理', en: 'Observations', path: '/console/detect/observations', anyOf: ['detection.read'], component: Observation, ready: true },
  { group: 'detect', key: 'decisions', title: '判定与来源', en: 'Decisions', path: '/console/detect/decisions', anyOf: ['detection.read'], component: Decisions, ready: true },
  { group: 'detect', key: 'events', title: '事件研判', en: 'Events', path: '/console/detect/events', anyOf: ['detection.read'], component: null, ready: false },
  { group: 'detect', key: 'feedback', title: '反馈与复核', en: 'Feedback', path: '/console/detect/feedback', anyOf: ['feedback.label', 'feedback.review'], component: null, ready: false },
  { group: 'response', key: 'actions', title: '处置动作', en: 'Actions', path: '/console/response/actions', anyOf: ['action.read'], component: Execution, ready: true, segment: 'actions' },
  { group: 'response', key: 'budgets', title: '目标预算', en: 'Budgets', path: '/console/response/budgets', anyOf: ['action.read'], component: Execution, ready: true, segment: 'budgets' },
  { group: 'release', key: 'models', title: '数据集与模型', en: 'Models', path: '/console/release/models', anyOf: ['model.manage', 'model.validate', 'dataset.manage', 'bundle.approve', 'evaluation.read'], component: null, ready: false },
  { group: 'release', key: 'evaluations', title: '评价与回放', en: 'Evaluations', path: '/console/release/evaluations', anyOf: ['evaluation.read'], component: Release, ready: true, segment: 'evaluations' },
  { group: 'release', key: 'policies', title: '决策策略', en: 'Policies', path: '/console/release/policies', anyOf: ['policy.draft', 'policy.approve', 'evaluation.read'], component: Release, ready: true, segment: 'policies' },
  { group: 'release', key: 'bundles', title: '能力与发布组合', en: 'Bundles', path: '/console/release/bundles', anyOf: ['bundle.request', 'bundle.approve', 'automation.stop', 'evaluation.read'], component: Release, ready: true, segment: 'bundles' },
  { group: 'release', key: 'lab', title: 'lab 验证与 G3', en: 'Lab', path: '/console/release/lab', anyOf: ['evaluation.read'], component: Lab, ready: true },
  { group: 'assets', key: 'list', title: '资产', en: 'Assets', path: '/console/assets/list', anyOf: ['asset.manage', 'authorization.request', 'authorization.approve', 'sensor.manage'], component: null, ready: false },
  { group: 'assets', key: 'authorizations', title: '资产授权', en: 'Authorizations', path: '/console/assets/authorizations', anyOf: ['authorization.request', 'authorization.approve', 'audit.read'], component: null, ready: false },
  { group: 'assets', key: 'agents', title: '传感器与执行器', en: 'Agents', path: '/console/assets/agents', anyOf: ['sensor.manage', 'authorization.approve', 'ops.read'], component: null, ready: false },
  { group: 'ops', key: 'health', title: '运行健康', en: 'Health', path: '/console/ops/health', anyOf: ['ops.read'], component: Health, ready: true, segment: 'ops' },
  { group: 'ops', key: 'audit', title: '审计日志', en: 'Audit', path: '/console/ops/audit', anyOf: ['audit.read'], component: Health, ready: true, segment: 'audit' },
  { group: 'system', key: 'users', title: '用户与角色绑定', en: 'Users', path: '/console/system/users', anyOf: ['iam.manage'], component: null, ready: false },
  { group: 'system', key: 'roles', title: '角色与权限目录', en: 'Roles', path: '/console/system/roles', anyOf: ['iam.manage', 'audit.read'], component: null, ready: false },
]

export const details: readonly NavDetail[] = [
  { group: 'detect', item: 'events', name: 'detect-events-detail', path: '/console/detect/events/:id', title: '事件详情', component: () => import('@/views/console/EventDetailView.vue') },
  { group: 'release', item: 'lab', name: 'release-lab-detail', path: '/console/release/lab/:id', title: 'lab 会话详情', component: () => import('@/views/console/LabRunDetailView.vue') },
]

/** 路由名：工作台为 `workbench`，其余为 `<group>-<key>`。 */
export const routeName = (i: Pick<NavItem, 'group' | 'key'>) => (i.group === i.key ? i.key : `${i.group}-${i.key}`)

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

export const groupOf = (key: string | undefined) => groups.find((g) => g.key === key)
export const itemOf = (group: string | undefined, key: string | undefined) => nav.find((i) => i.group === group && i.key === key)
