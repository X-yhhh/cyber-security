/**
 * 工作台卡片配置（权限设计第 7.4 节）。每张卡片声明 anyOf，与会话权限无交集即不渲染；
 * 计数取自 `GET /summary`，没有权限的字段后端不返回，行即不显示。F2 在此完善卡片内容。
 */
import type { RouteLocationRaw } from 'vue-router'
import type { SummaryLine } from '@/components/SummaryCard.vue'
import type { WorkbenchSummary } from '@/api/v2/summary'
import { fmtTime } from '@/api/types'
import { allowed, itemOf, routeName, type GroupKey, type Permission } from '@/router/nav'

/** 生成跳转目标；目标页尚未上线或当前会话无权访问时返回 undefined，卡片行只显示数字。 */
export type LinkFn = (group: GroupKey, key: string, status?: string) => RouteLocationRaw | undefined

export interface CardDef {
  key: string
  title: string
  en: string
  anyOf: readonly Permission[]
  lines: (s: WorkbenchSummary, link: LinkFn) => SummaryLine[]
  note?: (s: WorkbenchSummary) => string | undefined
}

export function linker(permissions: readonly string[]): LinkFn {
  return (group, key, status) => {
    const item = itemOf(group, key)
    if (!item?.ready || !allowed(item.anyOf, permissions)) return undefined
    return { name: routeName(item), query: status ? { status } : undefined }
  }
}

export const cards: readonly CardDef[] = [
  {
    key: 'events', title: '待研判事件', en: 'Events', anyOf: ['event.manage'],
    lines: (s, link) => [{ label: '未结事件', value: s.openEvents, to: link('detect', 'events', 'open'), tone: 'threat' }],
  },
  {
    key: 'approvals', title: '待我审批', en: 'Approvals', anyOf: ['authorization.approve', 'policy.approve', 'bundle.approve'],
    lines: (s, link) => [
      { label: '资产授权', value: s.pendingApprovals?.authorizations, to: link('assets', 'authorizations', 'pending'), tone: 'signal' },
      { label: '采集配置', value: s.pendingApprovals?.sensorConfigs, to: link('assets', 'agents', 'pending'), tone: 'signal' },
      { label: '人工动作', value: s.pendingApprovals?.actions, to: link('response', 'actions', 'pending'), tone: 'signal' },
      { label: 'lab 会话资格', value: s.pendingApprovals?.labRuns, to: link('release', 'lab', 'pending'), tone: 'signal' },
      { label: '决策策略', value: s.pendingApprovals?.policies, to: link('release', 'policies', 'draft'), tone: 'signal' },
      { label: '发布组合', value: s.pendingApprovals?.bundles, to: link('release', 'bundles', 'evaluated'), tone: 'signal' },
    ],
    note: () => '不含本人发起的对象；后端仍会逐个对象拒绝自批。',
  },
  {
    key: 'feedback', title: '待复核标注', en: 'Feedback', anyOf: ['feedback.review'],
    lines: (s, link) => [{ label: '待复核（不含本人标注）', value: s.pendingFeedbackReviews, to: link('detect', 'feedback', 'pending'), tone: 'signal' }],
  },
  {
    key: 'release', title: '发布进度', en: 'Release', anyOf: ['bundle.request', 'model.manage'],
    lines: (s, link) => [
      { label: '候选组合 candidate', value: s.releasePipeline?.candidate, to: link('release', 'bundles', 'candidate') },
      { label: '已封存待批 evaluated', value: s.releasePipeline?.evaluated, to: link('release', 'bundles', 'evaluated'), tone: 'signal' },
      { label: '待校验模型', value: s.modelsPendingValidation, to: link('release', 'models', 'pending'), tone: 'signal' },
    ],
  },
  {
    key: 'ops', title: '运行健康', en: 'Health', anyOf: ['ops.read'],
    lines: (s, link) => [
      { label: '采集不健康', value: s.ops?.sensorsUnhealthy, to: link('ops', 'health'), tone: 'threat' },
      { label: '执行器不健康', value: s.ops?.executorsUnhealthy, to: link('ops', 'health'), tone: 'threat' },
    ],
    note: (s) => (s.ops ? `最近健康窗口 ${s.ops.lastHealthAt ? fmtTime(s.ops.lastHealthAt) : '—'}` : undefined),
  },
  {
    key: 'audit', title: '最近审计', en: 'Audit', anyOf: ['audit.read'],
    lines: (s, link) => [{ label: '最近 24 小时', value: s.recentAuditCount24h, to: link('ops', 'audit') }],
  },
]
