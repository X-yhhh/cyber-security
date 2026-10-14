/**
 * `GET /api/v2/summary` 的 msw 模拟，严格按任务单 B2.5 契约：
 * 每个字段按调用者权限分别计算，没有权限的字段不返回（不是 0）。B2 合入后改为真实联调。
 */
import { http, HttpResponse } from 'msw'
import type { WorkbenchSummary } from '@/api/v2/summary'
import { currentUser } from './auth'

/** 全部字段都有值时的数字；各测试可覆盖。 */
export const fullSummary: Required<WorkbenchSummary> = {
  openEvents: 7,
  pendingApprovals: { authorizations: 1, sensorConfigs: 2, actions: 3, labRuns: 1, policies: 1, bundles: 2 },
  pendingFeedbackReviews: 4,
  releasePipeline: { candidate: 2, evaluated: 1, approved: 0, active: 1 },
  modelsPendingValidation: 1,
  ops: { sensorsUnhealthy: 1, executorsUnhealthy: 0, lastHealthAt: '2026-10-14T03:20:00' },
  recentAuditCount24h: 42,
}

/** 按权限裁剪字段（B2.5 字段与权限的对应关系）。 */
export function summaryFor(permissions: readonly string[], all: Required<WorkbenchSummary> = fullSummary): WorkbenchSummary {
  const has = (...p: string[]) => p.some((x) => permissions.includes(x))
  const s: WorkbenchSummary = {}
  if (has('event.manage', 'detection.read')) s.openEvents = all.openEvents
  if (has('authorization.approve')) {
    const a = all.pendingApprovals
    s.pendingApprovals = { authorizations: a.authorizations, sensorConfigs: a.sensorConfigs, actions: a.actions, labRuns: a.labRuns }
  }
  if (has('policy.approve')) s.pendingApprovals = { ...s.pendingApprovals, policies: all.pendingApprovals.policies }
  if (has('bundle.approve')) s.pendingApprovals = { ...s.pendingApprovals, bundles: all.pendingApprovals.bundles }
  if (has('feedback.review')) s.pendingFeedbackReviews = all.pendingFeedbackReviews
  if (has('bundle.request', 'bundle.approve', 'evaluation.read')) s.releasePipeline = all.releasePipeline
  if (has('model.manage', 'model.validate')) s.modelsPendingValidation = all.modelsPendingValidation
  if (has('ops.read')) s.ops = all.ops
  if (has('audit.read')) s.recentAuditCount24h = all.recentAuditCount24h
  return s
}

export const summaryHandlers = [
  http.get('/api/v2/summary', () => {
    const user = currentUser()
    if (!user) return HttpResponse.json({ requestId: 'req-test', data: null, error: { code: 'UNAUTHENTICATED', message: '请先登录' } }, { status: 401 })
    return HttpResponse.json({ requestId: 'req-summary', data: summaryFor(user.permissions), error: null })
  }),
]
