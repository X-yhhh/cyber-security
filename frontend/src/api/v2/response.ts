/**
 * F2 处置记录接口：只使用已登记的 /api/v2 路由，预算账本只读。
 *
 * active=true 由后端按期望状态和 blockUntil 筛选，不能据此推断防火墙实态；
 * 撤销和停用的 202 只表示受理，清理结果必须重新读取动作与执行器回执。
 * 写请求默认生成新的幂等键；同一次提交的网络重试可显式传入原键和原修订号。
 */
import { guard, idempotencyKey, type Cursor } from '@/api/client'
import type { GuardAction, GuardActionReceipt, GuardBudgetLedger, GuardBudgetTarget } from '@/api/types'

export type ActionState = 'pending' | 'dispatched' | 'applied' | 'revoked' | 'expired' | 'rejected' | 'uncertain' | 'recovery_failed'

export interface ResponseQuery {
  assetId?: string
  from?: string
  until?: string
  sort?: 'createdAt' | 'updatedAt'
  cursor?: string
  limit?: number
}

/** 时间为 UTC RFC3339 Z；status 筛选观测状态，缺省 active 表示全部动作。 */
export interface ActionQuery extends ResponseQuery { status?: ActionState; active?: true }
export interface ActionDecisionResult { id: string; observedState: 'pending' | 'rejected'; revision?: number }
export interface ActionRevocationResult { id: string; desiredState: 'revoked'; observedState: string }
export interface AutomationStopRequest { assetIds: readonly string[]; reason: string; revokeExisting: boolean }
export interface AutomationStopResult { status: 'accepted' }
type WriteKey = ReturnType<typeof idempotencyKey>

const queryParams = (q: ResponseQuery) => ({
  assetId: q.assetId, from: q.from, until: q.until, sort: q.sort, cursor: q.cursor, limit: q.limit ?? 50,
})

export const responseApi = {
  listActions: (q: ActionQuery = {}): Promise<Cursor<GuardAction>> =>
    guard.read('actions', { ...queryParams(q), status: q.status, active: q.active ? 'true' : undefined }),
  getAction: (id: string): Promise<GuardAction> => guard.get('actions', id),
  /** 没有命令时返回 items=[]，不合成成功回执。 */
  listReceipts: (id: string): Promise<{ items: GuardActionReceipt[] }> => guard.child('actions', id, 'receipts'),
  listBudgetTargets: (q: ResponseQuery = {}): Promise<Cursor<GuardBudgetTarget>> => guard.read('budget-targets', queryParams(q)),
  getBudgetLedger: (id: string): Promise<GuardBudgetLedger> => guard.get('budget-targets', id),

  /** authorization.approve；后端强制职责分离、修订号和处置硬约束。 */
  decideAction: (id: string, revision: number, decision: 'approve' | 'reject', reason: string, key?: WriteKey): Promise<ActionDecisionResult> =>
    guard.op('actions', id, 'decisions', { decision, reason }, revision, key),
  /** action.revoke；不能把返回的 desiredState 当作已完成清理。 */
  revokeAction: (id: string, revision: number, reason: string, key?: WriteKey): Promise<ActionRevocationResult> =>
    guard.op('actions', id, 'revocations', { reason }, revision, key),
  /** automation.stop；一次 1—32 个资产，调用者须对每个资产有权限；该集合操作没有 If-Match。 */
  stopAutomation: (body: AutomationStopRequest, key?: WriteKey): Promise<AutomationStopResult> =>
    guard.create('automation-stops', body, key),
}
