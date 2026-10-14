/**
 * 工作台汇总 `GET /api/v2/summary`（任务单 B2.5 契约）。
 *
 * - 只要求登录；每个字段按调用者权限分别计算，**没有权限的字段不返回**（不是 0），
 *   因此所有字段都是可选的，前端用“字段是否存在”而不是“值是否为 0”判断能否展示；
 * - 计数全部按调用者可见范围统计，待审批与待复核排除本人发起的对象；
 * - 只返回计数，不返回明细。
 * B2 合入前由 msw 按本契约模拟（`src/test/handlers/summary.ts`）。
 */
import { guard } from '@/api/client'

export interface WorkbenchSummary {
  /** event.manage 或 detection.read */
  openEvents?: number
  /** 各字段分别要求对应的批准权限 */
  pendingApprovals?: {
    authorizations?: number
    sensorConfigs?: number
    actions?: number
    labRuns?: number
    policies?: number
    bundles?: number
  }
  /** feedback.review，排除本人标注 */
  pendingFeedbackReviews?: number
  /** bundle.request、bundle.approve 或 evaluation.read */
  releasePipeline?: { candidate: number; evaluated: number; approved: number; active: number }
  /** model.manage 或 model.validate */
  modelsPendingValidation?: number
  /** ops.read */
  ops?: { sensorsUnhealthy: number; executorsUnhealthy: number; lastHealthAt: string | null }
  /** audit.read */
  recentAuditCount24h?: number
}

export const fetchSummary = () => guard.read<WorkbenchSummary>('summary')
