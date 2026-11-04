/**
 * 本人识别（BE-25 / FE-16a）：对象的 `createdBy` / `requestedBy` 与当前会话账户比较，只用于隐藏本人审批入口。
 *
 * - 只按账户数字 ID 比较（与 `auth/me.id` 同口径），不比 username；
 * - 字段缺失、为 null 或不是数字 ID 时视为未知：入口照常显示，由后端 `APPROVAL_SEPARATION_REQUIRED` 拦截；
 * - 结果只影响展示，前端不据此拦截提交，职责分离以后端为唯一强制点。
 */
import { session } from '@/api/session'

export type Owner = 'self' | 'other' | 'unknown'
export type OwnerId = number | string | null | undefined

export const SELF_APPROVAL_NOTE = '本人发起，需他人审批'

export function ownerOf(by: OwnerId): Owner {
  const id = typeof by === 'number' ? (Number.isSafeInteger(by) && by > 0 ? String(by) : '')
    : typeof by === 'string' && /^[1-9]\d{0,18}$/.test(by) ? by : ''
  const me = session.user?.id
  if (!id || me == null) return 'unknown'
  return id === String(me) ? 'self' : 'other'
}
/** 确定是本人：隐藏批准、驳回与激活入口。 */
export const isMine = (by: OwnerId) => ownerOf(by) === 'self'
/** 可能是本人（本人或未知）：本人才能做的操作（撤回、删除草稿）照常显示，由后端判定。 */
export const maybeMine = (by: OwnerId) => ownerOf(by) !== 'other'
