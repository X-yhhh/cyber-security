/**
 * 系统管理三页（用户管理、角色管理、审计日志，任务单 F5）共用的中文文案。
 *
 * - 权限说明取自权限设计第 4.1 节“含义”列；`GET /permissions` 只对 iam.manage 开放，审计员看角色时也要能读懂，
 *   所以中文说明在前端固定一份，权限键只放在 title 与技术细节里。
 * - asset 绑定的 scopeId 是资产内部十进制 ID（B4 契约），与 v2 资产列表的公开 UUID 不是同一个值，页面原样标注。
 */
import type { RoleBinding } from '@/api/v2/iam'
import type { Permission } from '@/router/nav'

export const permissionLabel: Record<Permission, string> = {
  'resource.read': '查看对象元数据',
  'detection.read': '查看安全数据',
  'event.manage': '研判事件',
  'feedback.label': '标注反馈',
  'feedback.review': '复核他人标注',
  'action.read': '查看动作与预算',
  'action.request': '发起人工处置',
  'action.revoke': '撤销动作',
  'automation.stop': '停止自动能力',
  'authorization.request': '申请资产授权',
  'authorization.approve': '独立批准授权类对象',
  'asset.manage': '登记与维护资产',
  'sensor.manage': '管理传感器、执行器与机器凭据',
  'dataset.manage': '登记数据集',
  'model.manage': '登记模型',
  'model.validate': '校验模型',
  'evaluation.read': '查看评价、回放与 lab 会话',
  'evaluation.run': '运行评价、回放与 lab 会话',
  'policy.draft': '起草决策策略',
  'policy.approve': '审核决策策略',
  'bundle.request': '申请与封存发布组合',
  'bundle.approve': '批准并激活发布组合',
  'audit.read': '查看审计',
  'ops.read': '查看运行状态与健康',
  'iam.manage': '管理身份与访问',
}
export const permText = (key: string) => permissionLabel[key as Permission] ?? key

export const userStatusLabel: Record<string, string> = { active: '启用', disabled: '已停用', locked: '已锁定' }
export const roleStatusLabel: Record<string, string> = { active: '启用', disabled: '已停用' }

/** 绑定范围：global 为全局；asset 显示内部资产编号，不冒充资产名称。 */
export const scopeText = (b: Pick<RoleBinding, 'scopeType' | 'scopeId'>) => (b.scopeType === 'global' ? '全局' : `资产 #${b.scopeId}`)

/** 本人账号的统一说明：后端返回 403 SELF_ADMINISTRATION_FORBIDDEN，页面事先禁用按钮。 */
export const SELF_REASON = '不能管理自己的账号或角色绑定；修改本人口令请使用右上角账户菜单。'

export const auditOutcomeLabel: Record<string, string> = { success: '成功', denied: '拒绝', failure: '失败', rejected: '驳回' }
export const auditActorLabel: Record<string, string> = { human: '人工', machine: '机器', system: '系统' }

/** 口令规则与后端一致：12—128 个字符，UTF-8 不超过 72 字节（bcrypt 上限）。 */
export function passwordProblem(pw: string, confirm: string): string {
  if (pw.length < 12) return '口令至少 12 位。'
  if (pw.length > 128 || new TextEncoder().encode(pw).length > 72) return '口令过长（UTF-8 不超过 72 字节）。'
  if (pw !== confirm) return '两次输入的口令不一致。'
  return ''
}
