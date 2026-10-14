/**
 * 人工角色的中文名（权限设计第 3.1 节）。账户菜单对所有登录用户显示角色名，
 * 而 `GET /roles` 只对 iam.manage / audit.read 开放，因此名称在前端固定一份；
 * 未登记的键（迁移前遗留的 v1 角色等）原样显示。
 */
export const roleNames: Record<string, string> = {
  platform_admin: '平台管理员',
  security_analyst: '安全分析员',
  security_reviewer: '安全审核员',
  model_operator: '模型操作员',
  evidence_reviewer: '证据复核员',
  auditor: '审计员',
}

export const roleName = (key: string) => roleNames[key] ?? key
