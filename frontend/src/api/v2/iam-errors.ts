/** IAM 稳定错误码的中文提示；保留 ApiError 的状态、错误码和 requestId，最终判定以后端为准。 */
export const iamErrorMessages: Readonly<Record<string, string>> = {
  ROLE_CONFLICT: '角色职责冲突，请调整该用户的角色绑定。',
  LAST_ADMIN_REQUIRED: '必须保留至少一位有效的全局平台管理员。',
  ROLE_IN_USE: '角色仍有绑定，请先撤销绑定或改为停用。',
  USER_IN_USE: '账号仍有角色绑定或审计引用，不能删除，可改为停用。',
  PERMISSION_CONFLICT: '所选权限包含互斥的申请与审批职责，请调整。',
  SELF_ADMINISTRATION_FORBIDDEN: '不能管理自己的账号或角色绑定；修改本人密码请使用账户菜单。',
  BUILTIN_ROLE_READONLY: '内置角色只读，不能修改、停用或删除。',
  ROLE_LIMIT_REACHED: '启用角色已达上限：6 个内置人工角色、最多 2 个自定义角色及 2 个机器模板。',
  ROLE_DISABLED: '所选角色已停用，请刷新角色目录后重新选择。',
}
