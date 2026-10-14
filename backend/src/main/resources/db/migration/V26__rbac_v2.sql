-- rbac-v2：仅向前迁移；保留账号、口令、用户绑定、角色/权限原行和旧 Flyway 校验和。
-- 用户修订用于 v2 If-Match；绑定增加稳定编号而不改原复合主键及范围。
ALTER TABLE sys_user ADD COLUMN revision BIGINT UNSIGNED NOT NULL DEFAULT 1 COMMENT 'v2 IAM 乐观锁修订号';
ALTER TABLE sys_user_role ADD COLUMN id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT 'v2 绑定稳定编号',
    ADD UNIQUE KEY uk_sys_user_role_id (id);
-- 身份管理/会话审计明确标记全局范围；资产绑定操作仍登记具体资产。
ALTER TABLE audit_resource_scope DROP CHECK ck_audit_resource_scope_type,
    ADD CONSTRAINT ck_audit_resource_scope_type CHECK (scope_type IN ('global','asset','data_source','model_registry'));

UPDATE sys_role SET name='平台管理员',description='管理身份、资产和采集接入，申请授权；不审批或研判',status='active' WHERE role_key='platform_admin';
UPDATE sys_role SET name='安全分析员',description='研判事件、标注反馈与申请处置；不审批或复核',status='active' WHERE role_key='security_analyst';
UPDATE sys_role SET name='安全审核员',description='独立审核授权、配置、动作、策略、组合及 lab 资格，支持撤销和停止',status='active' WHERE role_key='security_reviewer';
UPDATE sys_role SET name='模型操作员',description='登记模型、数据、评价与回放，起草策略和发布组合；不审批',status='active' WHERE role_key='model_operator';
UPDATE sys_role SET name='证据复核员',description='独立复核他人反馈，查看检测与评价依据',status='active' WHERE role_key='evidence_reviewer';
UPDATE sys_role SET name='审计员',description='只读审计、健康、检测、动作与评价；不执行写入',status='active' WHERE role_key='auditor';

UPDATE sys_role SET status='disabled' WHERE role_key IN ('asset_source_admin','response_approver','model_releaser');

-- 共享同名 v2 键保留；machine.* 含 v1 机器上行权限全部保持原状态与授权。
UPDATE sys_permission SET status='disabled' WHERE permission_key NOT LIKE 'machine.%' AND permission_key NOT IN ('action.read','action.request','action.revoke','asset.manage','audit.read','authorization.approve','authorization.request','automation.stop','bundle.approve','bundle.request','dataset.manage','detection.read','evaluation.read','evaluation.run','event.manage','feedback.label','feedback.review','iam.manage','model.manage','model.validate','ops.read','policy.approve','policy.draft','resource.read','sensor.manage');
UPDATE sys_permission SET status='active' WHERE permission_key IN ('action.read','action.request','action.revoke','asset.manage','audit.read','authorization.approve','authorization.request','automation.stop','bundle.approve','bundle.request','dataset.manage','detection.read','evaluation.read','evaluation.run','event.manage','feedback.label','feedback.review','iam.manage','model.manage','model.validate','ops.read','policy.approve','policy.draft','resource.read','sensor.manage');
DELETE rp FROM sys_role_permission rp JOIN sys_permission p ON p.id=rp.permission_id WHERE p.status='disabled' AND p.permission_key NOT LIKE 'machine.%';

-- 清空人工角色模板关联再按设计精确重建；用户绑定不自动迁移或扩权。
DELETE rp FROM sys_role_permission rp JOIN sys_role r ON r.id=rp.role_id WHERE r.role_key IN ('platform_admin','security_analyst','security_reviewer','model_operator','evidence_reviewer','auditor','asset_source_admin','response_approver','model_releaser');
INSERT INTO sys_role_permission(role_id,permission_id) SELECT r.id,p.id FROM sys_role r CROSS JOIN sys_permission p WHERE r.role_key='platform_admin' AND p.permission_key IN ('resource.read','authorization.request','asset.manage','sensor.manage','audit.read','ops.read','iam.manage');
INSERT INTO sys_role_permission(role_id,permission_id) SELECT r.id,p.id FROM sys_role r CROSS JOIN sys_permission p WHERE r.role_key='security_analyst' AND p.permission_key IN ('resource.read','detection.read','event.manage','feedback.label','action.read','action.request');
INSERT INTO sys_role_permission(role_id,permission_id) SELECT r.id,p.id FROM sys_role r CROSS JOIN sys_permission p WHERE r.role_key='security_reviewer' AND p.permission_key IN ('resource.read','detection.read','action.read','action.revoke','automation.stop','authorization.approve','evaluation.read','policy.approve','bundle.approve','ops.read');
INSERT INTO sys_role_permission(role_id,permission_id) SELECT r.id,p.id FROM sys_role r CROSS JOIN sys_permission p WHERE r.role_key='model_operator' AND p.permission_key IN ('resource.read','dataset.manage','model.manage','model.validate','evaluation.read','evaluation.run','policy.draft','bundle.request');
INSERT INTO sys_role_permission(role_id,permission_id) SELECT r.id,p.id FROM sys_role r CROSS JOIN sys_permission p WHERE r.role_key='evidence_reviewer' AND p.permission_key IN ('resource.read','detection.read','feedback.review','evaluation.read');
INSERT INTO sys_role_permission(role_id,permission_id) SELECT r.id,p.id FROM sys_role r CROSS JOIN sys_permission p WHERE r.role_key='auditor' AND p.permission_key IN ('resource.read','detection.read','action.read','evaluation.read','audit.read','ops.read');
