-- 模型校验和本机激活分别授权；发布审批仍由独立 model_releaser 决定。
INSERT INTO `sys_permission` (`permission_key`, `resource`, `action`, `description`) VALUES
  ('model.candidate.validate', 'model.candidate', 'validate', '验证候选模型制品及推理契约'),
  ('model.deployment.activate', 'model.deployment', 'activate', '激活已经独立批准的本机模型');

INSERT INTO `sys_role_permission` (`role_id`, `permission_id`)
SELECT r.`id`, p.`id`
FROM `sys_role` r
JOIN `sys_permission` p ON p.`permission_key` IN ('model.candidate.validate', 'model.deployment.activate')
WHERE r.`role_key` = 'model_operator';
