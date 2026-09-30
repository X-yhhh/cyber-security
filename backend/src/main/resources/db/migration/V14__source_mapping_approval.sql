-- V14：数据源映射独立批准（路线 B 阶段 5 R1 收口）。只向前追加，V1/V11 已有列与约束不变。
--   通过接口登记的映射为 draft；传感器与 connector 接入要求映射 approved。此前没有批准途径，
--   只能直接改库。V14 补齐申请人列与“申请人≠批准人”约束，并新增批准权限。
--   历史映射 requested_by 为 NULL：无法证明职责分离，服务层拒绝经接口批准。
-- 权限：source.mapping.approve（platform_admin，与 asset.authorization.approve 同一审批角色）。

ALTER TABLE `source_mapping`
  ADD COLUMN `requested_by` BIGINT UNSIGNED DEFAULT NULL COMMENT '映射登记用户' AFTER `status`,
  ADD KEY `idx_source_mapping_requester` (`requested_by`),
  ADD CONSTRAINT `fk_source_mapping_requester` FOREIGN KEY (`requested_by`) REFERENCES `sys_user` (`id`) ON DELETE RESTRICT,
  ADD CONSTRAINT `ck_source_mapping_separation`
    CHECK (`approved_by` IS NULL OR `requested_by` IS NULL OR `approved_by` <> `requested_by`);

INSERT INTO `sys_permission` (`permission_key`, `resource`, `action`, `description`) VALUES
  ('source.mapping.approve', 'source.mapping', 'approve', '独立批准他人登记的数据源映射');

INSERT INTO `sys_role_permission` (`role_id`, `permission_id`)
SELECT r.`id`, p.`id`
FROM `sys_role` r
JOIN `sys_permission` p ON p.`permission_key` = 'source.mapping.approve'
WHERE r.`role_key` = 'platform_admin';
