-- V17：开发路线阶段 1 功能线（§4.1 用户、资产、数据源、传感器、机器客户端增删改查补齐）。只向前追加，
--   V1 列、既有 CHECK 与唯一键语义保留；业务事实不删除，配置对象以停用、撤销、驳回、退役代替删除。
--   1. sys_user：password_changed_at 记录最近一次改密/重置时间（自助改密与管理员重置都写）。
--      冻结沿用 V1 状态 disabled；冻结、改密、改角色由服务层同事务撤销该用户全部会话。
--   2. asset_authorization：撤销人、时间与理由。pending/active → revoked，撤销后接入与处置立即 fail-closed
--      （现有查询只认 status='active' 且在有效期内的授权）。
--   3. source_mapping：审批决定人、时间、理由与退役人、时间；状态追加 rejected（待批准映射被驳回）与
--      retired（已批准映射退役）。V1 的 disabled 保留以兼容历史行，服务层不再写入。接入只认 approved。
--      CHECK 要求审批决定人 ≠ 登记人（与 V14 批准人 ≠ 登记人同口径）。
--   4. sensor_config：起草人、变更理由、审批决定人与时间、理由、启用人、退役时间；状态追加 rejected。
--      生命周期 pending → approved | rejected，approved → active（启用时同事务退役旧 active），active → retired。
--      V1～V16 经登记接口直接写入的首个配置没有起草人（requested_by 为空），保留原状。
--      CHECK 要求批准人、审批决定人 ≠ 起草人。
--   5. api_client：撤销人、时间、理由与最近轮换时间。吊销后凭据立即失效（机器过滤器只认 active）。
--      传感器下线沿用 V1 状态 sensor_agent.status='revoked'，同事务吊销其机器凭据、退役 active 配置；不可恢复。
--   6. 权限 sensor.config.approve（platform_admin）：批准或驳回他人起草的传感器配置版本。

ALTER TABLE `sys_user`
  ADD COLUMN `password_changed_at` DATETIME(3) DEFAULT NULL COMMENT '最近一次改密或管理员重置时间，UTC' AFTER `password_hash`;

ALTER TABLE `asset_authorization`
  ADD COLUMN `revoked_by` BIGINT UNSIGNED DEFAULT NULL COMMENT '撤销用户' AFTER `approved_by`,
  ADD COLUMN `revoked_at` DATETIME(3) DEFAULT NULL COMMENT '撤销时间，UTC' AFTER `revoked_by`,
  ADD COLUMN `revoke_reason` VARCHAR(1000) DEFAULT NULL COMMENT '撤销理由' AFTER `revoked_at`,
  ADD KEY `idx_asset_authorization_revoker` (`revoked_by`),
  ADD CONSTRAINT `fk_asset_authorization_revoker` FOREIGN KEY (`revoked_by`) REFERENCES `sys_user` (`id`) ON DELETE RESTRICT;

ALTER TABLE `source_mapping`
  ADD COLUMN `reviewed_by` BIGINT UNSIGNED DEFAULT NULL COMMENT '审批决定用户（批准或驳回）' AFTER `approved_by`,
  ADD COLUMN `reviewed_at` DATETIME(3) DEFAULT NULL COMMENT '审批决定时间，UTC' AFTER `reviewed_by`,
  ADD COLUMN `decision_reason` VARCHAR(1000) DEFAULT NULL COMMENT '驳回或退役理由' AFTER `reviewed_at`,
  ADD COLUMN `retired_by` BIGINT UNSIGNED DEFAULT NULL COMMENT '退役用户' AFTER `decision_reason`,
  ADD COLUMN `retired_at` DATETIME(3) DEFAULT NULL COMMENT '退役时间，UTC' AFTER `retired_by`,
  ADD KEY `idx_source_mapping_reviewer` (`reviewed_by`),
  ADD KEY `idx_source_mapping_retired_by` (`retired_by`),
  ADD CONSTRAINT `fk_source_mapping_reviewer` FOREIGN KEY (`reviewed_by`) REFERENCES `sys_user` (`id`) ON DELETE RESTRICT,
  ADD CONSTRAINT `fk_source_mapping_retired_by` FOREIGN KEY (`retired_by`) REFERENCES `sys_user` (`id`) ON DELETE RESTRICT,
  ADD CONSTRAINT `ck_source_mapping_review_separation`
    CHECK (`reviewed_by` IS NULL OR `requested_by` IS NULL OR `reviewed_by` <> `requested_by`);

ALTER TABLE `source_mapping` DROP CHECK `ck_source_mapping_status`;
ALTER TABLE `source_mapping` ADD CONSTRAINT `ck_source_mapping_status`
  CHECK (`status` IN ('draft', 'pending', 'approved', 'disabled', 'rejected', 'retired'));

ALTER TABLE `sensor_config`
  ADD COLUMN `requested_by` BIGINT UNSIGNED DEFAULT NULL COMMENT '起草用户；经登记接口写入的首个配置为空' AFTER `status`,
  ADD COLUMN `change_reason` VARCHAR(1000) DEFAULT NULL COMMENT '起草理由' AFTER `requested_by`,
  ADD COLUMN `reviewed_by` BIGINT UNSIGNED DEFAULT NULL COMMENT '审批决定用户（批准或驳回）' AFTER `approved_by`,
  ADD COLUMN `reviewed_at` DATETIME(3) DEFAULT NULL COMMENT '审批决定时间，UTC' AFTER `reviewed_by`,
  ADD COLUMN `decision_reason` VARCHAR(1000) DEFAULT NULL COMMENT '审批理由' AFTER `reviewed_at`,
  ADD COLUMN `activated_by` BIGINT UNSIGNED DEFAULT NULL COMMENT '启用用户' AFTER `activated_at`,
  ADD COLUMN `retired_at` DATETIME(3) DEFAULT NULL COMMENT '退役时间，UTC' AFTER `activated_by`,
  ADD KEY `idx_sensor_config_requester` (`requested_by`),
  ADD KEY `idx_sensor_config_reviewer` (`reviewed_by`),
  ADD KEY `idx_sensor_config_activator` (`activated_by`),
  ADD CONSTRAINT `fk_sensor_config_requester` FOREIGN KEY (`requested_by`) REFERENCES `sys_user` (`id`) ON DELETE RESTRICT,
  ADD CONSTRAINT `fk_sensor_config_reviewer` FOREIGN KEY (`reviewed_by`) REFERENCES `sys_user` (`id`) ON DELETE RESTRICT,
  ADD CONSTRAINT `fk_sensor_config_activator` FOREIGN KEY (`activated_by`) REFERENCES `sys_user` (`id`) ON DELETE RESTRICT,
  ADD CONSTRAINT `ck_sensor_config_separation`
    CHECK (`requested_by` IS NULL OR ((`approved_by` IS NULL OR `approved_by` <> `requested_by`)
      AND (`reviewed_by` IS NULL OR `reviewed_by` <> `requested_by`)));

ALTER TABLE `sensor_config` DROP CHECK `ck_sensor_config_status`;
ALTER TABLE `sensor_config` ADD CONSTRAINT `ck_sensor_config_status`
  CHECK (`status` IN ('draft', 'pending', 'approved', 'active', 'rejected', 'retired'));

ALTER TABLE `api_client`
  ADD COLUMN `rotated_at` DATETIME(3) DEFAULT NULL COMMENT '最近一次凭据轮换时间，UTC' AFTER `expires_at`,
  ADD COLUMN `revoked_by` BIGINT UNSIGNED DEFAULT NULL COMMENT '吊销用户' AFTER `rotated_at`,
  ADD COLUMN `revoked_at` DATETIME(3) DEFAULT NULL COMMENT '吊销时间，UTC' AFTER `revoked_by`,
  ADD COLUMN `revoke_reason` VARCHAR(1000) DEFAULT NULL COMMENT '吊销理由' AFTER `revoked_at`,
  ADD KEY `idx_api_client_revoker` (`revoked_by`),
  ADD CONSTRAINT `fk_api_client_revoker` FOREIGN KEY (`revoked_by`) REFERENCES `sys_user` (`id`) ON DELETE RESTRICT;

INSERT INTO `sys_permission` (`permission_key`, `resource`, `action`, `description`) VALUES
  ('sensor.config.approve', 'sensor.config', 'approve', '批准或驳回他人起草的传感器配置版本');

INSERT INTO `sys_role_permission` (`role_id`, `permission_id`)
SELECT r.`id`, p.`id`
FROM `sys_role` r
JOIN `sys_permission` p ON p.`permission_key` = 'sensor.config.approve' AND r.`role_key` = 'platform_admin';
