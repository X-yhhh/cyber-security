-- 扩展人工角色授权、机器身份权限范围、资源审计关联及 JDBC 服务端会话。
-- 不创建用户、不授予现存用户角色，也不修改任何密码哈希。

ALTER TABLE `sys_role`
  ADD COLUMN `is_builtin` BOOLEAN NOT NULL DEFAULT FALSE COMMENT '是否为代码维护的内置权限模板' AFTER `status`;

ALTER TABLE `sys_user_role`
  ADD CONSTRAINT `ck_sys_user_role_scope_type`
    CHECK (`scope_type` IN ('global', 'asset', 'data_source', 'model_registry')),
  ADD CONSTRAINT `ck_sys_user_role_global_scope`
    CHECK ((`scope_type` = 'global' AND `scope_id` = '*') OR (`scope_type` <> 'global' AND `scope_id` <> '*'));

CREATE TABLE `sys_permission` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  `permission_key` VARCHAR(96) NOT NULL COMMENT '稳定权限标识',
  `resource` VARCHAR(64) NOT NULL COMMENT '资源类型',
  `action` VARCHAR(64) NOT NULL COMMENT '单一操作',
  `description` VARCHAR(255) NOT NULL COMMENT '权限用途说明',
  `status` VARCHAR(24) NOT NULL DEFAULT 'active' COMMENT '权限状态',
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '创建时间，UTC',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_sys_permission_key` (`permission_key`),
  KEY `idx_sys_permission_status` (`status`),
  CONSTRAINT `ck_sys_permission_status` CHECK (`status` IN ('active', 'disabled'))
) ENGINE=InnoDB COMMENT='功能权限目录';

CREATE TABLE `sys_role_permission` (
  `role_id` BIGINT UNSIGNED NOT NULL COMMENT '角色主键',
  `permission_id` BIGINT UNSIGNED NOT NULL COMMENT '权限主键',
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '授权时间，UTC',
  PRIMARY KEY (`role_id`, `permission_id`),
  KEY `idx_sys_role_permission_permission` (`permission_id`),
  CONSTRAINT `fk_sys_role_permission_role` FOREIGN KEY (`role_id`) REFERENCES `sys_role` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `fk_sys_role_permission_permission` FOREIGN KEY (`permission_id`) REFERENCES `sys_permission` (`id`) ON DELETE RESTRICT
) ENGINE=InnoDB COMMENT='内置角色权限模板关系';

CREATE TABLE `api_client_permission` (
  `client_id` BIGINT UNSIGNED NOT NULL COMMENT '机器主体主键',
  `permission_id` BIGINT UNSIGNED NOT NULL COMMENT '权限主键',
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '授权时间，UTC',
  PRIMARY KEY (`client_id`, `permission_id`),
  KEY `idx_api_client_permission_permission` (`permission_id`),
  CONSTRAINT `fk_api_client_permission_client` FOREIGN KEY (`client_id`) REFERENCES `api_client` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `fk_api_client_permission_permission` FOREIGN KEY (`permission_id`) REFERENCES `sys_permission` (`id`) ON DELETE RESTRICT
) ENGINE=InnoDB COMMENT='机器身份显式权限';

CREATE TABLE `api_client_scope` (
  `client_id` BIGINT UNSIGNED NOT NULL COMMENT '机器主体主键',
  `scope_type` VARCHAR(32) NOT NULL COMMENT '授权范围类型',
  `scope_id` VARCHAR(128) NOT NULL COMMENT '授权范围标识',
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '授权时间，UTC',
  PRIMARY KEY (`client_id`, `scope_type`, `scope_id`),
  KEY `idx_api_client_scope_resource` (`scope_type`, `scope_id`, `client_id`),
  CONSTRAINT `fk_api_client_scope_client` FOREIGN KEY (`client_id`) REFERENCES `api_client` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `ck_api_client_scope_type` CHECK (`scope_type` IN ('global', 'asset', 'data_source', 'model_registry')),
  CONSTRAINT `ck_api_client_global_scope` CHECK ((`scope_type` = 'global' AND `scope_id` = '*') OR (`scope_type` <> 'global' AND `scope_id` <> '*'))
) ENGINE=InnoDB COMMENT='机器身份显式资源范围';

CREATE TABLE `audit_resource_scope` (
  `audit_id` BIGINT UNSIGNED NOT NULL COMMENT '审计记录主键',
  `scope_type` VARCHAR(32) NOT NULL COMMENT '关联资源范围类型',
  `scope_id` VARCHAR(128) NOT NULL COMMENT '关联资源范围标识',
  PRIMARY KEY (`audit_id`, `scope_type`, `scope_id`),
  KEY `idx_audit_resource_scope_lookup` (`scope_type`, `scope_id`, `audit_id`),
  CONSTRAINT `fk_audit_resource_scope_audit` FOREIGN KEY (`audit_id`) REFERENCES `audit_log` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `ck_audit_resource_scope_type` CHECK (`scope_type` IN ('asset', 'data_source', 'model_registry'))
) ENGINE=InnoDB COMMENT='审计记录关联的受控资源范围';

ALTER TABLE `asset_authorization`
  ADD COLUMN `requested_by` BIGINT UNSIGNED DEFAULT NULL COMMENT '申请用户；历史记录保持空值' AFTER `status`,
  ADD KEY `idx_asset_authorization_requester` (`requested_by`),
  ADD CONSTRAINT `fk_asset_authorization_requester` FOREIGN KEY (`requested_by`) REFERENCES `sys_user` (`id`) ON DELETE RESTRICT;

ALTER TABLE `model_release_record`
  ADD COLUMN `requested_by` BIGINT UNSIGNED DEFAULT NULL COMMENT '发布申请用户；历史记录保持空值' AFTER `release_status`,
  ADD KEY `idx_model_release_requester` (`requested_by`),
  ADD CONSTRAINT `fk_model_release_requester` FOREIGN KEY (`requested_by`) REFERENCES `sys_user` (`id`) ON DELETE RESTRICT;

CREATE TABLE `SPRING_SESSION` (
  `PRIMARY_ID` CHAR(36) NOT NULL,
  `SESSION_ID` CHAR(36) NOT NULL,
  `CREATION_TIME` BIGINT NOT NULL,
  `LAST_ACCESS_TIME` BIGINT NOT NULL,
  `MAX_INACTIVE_INTERVAL` INT NOT NULL,
  `EXPIRY_TIME` BIGINT NOT NULL,
  `PRINCIPAL_NAME` VARCHAR(100) DEFAULT NULL,
  CONSTRAINT `SPRING_SESSION_PK` PRIMARY KEY (`PRIMARY_ID`),
  UNIQUE KEY `SPRING_SESSION_IX1` (`SESSION_ID`),
  KEY `SPRING_SESSION_IX2` (`EXPIRY_TIME`),
  KEY `SPRING_SESSION_IX3` (`PRINCIPAL_NAME`)
) ENGINE=InnoDB ROW_FORMAT=DYNAMIC COMMENT='Spring Security 服务端会话';

CREATE TABLE `SPRING_SESSION_ATTRIBUTES` (
  `SESSION_PRIMARY_ID` CHAR(36) NOT NULL,
  `ATTRIBUTE_NAME` VARCHAR(200) NOT NULL,
  `ATTRIBUTE_BYTES` BLOB NOT NULL,
  CONSTRAINT `SPRING_SESSION_ATTRIBUTES_PK` PRIMARY KEY (`SESSION_PRIMARY_ID`, `ATTRIBUTE_NAME`),
  CONSTRAINT `SPRING_SESSION_ATTRIBUTES_FK` FOREIGN KEY (`SESSION_PRIMARY_ID`) REFERENCES `SPRING_SESSION` (`PRIMARY_ID`) ON DELETE CASCADE
) ENGINE=InnoDB ROW_FORMAT=DYNAMIC COMMENT='Spring Security 服务端会话属性';

INSERT INTO `sys_role` (`role_key`, `name`, `description`, `status`, `is_builtin`) VALUES
  ('platform_admin', '平台管理员', '管理身份与系统配置；告警、事件和审计全局只读', 'active', 1),
  ('asset_source_admin', '资产与数据源管理员', '维护显式范围内的资产、数据源及传感器', 'active', 1),
  ('security_analyst', '安全分析员', '调查范围内告警事件并提交处置申请', 'active', 1),
  ('response_approver', '响应审批员', '审批他人提交且仍在授权范围内的响应申请', 'active', 1),
  ('model_operator', '模型操作员', '登记候选模型元数据并请求验证/发布', 'active', 1),
  ('model_releaser', '模型发布审批员', '审批他人发起且验证门禁通过的模型发布', 'active', 1),
  ('auditor', '审计只读用户', '按显式资源范围查询审计及复盘记录', 'active', 1);

INSERT INTO `sys_permission` (`permission_key`, `resource`, `action`, `description`) VALUES
  ('iam.user.read', 'iam.user', 'read', '查询用户'),
  ('iam.user.manage', 'iam.user', 'manage', '创建及维护用户'),
  ('iam.role.read', 'iam.role', 'read', '查询预定义角色'),
  ('iam.role.assign', 'iam.role', 'assign', '分配预定义角色及资源范围'),
  ('system.config.read', 'system.config', 'read', '查询非秘密系统配置'),
  ('system.config.update', 'system.config', 'update', '维护非秘密系统配置'),
  ('asset.read', 'asset', 'read', '查询授权范围内资产'),
  ('asset.manage', 'asset', 'manage', '维护授权范围内资产'),
  ('asset.authorization.read', 'asset.authorization', 'read', '查询资产授权记录'),
  ('asset.authorization.manage', 'asset.authorization', 'manage', '提交资产授权申请'),
  ('asset.authorization.approve', 'asset.authorization', 'approve', '独立审批资产授权申请'),
  ('source.read', 'source', 'read', '查询数据源'),
  ('source.manage', 'source', 'manage', '维护数据源与映射'),
  ('ingest.batch.read', 'ingest.batch', 'read', '查询接入批次'),
  ('ingest.batch.submit', 'ingest.batch', 'submit', '提交接入批次'),
  ('sensor.read', 'sensor', 'read', '查询传感器状态与配置'),
  ('sensor.manage', 'sensor', 'manage', '登记及维护传感器'),
  ('alert.read', 'alert', 'read', '查询告警'),
  ('event.read', 'event', 'read', '查询事件及证据'),
  ('event.investigate', 'event', 'investigate', '按状态机研判事件'),
  ('response.policy.read', 'response.policy', 'read', '查询响应策略'),
  ('response.policy.manage', 'response.policy', 'manage', '维护响应策略；首期无角色授予'),
  ('action.request', 'action', 'request', '提交待策略校验的响应申请'),
  ('approval.read', 'approval', 'read', '查询待处理审批快照'),
  ('approval.decide', 'approval', 'decide', '批准或拒绝待审批任务'),
  ('model.candidate.manage', 'model.candidate', 'manage', '登记候选模型元数据'),
  ('model.validation.read', 'model.validation', 'read', '读取模型验证结果'),
  ('model.release.request', 'model.release', 'request', '提交模型发布申请'),
  ('model.release.approve', 'model.release', 'approve', '审批他人发起的模型发布'),
  ('audit.read', 'audit', 'read', '按授权范围查询审计'),
  ('ops.status.read', 'ops.status', 'read', '查询运行状态摘要');

INSERT INTO `sys_role_permission` (`role_id`, `permission_id`)
SELECT r.`id`, p.`id`
FROM `sys_role` r
JOIN `sys_permission` p ON
  (r.`role_key` = 'platform_admin' AND p.`permission_key` IN (
    'iam.user.read', 'iam.user.manage', 'iam.role.read', 'iam.role.assign',
    'system.config.read', 'system.config.update', 'asset.read', 'asset.manage',
    'asset.authorization.read', 'asset.authorization.manage', 'asset.authorization.approve',
    'source.read', 'source.manage', 'ingest.batch.read', 'ingest.batch.submit',
    'sensor.read', 'sensor.manage', 'alert.read', 'event.read', 'audit.read', 'ops.status.read'))
  OR (r.`role_key` = 'asset_source_admin' AND p.`permission_key` IN (
    'asset.read', 'asset.manage', 'asset.authorization.read', 'asset.authorization.manage',
    'source.read', 'source.manage', 'ingest.batch.read', 'ingest.batch.submit', 'sensor.read', 'sensor.manage'))
  OR (r.`role_key` = 'security_analyst' AND p.`permission_key` IN (
    'asset.read', 'source.read', 'ingest.batch.read', 'sensor.read', 'alert.read',
    'event.read', 'event.investigate', 'action.request'))
  OR (r.`role_key` = 'response_approver' AND p.`permission_key` IN (
    'asset.read', 'alert.read', 'response.policy.read', 'approval.read', 'approval.decide'))
  OR (r.`role_key` = 'model_operator' AND p.`permission_key` IN (
    'model.candidate.manage', 'model.validation.read', 'model.release.request'))
  OR (r.`role_key` = 'model_releaser' AND p.`permission_key` IN (
    'model.validation.read', 'model.release.approve'))
  OR (r.`role_key` = 'auditor' AND p.`permission_key` IN ('alert.read', 'event.read', 'audit.read'));
