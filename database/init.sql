-- 网络威胁研判平台 MySQL 8 首次建库脚本。
-- 本脚本只创建数据库/表，并初始化一个本机测试账户；不填充业务模拟数据。
SET NAMES utf8mb4;
SET time_zone = '+00:00';

CREATE DATABASE IF NOT EXISTS `cyber_security`
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_0900_ai_ci;

USE `cyber_security`;

CREATE TABLE IF NOT EXISTS `sys_user` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  `user_key` VARCHAR(64) NOT NULL COMMENT '稳定用户标识',
  `username` VARCHAR(64) NOT NULL COMMENT '登录用户名',
  `display_name` VARCHAR(128) NOT NULL COMMENT '显示名称',
  `status` VARCHAR(24) NOT NULL COMMENT '用户状态',
  `password_hash` VARCHAR(100) DEFAULT NULL COMMENT 'BCrypt 密码哈希；不得保存明文密码',
  `identity_subject` VARCHAR(255) DEFAULT NULL COMMENT '外部身份源主体标识',
  `last_login_at` DATETIME(3) DEFAULT NULL COMMENT '最近登录时间，UTC',
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '创建时间，UTC',
  `updated_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3) COMMENT '更新时间，UTC',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_sys_user_user_key` (`user_key`),
  UNIQUE KEY `uk_sys_user_username` (`username`),
  KEY `idx_sys_user_status` (`status`),
  CONSTRAINT `ck_sys_user_status` CHECK (`status` IN ('active', 'disabled', 'locked'))
) ENGINE=InnoDB COMMENT='平台用户主体';

CREATE TABLE IF NOT EXISTS `sys_role` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  `role_key` VARCHAR(64) NOT NULL COMMENT '稳定角色标识',
  `name` VARCHAR(128) NOT NULL COMMENT '角色名称',
  `description` VARCHAR(500) DEFAULT NULL COMMENT '角色说明',
  `status` VARCHAR(24) NOT NULL COMMENT '角色状态',
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '创建时间，UTC',
  `updated_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3) COMMENT '更新时间，UTC',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_sys_role_role_key` (`role_key`),
  KEY `idx_sys_role_status` (`status`),
  CONSTRAINT `ck_sys_role_status` CHECK (`status` IN ('active', 'disabled'))
) ENGINE=InnoDB COMMENT='平台角色定义';

CREATE TABLE IF NOT EXISTS `sys_user_role` (
  `user_id` BIGINT UNSIGNED NOT NULL COMMENT '用户主键',
  `role_id` BIGINT UNSIGNED NOT NULL COMMENT '角色主键',
  `scope_type` VARCHAR(32) NOT NULL DEFAULT 'global' COMMENT '授权范围类型',
  `scope_id` VARCHAR(128) NOT NULL DEFAULT '*' COMMENT '授权范围标识；全局范围使用 *',
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '授权时间，UTC',
  PRIMARY KEY (`user_id`, `role_id`, `scope_type`, `scope_id`),
  KEY `idx_sys_user_role_role` (`role_id`),
  CONSTRAINT `fk_sys_user_role_user` FOREIGN KEY (`user_id`) REFERENCES `sys_user` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `fk_sys_user_role_role` FOREIGN KEY (`role_id`) REFERENCES `sys_role` (`id`) ON DELETE RESTRICT
) ENGINE=InnoDB COMMENT='用户角色及资源范围';

CREATE TABLE IF NOT EXISTS `api_client` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  `client_key` VARCHAR(96) NOT NULL COMMENT '连接器身份标识',
  `secret_ref` VARCHAR(255) NOT NULL COMMENT '密钥系统引用，不存储密钥明文',
  `scope_json` JSON NOT NULL COMMENT '允许访问的数据源/资源范围',
  `status` VARCHAR(24) NOT NULL COMMENT '客户端状态',
  `expires_at` DATETIME(3) DEFAULT NULL COMMENT '凭据失效时间，UTC',
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '创建时间，UTC',
  `updated_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3) COMMENT '更新时间，UTC',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_api_client_client_key` (`client_key`),
  KEY `idx_api_client_status_expires` (`status`, `expires_at`),
  CONSTRAINT `ck_api_client_status` CHECK (`status` IN ('active', 'disabled', 'revoked'))
) ENGINE=InnoDB COMMENT='连接器及服务身份';

CREATE TABLE IF NOT EXISTS `asset` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  `asset_key` VARCHAR(128) NOT NULL COMMENT '稳定资产标识',
  `asset_type` VARCHAR(48) NOT NULL COMMENT '资产类型',
  `environment` VARCHAR(32) NOT NULL COMMENT '环境，如 lab 或 authorized',
  `criticality` VARCHAR(24) NOT NULL COMMENT '资产关键性',
  `owner` VARCHAR(128) DEFAULT NULL COMMENT '资产责任人/团队',
  `status` VARCHAR(24) NOT NULL COMMENT '资产状态',
  `labels_json` JSON NOT NULL COMMENT '资产标签',
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '创建时间，UTC',
  `updated_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3) COMMENT '更新时间，UTC',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_asset_asset_key` (`asset_key`),
  KEY `idx_asset_environment_status` (`environment`, `status`),
  KEY `idx_asset_criticality` (`criticality`),
  CONSTRAINT `ck_asset_status` CHECK (`status` IN ('active', 'disabled', 'retired'))
) ENGINE=InnoDB COMMENT='登记资产';

CREATE TABLE IF NOT EXISTS `asset_authorization` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  `asset_id` BIGINT UNSIGNED NOT NULL COMMENT '授权资产',
  `authorization_ref` VARCHAR(255) NOT NULL COMMENT '授权证明的受控引用',
  `scope_json` JSON NOT NULL COMMENT '授权范围快照',
  `valid_from` DATETIME(3) NOT NULL COMMENT '授权开始时间，UTC',
  `valid_until` DATETIME(3) NOT NULL COMMENT '授权到期时间，UTC',
  `status` VARCHAR(24) NOT NULL COMMENT '授权状态',
  `approved_by` BIGINT UNSIGNED DEFAULT NULL COMMENT '批准用户',
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '创建时间，UTC',
  `updated_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3) COMMENT '更新时间，UTC',
  PRIMARY KEY (`id`),
  KEY `idx_asset_authorization_asset_validity` (`asset_id`, `status`, `valid_from`, `valid_until`),
  KEY `idx_asset_authorization_approver` (`approved_by`),
  CONSTRAINT `fk_asset_authorization_asset` FOREIGN KEY (`asset_id`) REFERENCES `asset` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `fk_asset_authorization_approver` FOREIGN KEY (`approved_by`) REFERENCES `sys_user` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `ck_asset_authorization_status` CHECK (`status` IN ('pending', 'active', 'expired', 'revoked')),
  CONSTRAINT `ck_asset_authorization_period` CHECK (`valid_until` > `valid_from`)
) ENGINE=InnoDB COMMENT='资产授权及有效期';

CREATE TABLE IF NOT EXISTS `data_source` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  `source_key` VARCHAR(128) NOT NULL COMMENT '稳定来源标识',
  `source_type` VARCHAR(48) NOT NULL COMMENT '数据来源类型',
  `environment` VARCHAR(32) NOT NULL COMMENT '来源环境',
  `schema_version` VARCHAR(64) NOT NULL COMMENT '来源模式版本',
  `scope_json` JSON NOT NULL COMMENT '来源授权/资源范围',
  `status` VARCHAR(24) NOT NULL COMMENT '来源状态',
  `last_success_at` DATETIME(3) DEFAULT NULL COMMENT '最近成功接入时间，UTC',
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '创建时间，UTC',
  `updated_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3) COMMENT '更新时间，UTC',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_data_source_source_key` (`source_key`),
  KEY `idx_data_source_type_status` (`source_type`, `status`),
  CONSTRAINT `ck_data_source_status` CHECK (`status` IN ('active', 'disabled', 'retired'))
) ENGINE=InnoDB COMMENT='数据来源登记';

CREATE TABLE IF NOT EXISTS `source_mapping` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  `data_source_id` BIGINT UNSIGNED NOT NULL COMMENT '数据来源',
  `mapping_version` VARCHAR(64) NOT NULL COMMENT '映射版本',
  `source_schema_json` JSON NOT NULL COMMENT '来源字段模式快照',
  `mapping_json` JSON NOT NULL COMMENT '字段映射及单位转换定义',
  `status` VARCHAR(24) NOT NULL COMMENT '映射状态',
  `approved_by` BIGINT UNSIGNED DEFAULT NULL COMMENT '批准用户',
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '创建时间，UTC',
  `updated_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3) COMMENT '更新时间，UTC',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_source_mapping_version` (`data_source_id`, `mapping_version`),
  KEY `idx_source_mapping_status` (`data_source_id`, `status`),
  KEY `idx_source_mapping_approver` (`approved_by`),
  CONSTRAINT `fk_source_mapping_source` FOREIGN KEY (`data_source_id`) REFERENCES `data_source` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `fk_source_mapping_approver` FOREIGN KEY (`approved_by`) REFERENCES `sys_user` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `ck_source_mapping_status` CHECK (`status` IN ('draft', 'pending', 'approved', 'disabled'))
) ENGINE=InnoDB COMMENT='版本化来源字段映射';

CREATE TABLE IF NOT EXISTS `ingest_batch` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  `batch_key` VARCHAR(128) NOT NULL COMMENT '批次标识',
  `data_source_id` BIGINT UNSIGNED NOT NULL COMMENT '数据来源',
  `idempotency_key` VARCHAR(160) NOT NULL COMMENT '来源范围内幂等键',
  `status` VARCHAR(32) NOT NULL COMMENT '批次状态',
  `total_count` BIGINT UNSIGNED NOT NULL DEFAULT 0 COMMENT '记录总数',
  `accepted_count` BIGINT UNSIGNED NOT NULL DEFAULT 0 COMMENT '接受数',
  `rejected_count` BIGINT UNSIGNED NOT NULL DEFAULT 0 COMMENT '拒绝数',
  `started_at` DATETIME(3) DEFAULT NULL COMMENT '开始时间，UTC',
  `finished_at` DATETIME(3) DEFAULT NULL COMMENT '结束时间，UTC',
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '创建时间，UTC',
  `updated_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3) COMMENT '更新时间，UTC',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_ingest_batch_key` (`batch_key`),
  UNIQUE KEY `uk_ingest_batch_source_idempotency` (`data_source_id`, `idempotency_key`),
  KEY `idx_ingest_batch_status_created` (`status`, `created_at`),
  CONSTRAINT `fk_ingest_batch_source` FOREIGN KEY (`data_source_id`) REFERENCES `data_source` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `ck_ingest_batch_status` CHECK (`status` IN ('received', 'validating', 'processing', 'completed', 'completed_with_errors', 'rejected'))
) ENGINE=InnoDB COMMENT='接入/导入批次';

CREATE TABLE IF NOT EXISTS `ingest_record` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  `batch_id` BIGINT UNSIGNED NOT NULL COMMENT '所属接入批次',
  `source_record_key` VARCHAR(160) NOT NULL COMMENT '来源记录标识',
  `event_type` VARCHAR(64) NOT NULL COMMENT '规范事件类型',
  `event_time` DATETIME(3) NOT NULL COMMENT '事件发生时间，UTC',
  `asset_id` BIGINT UNSIGNED DEFAULT NULL COMMENT '关联资产',
  `normalized_payload` JSON DEFAULT NULL COMMENT '经裁剪的规范事件字段',
  `payload_ref` VARCHAR(512) DEFAULT NULL COMMENT '受控载荷对象引用',
  `quality_status` VARCHAR(32) NOT NULL COMMENT '质量门禁结果',
  `quality_issues_json` JSON DEFAULT NULL COMMENT '质量问题详情',
  `mapping_version` VARCHAR(64) NOT NULL COMMENT '使用的来源映射版本',
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '创建时间，UTC',
  `updated_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3) COMMENT '更新时间，UTC',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_ingest_record_source_key` (`batch_id`, `source_record_key`),
  KEY `idx_ingest_record_source_time` (`event_time`, `batch_id`),
  KEY `idx_ingest_record_batch_quality` (`batch_id`, `quality_status`),
  KEY `idx_ingest_record_asset_time` (`asset_id`, `event_time`),
  CONSTRAINT `fk_ingest_record_batch` FOREIGN KEY (`batch_id`) REFERENCES `ingest_batch` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `fk_ingest_record_asset` FOREIGN KEY (`asset_id`) REFERENCES `asset` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `ck_ingest_record_quality` CHECK (`quality_status` IN ('accepted', 'manual_review', 'rejected'))
) ENGINE=InnoDB COMMENT='规范化接入记录索引';

CREATE TABLE IF NOT EXISTS `sensor_agent` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  `agent_key` VARCHAR(128) NOT NULL COMMENT '传感器身份标识',
  `asset_id` BIGINT UNSIGNED NOT NULL COMMENT '绑定资产',
  `platform` VARCHAR(32) NOT NULL COMMENT '操作系统平台',
  `agent_version` VARCHAR(64) NOT NULL COMMENT '传感器版本',
  `capabilities_json` JSON NOT NULL COMMENT '经验证的能力清单',
  `credential_ref` VARCHAR(255) NOT NULL COMMENT '设备凭据安全引用',
  `status` VARCHAR(24) NOT NULL COMMENT '传感器状态',
  `registered_at` DATETIME(3) NOT NULL COMMENT '注册时间，UTC',
  `last_heartbeat_at` DATETIME(3) DEFAULT NULL COMMENT '最近心跳时间，UTC',
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '创建时间，UTC',
  `updated_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3) COMMENT '更新时间，UTC',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_sensor_agent_key` (`agent_key`),
  KEY `idx_sensor_agent_asset_status` (`asset_id`, `status`),
  KEY `idx_sensor_agent_heartbeat` (`last_heartbeat_at`),
  CONSTRAINT `fk_sensor_agent_asset` FOREIGN KEY (`asset_id`) REFERENCES `asset` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `ck_sensor_agent_status` CHECK (`status` IN ('pending', 'active', 'offline', 'revoked'))
) ENGINE=InnoDB COMMENT='主机传感器身份';

CREATE TABLE IF NOT EXISTS `sensor_config` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  `sensor_id` BIGINT UNSIGNED NOT NULL COMMENT '传感器',
  `config_version` VARCHAR(64) NOT NULL COMMENT '配置版本',
  `interface_scope_json` JSON NOT NULL COMMENT '允许采集的接口范围',
  `filter_policy_json` JSON NOT NULL COMMENT '受控过滤策略',
  `flow_window_seconds` INT UNSIGNED NOT NULL COMMENT '流/时间窗秒数',
  `feature_contract_version` VARCHAR(64) NOT NULL COMMENT '特征契约版本',
  `sampling_policy_json` JSON NOT NULL COMMENT '采样及留存策略',
  `status` VARCHAR(24) NOT NULL COMMENT '配置状态',
  `approved_by` BIGINT UNSIGNED DEFAULT NULL COMMENT '批准用户',
  `activated_at` DATETIME(3) DEFAULT NULL COMMENT '激活时间，UTC',
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '创建时间，UTC',
  `updated_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3) COMMENT '更新时间，UTC',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_sensor_config_version` (`sensor_id`, `config_version`),
  KEY `idx_sensor_config_status` (`sensor_id`, `status`),
  KEY `idx_sensor_config_approver` (`approved_by`),
  CONSTRAINT `fk_sensor_config_sensor` FOREIGN KEY (`sensor_id`) REFERENCES `sensor_agent` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `fk_sensor_config_approver` FOREIGN KEY (`approved_by`) REFERENCES `sys_user` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `ck_sensor_config_status` CHECK (`status` IN ('draft', 'pending', 'approved', 'active', 'retired')),
  CONSTRAINT `ck_sensor_config_flow_window` CHECK (`flow_window_seconds` > 0)
) ENGINE=InnoDB COMMENT='版本化传感器配置';

CREATE TABLE IF NOT EXISTS `sensor_health_window` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  `sensor_id` BIGINT UNSIGNED NOT NULL COMMENT '传感器',
  `window_start` DATETIME(3) NOT NULL COMMENT '窗口开始时间，UTC',
  `window_end` DATETIME(3) NOT NULL COMMENT '窗口结束时间，UTC',
  `flows_seen` BIGINT UNSIGNED NOT NULL DEFAULT 0 COMMENT '观察到的流数',
  `flows_emitted` BIGINT UNSIGNED NOT NULL DEFAULT 0 COMMENT '输出流数',
  `flows_dropped` BIGINT UNSIGNED NOT NULL DEFAULT 0 COMMENT '丢弃流数',
  `queue_depth_max` BIGINT UNSIGNED NOT NULL DEFAULT 0 COMMENT '最大队列深度',
  `cpu_percent` DECIMAL(6,3) DEFAULT NULL COMMENT 'CPU 使用率百分比',
  `memory_bytes` BIGINT UNSIGNED DEFAULT NULL COMMENT '内存用量字节数',
  `errors_json` JSON DEFAULT NULL COMMENT '窗口内错误摘要',
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '写入时间，UTC',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_sensor_health_window` (`sensor_id`, `window_start`, `window_end`),
  KEY `idx_sensor_health_start` (`sensor_id`, `window_start`),
  CONSTRAINT `fk_sensor_health_sensor` FOREIGN KEY (`sensor_id`) REFERENCES `sensor_agent` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `ck_sensor_health_window` CHECK (`window_end` > `window_start`),
  CONSTRAINT `ck_sensor_health_cpu` CHECK (`cpu_percent` IS NULL OR (`cpu_percent` >= 0 AND `cpu_percent` <= 100))
) ENGINE=InnoDB COMMENT='传感器采集健康窗口';

CREATE TABLE IF NOT EXISTS `detection_rule` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  `rule_key` VARCHAR(128) NOT NULL COMMENT '稳定规则标识',
  `version` VARCHAR(64) NOT NULL COMMENT '规则版本',
  `scope_json` JSON NOT NULL COMMENT '规则适用范围',
  `condition_json` JSON NOT NULL COMMENT '受限结构化条件，不允许任意脚本',
  `severity` VARCHAR(24) NOT NULL COMMENT '规则严重性',
  `action_hint` VARCHAR(48) DEFAULT NULL COMMENT '仅作建议的动作类型',
  `status` VARCHAR(24) NOT NULL COMMENT '规则状态',
  `approved_by` BIGINT UNSIGNED DEFAULT NULL COMMENT '批准用户',
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '创建时间，UTC',
  `updated_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3) COMMENT '更新时间，UTC',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_detection_rule_version` (`rule_key`, `version`),
  KEY `idx_detection_rule_status_severity` (`status`, `severity`),
  KEY `idx_detection_rule_approver` (`approved_by`),
  CONSTRAINT `fk_detection_rule_approver` FOREIGN KEY (`approved_by`) REFERENCES `sys_user` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `ck_detection_rule_status` CHECK (`status` IN ('draft', 'pending', 'approved', 'active', 'retired'))
) ENGINE=InnoDB COMMENT='确定性流量检测规则';

CREATE TABLE IF NOT EXISTS `drift_metric_window` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  `data_source_id` BIGINT UNSIGNED NOT NULL COMMENT '数据来源',
  `model_version_id` BIGINT UNSIGNED DEFAULT NULL COMMENT '关联模型版本',
  `window_start` DATETIME(3) NOT NULL COMMENT '窗口开始时间，UTC',
  `window_end` DATETIME(3) NOT NULL COMMENT '窗口结束时间，UTC',
  `feature_stats_json` JSON NOT NULL COMMENT '特征分布统计',
  `score_stats_json` JSON DEFAULT NULL COMMENT '模型分数统计',
  `label_feedback_stats_json` JSON DEFAULT NULL COMMENT '人工反馈统计',
  `quality_reject_rate` DECIMAL(9,6) DEFAULT NULL COMMENT '质量拒绝率',
  `drift_status` VARCHAR(24) NOT NULL COMMENT '漂移观察状态',
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '创建时间，UTC',
  PRIMARY KEY (`id`),
  KEY `idx_drift_metric_source_model_window` (`data_source_id`, `model_version_id`, `window_start`),
  CONSTRAINT `fk_drift_metric_source` FOREIGN KEY (`data_source_id`) REFERENCES `data_source` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `ck_drift_metric_window` CHECK (`window_end` > `window_start`),
  CONSTRAINT `ck_drift_metric_reject_rate` CHECK (`quality_reject_rate` IS NULL OR (`quality_reject_rate` >= 0 AND `quality_reject_rate` <= 1))
) ENGINE=InnoDB COMMENT='模型输入漂移统计窗口';

CREATE TABLE IF NOT EXISTS `feedback_sample` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  `source_record_id` BIGINT UNSIGNED NOT NULL COMMENT '来源规范记录',
  `alert_id` BIGINT UNSIGNED DEFAULT NULL COMMENT '关联检测告警',
  `label` VARCHAR(96) NOT NULL COMMENT '人工确认标签',
  `label_source` VARCHAR(48) NOT NULL COMMENT '标签来源/依据类型',
  `evidence_ref` VARCHAR(512) NOT NULL COMMENT '审核证据引用',
  `reviewed_by` BIGINT UNSIGNED NOT NULL COMMENT '审核用户',
  `reviewed_at` DATETIME(3) NOT NULL COMMENT '审核时间，UTC',
  `dataset_version` VARCHAR(96) DEFAULT NULL COMMENT '候选数据集版本',
  `training_eligible` BOOLEAN NOT NULL DEFAULT FALSE COMMENT '是否经过训练用途审批',
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '创建时间，UTC',
  `updated_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3) COMMENT '更新时间，UTC',
  PRIMARY KEY (`id`),
  KEY `idx_feedback_training_reviewed` (`training_eligible`, `reviewed_at`),
  KEY `idx_feedback_source_record` (`source_record_id`),
  KEY `idx_feedback_alert` (`alert_id`),
  KEY `idx_feedback_reviewer` (`reviewed_by`),
  CONSTRAINT `fk_feedback_source_record` FOREIGN KEY (`source_record_id`) REFERENCES `ingest_record` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `fk_feedback_reviewer` FOREIGN KEY (`reviewed_by`) REFERENCES `sys_user` (`id`) ON DELETE RESTRICT
) ENGINE=InnoDB COMMENT='人工审核反馈样本';

CREATE TABLE IF NOT EXISTS `model_version` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  `model_key` VARCHAR(128) NOT NULL COMMENT '稳定模型标识',
  `version` VARCHAR(64) NOT NULL COMMENT '不可变模型版本',
  `task_type` VARCHAR(48) NOT NULL COMMENT '模型任务类型',
  `manifest_version` VARCHAR(64) NOT NULL COMMENT 'manifest 模式版本',
  `manifest_json` JSON NOT NULL COMMENT '模型契约、评估和运行时快照',
  `artifact_ref` VARCHAR(512) NOT NULL COMMENT '受控模型制品引用',
  `artifact_sha256` CHAR(64) NOT NULL COMMENT '制品 SHA-256',
  `feature_contract_version` VARCHAR(64) NOT NULL COMMENT '特征契约版本',
  `approval_status` VARCHAR(24) NOT NULL COMMENT '候选及审批状态',
  `approved_by` BIGINT UNSIGNED DEFAULT NULL COMMENT '批准用户',
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '登记时间，UTC',
  `updated_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3) COMMENT '更新时间，UTC',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_model_version_key_version` (`model_key`, `version`),
  KEY `idx_model_version_approval` (`approval_status`, `created_at`),
  KEY `idx_model_version_approver` (`approved_by`),
  CONSTRAINT `fk_model_version_approver` FOREIGN KEY (`approved_by`) REFERENCES `sys_user` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `ck_model_version_approval` CHECK (`approval_status` IN ('candidate', 'validated', 'approved', 'rejected', 'retired')),
  CONSTRAINT `ck_model_version_sha256` CHECK (`artifact_sha256` REGEXP '^[0-9A-Fa-f]{64}$')
) ENGINE=InnoDB COMMENT='不可变模型版本登记';

CREATE TABLE IF NOT EXISTS `model_deployment` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  `environment` VARCHAR(32) NOT NULL COMMENT '部署环境',
  `mode` VARCHAR(24) NOT NULL COMMENT '推理模式：local 或 remote',
  `model_version_id` BIGINT UNSIGNED NOT NULL COMMENT '批准的模型版本',
  `runtime_type` VARCHAR(64) NOT NULL COMMENT '推理运行时类型',
  `endpoint_ref` VARCHAR(512) DEFAULT NULL COMMENT '受控端点引用，不存放凭据',
  `status` VARCHAR(24) NOT NULL COMMENT '部署状态',
  `activated_at` DATETIME(3) DEFAULT NULL COMMENT '激活时间，UTC',
  `activated_by` BIGINT UNSIGNED DEFAULT NULL COMMENT '激活用户',
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '创建时间，UTC',
  `updated_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3) COMMENT '更新时间，UTC',
  PRIMARY KEY (`id`),
  KEY `idx_model_deployment_environment_status` (`environment`, `status`),
  KEY `idx_model_deployment_version` (`model_version_id`),
  KEY `idx_model_deployment_activator` (`activated_by`),
  CONSTRAINT `fk_model_deployment_version` FOREIGN KEY (`model_version_id`) REFERENCES `model_version` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `fk_model_deployment_activator` FOREIGN KEY (`activated_by`) REFERENCES `sys_user` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `ck_model_deployment_mode` CHECK (`mode` IN ('local', 'remote')),
  CONSTRAINT `ck_model_deployment_status` CHECK (`status` IN ('inactive', 'pending', 'active', 'failed', 'retired'))
) ENGINE=InnoDB COMMENT='模型推理部署路由';

CREATE TABLE IF NOT EXISTS `inference_request` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  `request_key` VARCHAR(160) NOT NULL COMMENT '推理请求幂等标识',
  `ingest_record_id` BIGINT UNSIGNED NOT NULL COMMENT '输入规范记录',
  `model_version_id` BIGINT UNSIGNED NOT NULL COMMENT '实际使用模型版本',
  `contract_version` VARCHAR(64) NOT NULL COMMENT '输入特征契约版本',
  `deployment_mode` VARCHAR(24) NOT NULL COMMENT '本机或远端推理模式',
  `status` VARCHAR(24) NOT NULL COMMENT '推理状态',
  `latency_ms` BIGINT UNSIGNED DEFAULT NULL COMMENT '推理耗时毫秒',
  `error_code` VARCHAR(96) DEFAULT NULL COMMENT '脱敏稳定错误码',
  `requested_at` DATETIME(3) NOT NULL COMMENT '请求时间，UTC',
  `completed_at` DATETIME(3) DEFAULT NULL COMMENT '完成时间，UTC',
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '创建时间，UTC',
  `updated_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3) COMMENT '更新时间，UTC',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_inference_request_key` (`request_key`),
  KEY `idx_inference_request_status_time` (`status`, `requested_at`),
  KEY `idx_inference_request_record` (`ingest_record_id`),
  KEY `idx_inference_request_model` (`model_version_id`),
  CONSTRAINT `fk_inference_request_record` FOREIGN KEY (`ingest_record_id`) REFERENCES `ingest_record` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `fk_inference_request_model` FOREIGN KEY (`model_version_id`) REFERENCES `model_version` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `ck_inference_request_status` CHECK (`status` IN ('queued', 'running', 'succeeded', 'rejected', 'failed', 'timed_out')),
  CONSTRAINT `ck_inference_request_mode` CHECK (`deployment_mode` IN ('local', 'remote'))
) ENGINE=InnoDB COMMENT='模型推理请求及结果状态';

CREATE TABLE IF NOT EXISTS `detection_alert` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  `alert_key` VARCHAR(160) NOT NULL COMMENT '稳定告警标识',
  `ingest_record_id` BIGINT UNSIGNED NOT NULL COMMENT '输入规范记录',
  `inference_request_id` BIGINT UNSIGNED DEFAULT NULL COMMENT '关联推理请求',
  `alert_type` VARCHAR(48) NOT NULL COMMENT '模型/规则告警类型',
  `severity` VARCHAR(24) NOT NULL COMMENT '告警严重性',
  `score` DECIMAL(12,8) DEFAULT NULL COMMENT '模型/规则分数，不默认解释为概率',
  `threshold_version` VARCHAR(64) DEFAULT NULL COMMENT '使用的阈值策略版本',
  `status` VARCHAR(24) NOT NULL COMMENT '告警处理状态',
  `detected_at` DATETIME(3) NOT NULL COMMENT '检测时间，UTC',
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '创建时间，UTC',
  `updated_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3) COMMENT '更新时间，UTC',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_detection_alert_key` (`alert_key`),
  KEY `idx_detection_alert_status_severity_time` (`status`, `severity`, `detected_at`),
  KEY `idx_detection_alert_record` (`ingest_record_id`),
  KEY `idx_detection_alert_inference` (`inference_request_id`),
  CONSTRAINT `fk_detection_alert_record` FOREIGN KEY (`ingest_record_id`) REFERENCES `ingest_record` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `fk_detection_alert_inference` FOREIGN KEY (`inference_request_id`) REFERENCES `inference_request` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `ck_detection_alert_status` CHECK (`status` IN ('new', 'acknowledged', 'resolved', 'false_positive', 'closed'))
) ENGINE=InnoDB COMMENT='检测告警';

CREATE TABLE IF NOT EXISTS `model_training_job` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  `job_key` VARCHAR(160) NOT NULL COMMENT '训练任务标识',
  `dataset_version` VARCHAR(96) NOT NULL COMMENT '经批准的数据集版本',
  `sample_manifest_ref` VARCHAR(512) NOT NULL COMMENT '样本清单引用',
  `algorithm_set_json` JSON NOT NULL COMMENT '候选算法与参数范围',
  `train_host_ref` VARCHAR(255) NOT NULL COMMENT 'Windows 离线训练环境引用',
  `status` VARCHAR(24) NOT NULL COMMENT '离线候选训练状态',
  `requested_by` BIGINT UNSIGNED NOT NULL COMMENT '任务发起用户',
  `approved_by` BIGINT UNSIGNED DEFAULT NULL COMMENT '批准用户',
  `started_at` DATETIME(3) DEFAULT NULL COMMENT '开始时间，UTC',
  `finished_at` DATETIME(3) DEFAULT NULL COMMENT '结束时间，UTC',
  `result_manifest_ref` VARCHAR(512) DEFAULT NULL COMMENT '候选结果 manifest 引用',
  `failure_reason` VARCHAR(1000) DEFAULT NULL COMMENT '脱敏失败原因',
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '创建时间，UTC',
  `updated_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3) COMMENT '更新时间，UTC',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_model_training_job_key` (`job_key`),
  KEY `idx_model_training_job_status_created` (`status`, `created_at`),
  KEY `idx_model_training_job_requester` (`requested_by`),
  KEY `idx_model_training_job_approver` (`approved_by`),
  CONSTRAINT `fk_model_training_job_requester` FOREIGN KEY (`requested_by`) REFERENCES `sys_user` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `fk_model_training_job_approver` FOREIGN KEY (`approved_by`) REFERENCES `sys_user` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `ck_model_training_job_status` CHECK (`status` IN ('requested', 'approved', 'queued', 'running', 'completed', 'failed', 'cancelled'))
) ENGINE=InnoDB COMMENT='Windows 离线模型候选训练任务';

CREATE TABLE IF NOT EXISTS `model_release_record` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  `model_version_id` BIGINT UNSIGNED NOT NULL COMMENT '候选/发布模型版本',
  `release_status` VARCHAR(24) NOT NULL COMMENT '候选、验证、影子、发布或回退状态',
  `validation_report_ref` VARCHAR(512) DEFAULT NULL COMMENT '验证报告引用',
  `shadow_started_at` DATETIME(3) DEFAULT NULL COMMENT '影子验证开始时间，UTC',
  `approved_by` BIGINT UNSIGNED DEFAULT NULL COMMENT '批准用户',
  `released_by` BIGINT UNSIGNED DEFAULT NULL COMMENT '发布操作者',
  `released_at` DATETIME(3) DEFAULT NULL COMMENT '发布时间，UTC',
  `rollback_from_version_id` BIGINT UNSIGNED DEFAULT NULL COMMENT '回退前版本',
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '创建时间，UTC',
  `updated_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3) COMMENT '更新时间，UTC',
  PRIMARY KEY (`id`),
  KEY `idx_model_release_status_created` (`release_status`, `created_at`),
  KEY `idx_model_release_model` (`model_version_id`),
  KEY `idx_model_release_approver` (`approved_by`),
  CONSTRAINT `fk_model_release_model` FOREIGN KEY (`model_version_id`) REFERENCES `model_version` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `fk_model_release_rollback_model` FOREIGN KEY (`rollback_from_version_id`) REFERENCES `model_version` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `fk_model_release_approver` FOREIGN KEY (`approved_by`) REFERENCES `sys_user` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `fk_model_release_actor` FOREIGN KEY (`released_by`) REFERENCES `sys_user` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `ck_model_release_status` CHECK (`release_status` IN ('candidate', 'validated', 'shadow', 'approved', 'active', 'retired', 'rolled_back'))
) ENGINE=InnoDB COMMENT='模型验证、影子、发布和回退记录';

CREATE TABLE IF NOT EXISTS `security_event` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  `event_key` VARCHAR(160) NOT NULL COMMENT '稳定事件标识',
  `title` VARCHAR(255) NOT NULL COMMENT '事件标题',
  `category` VARCHAR(64) NOT NULL COMMENT '事件类别',
  `severity` VARCHAR(24) NOT NULL COMMENT '事件严重性',
  `status` VARCHAR(32) NOT NULL COMMENT '事件领域状态',
  `risk_score` DECIMAL(12,8) DEFAULT NULL COMMENT '可解释风险评分',
  `risk_rule_version` VARCHAR(64) DEFAULT NULL COMMENT '风险规则版本',
  `first_seen_at` DATETIME(3) NOT NULL COMMENT '首次发现时间，UTC',
  `last_seen_at` DATETIME(3) NOT NULL COMMENT '最近发现时间，UTC',
  `assignee_id` BIGINT UNSIGNED DEFAULT NULL COMMENT '处理责任用户',
  `closed_at` DATETIME(3) DEFAULT NULL COMMENT '关闭时间，UTC',
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '创建时间，UTC',
  `updated_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3) COMMENT '更新时间，UTC',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_security_event_key` (`event_key`),
  KEY `idx_security_event_status_severity_last_seen` (`status`, `severity`, `last_seen_at`),
  KEY `idx_security_event_assignee` (`assignee_id`, `status`),
  CONSTRAINT `fk_security_event_assignee` FOREIGN KEY (`assignee_id`) REFERENCES `sys_user` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `ck_security_event_status` CHECK (`status` IN ('open', 'investigating', 'contained', 'resolved', 'false_positive', 'closed'))
) ENGINE=InnoDB COMMENT='安全事件/案件';

CREATE TABLE IF NOT EXISTS `event_alert_link` (
  `event_id` BIGINT UNSIGNED NOT NULL COMMENT '安全事件',
  `alert_id` BIGINT UNSIGNED NOT NULL COMMENT '检测告警',
  `link_type` VARCHAR(32) NOT NULL COMMENT '关联类型',
  `linked_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '关联时间，UTC',
  `linked_by` BIGINT UNSIGNED DEFAULT NULL COMMENT '关联操作者',
  PRIMARY KEY (`event_id`, `alert_id`),
  KEY `idx_event_alert_alert` (`alert_id`),
  KEY `idx_event_alert_actor` (`linked_by`),
  CONSTRAINT `fk_event_alert_event` FOREIGN KEY (`event_id`) REFERENCES `security_event` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `fk_event_alert_alert` FOREIGN KEY (`alert_id`) REFERENCES `detection_alert` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `fk_event_alert_actor` FOREIGN KEY (`linked_by`) REFERENCES `sys_user` (`id`) ON DELETE RESTRICT
) ENGINE=InnoDB COMMENT='事件与检测告警关联';

CREATE TABLE IF NOT EXISTS `event_asset_link` (
  `event_id` BIGINT UNSIGNED NOT NULL COMMENT '安全事件',
  `asset_id` BIGINT UNSIGNED NOT NULL COMMENT '影响资产',
  `relation_type` VARCHAR(32) NOT NULL COMMENT '资产与事件关系',
  `evidence_count` BIGINT UNSIGNED NOT NULL DEFAULT 0 COMMENT '关联证据数量',
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '关联时间，UTC',
  PRIMARY KEY (`event_id`, `asset_id`, `relation_type`),
  KEY `idx_event_asset_asset` (`asset_id`),
  CONSTRAINT `fk_event_asset_event` FOREIGN KEY (`event_id`) REFERENCES `security_event` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `fk_event_asset_asset` FOREIGN KEY (`asset_id`) REFERENCES `asset` (`id`) ON DELETE RESTRICT
) ENGINE=InnoDB COMMENT='事件影响资产关联';

CREATE TABLE IF NOT EXISTS `event_timeline` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  `event_id` BIGINT UNSIGNED NOT NULL COMMENT '安全事件',
  `occurred_at` DATETIME(3) NOT NULL COMMENT '证据/状态发生时间，UTC',
  `entry_type` VARCHAR(48) NOT NULL COMMENT '时间线条目类型',
  `actor_type` VARCHAR(32) NOT NULL COMMENT '操作者主体类型',
  `actor_id` VARCHAR(128) DEFAULT NULL COMMENT '主体标识；允许系统或适配器身份',
  `summary` VARCHAR(1000) NOT NULL COMMENT '脱敏摘要',
  `evidence_ref` VARCHAR(512) DEFAULT NULL COMMENT '受控证据引用',
  `details_json` JSON DEFAULT NULL COMMENT '结构化详情快照',
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '写入时间，UTC',
  PRIMARY KEY (`id`),
  KEY `idx_event_timeline_event_time` (`event_id`, `occurred_at`),
  CONSTRAINT `fk_event_timeline_event` FOREIGN KEY (`event_id`) REFERENCES `security_event` (`id`) ON DELETE RESTRICT
) ENGINE=InnoDB COMMENT='追加式事件证据与研判时间线';

CREATE TABLE IF NOT EXISTS `response_policy` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  `policy_key` VARCHAR(128) NOT NULL COMMENT '稳定策略标识',
  `version` VARCHAR(64) NOT NULL COMMENT '不可变策略版本',
  `environment` VARCHAR(32) NOT NULL COMMENT '适用环境',
  `match_json` JSON NOT NULL COMMENT '资产/告警匹配范围',
  `action_type` VARCHAR(48) NOT NULL COMMENT '适配器白名单动作',
  `action_params_json` JSON NOT NULL COMMENT '受限结构化动作参数',
  `risk_limit` DECIMAL(12,8) DEFAULT NULL COMMENT '策略风险门槛',
  `auto_execute` BOOLEAN NOT NULL DEFAULT FALSE COMMENT '是否允许策略内自动执行',
  `approval_required` BOOLEAN NOT NULL DEFAULT TRUE COMMENT '是否要求人工审批',
  `max_duration_seconds` INT UNSIGNED NOT NULL COMMENT '动作最大持续时间',
  `status` VARCHAR(24) NOT NULL COMMENT '策略状态',
  `approved_by` BIGINT UNSIGNED DEFAULT NULL COMMENT '批准用户',
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '创建时间，UTC',
  `updated_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3) COMMENT '更新时间，UTC',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_response_policy_version` (`policy_key`, `version`),
  KEY `idx_response_policy_environment_status` (`environment`, `status`),
  KEY `idx_response_policy_approver` (`approved_by`),
  CONSTRAINT `fk_response_policy_approver` FOREIGN KEY (`approved_by`) REFERENCES `sys_user` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `ck_response_policy_status` CHECK (`status` IN ('draft', 'pending', 'approved', 'active', 'retired')),
  CONSTRAINT `ck_response_policy_duration` CHECK (`max_duration_seconds` > 0),
  CONSTRAINT `ck_response_policy_approval` CHECK (`auto_execute` = FALSE OR `approval_required` = FALSE)
) ENGINE=InnoDB COMMENT='版本化受控响应策略';

CREATE TABLE IF NOT EXISTS `approval_task` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  `task_key` VARCHAR(160) NOT NULL COMMENT '审批任务标识',
  `event_id` BIGINT UNSIGNED NOT NULL COMMENT '关联安全事件',
  `policy_id` BIGINT UNSIGNED DEFAULT NULL COMMENT '命中响应策略',
  `action_request_json` JSON NOT NULL COMMENT '待审批的不可变动作快照',
  `status` VARCHAR(24) NOT NULL COMMENT '审批状态',
  `requested_by` BIGINT UNSIGNED NOT NULL COMMENT '申请用户',
  `reviewed_by` BIGINT UNSIGNED DEFAULT NULL COMMENT '审批用户',
  `reviewed_at` DATETIME(3) DEFAULT NULL COMMENT '审批时间，UTC',
  `decision_reason` VARCHAR(1000) DEFAULT NULL COMMENT '审批理由',
  `expires_at` DATETIME(3) NOT NULL COMMENT '审批请求到期时间，UTC',
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '创建时间，UTC',
  `updated_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3) COMMENT '更新时间，UTC',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_approval_task_key` (`task_key`),
  KEY `idx_approval_task_status_expires` (`status`, `expires_at`),
  KEY `idx_approval_task_event` (`event_id`),
  KEY `idx_approval_task_policy` (`policy_id`),
  KEY `idx_approval_task_requester` (`requested_by`),
  KEY `idx_approval_task_reviewer` (`reviewed_by`),
  CONSTRAINT `fk_approval_task_event` FOREIGN KEY (`event_id`) REFERENCES `security_event` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `fk_approval_task_policy` FOREIGN KEY (`policy_id`) REFERENCES `response_policy` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `fk_approval_task_requester` FOREIGN KEY (`requested_by`) REFERENCES `sys_user` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `fk_approval_task_reviewer` FOREIGN KEY (`reviewed_by`) REFERENCES `sys_user` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `ck_approval_task_status` CHECK (`status` IN ('pending', 'approved', 'rejected', 'expired', 'cancelled')),
  CONSTRAINT `ck_approval_task_separation` CHECK (`reviewed_by` IS NULL OR `reviewed_by` <> `requested_by`)
) ENGINE=InnoDB COMMENT='高影响响应动作人工审批';

CREATE TABLE IF NOT EXISTS `action_execution` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  `execution_key` VARCHAR(160) NOT NULL COMMENT '执行标识',
  `event_id` BIGINT UNSIGNED NOT NULL COMMENT '关联安全事件',
  `approval_task_id` BIGINT UNSIGNED DEFAULT NULL COMMENT '已批准任务',
  `asset_id` BIGINT UNSIGNED NOT NULL COMMENT '登记授权目标资产',
  `policy_version` VARCHAR(64) NOT NULL COMMENT '执行时策略版本快照',
  `adapter_key` VARCHAR(128) NOT NULL COMMENT '受控适配器标识',
  `action_type` VARCHAR(48) NOT NULL COMMENT '适配器允许的动作类型',
  `target_scope_json` JSON NOT NULL COMMENT '窄范围目标快照',
  `expires_at` DATETIME(3) NOT NULL COMMENT '动作到期/自动解除时间，UTC',
  `status` VARCHAR(32) NOT NULL COMMENT '执行/回滚状态',
  `idempotency_key` VARCHAR(160) NOT NULL COMMENT '全局动作幂等键',
  `request_snapshot` JSON NOT NULL COMMENT '授权、策略和动作请求快照',
  `result_json` JSON DEFAULT NULL COMMENT '脱敏适配器回执',
  `rollback_ref` VARCHAR(512) DEFAULT NULL COMMENT '适配器回滚句柄引用',
  `started_at` DATETIME(3) DEFAULT NULL COMMENT '执行开始时间，UTC',
  `finished_at` DATETIME(3) DEFAULT NULL COMMENT '执行结束时间，UTC',
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '创建时间，UTC',
  `updated_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3) COMMENT '更新时间，UTC',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_action_execution_key` (`execution_key`),
  UNIQUE KEY `uk_action_execution_idempotency` (`idempotency_key`),
  KEY `idx_action_execution_status_started` (`status`, `started_at`),
  KEY `idx_action_execution_event` (`event_id`),
  KEY `idx_action_execution_approval` (`approval_task_id`),
  KEY `idx_action_execution_asset` (`asset_id`, `status`),
  CONSTRAINT `fk_action_execution_event` FOREIGN KEY (`event_id`) REFERENCES `security_event` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `fk_action_execution_approval` FOREIGN KEY (`approval_task_id`) REFERENCES `approval_task` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `fk_action_execution_asset` FOREIGN KEY (`asset_id`) REFERENCES `asset` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `ck_action_execution_status` CHECK (`status` IN ('queued', 'running', 'succeeded', 'failed', 'timed_out', 'rollback_pending', 'rolled_back', 'rollback_failed'))
) ENGINE=InnoDB COMMENT='带幂等、TTL 和回滚记录的受控动作';

CREATE TABLE IF NOT EXISTS `audit_log` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  `occurred_at` DATETIME(3) NOT NULL COMMENT '审计事件时间，UTC',
  `actor_type` VARCHAR(32) NOT NULL COMMENT '操作者主体类型',
  `actor_id` VARCHAR(128) DEFAULT NULL COMMENT '操作者标识',
  `action` VARCHAR(128) NOT NULL COMMENT '审计动作',
  `resource_type` VARCHAR(64) NOT NULL COMMENT '资源类型',
  `resource_id` VARCHAR(160) DEFAULT NULL COMMENT '资源标识',
  `request_id` VARCHAR(128) DEFAULT NULL COMMENT '请求关联标识',
  `outcome` VARCHAR(32) NOT NULL COMMENT '操作结果',
  `reason` VARCHAR(1000) DEFAULT NULL COMMENT '脱敏理由/失败原因',
  `before_hash` CHAR(64) DEFAULT NULL COMMENT '变更前快照哈希',
  `after_hash` CHAR(64) DEFAULT NULL COMMENT '变更后快照哈希',
  `metadata_json` JSON DEFAULT NULL COMMENT '脱敏审计元数据',
  PRIMARY KEY (`id`),
  KEY `idx_audit_log_resource_time` (`resource_type`, `resource_id`, `occurred_at`),
  KEY `idx_audit_log_actor_time` (`actor_type`, `actor_id`, `occurred_at`),
  KEY `idx_audit_log_request` (`request_id`),
  KEY `idx_audit_log_time` (`occurred_at`)
) ENGINE=InnoDB COMMENT='追加式安全审计记录；业务接口不得更新或删除';

CREATE TABLE IF NOT EXISTS `replay_scenario` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  `scenario_key` VARCHAR(128) NOT NULL COMMENT '稳定场景标识',
  `name` VARCHAR(255) NOT NULL COMMENT '场景名称',
  `dataset_ref` VARCHAR(512) NOT NULL COMMENT '受控样本/数据集引用',
  `environment` VARCHAR(32) NOT NULL COMMENT '隔离回放环境',
  `safety_profile` VARCHAR(96) NOT NULL COMMENT '回放安全配置标识',
  `status` VARCHAR(24) NOT NULL COMMENT '场景状态',
  `created_by` BIGINT UNSIGNED DEFAULT NULL COMMENT '创建用户',
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '创建时间，UTC',
  `updated_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3) COMMENT '更新时间，UTC',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_replay_scenario_key` (`scenario_key`),
  KEY `idx_replay_scenario_status` (`status`),
  KEY `idx_replay_scenario_creator` (`created_by`),
  CONSTRAINT `fk_replay_scenario_creator` FOREIGN KEY (`created_by`) REFERENCES `sys_user` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `ck_replay_scenario_status` CHECK (`status` IN ('draft', 'approved', 'active', 'disabled'))
) ENGINE=InnoDB COMMENT='离线数据回放场景';

CREATE TABLE IF NOT EXISTS `replay_run` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  `run_key` VARCHAR(160) NOT NULL COMMENT '回放运行标识',
  `scenario_id` BIGINT UNSIGNED NOT NULL COMMENT '回放场景',
  `model_version_id` BIGINT UNSIGNED DEFAULT NULL COMMENT '本次对比模型版本',
  `status` VARCHAR(24) NOT NULL COMMENT '回放任务状态',
  `speed` DECIMAL(10,4) NOT NULL DEFAULT 1.0000 COMMENT '回放速度倍数',
  `progress` DECIMAL(7,4) NOT NULL DEFAULT 0.0000 COMMENT '完成百分比',
  `started_at` DATETIME(3) DEFAULT NULL COMMENT '开始时间，UTC',
  `finished_at` DATETIME(3) DEFAULT NULL COMMENT '结束时间，UTC',
  `summary_json` JSON DEFAULT NULL COMMENT '运行结果摘要',
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '创建时间，UTC',
  `updated_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3) COMMENT '更新时间，UTC',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_replay_run_key` (`run_key`),
  KEY `idx_replay_run_scenario_status` (`scenario_id`, `status`),
  KEY `idx_replay_run_model` (`model_version_id`),
  CONSTRAINT `fk_replay_run_scenario` FOREIGN KEY (`scenario_id`) REFERENCES `replay_scenario` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `fk_replay_run_model` FOREIGN KEY (`model_version_id`) REFERENCES `model_version` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `ck_replay_run_status` CHECK (`status` IN ('queued', 'running', 'paused', 'completed', 'failed', 'cancelled')),
  CONSTRAINT `ck_replay_run_progress` CHECK (`progress` >= 0 AND `progress` <= 100),
  CONSTRAINT `ck_replay_run_speed` CHECK (`speed` > 0)
) ENGINE=InnoDB COMMENT='回放运行与结果摘要';

CREATE TABLE IF NOT EXISTS `outbox_event` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  `event_key` VARCHAR(160) NOT NULL COMMENT '消息幂等标识',
  `aggregate_type` VARCHAR(64) NOT NULL COMMENT '业务聚合类型',
  `aggregate_id` VARCHAR(160) NOT NULL COMMENT '业务聚合标识',
  `topic` VARCHAR(255) NOT NULL COMMENT '消息主题',
  `payload_json` JSON NOT NULL COMMENT '最小必要业务消息',
  `status` VARCHAR(24) NOT NULL COMMENT '发布状态',
  `attempts` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '发布尝试次数',
  `next_attempt_at` DATETIME(3) DEFAULT NULL COMMENT '下次尝试时间，UTC',
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '创建时间，UTC',
  `published_at` DATETIME(3) DEFAULT NULL COMMENT '成功发布确认时间，UTC',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_outbox_event_key` (`event_key`),
  KEY `idx_outbox_event_status_next_attempt` (`status`, `next_attempt_at`, `id`),
  KEY `idx_outbox_event_aggregate` (`aggregate_type`, `aggregate_id`),
  CONSTRAINT `ck_outbox_event_status` CHECK (`status` IN ('pending', 'publishing', 'published', 'failed', 'dead_letter'))
) ENGINE=InnoDB COMMENT='事务发件箱事件';

CREATE TABLE IF NOT EXISTS `report_job` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  `job_key` VARCHAR(160) NOT NULL COMMENT '报告任务标识',
  `report_type` VARCHAR(64) NOT NULL COMMENT '报告类型',
  `filter_json` JSON NOT NULL COMMENT '报告范围和筛选条件',
  `requested_by` BIGINT UNSIGNED NOT NULL COMMENT '申请用户',
  `status` VARCHAR(24) NOT NULL COMMENT '报告生成状态',
  `artifact_ref` VARCHAR(512) DEFAULT NULL COMMENT '受控导出文件引用',
  `expires_at` DATETIME(3) DEFAULT NULL COMMENT '导出文件过期时间，UTC',
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '创建时间，UTC',
  `updated_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3) COMMENT '更新时间，UTC',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_report_job_key` (`job_key`),
  KEY `idx_report_job_status_created` (`status`, `created_at`),
  KEY `idx_report_job_requester` (`requested_by`),
  KEY `idx_report_job_expiry` (`expires_at`),
  CONSTRAINT `fk_report_job_requester` FOREIGN KEY (`requested_by`) REFERENCES `sys_user` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `ck_report_job_status` CHECK (`status` IN ('queued', 'running', 'completed', 'failed', 'expired', 'cancelled'))
) ENGINE=InnoDB COMMENT='异步脱敏报告任务';

-- 仅为空库创建本机测试登录账号；冲突时保留现有账号，不覆盖其密码。
INSERT INTO `sys_user` (
  `user_key`, `username`, `display_name`, `status`, `password_hash`
) VALUES (
  'bootstrap-admin', 'admin', '本机测试管理员', 'active',
  '$2a$12$AgsJgckbRfhmFRC7TONFQem9qDzn1W5YsI8PHfsPPr0.qKXZCPhwa'
)
ON DUPLICATE KEY UPDATE `id` = `id`;
