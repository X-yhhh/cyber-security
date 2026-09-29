-- V13：路线 B 阶段 5（M4 告警生成与事件关联）。只向前追加，V1 已有列与约束不变。
--   1. detection_policy：分级映射、关联时间窗、风险评分参数的版本化配置；每类至多一个 active 版本
--      （生成列 + 唯一键保证）。告警/事件写入所用版本，历史语义不随参数修改而变。
--   2. detection_alert：追加模型版本、契约版本与哈希、规则引用、分级策略版本和评分依据快照；
--      alert_type 限定为 model / rule；模型告警必须能追溯到推理请求、模型版本与分级策略。
--   3. security_event：追加关联键、关联策略版本与风险评分依据。关联键为资产维度（v4 不入库对端地址，
--      见路线 B §21）。
--   4. detection_rule：追加申请人，规则启用须由不同用户批准（申请人与批准人分离）。
-- 权限：detection.rule.read / detection.rule.manage / detection.rule.approve。

CREATE TABLE `detection_policy` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  `policy_type` VARCHAR(48) NOT NULL COMMENT '策略类型：severity_mapping / correlation / risk_score',
  `version` VARCHAR(64) NOT NULL COMMENT '策略版本',
  `config_json` JSON NOT NULL COMMENT '结构化参数，不允许脚本',
  `status` VARCHAR(24) NOT NULL COMMENT '策略状态',
  `active_policy_type` VARCHAR(48) GENERATED ALWAYS AS (CASE WHEN `status` = 'active' THEN `policy_type` END) STORED
    COMMENT '仅 active 行非空，用于保证每类至多一个 active 版本',
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '创建时间，UTC',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_detection_policy_version` (`policy_type`, `version`),
  UNIQUE KEY `uk_detection_policy_active` (`active_policy_type`),
  CONSTRAINT `ck_detection_policy_type` CHECK (`policy_type` IN ('severity_mapping', 'correlation', 'risk_score')),
  CONSTRAINT `ck_detection_policy_status` CHECK (`status` IN ('active', 'retired'))
) ENGINE=InnoDB COMMENT='告警分级、事件关联与风险评分的版本化策略';

INSERT INTO `detection_policy` (`policy_type`, `version`, `config_json`, `status`) VALUES
  ('severity_mapping', 'severity-v1',
   JSON_OBJECT('model', JSON_ARRAY(
       JSON_OBJECT('minScore', 0.9, 'severity', 'critical'),
       JSON_OBJECT('minScore', 0.7, 'severity', 'high'),
       JSON_OBJECT('minScore', 0.0, 'severity', 'medium'))),
   'active'),
  ('correlation', 'correlation-v1', JSON_OBJECT('windowSeconds', 900, 'dimensions', JSON_ARRAY('asset')), 'active'),
  ('risk_score', 'risk-v1',
   JSON_OBJECT('severityWeight', JSON_OBJECT('low', 0.25, 'medium', 0.5, 'high', 0.75, 'critical', 1.0),
               'criticalityWeight', JSON_OBJECT('low', 0.5, 'medium', 0.75, 'high', 0.9, 'critical', 1.0),
               'repeatStep', 0.05, 'repeatCap', 0.2),
   'active');

ALTER TABLE `detection_alert`
  ADD COLUMN `model_version_id` BIGINT UNSIGNED DEFAULT NULL COMMENT '模型告警所用模型版本' AFTER `inference_request_id`,
  ADD COLUMN `contract_version` VARCHAR(64) DEFAULT NULL COMMENT '输入特征契约版本' AFTER `model_version_id`,
  ADD COLUMN `contract_sha256` CHAR(64) DEFAULT NULL COMMENT '契约文件 SHA-256' AFTER `contract_version`,
  ADD COLUMN `detection_rule_id` BIGINT UNSIGNED DEFAULT NULL COMMENT '规则告警所用规则版本' AFTER `contract_sha256`,
  ADD COLUMN `severity_policy_version` VARCHAR(64) DEFAULT NULL COMMENT '分级映射策略版本快照' AFTER `severity`,
  ADD COLUMN `basis_json` JSON DEFAULT NULL COMMENT '评分依据快照（分数、阈值、命中条件），不含记录原文' AFTER `threshold_version`,
  ADD KEY `idx_detection_alert_model` (`model_version_id`),
  ADD KEY `idx_detection_alert_rule` (`detection_rule_id`),
  ADD CONSTRAINT `fk_detection_alert_model` FOREIGN KEY (`model_version_id`) REFERENCES `model_version` (`id`) ON DELETE RESTRICT,
  ADD CONSTRAINT `fk_detection_alert_rule` FOREIGN KEY (`detection_rule_id`) REFERENCES `detection_rule` (`id`) ON DELETE RESTRICT,
  ADD CONSTRAINT `ck_detection_alert_type` CHECK (`alert_type` IN ('model', 'rule')),
  ADD CONSTRAINT `ck_detection_alert_severity` CHECK (`severity` IN ('low', 'medium', 'high', 'critical')),
  ADD CONSTRAINT `ck_detection_alert_contract_sha256`
    CHECK (`contract_sha256` IS NULL OR REGEXP_LIKE(`contract_sha256`, '^[0-9a-f]{64}$', 'c')),
  ADD CONSTRAINT `ck_detection_alert_model_trace`
    CHECK (`alert_type` <> 'model' OR (`inference_request_id` IS NOT NULL AND `model_version_id` IS NOT NULL
        AND `severity_policy_version` IS NOT NULL AND `detection_rule_id` IS NULL)),
  ADD CONSTRAINT `ck_detection_alert_rule_trace`
    CHECK (`alert_type` <> 'rule' OR `model_version_id` IS NULL);

ALTER TABLE `security_event`
  ADD COLUMN `correlation_key` VARCHAR(160) DEFAULT NULL COMMENT '自动关联维度键，例如 asset:<id>' AFTER `risk_rule_version`,
  ADD COLUMN `correlation_policy_version` VARCHAR(64) DEFAULT NULL COMMENT '关联策略版本快照' AFTER `correlation_key`,
  ADD COLUMN `risk_basis_json` JSON DEFAULT NULL COMMENT '风险评分计算依据' AFTER `correlation_policy_version`,
  ADD KEY `idx_security_event_correlation` (`correlation_key`, `status`, `last_seen_at`);

ALTER TABLE `detection_rule`
  ADD COLUMN `requested_by` BIGINT UNSIGNED DEFAULT NULL COMMENT '规则登记用户' AFTER `status`,
  ADD KEY `idx_detection_rule_requester` (`requested_by`),
  ADD CONSTRAINT `fk_detection_rule_requester` FOREIGN KEY (`requested_by`) REFERENCES `sys_user` (`id`) ON DELETE RESTRICT,
  ADD CONSTRAINT `ck_detection_rule_severity` CHECK (`severity` IN ('low', 'medium', 'high', 'critical')),
  ADD CONSTRAINT `ck_detection_rule_separation`
    CHECK (`approved_by` IS NULL OR `requested_by` IS NULL OR `approved_by` <> `requested_by`);

INSERT INTO `sys_permission` (`permission_key`, `resource`, `action`, `description`) VALUES
  ('detection.rule.read', 'detection.rule', 'read', '查看确定性检测规则'),
  ('detection.rule.manage', 'detection.rule', 'manage', '登记待批准的确定性检测规则'),
  ('detection.rule.approve', 'detection.rule', 'approve', '批准或拒绝他人登记的检测规则');

INSERT INTO `sys_role_permission` (`role_id`, `permission_id`)
SELECT r.`id`, p.`id`
FROM `sys_role` r
JOIN `sys_permission` p ON
  (p.`permission_key` = 'detection.rule.read' AND r.`role_key` IN ('platform_admin', 'security_analyst', 'response_approver'))
  OR (p.`permission_key` = 'detection.rule.manage' AND r.`role_key` = 'security_analyst')
  OR (p.`permission_key` = 'detection.rule.approve' AND r.`role_key` = 'response_approver');
