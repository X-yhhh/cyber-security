-- V12：路线 B 阶段 4（M3 本机 ONNX 推理）。V1 的 inference_request 只有状态与错误码，
-- 无法保存推理结果快照，也无法记录“无激活模型”或“不在模型评估范围”的请求，本迁移只向前补齐：
--   1. model_version_id 改为可空：无激活模型时仍需写一行 rejected 证据，不能伪造模型引用；
--      外键保持不变，非空值仍必须引用已登记模型。contract_version 同理改为可空：
--      未声明特征契约的批次（connector 通用事件）记 rejected，不写占位契约名。
--   2. 追加结果快照列：分数、二分类标签、决策阈值与阈值策略版本、契约文件哈希、细分拒绝原因。
--   3. 状态增加 not_in_model_scope（路线 B §4.3 D2：视角/地址族不在模型评估范围，不推理、不算拒绝）。
--      超时沿用 V1 已有的 timed_out 状态，错误码 INFERENCE_TIMEOUT，不另起 timeout 状态。
--   4. 状态与结果列之间的不变量由 CHECK 约束兜底：只有 succeeded 行带分数和阈值快照；
--      rejected/failed/timed_out 必须带稳定错误码，服务层不能写出“失败但有分数”的行。
-- 权限：新增 inference.request.read（按数据源范围只读推理台账）与 model.replay.run
-- （对 source_type='replay' 的数据源执行不落库的 dry-run）。

ALTER TABLE `inference_request`
  MODIFY COLUMN `model_version_id` BIGINT UNSIGNED DEFAULT NULL COMMENT '实际使用模型版本；无激活模型时为空',
  MODIFY COLUMN `contract_version` VARCHAR(64) DEFAULT NULL COMMENT '输入特征契约版本；批次未声明契约时为空',
  ADD COLUMN `contract_sha256` CHAR(64) DEFAULT NULL COMMENT '推理时注册表中的契约文件 SHA-256' AFTER `contract_version`,
  ADD COLUMN `attack_probability` DOUBLE DEFAULT NULL COMMENT 'ONNX 输出的攻击概率（float32 原值）' AFTER `status`,
  ADD COLUMN `binary_label` VARCHAR(16) DEFAULT NULL COMMENT '模型图输出标签：Normal 或 Attack' AFTER `attack_probability`,
  ADD COLUMN `decision_threshold` DOUBLE DEFAULT NULL COMMENT '推理时 manifest 决策阈值快照' AFTER `binary_label`,
  ADD COLUMN `threshold_policy_version` VARCHAR(96) DEFAULT NULL COMMENT '阈值策略版本快照' AFTER `decision_threshold`,
  ADD COLUMN `reject_reason` VARCHAR(64) DEFAULT NULL COMMENT '机器可读的细分原因，不含记录内容' AFTER `error_code`,
  ADD KEY `idx_inference_request_time` (`requested_at`, `id`);

ALTER TABLE `inference_request` DROP CHECK `ck_inference_request_status`;

ALTER TABLE `inference_request`
  ADD CONSTRAINT `ck_inference_request_status_v12`
    CHECK (`status` IN ('queued', 'running', 'succeeded', 'rejected', 'failed', 'timed_out', 'not_in_model_scope')),
  ADD CONSTRAINT `ck_inference_request_contract_sha256`
    CHECK (`contract_sha256` IS NULL OR REGEXP_LIKE(`contract_sha256`, '^[0-9a-f]{64}$', 'c')),
  ADD CONSTRAINT `ck_inference_request_label`
    CHECK (`binary_label` IS NULL OR `binary_label` IN ('Normal', 'Attack')),
  ADD CONSTRAINT `ck_inference_request_probability`
    CHECK (`attack_probability` IS NULL OR (`attack_probability` >= 0 AND `attack_probability` <= 1)),
  ADD CONSTRAINT `ck_inference_request_threshold`
    CHECK (`decision_threshold` IS NULL OR (`decision_threshold` >= 0 AND `decision_threshold` <= 1)),
  ADD CONSTRAINT `ck_inference_request_result_snapshot`
    CHECK ((`status` = 'succeeded'
            AND `model_version_id` IS NOT NULL AND `contract_version` IS NOT NULL AND `contract_sha256` IS NOT NULL
            AND `attack_probability` IS NOT NULL AND `binary_label` IS NOT NULL
            AND `decision_threshold` IS NOT NULL AND `threshold_policy_version` IS NOT NULL AND `error_code` IS NULL)
        OR (`status` <> 'succeeded'
            AND `attack_probability` IS NULL AND `binary_label` IS NULL)),
  ADD CONSTRAINT `ck_inference_request_error_code`
    CHECK (`status` NOT IN ('rejected', 'failed', 'timed_out') OR `error_code` IS NOT NULL);

INSERT INTO `sys_permission` (`permission_key`, `resource`, `action`, `description`) VALUES
  ('inference.request.read', 'inference.request', 'read', '按数据源范围查询推理请求台账'),
  ('model.replay.run', 'model.replay', 'run', '对回放数据源执行不落库的推理 dry-run');

INSERT INTO `sys_role_permission` (`role_id`, `permission_id`)
SELECT r.`id`, p.`id`
FROM `sys_role` r
JOIN `sys_permission` p ON
  (p.`permission_key` = 'inference.request.read'
    AND r.`role_key` IN ('platform_admin', 'asset_source_admin', 'security_analyst', 'model_operator'))
  OR (p.`permission_key` = 'model.replay.run' AND r.`role_key` = 'model_operator');
