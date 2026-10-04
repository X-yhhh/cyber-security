ALTER TABLE `model_release_record`
  ADD COLUMN `review_status` VARCHAR(24) NOT NULL DEFAULT 'not_requested'
    COMMENT '发布申请审查状态；与模型候选状态分离' AFTER `release_status`,
  ADD COLUMN `request_reason` VARCHAR(1000) DEFAULT NULL COMMENT '发布申请理由' AFTER `requested_by`,
  ADD COLUMN `decision_reason` VARCHAR(1000) DEFAULT NULL COMMENT '发布审批理由' AFTER `approved_by`,
  ADD COLUMN `reviewed_at` DATETIME(3) DEFAULT NULL COMMENT '发布申请审查时间，UTC' AFTER `decision_reason`,
  ADD CONSTRAINT `ck_model_release_review_status`
    CHECK (`review_status` IN ('not_requested', 'pending', 'approved', 'rejected')),
  ADD CONSTRAINT `ck_model_release_review_separation`
    CHECK (`approved_by` IS NULL OR `requested_by` IS NULL OR `approved_by` <> `requested_by`);

ALTER TABLE `approval_task`
  ADD COLUMN `idempotency_key` VARCHAR(160) DEFAULT NULL COMMENT '申请用户范围内的幂等键' AFTER `requested_by`,
  ADD COLUMN `request_digest` CHAR(64) DEFAULT NULL COMMENT '规范化申请快照的 SHA-256' AFTER `idempotency_key`,
  ADD UNIQUE KEY `uk_approval_task_requester_idempotency` (`requested_by`, `idempotency_key`),
  ADD CONSTRAINT `ck_approval_task_idempotency_pair`
    CHECK ((`idempotency_key` IS NULL AND `request_digest` IS NULL)
        OR (`idempotency_key` IS NOT NULL AND `request_digest` REGEXP '^[0-9a-f]{64}$'));
