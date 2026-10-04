-- 为 24 小时质量汇总、审计时间线和审批台账补齐排序/过滤索引；不改变业务事实或权限语义。
CREATE INDEX `idx_ingest_record_created_quality_asset`
    ON `ingest_record` (`created_at`, `quality_status`, `asset_id`);

CREATE INDEX `idx_audit_log_occurred_id`
    ON `audit_log` (`occurred_at`, `id`);

CREATE INDEX `idx_approval_task_status_created`
    ON `approval_task` (`status`, `created_at`, `id`);
