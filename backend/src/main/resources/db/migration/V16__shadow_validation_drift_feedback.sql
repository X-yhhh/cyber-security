-- V16：路线 B 阶段 7 影子验证（§13）与 M8 漂移/反馈的最小落地。只向前追加，V1 列与既有 CHECK 语义保留。
--   1. drift_metric_window：追加样本量、基线来源与窗口唯一键。每小时窗口按 (数据源, 模型版本, 窗口开始) 唯一，
--      计算任务重跑时插入被唯一键拦下，不重复写窗口；窗口只写入已结束的整点小时，写入后不再修改。
--      feature_stats_json 保存每字段的分箱计数（而非只存 PSI），影子报告可把多个窗口的计数相加后重算整段 PSI。
--      drift_status 取值：ok / warning（任一字段 PSI > 0.2）/ alert（任一字段 PSI > 0.3）/
--      insufficient_samples（样本不足以计算 PSI，仍保存计数）/ baseline_unavailable（manifest 无基线统计）。
--   2. feedback_sample：追加告警级人工标注的复核字段。一条告警至多一条“有效”标注（pending 或 training_approved），
--      被第二人驳回（rejected）的标注保留为证据，允许重新标注。训练用途须第二人（≠标注人）批准，
--      training_eligible 只能在 training_approved 时为真，由 CHECK 兜底。
--   3. 权限：alert.feedback.label（security_analyst）标注告警真/误报；feedback.review（security_analyst、
--      response_approver）复核他人标注；shadow.report.read（platform_admin、security_analyst、model_operator）
--      按数据源范围读取影子验证汇总。标注人与复核人不同由服务层与 CHECK 共同保证。

ALTER TABLE `drift_metric_window`
  ADD COLUMN `sample_count` BIGINT UNSIGNED NOT NULL DEFAULT 0 COMMENT '窗口内推理成功（模型范围内）的记录数' AFTER `window_end`,
  ADD COLUMN `request_count` BIGINT UNSIGNED NOT NULL DEFAULT 0 COMMENT '窗口内全部推理请求数（含拒绝与范围外）' AFTER `sample_count`,
  ADD COLUMN `baseline_ref` VARCHAR(160) DEFAULT NULL COMMENT '基线来源：模型版本与 manifest 基线方法；无基线时为空' AFTER `request_count`,
  ADD COLUMN `computed_by` VARCHAR(64) NOT NULL DEFAULT 'drift-job-v1' COMMENT '计算任务与算法版本' AFTER `drift_status`,
  ADD UNIQUE KEY `uk_drift_metric_window` (`data_source_id`, `model_version_id`, `window_start`),
  ADD CONSTRAINT `fk_drift_metric_model` FOREIGN KEY (`model_version_id`) REFERENCES `model_version` (`id`) ON DELETE RESTRICT,
  ADD CONSTRAINT `ck_drift_metric_status`
    CHECK (`drift_status` IN ('ok', 'warning', 'alert', 'insufficient_samples', 'baseline_unavailable'));

ALTER TABLE `feedback_sample`
  ADD COLUMN `note` VARCHAR(1000) DEFAULT NULL COMMENT '标注说明，不含地址等原始网络数据' AFTER `evidence_ref`,
  ADD COLUMN `review_status` VARCHAR(24) NOT NULL DEFAULT 'pending' COMMENT '第二人复核状态' AFTER `training_eligible`,
  ADD COLUMN `second_reviewed_by` BIGINT UNSIGNED DEFAULT NULL COMMENT '复核用户（须不同于标注用户）' AFTER `review_status`,
  ADD COLUMN `second_reviewed_at` DATETIME(3) DEFAULT NULL COMMENT '复核时间，UTC' AFTER `second_reviewed_by`,
  ADD COLUMN `second_review_reason` VARCHAR(1000) DEFAULT NULL COMMENT '复核理由' AFTER `second_reviewed_at`,
  ADD COLUMN `active_alert_id` BIGINT UNSIGNED
    GENERATED ALWAYS AS (CASE WHEN `review_status` IN ('pending', 'training_approved') THEN `alert_id` ELSE NULL END) STORED
    COMMENT '仅有效标注非空，保证一条告警至多一条有效标注' AFTER `second_review_reason`,
  ADD UNIQUE KEY `uk_feedback_active_alert` (`active_alert_id`),
  ADD KEY `idx_feedback_second_reviewer` (`second_reviewed_by`),
  ADD CONSTRAINT `fk_feedback_alert` FOREIGN KEY (`alert_id`) REFERENCES `detection_alert` (`id`) ON DELETE RESTRICT,
  ADD CONSTRAINT `fk_feedback_second_reviewer` FOREIGN KEY (`second_reviewed_by`) REFERENCES `sys_user` (`id`) ON DELETE RESTRICT,
  ADD CONSTRAINT `ck_feedback_review_status`
    CHECK (`review_status` IN ('pending', 'training_approved', 'rejected')),
  ADD CONSTRAINT `ck_feedback_review_separation`
    CHECK (`second_reviewed_by` IS NULL OR `second_reviewed_by` <> `reviewed_by`),
  ADD CONSTRAINT `ck_feedback_review_complete`
    CHECK ((`review_status` = 'pending' AND `second_reviewed_by` IS NULL AND `second_reviewed_at` IS NULL)
        OR (`review_status` <> 'pending' AND `second_reviewed_by` IS NOT NULL AND `second_reviewed_at` IS NOT NULL)),
  ADD CONSTRAINT `ck_feedback_training_eligible`
    CHECK (`training_eligible` = FALSE OR `review_status` = 'training_approved');

INSERT INTO `sys_permission` (`permission_key`, `resource`, `action`, `description`) VALUES
  ('alert.feedback.label', 'alert.feedback', 'label', '对范围内告警标注真/误报'),
  ('feedback.review', 'feedback', 'review', '复核他人的告警标注，决定是否可用于离线训练'),
  ('shadow.report.read', 'shadow.report', 'read', '按数据源范围读取影子验证汇总');

INSERT INTO `sys_role_permission` (`role_id`, `permission_id`)
SELECT r.`id`, p.`id`
FROM `sys_role` r
JOIN `sys_permission` p ON
  (p.`permission_key` = 'alert.feedback.label' AND r.`role_key` = 'security_analyst')
  OR (p.`permission_key` = 'feedback.review' AND r.`role_key` IN ('security_analyst', 'response_approver'))
  OR (p.`permission_key` = 'shadow.report.read' AND r.`role_key` IN ('platform_admin', 'security_analyst', 'model_operator'));
