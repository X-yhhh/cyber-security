-- V15：M6 响应策略管理（路线 B §14.1）。只向前追加；V1 已有列、唯一键与 CHECK 语义保留。
--   策略版本不可原地修改：每次变更新建版本（draft），经提交（pending）、他人批准后成为 active；
--   同一 policy_key 至多一个 active（生成列 + 唯一键），批准新版本时旧 active 版本同事务退役。
--   状态沿用 V1 取值并追加 rejected：draft → pending → active | rejected；active/draft/pending → retired。
--   V1 的 approved 状态保留在 CHECK 中以兼容历史行，M6 服务层不写入该状态（批准即生效）。
--   V1 前已存在、缺起草人的策略 created_by 为 NULL：无法证明职责分离，服务层拒绝经接口处理。
-- 权限：response.policy.draft（security_analyst）起草/提交/撤回本人草稿；
--       response.policy.approve（response_approver）批准/拒绝他人提交的版本、退役 active 版本；
--       security_analyst 追加 response.policy.read 以查看本人草稿。response.policy.manage 仍不授予任何角色。

ALTER TABLE `response_policy`
  ADD COLUMN `created_by` BIGINT UNSIGNED DEFAULT NULL COMMENT '起草用户' AFTER `status`,
  ADD COLUMN `based_on_policy_id` BIGINT UNSIGNED DEFAULT NULL COMMENT '派生来源版本' AFTER `created_by`,
  ADD COLUMN `change_reason` VARCHAR(1000) DEFAULT NULL COMMENT '起草/变更理由' AFTER `based_on_policy_id`,
  ADD COLUMN `content_sha256` CHAR(64) DEFAULT NULL COMMENT '规范化策略内容 SHA-256，由服务端计算' AFTER `change_reason`,
  ADD COLUMN `submitted_at` DATETIME(3) DEFAULT NULL COMMENT '提交审批时间，UTC' AFTER `content_sha256`,
  ADD COLUMN `reviewed_by` BIGINT UNSIGNED DEFAULT NULL COMMENT '审批决定用户（批准或拒绝）' AFTER `approved_by`,
  ADD COLUMN `reviewed_at` DATETIME(3) DEFAULT NULL COMMENT '审批决定时间，UTC' AFTER `reviewed_by`,
  ADD COLUMN `decision_reason` VARCHAR(1000) DEFAULT NULL COMMENT '审批理由' AFTER `reviewed_at`,
  ADD COLUMN `retired_at` DATETIME(3) DEFAULT NULL COMMENT '退役时间，UTC' AFTER `decision_reason`,
  ADD COLUMN `retired_by` BIGINT UNSIGNED DEFAULT NULL COMMENT '退役操作用户；被新版本取代时为批准人' AFTER `retired_at`,
  ADD COLUMN `active_key` VARCHAR(128)
    GENERATED ALWAYS AS (CASE WHEN `status` = 'active' THEN `policy_key` ELSE NULL END) STORED
    COMMENT '仅 active 行非空，用于保证同一策略键至多一个 active 版本' AFTER `retired_by`,
  ADD UNIQUE KEY `uk_response_policy_active` (`active_key`),
  ADD KEY `idx_response_policy_creator` (`created_by`),
  ADD KEY `idx_response_policy_based_on` (`based_on_policy_id`),
  ADD KEY `idx_response_policy_retired_by` (`retired_by`),
  ADD KEY `idx_response_policy_reviewer` (`reviewed_by`),
  ADD CONSTRAINT `fk_response_policy_reviewer` FOREIGN KEY (`reviewed_by`) REFERENCES `sys_user` (`id`) ON DELETE RESTRICT,
  ADD CONSTRAINT `ck_response_policy_review_separation`
    CHECK (`reviewed_by` IS NULL OR `created_by` IS NULL OR `reviewed_by` <> `created_by`),
  ADD CONSTRAINT `ck_response_policy_content_sha256`
    CHECK (`content_sha256` IS NULL OR `content_sha256` REGEXP '^[0-9a-f]{64}$'),
  ADD CONSTRAINT `fk_response_policy_creator` FOREIGN KEY (`created_by`) REFERENCES `sys_user` (`id`) ON DELETE RESTRICT,
  ADD CONSTRAINT `fk_response_policy_based_on` FOREIGN KEY (`based_on_policy_id`) REFERENCES `response_policy` (`id`) ON DELETE RESTRICT,
  ADD CONSTRAINT `fk_response_policy_retired_by` FOREIGN KEY (`retired_by`) REFERENCES `sys_user` (`id`) ON DELETE RESTRICT,
  ADD CONSTRAINT `ck_response_policy_separation`
    CHECK (`approved_by` IS NULL OR `created_by` IS NULL OR `approved_by` <> `created_by`),
  ADD CONSTRAINT `ck_response_policy_active_approved`
    CHECK (`status` <> 'active' OR `approved_by` IS NOT NULL);

-- 状态 CHECK 替换为含 rejected 的集合；分两条语句，避免同名约束在单条 ALTER 中先删后加。
ALTER TABLE `response_policy` DROP CHECK `ck_response_policy_status`;
ALTER TABLE `response_policy` ADD CONSTRAINT `ck_response_policy_status`
  CHECK (`status` IN ('draft', 'pending', 'approved', 'active', 'rejected', 'retired'));

INSERT INTO `sys_permission` (`permission_key`, `resource`, `action`, `description`) VALUES
  ('response.policy.draft', 'response.policy', 'draft', '起草、提交或撤回本人的响应策略版本'),
  ('response.policy.approve', 'response.policy', 'approve', '批准或拒绝他人提交的响应策略版本，退役 active 版本');

INSERT INTO `sys_role_permission` (`role_id`, `permission_id`)
SELECT r.`id`, p.`id`
FROM `sys_role` r
JOIN `sys_permission` p ON
  (p.`permission_key` = 'response.policy.draft' AND r.`role_key` = 'security_analyst')
  OR (p.`permission_key` = 'response.policy.approve' AND r.`role_key` = 'response_approver')
  OR (p.`permission_key` = 'response.policy.read' AND r.`role_key` = 'security_analyst');
