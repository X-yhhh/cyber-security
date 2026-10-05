-- P4：v5 案件/复核独立引用与首次 lab 联合试验资格。旧 v4 案件保留原状态和接口。
ALTER TABLE security_event
 ADD COLUMN public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL COMMENT 'v2 外部 UUID',
 ADD COLUMN guard_asset_id BIGINT UNSIGNED NULL COMMENT 'v5 单资产案件范围；旧多资产案件保持空值',
 ADD COLUMN revision BIGINT NOT NULL DEFAULT 1 COMMENT 'v2 状态并发版本',
 ADD FOREIGN KEY (guard_asset_id) REFERENCES asset(id) ON DELETE RESTRICT;
UPDATE security_event SET public_id=UUID() WHERE public_id IS NULL;
ALTER TABLE security_event MODIFY public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT (UUID()) COMMENT 'v2 外部 UUID',
 ADD UNIQUE KEY uk_event_public_id(public_id);
-- 同一规范作用域不能通过更换稳定 token 获得新预算；身份迁移必须独立审查。
ALTER TABLE guard_budget_target ADD UNIQUE KEY uk_guard_budget_scope(asset_id,environment,scope_digest);
CREATE TABLE guard_feedback (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
 public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT '外部 UUID',
 created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) COMMENT '登记时间，UTC',
 asset_id BIGINT UNSIGNED NOT NULL COMMENT '资产范围',
 observation_id BIGINT UNSIGNED NOT NULL COMMENT '不可变原观察',
 label VARCHAR(24) NOT NULL COMMENT 'benign attack ambiguous',
 evidence_ref VARCHAR(255) NOT NULL COMMENT '受控脱敏证据引用',
 created_by BIGINT UNSIGNED NOT NULL COMMENT '标注人',
 reviewed_by BIGINT UNSIGNED NULL COMMENT '独立复核人',
 status VARCHAR(24) NOT NULL DEFAULT 'pending' COMMENT '复核状态，不自动进入训练',
 review_reason VARCHAR(1000) NULL COMMENT '复核依据',
 revision BIGINT NOT NULL DEFAULT 1 COMMENT '并发版本',
 PRIMARY KEY(id), UNIQUE KEY uk_guard_feedback_public(public_id),
 FOREIGN KEY(asset_id) REFERENCES asset(id) ON DELETE RESTRICT,
 FOREIGN KEY(observation_id) REFERENCES guard_observation(id) ON DELETE RESTRICT,
 FOREIGN KEY(created_by) REFERENCES sys_user(id) ON DELETE RESTRICT,
 FOREIGN KEY(reviewed_by) REFERENCES sys_user(id) ON DELETE RESTRICT,
 CHECK(reviewed_by IS NULL OR reviewed_by<>created_by),
 CHECK(label IN ('benign','attack','ambiguous')),
 CHECK(status IN ('pending','reviewed','rejected'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin COMMENT='v5 观察反馈；不伪造 v4 source_record';
CREATE TABLE guard_validation_session (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
 public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT '外部 UUID',
 created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) COMMENT '登记时间，UTC',
 asset_id BIGINT UNSIGNED NOT NULL COMMENT '明确登记的隔离资产',
 bundle_id BIGINT UNSIGNED NOT NULL COMMENT '固定评估对象',
 authorization_id BIGINT UNSIGNED NOT NULL COMMENT '独立批准的 lab 执行授权',
 requested_by BIGINT UNSIGNED NOT NULL COMMENT '试验申请人',
 approved_by BIGINT UNSIGNED NULL COMMENT '独立批准人',
 status VARCHAR(24) NOT NULL DEFAULT 'pending' COMMENT 'pending active revoked',
 payload_json JSON NOT NULL COMMENT '签名的 P5/P6、场景映射及网络隔离证明',
 content_sha256 CHAR(64) NOT NULL COMMENT '完整试验 JCS 摘要',
 valid_until DATETIME(6) NOT NULL COMMENT '试验终止时间',
 revision BIGINT NOT NULL DEFAULT 1 COMMENT '并发版本',
 PRIMARY KEY(id), UNIQUE KEY uk_guard_validation_session_public(public_id),
 FOREIGN KEY(asset_id) REFERENCES asset(id) ON DELETE RESTRICT,
 FOREIGN KEY(bundle_id) REFERENCES guard_release_bundle(id) ON DELETE RESTRICT,
 FOREIGN KEY(authorization_id) REFERENCES asset_authorization(id) ON DELETE RESTRICT,
 FOREIGN KEY(requested_by) REFERENCES sys_user(id) ON DELETE RESTRICT,
 FOREIGN KEY(approved_by) REFERENCES sys_user(id) ON DELETE RESTRICT,
 CHECK(approved_by IS NULL OR approved_by<>requested_by)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin COMMENT='P7 首次 lab 试验资格不冒充 lab_auto';
