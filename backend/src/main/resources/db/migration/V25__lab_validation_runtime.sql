-- L2/B4 lab 验证会话使用 V25（任务单分配，紧接 V24）。只追加 lab 运行投影与事实两张表，
-- 不改 V20 资格表结构与状态含义，不改 V1—V24、Flyway 历史或既有账号。
-- 并行线如需新迁移须另取更高版本号；不得用 outOfOrder 绕过已落库版本。
CREATE TABLE guard_lab_run (
 session_id BIGINT UNSIGNED NOT NULL COMMENT 'V20 试验资格，一对一',
 sensor_id BIGINT UNSIGNED NOT NULL COMMENT '固定传感器，禁止跨会话借用观察',
 boot_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT '固定采集启动身份',
 status VARCHAR(24) NOT NULL DEFAULT 'registered' COMMENT 'registered running interrupted completed failed cancelled expired',
 manifest_ref VARCHAR(255) NOT NULL COMMENT '受控制品引用，不是 URL',
 manifest_sha256 CHAR(64) NOT NULL COMMENT '签名封装文件原字节 SHA256',
 manifest_jcs LONGTEXT NOT NULL COMMENT '保留签名 payload JCS 原文，避免 JSON 数值改写',
 scenarios_jcs LONGTEXT NOT NULL COMMENT '冻结场景原件的 JCS',
 mapping_jcs LONGTEXT NOT NULL COMMENT '冻结映射原件的 JCS',
 started_at DATETIME(6) NULL COMMENT '真实运行起点 UTC',
 ended_at DATETIME(6) NULL COMMENT '运行结束，不表示验收通过或清理完成',
 last_activity_at DATETIME(6) NULL COMMENT '最后成功事件或恢复的后台时间',
 stop_requested_at DATETIME(6) NULL COMMENT '请求停止时刻，与实际规则清理分开',
 PRIMARY KEY(session_id), UNIQUE KEY uk_lab_sensor_boot(sensor_id,boot_id),
 FOREIGN KEY(session_id) REFERENCES guard_validation_session(id) ON DELETE RESTRICT,
 FOREIGN KEY(sensor_id) REFERENCES sensor_agent(id) ON DELETE RESTRICT,
 CHECK(status IN ('registered','running','interrupted','completed','failed','cancelled','expired')),
 CHECK(JSON_VALID(manifest_jcs)), CHECK(JSON_VALID(scenarios_jcs)), CHECK(JSON_VALID(mapping_jcs))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin COMMENT='lab 会话运行投影，独立于试验资格';

CREATE TABLE guard_lab_event (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '会话读取游标',
 public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT '外部事件 UUID',
 session_id BIGINT UNSIGNED NOT NULL COMMENT '所属试验',
 fact_key VARCHAR(180) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT '来源类型及不可变外部标识，自然幂等键',
 scenario_id VARCHAR(96) CHARACTER SET ascii COLLATE ascii_bin NULL COMMENT '空值为生命周期或报告事件',
 kind VARCHAR(32) NOT NULL COMMENT '事件类型，不能作为执行指令',
 occurred_at DATETIME(6) NULL COMMENT '原事实发生时刻；未知保持 NULL',
 received_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) COMMENT '后台登记时间 UTC',
 payload_jcs LONGTEXT NOT NULL COMMENT '脱敏事实快照 JCS，仅追加',
 content_sha256 CHAR(64) NOT NULL COMMENT 'payload JCS SHA256',
 request_sha256 CHAR(64) NOT NULL COMMENT '去除 eventId 的请求摘要，用于自然键冲突验证',
 PRIMARY KEY(id), UNIQUE KEY uk_lab_event_public(public_id),
 UNIQUE KEY uk_lab_event_fact(session_id,fact_key), KEY ix_lab_event_session(session_id,id),
 FOREIGN KEY(session_id) REFERENCES guard_validation_session(id) ON DELETE RESTRICT,
 CHECK(JSON_VALID(payload_jcs))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin COMMENT='lab 生命周期与可信运行事实，只追加';
