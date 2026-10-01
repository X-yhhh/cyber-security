-- 阶段 2：检测策略独立审批、模型信号分层与生命周期补齐。保留全部历史事实及预置策略。
CREATE TABLE detection_policy_lock (
  policy_type VARCHAR(48) NOT NULL COMMENT '策略类型互斥锁；批准/退役与版本分配统一锁顺序',
  PRIMARY KEY (policy_type)
) ENGINE=InnoDB COMMENT='检测策略类型串行化锁';
INSERT INTO detection_policy_lock VALUES ('severity_mapping'), ('correlation'), ('risk_score');

ALTER TABLE detection_policy
  DROP CHECK ck_detection_policy_status,
  ADD COLUMN created_by BIGINT UNSIGNED NULL COMMENT '起草人；历史预置版本为空',
  ADD COLUMN based_on_policy_id BIGINT UNSIGNED NULL COMMENT '复制来源版本，原版本不可覆盖',
  ADD COLUMN change_reason VARCHAR(1000) NULL COMMENT '起草理由',
  ADD COLUMN content_sha256 CHAR(64) NULL COMMENT '规范化内容哈希；历史预置版本为空',
  ADD COLUMN submitted_at DATETIME(3) NULL COMMENT '提交审批时间 UTC',
  ADD COLUMN reviewed_by BIGINT UNSIGNED NULL COMMENT '独立审批人',
  ADD COLUMN reviewed_at DATETIME(3) NULL COMMENT '审批时间 UTC',
  ADD COLUMN decision_reason VARCHAR(1000) NULL COMMENT '审批理由',
  ADD COLUMN retired_by BIGINT UNSIGNED NULL COMMENT '退役或撤回操作者',
  ADD COLUMN retired_at DATETIME(3) NULL COMMENT '退役时间 UTC',
  ADD CONSTRAINT fk_detection_policy_author FOREIGN KEY (created_by) REFERENCES sys_user(id),
  ADD CONSTRAINT fk_detection_policy_base FOREIGN KEY (based_on_policy_id) REFERENCES detection_policy(id),
  ADD CONSTRAINT fk_detection_policy_reviewer FOREIGN KEY (reviewed_by) REFERENCES sys_user(id),
  ADD CONSTRAINT fk_detection_policy_retirer FOREIGN KEY (retired_by) REFERENCES sys_user(id),
  ADD CONSTRAINT ck_detection_policy_status CHECK (status IN ('draft','pending','active','rejected','retired')),
  ADD CONSTRAINT ck_detection_policy_separation CHECK (reviewed_by IS NULL OR (created_by IS NOT NULL AND reviewed_by <> created_by));

ALTER TABLE detection_alert
  ADD COLUMN alert_layer VARCHAR(16) NOT NULL DEFAULT 'alert' COMMENT 'signal 不进人工告警队列；历史保留 alert',
  ADD COLUMN correlation_policy_version VARCHAR(64) NULL COMMENT '分层所用关联窗口版本快照',
  ADD COLUMN promoted_at DATETIME(3) NULL COMMENT '模型信号升级时间 UTC；历史告警不回写',
  ADD KEY idx_detection_alert_layer_time (alert_layer, detected_at),
  ADD CONSTRAINT ck_detection_alert_layer CHECK (alert_layer IN ('signal','alert')),
  ADD CONSTRAINT ck_detection_signal_model CHECK (alert_layer <> 'signal' OR (alert_type='model' AND severity='low'));

ALTER TABLE approval_task
  ADD COLUMN withdrawn_at DATETIME(3) NULL COMMENT '申请人撤回时间 UTC',
  ADD COLUMN withdraw_reason VARCHAR(1000) NULL COMMENT '申请人撤回理由，审批事实不改写';

ALTER TABLE model_version
  ADD COLUMN retired_at DATETIME(3) NULL COMMENT '显式退役时间 UTC；制品与审批事实保留',
  ADD COLUMN retired_by BIGINT UNSIGNED NULL COMMENT '退役操作人',
  ADD COLUMN retire_reason VARCHAR(1000) NULL COMMENT '退役理由',
  ADD CONSTRAINT fk_model_version_retired_by FOREIGN KEY (retired_by) REFERENCES sys_user(id);

INSERT INTO sys_permission (permission_key, resource, action, description) VALUES
 ('detection.policy.read','detection.policy','read','查看版本化检测策略'),
 ('detection.policy.manage','detection.policy','manage','起草和提交检测策略'),
 ('detection.policy.approve','detection.policy','approve','独立审批及退役检测策略');
INSERT INTO sys_role_permission (role_id, permission_id)
SELECT r.id,p.id FROM sys_role r JOIN sys_permission p ON
 (p.permission_key='detection.policy.read' AND r.role_key IN ('platform_admin','security_analyst','response_approver')) OR
 (p.permission_key='detection.policy.manage' AND r.role_key='security_analyst') OR
 (p.permission_key='detection.policy.approve' AND r.role_key='response_approver');

-- 单例锁覆盖空部署表以及激活/退役/回退并发；不存储模型或凭据。
CREATE TABLE model_lifecycle_lock (
  id TINYINT NOT NULL COMMENT '本机生命周期互斥锁', PRIMARY KEY(id),
  CONSTRAINT ck_model_lifecycle_singleton CHECK(id=1)
) ENGINE=InnoDB COMMENT='模型部署生命周期串行化锁';
INSERT INTO model_lifecycle_lock VALUES (1);
