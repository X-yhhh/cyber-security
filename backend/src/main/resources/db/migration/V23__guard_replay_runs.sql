-- P7 B4：研究回放只保存不透明场景与已批准的 research 发布包，不保存资产、授权、执行器或目标引用。
CREATE TABLE guard_replay_run (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT '外部 UUID',
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) COMMENT '创建时间，UTC',
  scenario_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT '研究场景不透明标识',
  scenario_sha256 CHAR(64) NOT NULL COMMENT '场景内容摘要',
  model_id BIGINT UNSIGNED NOT NULL COMMENT '回放模型',
  policy_id BIGINT UNSIGNED NOT NULL COMMENT '回放策略',
  bundle_id BIGINT UNSIGNED NOT NULL COMMENT '已批准 research 发布包',
  speed DECIMAL(4,2) NOT NULL COMMENT '固定为 1.00 倍速',
  status VARCHAR(24) NOT NULL DEFAULT 'queued' COMMENT 'queued 或 failed',
  requested_by BIGINT UNSIGNED NOT NULL COMMENT '申请人',
  payload_json JSON NOT NULL COMMENT '研究回放请求，不含真实目标引用',
  content_sha256 CHAR(64) NOT NULL COMMENT '请求摘要',
  PRIMARY KEY (id),
  UNIQUE KEY uk_guard_replay_run_public (public_id),
  FOREIGN KEY (model_id) REFERENCES guard_model(id) ON DELETE RESTRICT,
  FOREIGN KEY (policy_id) REFERENCES guard_decision_policy(id) ON DELETE RESTRICT,
  FOREIGN KEY (bundle_id) REFERENCES guard_release_bundle(id) ON DELETE RESTRICT,
  FOREIGN KEY (requested_by) REFERENCES sys_user(id) ON DELETE RESTRICT,
  CHECK (speed = 1.00),
  CHECK (status IN ('queued','failed'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin COMMENT='P7 B4 research-only 回放会话；不产生真实动作';
