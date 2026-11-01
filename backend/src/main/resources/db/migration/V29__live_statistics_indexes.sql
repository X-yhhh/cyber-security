-- 实时态势按时间窗口聚合；复合索引缩小时间扫描，并覆盖权限过滤所需的资产键。
CREATE INDEX idx_guard_observation_live_time
  ON guard_observation (as_of, asset_id);

CREATE INDEX idx_guard_decision_live_time
  ON guard_decision (decided_at, decision, asset_id);

-- 覆盖窗口交集与最新接收时间查询。
CREATE INDEX idx_guard_health_live_range
  ON guard_capture_health_window (interval_end, interval_start, asset_id);

CREATE INDEX idx_guard_health_live_received
  ON guard_capture_health_window (received_at, asset_id);

-- 保留按 command_id 求最早 applied 时间的口径，同时避免读取回执 JSON 大字段。
CREATE INDEX idx_guard_action_receipt_first_applied
  ON guard_action_receipt (status, projected, revocation_id, command_id, observed_at, asset_id);
