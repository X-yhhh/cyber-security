-- J1 research 回放追加 running/completed 状态；保留 V23 原字节与历史会话。
-- 不改变模型、策略、资产授权、执行器、动作或命令，完成状态不代表 J1 验收通过。
ALTER TABLE guard_replay_run
  DROP CHECK guard_replay_run_chk_2,
  MODIFY status VARCHAR(24) NOT NULL DEFAULT 'queued' COMMENT 'queued/running/completed/failed；J1 结果独立登记',
  ADD CONSTRAINT ck_guard_replay_run_lifecycle CHECK (status IN ('queued','running','completed','failed'));

-- latest-parent 复核沿用同一因果排序，增加索引避免每条观察反复全表扫描。
CREATE INDEX idx_guard_observation_parent
  ON guard_observation(asset_id,sensor_id,boot_id,parent_connection_id,as_of,snapshot_index,id);
