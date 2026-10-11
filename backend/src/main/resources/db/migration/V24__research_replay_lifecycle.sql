-- J1 research 回放追加 running/completed 状态；保留 V23 原字节与历史会话。
-- 不改变模型、策略、资产授权、执行器、动作或命令，完成状态不代表 J1 验收通过。
ALTER TABLE guard_replay_run
  DROP CHECK guard_replay_run_chk_2,
  MODIFY status VARCHAR(24) NOT NULL DEFAULT 'queued' COMMENT 'queued/running/completed/failed；J1 结果独立登记',
  ADD CONSTRAINT ck_guard_replay_run_lifecycle CHECK (status IN ('queued','running','completed','failed'));

-- latest-parent 复核沿用同一因果排序，增加索引避免每条观察反复全表扫描。
CREATE INDEX idx_guard_observation_parent
  ON guard_observation(asset_id,sensor_id,boot_id,parent_connection_id,as_of,snapshot_index,id);

-- 观察原文与策略定义改为按原字节存储：MySQL JSON 列在解析部分十进制双精度数时会改动末位
-- （J1 两轮各 2,563 条观察、策略 10 处阈值），使推理输入与原件不再逐位一致。LONGTEXT 保存 RFC 8785 原文，
-- CHECK 保留 JSON 合法性；既有行按当时 JSON 文本转换，已改动的末位不会因此恢复，须按原件摘要另行修复。
ALTER TABLE guard_observation
  MODIFY payload_json LONGTEXT NOT NULL COMMENT '原始结构化不可变证据（RFC 8785 原文，数值无损）',
  ADD CONSTRAINT ck_guard_observation_payload_json CHECK (JSON_VALID(payload_json));
ALTER TABLE guard_decision_policy
  MODIFY definition_json LONGTEXT NOT NULL COMMENT '完整冻结策略（RFC 8785 原文，数值无损）',
  ADD CONSTRAINT ck_guard_decision_policy_definition_json CHECK (JSON_VALID(definition_json));
