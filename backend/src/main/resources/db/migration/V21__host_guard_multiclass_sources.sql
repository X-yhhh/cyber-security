-- 多分类接入只向前追加；V19/V20 与既有账号、发布组合、推理事实保持原样。
ALTER TABLE guard_inference
  ADD COLUMN family_scores_json JSON NULL COMMENT 'rc.3 按 manifest 顺序保存四类概率；旧二分类事实为空';

-- NULL 端口用生成列归一化，防止 MySQL 唯一键把多个 NULL 当成不同来源。
ALTER TABLE guard_episode
  DROP INDEX uk_guard_episode,
  MODIFY service_port INT NULL COMMENT 'peer_inbound 为 NULL；旧 peer_service 未知端口为零',
  ADD COLUMN scope VARCHAR(24) NOT NULL DEFAULT 'peer_service' COMMENT '来源全部入站或单服务汇总',
  ADD COLUMN source VARCHAR(16) NOT NULL DEFAULT 'model' COMMENT '模型和规则分别形成决策路径',
  ADD COLUMN rule_id VARCHAR(160) NOT NULL DEFAULT '' COMMENT '模型为空串；规则编号隔离计数',
  ADD COLUMN service_port_key INT GENERATED ALWAYS AS (COALESCE(service_port,0)) STORED,
  ADD UNIQUE KEY uk_guard_episode (asset_id,sensor_id,boot_id,peer_key,key_epoch,direction,transport,service_port_key,family,scope,source,rule_id,bundle_id,bucket_start),
  ADD CONSTRAINT ck_guard_episode_scope CHECK ((scope='peer_inbound' AND service_port IS NULL AND direction='inbound') OR (scope='peer_service' AND service_port IS NOT NULL)),
  ADD CONSTRAINT ck_guard_episode_source CHECK ((source='model' AND rule_id='') OR (source='rule' AND rule_id<>''));

ALTER TABLE guard_episode_evidence
  DROP INDEX uk_guard_episode_parent,
  ADD COLUMN family VARCHAR(64) NULL COMMENT '最新模型预测或规则类别；不沿用旧最高分类',
  ADD COLUMN source VARCHAR(16) NOT NULL DEFAULT 'model' COMMENT '证据来源',
  ADD COLUMN rule_id VARCHAR(160) NOT NULL DEFAULT '' COMMENT '模型为空串；规则编号',
  ADD COLUMN rule_matched BOOLEAN NOT NULL DEFAULT FALSE COMMENT '最新规则是否命中；未命中同样覆盖投影',
  ADD COLUMN family_scores_json JSON NULL COMMENT '最新模型四类概率，规则为空',
  ADD UNIQUE KEY uk_guard_episode_parent (episode_id,parent_connection_id,source,rule_id),
  ADD CONSTRAINT ck_guard_evidence_source CHECK ((source='model' AND rule_id='' AND rule_matched=FALSE) OR (source='rule' AND rule_id<>'' AND score IS NULL));

CREATE TABLE guard_rule_evaluation (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT '外部 UUID',
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) COMMENT '创建时间 UTC',
  asset_id BIGINT UNSIGNED NOT NULL COMMENT '查询资产范围',
  observation_id BIGINT UNSIGNED NOT NULL COMMENT '不可变观察事实',
  policy_id BIGINT UNSIGNED NOT NULL COMMENT '不可变规则与阈值所在策略',
  rule_version VARCHAR(64) NOT NULL COMMENT 'host-guard-rules/1',
  rule_id VARCHAR(160) NOT NULL COMMENT '策略内唯一规则编号',
  family VARCHAR(64) NOT NULL COMMENT '规则登记类别',
  matched BOOLEAN NOT NULL COMMENT '含未命中的追加事实',
  applicable BOOLEAN NOT NULL COMMENT '字段已观测且为有限数值',
  payload_json JSON NOT NULL COMMENT '规则、读值和因果时间证据',
  PRIMARY KEY (id),
  UNIQUE KEY uk_guard_rule_public (public_id),
  UNIQUE KEY uk_guard_rule_observation (observation_id,policy_id,rule_id),
  FOREIGN KEY (asset_id) REFERENCES asset(id) ON DELETE RESTRICT,
  FOREIGN KEY (observation_id) REFERENCES guard_observation(id) ON DELETE RESTRICT,
  FOREIGN KEY (policy_id) REFERENCES guard_decision_policy(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin COMMENT='规则命中及未命中不可变事实，不依赖模型成功';
