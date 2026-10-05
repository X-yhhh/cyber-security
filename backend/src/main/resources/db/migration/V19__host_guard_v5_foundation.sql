-- P4：v5 独立事实模型。仅向前追加；不修改旧迁移、账号口令或 v4 状态。
-- UUID 只供外部引用，关联采用内部外键；UTC 微秒与二进制比较防止身份折叠。
ALTER TABLE api_client DROP CHECK ck_api_client_type,
 ADD CONSTRAINT ck_api_client_type CHECK (client_type IN ('connector','sensor','response_adapter','executor'));

ALTER TABLE asset ADD COLUMN public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL COMMENT 'v2 外部 UUID，与内部主键分离';
UPDATE asset SET public_id=UUID() WHERE public_id IS NULL;
ALTER TABLE asset MODIFY public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT (UUID()) COMMENT 'v2 外部 UUID', ADD UNIQUE KEY uk_asset_public (public_id);

ALTER TABLE asset_authorization ADD COLUMN public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL COMMENT 'v2 外部 UUID，与内部主键分离';
UPDATE asset_authorization SET public_id=UUID() WHERE public_id IS NULL;
ALTER TABLE asset_authorization MODIFY public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT (UUID()) COMMENT 'v2 外部 UUID', ADD UNIQUE KEY uk_asset_authorization_public (public_id);

ALTER TABLE sensor_agent ADD COLUMN public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL COMMENT 'v2 外部 UUID，与内部主键分离';
UPDATE sensor_agent SET public_id=UUID() WHERE public_id IS NULL;
ALTER TABLE sensor_agent MODIFY public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT (UUID()) COMMENT 'v2 外部 UUID', ADD UNIQUE KEY uk_sensor_agent_public (public_id);

ALTER TABLE sensor_config ADD COLUMN public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL COMMENT 'v2 外部 UUID，与内部主键分离';
UPDATE sensor_config SET public_id=UUID() WHERE public_id IS NULL;
ALTER TABLE sensor_config MODIFY public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT (UUID()) COMMENT 'v2 外部 UUID', ADD UNIQUE KEY uk_sensor_config_public (public_id);

ALTER TABLE api_client ADD COLUMN public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL COMMENT 'v2 外部 UUID，与内部主键分离';
UPDATE api_client SET public_id=UUID() WHERE public_id IS NULL;
ALTER TABLE api_client MODIFY public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT (UUID()) COMMENT 'v2 外部 UUID', ADD UNIQUE KEY uk_api_client_public (public_id);

ALTER TABLE asset ADD COLUMN revision BIGINT NOT NULL DEFAULT 1 COMMENT '乐观并发与租约版本';

ALTER TABLE asset_authorization ADD COLUMN revision BIGINT NOT NULL DEFAULT 1 COMMENT '乐观并发与租约版本';

ALTER TABLE sensor_agent ADD COLUMN revision BIGINT NOT NULL DEFAULT 1 COMMENT '乐观并发与租约版本';

ALTER TABLE sensor_config ADD COLUMN revision BIGINT NOT NULL DEFAULT 1 COMMENT '乐观并发与租约版本';

ALTER TABLE sensor_config ADD COLUMN guard_definition_json JSON NULL COMMENT 'v5 已冻结配置，旧配置保持空值', ADD COLUMN content_sha256 CHAR(64) NULL COMMENT 'v5 配置 JCS 摘要';
ALTER TABLE sensor_agent ADD COLUMN guard_boot_id CHAR(36) NULL COMMENT 'v5 当前采集器启动身份';

CREATE TABLE guard_idempotency (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT '外部 UUID',
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) COMMENT '创建时间，UTC',
  request_scope CHAR(64) NOT NULL COMMENT '主体方法路由资源的摘要',
  idempotency_key CHAR(36) NOT NULL COMMENT '调用方重试键',
  request_sha256 CHAR(64) NOT NULL COMMENT 'JCS 请求摘要',
  response_json JSON NULL COMMENT '成功提交的响应，凭据不进入本表',
  http_status INT NULL COMMENT '原始响应状态',
  PRIMARY KEY (id),
  UNIQUE KEY uk_guard_idempotency_public (public_id),
  UNIQUE KEY uk_guard_idempotency_scope (request_scope,idempotency_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin COMMENT='主体、路由和资源作用域内的永久写入幂等结果';

CREATE TABLE guard_contract (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT '外部 UUID',
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) COMMENT '创建时间，UTC',
  contract_version VARCHAR(64) NOT NULL COMMENT '观测结构版本',
  profile_sha256 CHAR(64) NOT NULL COMMENT '原始特征 profile 文件摘要',
  schema_set_sha256 CHAR(64) NOT NULL COMMENT '有序 Schema 哈希集合摘要',
  extractor_sha256 CHAR(64) NOT NULL COMMENT '提取器制品摘要',
  status VARCHAR(24) NOT NULL COMMENT '登记状态',
  PRIMARY KEY (id),
  UNIQUE KEY uk_guard_contract_public (public_id),
  UNIQUE KEY uk_guard_contract_artifact (contract_version,profile_sha256,schema_set_sha256,extractor_sha256)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin COMMENT='冻结的观测及提取器制品组合';

CREATE TABLE guard_dataset (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT '外部 UUID',
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) COMMENT '创建时间，UTC',
  dataset_key VARCHAR(96) NOT NULL COMMENT '数据集逻辑键',
  version VARCHAR(96) NOT NULL COMMENT '数据版本',
  manifest_ref VARCHAR(255) NOT NULL COMMENT '受控清单引用',
  manifest_sha256 CHAR(64) NOT NULL COMMENT '原件摘要',
  payload_json JSON NOT NULL COMMENT '冻结来源与标签信息',
  PRIMARY KEY (id),
  UNIQUE KEY uk_guard_dataset_public (public_id),
  UNIQUE KEY uk_guard_dataset_version (dataset_key,version)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin COMMENT='不可变来源和标签清单';

CREATE TABLE guard_model (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT '外部 UUID',
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) COMMENT '创建时间，UTC',
  model_key VARCHAR(96) NOT NULL COMMENT '模型逻辑键',
  version VARCHAR(96) NOT NULL COMMENT '模型版本',
  manifest_ref VARCHAR(255) NOT NULL COMMENT '受控制品根目录相对引用',
  manifest_sha256 CHAR(64) NOT NULL COMMENT '原始 manifest 摘要',
  artifact_sha256 CHAR(64) NOT NULL COMMENT 'ONNX 原件摘要',
  contract_id BIGINT UNSIGNED NOT NULL COMMENT '冻结契约组合',
  manifest_json JSON NOT NULL COMMENT '不可变候选清单',
  validation_status VARCHAR(24) NOT NULL DEFAULT 'pending' COMMENT '实际运行时验证状态',
  validation_json JSON NULL COMMENT '运行时验证事实',
  created_by BIGINT UNSIGNED NOT NULL COMMENT '登记主体',
  PRIMARY KEY (id),
  UNIQUE KEY uk_guard_model_public (public_id),
  UNIQUE KEY uk_guard_model_version (model_key,version),
  FOREIGN KEY (contract_id) REFERENCES guard_contract(id) ON DELETE RESTRICT,
  FOREIGN KEY (created_by) REFERENCES sys_user(id) ON DELETE RESTRICT,
  CHECK (JSON_EXTRACT(manifest_json,'$.candidateOnly') = TRUE)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin COMMENT='不可变候选模型与独立验证状态';

CREATE TABLE guard_evaluation_plan (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT '外部 UUID',
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) COMMENT '创建时间，UTC',
  plan_key VARCHAR(96) NOT NULL COMMENT '计划标识',
  version VARCHAR(96) NOT NULL COMMENT '计划版本',
  plan_sha256 CHAR(64) NOT NULL COMMENT '冻结计划 JCS 摘要',
  payload_json JSON NOT NULL COMMENT '角色范围时效与选择预算',
  created_by BIGINT UNSIGNED NOT NULL COMMENT '登记主体',
  PRIMARY KEY (id),
  UNIQUE KEY uk_guard_evaluation_plan_public (public_id),
  UNIQUE KEY uk_guard_plan_version (plan_key,version),
  FOREIGN KEY (created_by) REFERENCES sys_user(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin COMMENT='新决策健康评价版本绑定的不可变计划';

CREATE TABLE guard_capability (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT '外部 UUID',
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) COMMENT '创建时间，UTC',
  capability_key VARCHAR(96) NOT NULL COMMENT '能力逻辑键',
  version VARCHAR(96) NOT NULL COMMENT '不可变版本',
  platform VARCHAR(32) NOT NULL COMMENT '目标操作系统',
  level VARCHAR(32) NOT NULL COMMENT '研究告警或自动能力等级',
  payload_json JSON NOT NULL COMMENT '平台报告、范围与时效限制',
  created_by BIGINT UNSIGNED NOT NULL COMMENT '登记主体',
  PRIMARY KEY (id),
  UNIQUE KEY uk_guard_capability_public (public_id),
  UNIQUE KEY uk_guard_capability_version (capability_key,version),
  FOREIGN KEY (created_by) REFERENCES sys_user(id) ON DELETE RESTRICT,
  CHECK (level IN ('research','alert_only','lab_auto','authorized_auto','suspended'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin COMMENT='已审查平台与行为的声明范围';

CREATE TABLE guard_decision_policy (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT '外部 UUID',
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) COMMENT '创建时间，UTC',
  policy_key VARCHAR(96) NOT NULL COMMENT '策略逻辑键',
  version VARCHAR(96) NOT NULL COMMENT '策略版本',
  model_id BIGINT UNSIGNED NOT NULL COMMENT '绑定候选',
  plan_id BIGINT UNSIGNED NOT NULL COMMENT '评价计划',
   decision_contract_version VARCHAR(96) NOT NULL COMMENT '决策语义版本',
  definition_json JSON NOT NULL COMMENT '完整冻结策略',
  definition_sha256 CHAR(64) NOT NULL COMMENT '策略 JCS 摘要',
  status VARCHAR(24) NOT NULL DEFAULT 'draft' COMMENT '起草审核退役状态',
  created_by BIGINT UNSIGNED NOT NULL COMMENT '起草人',
  reviewed_by BIGINT UNSIGNED NULL COMMENT '独立审核人',
  revision BIGINT NOT NULL DEFAULT 1 COMMENT '状态版本',
  PRIMARY KEY (id),
  UNIQUE KEY uk_guard_decision_policy_public (public_id),
  UNIQUE KEY uk_guard_policy_version (policy_key,version),
  FOREIGN KEY (model_id) REFERENCES guard_model(id) ON DELETE RESTRICT,
  FOREIGN KEY (plan_id) REFERENCES guard_evaluation_plan(id) ON DELETE RESTRICT,
  FOREIGN KEY (created_by) REFERENCES sys_user(id) ON DELETE RESTRICT,
  FOREIGN KEY (reviewed_by) REFERENCES sys_user(id) ON DELETE RESTRICT,
  CHECK (reviewed_by IS NULL OR reviewed_by<>created_by),
  CHECK (status IN ('draft','reviewed','retired'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin COMMENT='与旧响应策略分离的 v5 不可变决策策略';

CREATE TABLE guard_release_bundle (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT '外部 UUID',
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) COMMENT '创建时间，UTC',
  bundle_key VARCHAR(96) NOT NULL COMMENT '组合逻辑键',
  version VARCHAR(96) NOT NULL COMMENT '组合版本',
  model_id BIGINT UNSIGNED NOT NULL COMMENT '绑定候选模型',
  policy_id BIGINT UNSIGNED NOT NULL COMMENT '绑定冻结策略',
  contract_id BIGINT UNSIGNED NOT NULL COMMENT '绑定契约组合',
  plan_id BIGINT UNSIGNED NOT NULL COMMENT '绑定评价计划',
  environment VARCHAR(24) NOT NULL COMMENT '研究隔离或授权环境',
  subject_sha256 CHAR(64) NOT NULL COMMENT '不含报告的 subject 摘要',
  subject_json JSON NOT NULL COMMENT '不可变评估对象',
  sealed_manifest_sha256 CHAR(64) NULL COMMENT '后置报告封存摘要',
  sealed_manifest_json JSON NULL COMMENT 'subject 与同对象报告的封存',
  status VARCHAR(24) NOT NULL DEFAULT 'candidate' COMMENT '候选评估审批激活状态',
  requested_by BIGINT UNSIGNED NOT NULL COMMENT '申请人',
  approved_by BIGINT UNSIGNED NULL COMMENT '独立批准人',
  revision BIGINT NOT NULL DEFAULT 1 COMMENT '状态并发版本',
  PRIMARY KEY (id),
  UNIQUE KEY uk_guard_release_bundle_public (public_id),
  UNIQUE KEY uk_guard_bundle_version (bundle_key,version),
  FOREIGN KEY (model_id) REFERENCES guard_model(id) ON DELETE RESTRICT,
  FOREIGN KEY (policy_id) REFERENCES guard_decision_policy(id) ON DELETE RESTRICT,
  FOREIGN KEY (contract_id) REFERENCES guard_contract(id) ON DELETE RESTRICT,
  FOREIGN KEY (plan_id) REFERENCES guard_evaluation_plan(id) ON DELETE RESTRICT,
  FOREIGN KEY (requested_by) REFERENCES sys_user(id) ON DELETE RESTRICT,
  FOREIGN KEY (approved_by) REFERENCES sys_user(id) ON DELETE RESTRICT,
  CHECK (approved_by IS NULL OR approved_by<>requested_by),
  CHECK (status IN ('candidate','evaluated','approved','active','suspended','retired')),
  CHECK (environment IN ('research','lab','authorized'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin COMMENT='候选 subject 与报告封存分离的发布组合';

CREATE TABLE guard_bundle_capability (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT '外部 UUID',
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) COMMENT '创建时间，UTC',
  bundle_id BIGINT UNSIGNED NOT NULL COMMENT '发布组合',
  capability_id BIGINT UNSIGNED NOT NULL COMMENT '确切能力版本',
  PRIMARY KEY (id),
  UNIQUE KEY uk_guard_bundle_capability_public (public_id),
  UNIQUE KEY uk_guard_bundle_capability (bundle_id,capability_id),
  FOREIGN KEY (bundle_id) REFERENCES guard_release_bundle(id) ON DELETE RESTRICT,
  FOREIGN KEY (capability_id) REFERENCES guard_capability(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin COMMENT='组合对应的不可变能力清单';

CREATE TABLE guard_evaluation_run (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT '外部 UUID',
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) COMMENT '创建时间，UTC',
  plan_id BIGINT UNSIGNED NOT NULL COMMENT '预登记计划',
  bundle_id BIGINT UNSIGNED NOT NULL COMMENT '被评估对象',
  run_kind VARCHAR(24) NOT NULL COMMENT 'development final replay canary platform',
  runner_identity VARCHAR(96) NOT NULL COMMENT '配置允许的报告来源',
  status VARCHAR(24) NOT NULL COMMENT '报告验证结果',
  report_ref VARCHAR(255) NOT NULL COMMENT '受控原件引用',
  report_sha256 CHAR(64) NOT NULL COMMENT '原件摘要',
  payload_json JSON NOT NULL COMMENT '同 subject 报告与范围',
  PRIMARY KEY (id),
  UNIQUE KEY uk_guard_evaluation_run_public (public_id),
  FOREIGN KEY (plan_id) REFERENCES guard_evaluation_plan(id) ON DELETE RESTRICT,
  FOREIGN KEY (bundle_id) REFERENCES guard_release_bundle(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin COMMENT='受信任本地报告的验证登记';

CREATE TABLE guard_asset_binding (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT '外部 UUID',
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) COMMENT '创建时间，UTC',
  asset_id BIGINT UNSIGNED NOT NULL COMMENT '登记资产',
  bundle_id BIGINT UNSIGNED NOT NULL COMMENT '批准组合',
  authorization_id BIGINT UNSIGNED NOT NULL COMMENT '观察与执行授权',
  authorization_revision BIGINT NOT NULL COMMENT '绑定授权版本',
  status VARCHAR(24) NOT NULL COMMENT '活动或暂停',
  activated_by BIGINT UNSIGNED NOT NULL COMMENT '激活主体',
  revision BIGINT NOT NULL DEFAULT 1 COMMENT '绑定版本',
  active_asset BIGINT UNSIGNED GENERATED ALWAYS AS (IF(status='active',asset_id,NULL)) STORED COMMENT '首期每资产一个活动组合',
  PRIMARY KEY (id),
  UNIQUE KEY uk_guard_asset_binding_public (public_id),
  UNIQUE KEY uk_guard_asset_active (active_asset),
  FOREIGN KEY (asset_id) REFERENCES asset(id) ON DELETE RESTRICT,
  FOREIGN KEY (bundle_id) REFERENCES guard_release_bundle(id) ON DELETE RESTRICT,
  FOREIGN KEY (authorization_id) REFERENCES asset_authorization(id) ON DELETE RESTRICT,
  FOREIGN KEY (activated_by) REFERENCES sys_user(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin COMMENT='资产授权与自动能力唯一路由';

CREATE TABLE guard_capture_scope (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT '外部 UUID',
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) COMMENT '创建时间，UTC',
  asset_id BIGINT UNSIGNED NOT NULL COMMENT '登记资产',
  sensor_id BIGINT UNSIGNED NOT NULL COMMENT '采集身份',
  scope_key VARCHAR(96) NOT NULL COMMENT '授权接口引用',
  address_family VARCHAR(12) NOT NULL COMMENT '地址族',
  config_id BIGINT UNSIGNED NULL COMMENT '批准配置',
  status VARCHAR(24) NOT NULL COMMENT '域状态',
  active_asset BIGINT UNSIGNED GENERATED ALWAYS AS (IF(status='active',asset_id,NULL)) STORED COMMENT '活动域排他键',
  PRIMARY KEY (id),
  UNIQUE KEY uk_guard_capture_scope_public (public_id),
  UNIQUE KEY uk_guard_capture (sensor_id,scope_key,address_family),
  UNIQUE KEY uk_guard_capture_active (active_asset,address_family),
  FOREIGN KEY (asset_id) REFERENCES asset(id) ON DELETE RESTRICT,
  FOREIGN KEY (sensor_id) REFERENCES sensor_agent(id) ON DELETE RESTRICT,
  FOREIGN KEY (config_id) REFERENCES sensor_config(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin COMMENT='首期每资产地址族一个活动捕获域';

CREATE TABLE guard_observation_batch (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT '外部 UUID',
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) COMMENT '创建时间，UTC',
  sensor_id BIGINT UNSIGNED NOT NULL COMMENT '认证传感器',
  asset_id BIGINT UNSIGNED NOT NULL COMMENT '范围过滤资产',
  boot_id CHAR(36) NOT NULL COMMENT '采集启动身份',
  sequence_no BIGINT NOT NULL COMMENT '启动域内批次序号',
  config_id BIGINT UNSIGNED NOT NULL COMMENT '批准配置',
  request_sha256 CHAR(64) NOT NULL COMMENT '原批次 JCS 摘要',
  result_json JSON NOT NULL COMMENT '逐条接受与拒绝结果',
  PRIMARY KEY (id),
  UNIQUE KEY uk_guard_observation_batch_public (public_id),
  UNIQUE KEY uk_guard_batch_sequence (sensor_id,boot_id,sequence_no),
  FOREIGN KEY (sensor_id) REFERENCES sensor_agent(id) ON DELETE RESTRICT,
  FOREIGN KEY (asset_id) REFERENCES asset(id) ON DELETE RESTRICT,
  FOREIGN KEY (config_id) REFERENCES sensor_config(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin COMMENT='不可变机器批次与接入结果';

CREATE TABLE guard_observation (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT '外部 UUID',
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) COMMENT '创建时间，UTC',
  batch_id BIGINT UNSIGNED NOT NULL COMMENT '接入批次',
  sensor_id BIGINT UNSIGNED NOT NULL COMMENT '认证传感器',
  asset_id BIGINT UNSIGNED NOT NULL COMMENT '认证资产',
  boot_id CHAR(36) NOT NULL COMMENT '采集器启动',
  capture_scope_id BIGINT UNSIGNED NOT NULL COMMENT '捕获域',
  flow_id CHAR(36) NOT NULL COMMENT '连接段',
  parent_connection_id CHAR(36) NOT NULL COMMENT '独立连接',
  snapshot_index BIGINT NOT NULL COMMENT '段内快照序号',
  profile VARCHAR(32) NOT NULL COMMENT 'prefix 或 final',
  as_of DATETIME(6) NOT NULL COMMENT '因果证据时间',
  last_packet_at DATETIME(6) NOT NULL COMMENT '最后真实报文时间',
  peer_key CHAR(64) NOT NULL COMMENT '不可反查假名',
  key_epoch BIGINT NOT NULL COMMENT '证据密钥代际',
  direction VARCHAR(16) NOT NULL COMMENT '连接方向',
  transport VARCHAR(12) NOT NULL COMMENT '传输协议',
  service_port INT NULL COMMENT '服务端口，仅作目标元数据',
  environment VARCHAR(24) NOT NULL COMMENT '认证环境',
  payload_json JSON NOT NULL COMMENT '原始结构化不可变证据',
  content_sha256 CHAR(64) NOT NULL COMMENT 'JCS 内容摘要',
  PRIMARY KEY (id),
  UNIQUE KEY uk_guard_observation_public (public_id),
  UNIQUE KEY uk_guard_observation_snapshot (sensor_id,boot_id,flow_id,snapshot_index),
  KEY idx_guard_observation_time (asset_id,as_of),
  FOREIGN KEY (batch_id) REFERENCES guard_observation_batch(id) ON DELETE RESTRICT,
  FOREIGN KEY (asset_id) REFERENCES asset(id) ON DELETE RESTRICT,
  FOREIGN KEY (sensor_id) REFERENCES sensor_agent(id) ON DELETE RESTRICT,
  FOREIGN KEY (capture_scope_id) REFERENCES guard_capture_scope(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin COMMENT='v5 不可变因果快照';

CREATE TABLE guard_ingest_rejection (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT '外部 UUID',
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) COMMENT '创建时间，UTC',
  batch_id BIGINT UNSIGNED NOT NULL COMMENT '对应批次',
  observation_external_id CHAR(36) NULL COMMENT '可解析的观察 UUID',
  reason_code VARCHAR(96) NOT NULL COMMENT '稳定拒绝原因',
  content_sha256 CHAR(64) NOT NULL COMMENT '被拒绝内容摘要',
  PRIMARY KEY (id),
  UNIQUE KEY uk_guard_ingest_rejection_public (public_id),
  FOREIGN KEY (batch_id) REFERENCES guard_observation_batch(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin COMMENT='逐条拒绝事实不保存秘密原文';

CREATE TABLE guard_inference (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT '外部 UUID',
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) COMMENT '创建时间，UTC',
  observation_id BIGINT UNSIGNED NOT NULL COMMENT '观察记录',
  asset_id BIGINT UNSIGNED NOT NULL COMMENT '查询范围',
  model_id BIGINT UNSIGNED NOT NULL COMMENT '不可变候选',
  status VARCHAR(24) NOT NULL COMMENT '成功不适用失败或过期',
  score DOUBLE NULL COMMENT '只在成功且适用时存在',
  family VARCHAR(64) NULL COMMENT '二分类为空',
  applicability VARCHAR(32) NOT NULL COMMENT 'supported 或拒绝分类',
  manifest_sha256 CHAR(64) NOT NULL COMMENT '实际模型清单摘要',
  completed_at DATETIME(6) NOT NULL COMMENT '完成时间',
  error_code VARCHAR(96) NULL COMMENT '明确失败代码',
  PRIMARY KEY (id),
  UNIQUE KEY uk_guard_inference_public (public_id),
  UNIQUE KEY uk_guard_inference (observation_id,model_id),
  FOREIGN KEY (observation_id) REFERENCES guard_observation(id) ON DELETE RESTRICT,
  FOREIGN KEY (asset_id) REFERENCES asset(id) ON DELETE RESTRICT,
  FOREIGN KEY (model_id) REFERENCES guard_model(id) ON DELETE RESTRICT,
  CHECK ((status='succeeded' AND applicability='supported' AND score IS NOT NULL AND score BETWEEN 0 AND 1) OR (status<>'succeeded' AND score IS NULL))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin COMMENT='绑定确切模型的推理结果';

CREATE TABLE guard_capture_health_window (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT '外部 UUID',
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) COMMENT '创建时间，UTC',
  sensor_id BIGINT UNSIGNED NOT NULL COMMENT '认证传感器',
  asset_id BIGINT UNSIGNED NOT NULL COMMENT '认证资产',
  capture_scope_id BIGINT UNSIGNED NOT NULL COMMENT '捕获域',
  observer_session_id CHAR(36) NOT NULL COMMENT '持续观察器会话',
  sequence_no BIGINT NOT NULL COMMENT '会话内序号',
  interval_start DATETIME(6) NOT NULL COMMENT '窗口起点',
  interval_end DATETIME(6) NOT NULL COMMENT '窗口终点',
  previous_sha256 CHAR(64) NULL COMMENT '前一原件摘要',
  content_sha256 CHAR(64) NOT NULL COMMENT '当前完整 payload JCS 摘要',
  payload_json JSON NOT NULL COMMENT '计数、时钟、配置与构建身份',
  verification_status VARCHAR(32) NOT NULL COMMENT 'healthy 或具体不合格码',
  received_at DATETIME(6) NOT NULL COMMENT '真实接收时间',
  PRIMARY KEY (id),
  UNIQUE KEY uk_guard_capture_health_window_public (public_id),
  UNIQUE KEY uk_guard_health_sequence (sensor_id,observer_session_id,sequence_no),
  KEY idx_guard_health_range (asset_id,capture_scope_id,interval_end),
  FOREIGN KEY (sensor_id) REFERENCES sensor_agent(id) ON DELETE RESTRICT,
  FOREIGN KEY (asset_id) REFERENCES asset(id) ON DELETE RESTRICT,
  FOREIGN KEY (capture_scope_id) REFERENCES guard_capture_scope(id) ON DELETE RESTRICT,
  CHECK (interval_end>interval_start AND TIMESTAMPDIFF(MICROSECOND,interval_start,interval_end)<=5000000)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin COMMENT='独立认证健康原件与连续性裁决';

CREATE TABLE guard_executor (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT '外部 UUID',
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) COMMENT '创建时间，UTC',
  asset_id BIGINT UNSIGNED NOT NULL COMMENT '登记资产',
  api_client_id BIGINT UNSIGNED NOT NULL COMMENT '专用 executor 凭据',
  platform VARCHAR(32) NOT NULL COMMENT '实测平台',
  adapter_version VARCHAR(96) NOT NULL COMMENT '适配器版本',
  capability_hash CHAR(64) NULL COMMENT '启动能力摘要',
  boot_id CHAR(36) NULL COMMENT '执行器当前启动身份',
  status VARCHAR(24) NOT NULL DEFAULT 'pending' COMMENT 'pending active suspended revoked',
  last_heartbeat DATETIME(6) NULL COMMENT '最近认证心跳',
  health_json JSON NULL COMMENT '恢复状态及未知计数',
  revision BIGINT NOT NULL DEFAULT 1 COMMENT '并发版本',
  PRIMARY KEY (id),
  UNIQUE KEY uk_guard_executor_public (public_id),
  UNIQUE KEY uk_guard_executor_client (api_client_id),
  FOREIGN KEY (asset_id) REFERENCES asset(id) ON DELETE RESTRICT,
  FOREIGN KEY (api_client_id) REFERENCES api_client(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin COMMENT='独立执行凭据与实态健康';

CREATE TABLE guard_budget_target (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT '外部 UUID',
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) COMMENT '创建时间，UTC',
  asset_id BIGINT UNSIGNED NOT NULL COMMENT '登记资产',
  environment VARCHAR(24) NOT NULL COMMENT '认证环境',
  stable_target_token CHAR(64) NOT NULL COMMENT '本地持久密钥 HMAC，不是轮换 peerKey',
  resolver_executor_id BIGINT UNSIGNED NOT NULL COMMENT '可信解析器',
  scope_digest CHAR(64) NOT NULL COMMENT '规范目标作用域摘要',
  identity_status VARCHAR(24) NOT NULL DEFAULT 'verified' COMMENT '无法连续关联则拒绝',
  PRIMARY KEY (id),
  UNIQUE KEY uk_guard_budget_target_public (public_id),
  UNIQUE KEY uk_guard_budget_identity (asset_id,environment,stable_target_token),
  FOREIGN KEY (asset_id) REFERENCES asset(id) ON DELETE RESTRICT,
  FOREIGN KEY (resolver_executor_id) REFERENCES guard_executor(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin COMMENT='跨启动密钥代际策略的稳定预算身份';

CREATE TABLE guard_target_binding (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT '外部 UUID',
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) COMMENT '创建时间，UTC',
  target_ref CHAR(36) NOT NULL COMMENT '本机随机目标引用',
  budget_target_id BIGINT UNSIGNED NOT NULL COMMENT '稳定预算',
  executor_id BIGINT UNSIGNED NOT NULL COMMENT '认证解析器',
  executor_boot_id CHAR(36) NOT NULL COMMENT '执行启动',
  sensor_id BIGINT UNSIGNED NOT NULL COMMENT '采集身份',
  collector_boot_id CHAR(36) NOT NULL COMMENT '采集启动',
  capture_scope_id BIGINT UNSIGNED NOT NULL COMMENT '捕获域',
  peer_key CHAR(64) NOT NULL COMMENT '当代假名',
  key_epoch BIGINT NOT NULL COMMENT '假名代际',
  scope_digest CHAR(64) NOT NULL COMMENT '目标作用域摘要',
  expires_at DATETIME(6) NOT NULL COMMENT '本次绑定租约',
  payload_json JSON NOT NULL COMMENT '不含原始端点的完整绑定',
  content_sha256 CHAR(64) NOT NULL COMMENT '绑定 JCS 摘要',
  PRIMARY KEY (id),
  UNIQUE KEY uk_guard_target_binding_public (public_id),
  UNIQUE KEY uk_guard_target_ref (target_ref),
  FOREIGN KEY (budget_target_id) REFERENCES guard_budget_target(id) ON DELETE RESTRICT,
  FOREIGN KEY (executor_id) REFERENCES guard_executor(id) ON DELETE RESTRICT,
  FOREIGN KEY (sensor_id) REFERENCES sensor_agent(id) ON DELETE RESTRICT,
  FOREIGN KEY (capture_scope_id) REFERENCES guard_capture_scope(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin COMMENT='不可变 targetRef 与稳定预算关联';

CREATE TABLE guard_target_budget (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT '外部 UUID',
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) COMMENT '创建时间，UTC',
  budget_target_id BIGINT UNSIGNED NOT NULL COMMENT '稳定预算身份',
  charged_ms BIGINT NOT NULL DEFAULT 0 COMMENT '本周期区间并集计费',
  last_block_end_at DATETIME(6) NULL COMMENT '可信实际清零时间',
  last_evidence_at DATETIME(6) NULL COMMENT '最后合格攻击证据，预算拒绝仍推进',
  health_proof_sha256 CHAR(64) NULL COMMENT '最近自动恢复证明',
  cycle_started_at DATETIME(6) NOT NULL COMMENT '上次已审计恢复点',
  revision BIGINT NOT NULL DEFAULT 1 COMMENT '与预留串行的预算版本',
  PRIMARY KEY (id),
  UNIQUE KEY uk_guard_target_budget_public (public_id),
  UNIQUE KEY uk_guard_target_budget (budget_target_id),
  FOREIGN KEY (budget_target_id) REFERENCES guard_budget_target(id) ON DELETE RESTRICT,
  CHECK (charged_ms BETWEEN 0 AND 120000)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin COMMENT='稳定目标累计与恢复投影';

CREATE TABLE guard_asset_budget (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT '外部 UUID',
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) COMMENT '创建时间，UTC',
  asset_id BIGINT UNSIGNED NOT NULL COMMENT '登记资产',
  last_monotonic_at DATETIME(6) NOT NULL COMMENT '数据库推进时点，回退不能重开窗口',
  revision BIGINT NOT NULL DEFAULT 1 COMMENT '每次预留或恢复推进',
  PRIMARY KEY (id),
  UNIQUE KEY uk_guard_asset_budget_public (public_id),
  UNIQUE KEY uk_guard_asset_budget (asset_id),
  FOREIGN KEY (asset_id) REFERENCES asset(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin COMMENT='所有能力共享的额度锁与单调窗口';

CREATE TABLE guard_episode (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT '外部 UUID',
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) COMMENT '创建时间，UTC',
  asset_id BIGINT UNSIGNED NOT NULL COMMENT '登记资产',
  sensor_id BIGINT UNSIGNED NOT NULL COMMENT '采集身份',
  boot_id CHAR(36) NOT NULL COMMENT '证据启动边界',
  peer_key CHAR(64) NOT NULL COMMENT '证据对象',
  key_epoch BIGINT NOT NULL COMMENT '假名边界',
  direction VARCHAR(16) NOT NULL COMMENT '方向',
  transport VARCHAR(12) NOT NULL COMMENT '协议',
  service_port INT NOT NULL COMMENT '未知以零表示且不可动作',
  family VARCHAR(64) NOT NULL COMMENT '策略声明的任务家族',
  bundle_id BIGINT UNSIGNED NOT NULL COMMENT '确切版本组合',
  bucket_start DATETIME(6) NOT NULL COMMENT 'UTC 三十秒索引桶',
  revision BIGINT NOT NULL DEFAULT 1 COMMENT '决策追加版本',
  PRIMARY KEY (id),
  UNIQUE KEY uk_guard_episode_public (public_id),
  UNIQUE KEY uk_guard_episode (asset_id,sensor_id,boot_id,peer_key,key_epoch,direction,transport,service_port,family,bundle_id,bucket_start),
  FOREIGN KEY (asset_id) REFERENCES asset(id) ON DELETE RESTRICT,
  FOREIGN KEY (sensor_id) REFERENCES sensor_agent(id) ON DELETE RESTRICT,
  FOREIGN KEY (bundle_id) REFERENCES guard_release_bundle(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin COMMENT='对象服务版本与固定三十秒桶的证据聚合';

CREATE TABLE guard_episode_evidence (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT '外部 UUID',
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) COMMENT '创建时间，UTC',
  episode_id BIGINT UNSIGNED NOT NULL COMMENT '对象 episode',
  parent_connection_id CHAR(36) NOT NULL COMMENT '独立连接去重键',
  observation_id BIGINT UNSIGNED NOT NULL COMMENT '最新观察，即使降分也替换',
  inference_id BIGINT UNSIGNED NOT NULL COMMENT '绑定模型结果',
  score DOUBLE NULL COMMENT '不适用没有分数',
  as_of DATETIME(6) NOT NULL COMMENT '最新因果时间',
  PRIMARY KEY (id),
  UNIQUE KEY uk_guard_episode_evidence_public (public_id),
  UNIQUE KEY uk_guard_episode_parent (episode_id,parent_connection_id),
  FOREIGN KEY (episode_id) REFERENCES guard_episode(id) ON DELETE RESTRICT,
  FOREIGN KEY (observation_id) REFERENCES guard_observation(id) ON DELETE RESTRICT,
  FOREIGN KEY (inference_id) REFERENCES guard_inference(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin COMMENT='每个 parent 只保留最新快照的证据投影';

CREATE TABLE guard_decision (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT '外部 UUID',
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) COMMENT '创建时间，UTC',
  episode_id BIGINT UNSIGNED NOT NULL COMMENT '证据 episode',
  asset_id BIGINT UNSIGNED NOT NULL COMMENT '查询范围',
  bundle_id BIGINT UNSIGNED NOT NULL COMMENT '发布组合',
  decision_revision BIGINT NOT NULL COMMENT 'episode 内追加版本',
  decision_contract_version VARCHAR(96) NOT NULL COMMENT '决策语义版本',
  decision VARCHAR(24) NOT NULL COMMENT 'observe alert block_candidate',
  reason_code VARCHAR(96) NULL COMMENT '首个失败项',
  budget_target_id BIGINT UNSIGNED NULL COMMENT '稳定目标',
  budget_revision BIGINT NULL COMMENT '决策时预算版本',
  evidence_sha256 CHAR(64) NOT NULL COMMENT 'guard-evidence/1 JCS 摘要',
  evidence_json JSON NOT NULL COMMENT '完整可复算证据对象',
  decided_at DATETIME(6) NOT NULL COMMENT '真实决策时间',
  PRIMARY KEY (id),
  UNIQUE KEY uk_guard_decision_public (public_id),
  UNIQUE KEY uk_guard_decision_revision (episode_id,decision_revision),
  FOREIGN KEY (episode_id) REFERENCES guard_episode(id) ON DELETE RESTRICT,
  FOREIGN KEY (asset_id) REFERENCES asset(id) ON DELETE RESTRICT,
  FOREIGN KEY (bundle_id) REFERENCES guard_release_bundle(id) ON DELETE RESTRICT,
  FOREIGN KEY (budget_target_id) REFERENCES guard_budget_target(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin COMMENT='固定 T1 至 T9 顺序的不可变决策及完整证据';

CREATE TABLE guard_event_episode (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT '外部 UUID',
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) COMMENT '创建时间，UTC',
  event_id BIGINT UNSIGNED NOT NULL COMMENT '现有案件',
  episode_id BIGINT UNSIGNED NOT NULL COMMENT '对象证据',
  PRIMARY KEY (id),
  UNIQUE KEY uk_guard_event_episode_public (public_id),
  UNIQUE KEY uk_guard_event_episode (event_id,episode_id),
  FOREIGN KEY (event_id) REFERENCES security_event(id) ON DELETE RESTRICT,
  FOREIGN KEY (episode_id) REFERENCES guard_episode(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin COMMENT='人工案件链接不改变动作目标';

CREATE TABLE guard_action (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT '外部 UUID',
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) COMMENT '创建时间，UTC',
  decision_id BIGINT UNSIGNED NOT NULL COMMENT '不可变决策依据',
  asset_id BIGINT UNSIGNED NOT NULL COMMENT '登记资产',
  executor_id BIGINT UNSIGNED NOT NULL COMMENT '执行身份',
  budget_target_id BIGINT UNSIGNED NOT NULL COMMENT '稳定目标',
  budget_revision BIGINT NOT NULL COMMENT '预留预算版本',
  bundle_id BIGINT UNSIGNED NOT NULL COMMENT '确切发布组合',
  authorization_id BIGINT UNSIGNED NOT NULL COMMENT '执行授权',
  authorization_revision BIGINT NOT NULL COMMENT '执行授权版本',
  mode VARCHAR(12) NOT NULL COMMENT 'auto 或 manual',
  desired_state VARCHAR(24) NOT NULL DEFAULT 'active' COMMENT '请求意图',
  desired_revision BIGINT NOT NULL DEFAULT 1 COMMENT '撤销单调版本',
  observed_state VARCHAR(24) NOT NULL DEFAULT 'pending' COMMENT '可信执行状态',
  idempotency_key CHAR(36) NOT NULL COMMENT '永久动作去重键',
  target_snapshot JSON NOT NULL COMMENT '不含原始地址的冻结目标',
  block_until DATETIME(6) NOT NULL COMMENT '不可延长的预留截止',
  created_by BIGINT UNSIGNED NULL COMMENT '人工申请主体',
  approved_by BIGINT UNSIGNED NULL COMMENT '人工独立批准主体',
  revision BIGINT NOT NULL DEFAULT 1 COMMENT '并发版本',
  PRIMARY KEY (id),
  UNIQUE KEY uk_guard_action_public (public_id),
  UNIQUE KEY uk_guard_action_idempotency (idempotency_key),
  KEY idx_guard_action_asset (asset_id,created_at,observed_state),
  FOREIGN KEY (decision_id) REFERENCES guard_decision(id) ON DELETE RESTRICT,
  FOREIGN KEY (asset_id) REFERENCES asset(id) ON DELETE RESTRICT,
  FOREIGN KEY (executor_id) REFERENCES guard_executor(id) ON DELETE RESTRICT,
  FOREIGN KEY (budget_target_id) REFERENCES guard_budget_target(id) ON DELETE RESTRICT,
  FOREIGN KEY (bundle_id) REFERENCES guard_release_bundle(id) ON DELETE RESTRICT,
  FOREIGN KEY (authorization_id) REFERENCES asset_authorization(id) ON DELETE RESTRICT,
  FOREIGN KEY (created_by) REFERENCES sys_user(id) ON DELETE RESTRICT,
  FOREIGN KEY (approved_by) REFERENCES sys_user(id) ON DELETE RESTRICT,
  CHECK (mode IN ('auto','manual')),
  CHECK (desired_state IN ('active','revoked')),
  CHECK (observed_state IN ('pending','dispatched','applied','rejected','revoked','expired','uncertain','recovery_failed')),
  CHECK (approved_by IS NULL OR approved_by<>created_by)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin COMMENT='意图与实际规则状态分离的动作台账';

CREATE TABLE guard_budget_interval (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT '外部 UUID',
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) COMMENT '创建时间，UTC',
  budget_target_id BIGINT UNSIGNED NOT NULL COMMENT '稳定目标',
  action_id BIGINT UNSIGNED NOT NULL COMMENT '唯一动作',
  reserved_start DATETIME(6) NOT NULL COMMENT '预留开始',
  reserved_end DATETIME(6) NOT NULL COMMENT '预留结束',
  verified_end DATETIME(6) NULL COMMENT '实际清零事实',
  status VARCHAR(24) NOT NULL COMMENT 'reserved ended not_applied',
  proof_sha256 CHAR(64) NULL COMMENT '可信回执或核对摘要',
  PRIMARY KEY (id),
  UNIQUE KEY uk_guard_budget_interval_public (public_id),
  UNIQUE KEY uk_guard_interval_action (action_id),
  FOREIGN KEY (budget_target_id) REFERENCES guard_budget_target(id) ON DELETE RESTRICT,
  FOREIGN KEY (action_id) REFERENCES guard_action(id) ON DELETE RESTRICT,
  CHECK (reserved_end>reserved_start)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin COMMENT='动作预留与可信终结，恢复前不丢弃已消耗区间';

CREATE TABLE guard_budget_event (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT '外部 UUID',
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) COMMENT '创建时间，UTC',
  budget_target_id BIGINT UNSIGNED NOT NULL COMMENT '稳定预算',
  event_kind VARCHAR(24) NOT NULL COMMENT 'reserve reconcile reset evidence',
  old_revision BIGINT NOT NULL COMMENT '原预算版本',
  new_revision BIGINT NOT NULL COMMENT '新预算版本',
  before_json JSON NOT NULL COMMENT '原投影',
  after_json JSON NOT NULL COMMENT '新投影',
  proof_json JSON NOT NULL COMMENT '完整证明对象',
  proof_sha256 CHAR(64) NOT NULL COMMENT '证明 JCS 摘要',
  PRIMARY KEY (id),
  UNIQUE KEY uk_guard_budget_event_public (public_id),
  FOREIGN KEY (budget_target_id) REFERENCES guard_budget_target(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin COMMENT='预留、实态核对与自动恢复追加审计';

CREATE TABLE guard_command (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT '外部 UUID',
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) COMMENT '创建时间，UTC',
  action_id BIGINT UNSIGNED NOT NULL COMMENT '对应动作',
  executor_boot_id CHAR(36) NOT NULL COMMENT '签发时执行启动身份',
  payload_json JSON NOT NULL COMMENT '完整签名载荷',
  payload_sha256 CHAR(64) NOT NULL COMMENT 'JCS 摘要',
  key_id VARCHAR(96) NOT NULL COMMENT '控制面可信密钥引用',
  signature VARCHAR(128) NOT NULL COMMENT 'Ed25519 base64url 签名',
  issued_at DATETIME(6) NOT NULL COMMENT '签发时刻',
  apply_by DATETIME(6) NOT NULL COMMENT '最后应用时刻',
  lease_expires_at DATETIME(6) NOT NULL COMMENT '固定授权租约截止',
  PRIMARY KEY (id),
  UNIQUE KEY uk_guard_command_public (public_id),
  UNIQUE KEY uk_guard_command_action (action_id),
  FOREIGN KEY (action_id) REFERENCES guard_action(id) ON DELETE RESTRICT,
  CHECK (issued_at<=apply_by AND apply_by<lease_expires_at AND TIMESTAMPDIFF(MICROSECOND,issued_at,apply_by)<=5000000)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin COMMENT='Ed25519 签名的不可变短期命令';

CREATE TABLE guard_authorization_lease (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT '外部 UUID',
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) COMMENT '创建时间，UTC',
  command_id BIGINT UNSIGNED NOT NULL COMMENT '签名命令',
  authorization_id BIGINT UNSIGNED NOT NULL COMMENT '有效授权',
  revision BIGINT NOT NULL COMMENT '授权版本',
  expires_at DATETIME(6) NOT NULL COMMENT '不晚于授权结束',
  status VARCHAR(24) NOT NULL COMMENT 'active revoked',
  PRIMARY KEY (id),
  UNIQUE KEY uk_guard_authorization_lease_public (public_id),
  UNIQUE KEY uk_guard_lease_command (command_id),
  FOREIGN KEY (command_id) REFERENCES guard_command(id) ON DELETE RESTRICT,
  FOREIGN KEY (authorization_id) REFERENCES asset_authorization(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin COMMENT='签发时授权版本快照';

CREATE TABLE guard_revocation (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT '外部 UUID',
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) COMMENT '创建时间，UTC',
  action_id BIGINT UNSIGNED NOT NULL COMMENT '撤销动作',
  command_id BIGINT UNSIGNED NOT NULL COMMENT '确切命令',
  executor_id BIGINT UNSIGNED NOT NULL COMMENT '规则所有者',
  desired_revision BIGINT NOT NULL COMMENT '撤销版本',
  payload_json JSON NOT NULL COMMENT '不可变撤销任务',
  content_sha256 CHAR(64) NOT NULL COMMENT 'JCS 内容摘要',
  status VARCHAR(24) NOT NULL DEFAULT 'pending' COMMENT 'pending confirmed',
  PRIMARY KEY (id),
  UNIQUE KEY uk_guard_revocation_public (public_id),
  UNIQUE KEY uk_guard_revocation_revision (action_id,desired_revision),
  FOREIGN KEY (action_id) REFERENCES guard_action(id) ON DELETE RESTRICT,
  FOREIGN KEY (command_id) REFERENCES guard_command(id) ON DELETE RESTRICT,
  FOREIGN KEY (executor_id) REFERENCES guard_executor(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin COMMENT='先持久化意图，清理确认前持续领取';

CREATE TABLE guard_action_receipt (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT '外部 UUID',
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) COMMENT '创建时间，UTC',
  command_id BIGINT UNSIGNED NOT NULL COMMENT '所属命令',
  executor_id BIGINT UNSIGNED NOT NULL COMMENT '认证执行器',
  asset_id BIGINT UNSIGNED NOT NULL COMMENT '查询范围',
  revocation_id BIGINT UNSIGNED NULL COMMENT '对应撤销任务',
  status VARCHAR(24) NOT NULL COMMENT '回执状态',
  observed_at DATETIME(6) NOT NULL COMMENT '实际读取时刻',
  state_digest CHAR(64) NOT NULL COMMENT 'guard-state/1 摘要',
  content_sha256 CHAR(64) NOT NULL COMMENT '完整回执 JCS 摘要',
  payload_json JSON NOT NULL COMMENT '原始回执',
  projected BOOLEAN NOT NULL DEFAULT FALSE COMMENT '是否通过时序与实态核对',
  PRIMARY KEY (id),
  UNIQUE KEY uk_guard_action_receipt_public (public_id),
  FOREIGN KEY (command_id) REFERENCES guard_command(id) ON DELETE RESTRICT,
  FOREIGN KEY (executor_id) REFERENCES guard_executor(id) ON DELETE RESTRICT,
  FOREIGN KEY (asset_id) REFERENCES asset(id) ON DELETE RESTRICT,
  FOREIGN KEY (revocation_id) REFERENCES guard_revocation(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin COMMENT='独立机器认证的追加回执原件';

CREATE TABLE guard_reconciliation (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT '外部 UUID',
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) COMMENT '创建时间，UTC',
  executor_id BIGINT UNSIGNED NOT NULL COMMENT '认证执行器',
  asset_id BIGINT UNSIGNED NOT NULL COMMENT '资产范围',
  boot_id CHAR(36) NOT NULL COMMENT '核对进程启动身份',
  observed_at DATETIME(6) NOT NULL COMMENT '读取时刻',
  owned_state_sha256 CHAR(64) NOT NULL COMMENT '规范化状态摘要',
  payload_json JSON NOT NULL COMMENT '实际枚举与恢复错误',
  error_count INT NOT NULL COMMENT '恢复错误数量',
  PRIMARY KEY (id),
  UNIQUE KEY uk_guard_reconciliation_public (public_id),
  FOREIGN KEY (executor_id) REFERENCES guard_executor(id) ON DELETE RESTRICT,
  FOREIGN KEY (asset_id) REFERENCES asset(id) ON DELETE RESTRICT,
  KEY idx_guard_reconciliation_state (executor_id,owned_state_sha256,observed_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin COMMENT='完整枚举的实际规则状态，不能由时钟替代';

CREATE TABLE guard_automation_stop (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  public_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT '外部 UUID',
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) COMMENT '创建时间，UTC',
  asset_id BIGINT UNSIGNED NOT NULL COMMENT '暂停资产',
  bundle_id BIGINT UNSIGNED NULL COMMENT '可选特定发布组合',
  reason VARCHAR(1000) NOT NULL COMMENT '脱敏停止原因',
  requested_by BIGINT UNSIGNED NULL COMMENT '人工主体；系统故障为空',
  revoke_existing BOOLEAN NOT NULL COMMENT '是否请求清理已有规则',
  PRIMARY KEY (id),
  UNIQUE KEY uk_guard_automation_stop_public (public_id),
  FOREIGN KEY (asset_id) REFERENCES asset(id) ON DELETE RESTRICT,
  FOREIGN KEY (bundle_id) REFERENCES guard_release_bundle(id) ON DELETE RESTRICT,
  FOREIGN KEY (requested_by) REFERENCES sys_user(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_bin COMMENT='暂停新命令与异步清理分别登记';

-- 新权限仅添加到匹配职责的角色模板，不给现存用户增加角色或重置账号。
INSERT INTO sys_role(role_key,name,description,status,is_builtin) VALUES
 ('security_reviewer','安全审核员','v2 独立审核与停止能力','active',1),
 ('evidence_reviewer','证据复核员','v2 独立证据复核','active',1);

INSERT INTO sys_permission(permission_key,resource,action,description) SELECT 'action.read','action','read','v2 显式权限：action.read' WHERE NOT EXISTS(SELECT 1 FROM sys_permission WHERE permission_key='action.read');

INSERT INTO sys_permission(permission_key,resource,action,description) SELECT 'action.request','action','request','v2 显式权限：action.request' WHERE NOT EXISTS(SELECT 1 FROM sys_permission WHERE permission_key='action.request');

INSERT INTO sys_permission(permission_key,resource,action,description) SELECT 'action.revoke','action','revoke','v2 显式权限：action.revoke' WHERE NOT EXISTS(SELECT 1 FROM sys_permission WHERE permission_key='action.revoke');

INSERT INTO sys_permission(permission_key,resource,action,description) SELECT 'asset.manage','asset','manage','v2 显式权限：asset.manage' WHERE NOT EXISTS(SELECT 1 FROM sys_permission WHERE permission_key='asset.manage');

INSERT INTO sys_permission(permission_key,resource,action,description) SELECT 'audit.read','audit','read','v2 显式权限：audit.read' WHERE NOT EXISTS(SELECT 1 FROM sys_permission WHERE permission_key='audit.read');

INSERT INTO sys_permission(permission_key,resource,action,description) SELECT 'authorization.approve','authorization','approve','v2 显式权限：authorization.approve' WHERE NOT EXISTS(SELECT 1 FROM sys_permission WHERE permission_key='authorization.approve');

INSERT INTO sys_permission(permission_key,resource,action,description) SELECT 'authorization.request','authorization','request','v2 显式权限：authorization.request' WHERE NOT EXISTS(SELECT 1 FROM sys_permission WHERE permission_key='authorization.request');

INSERT INTO sys_permission(permission_key,resource,action,description) SELECT 'automation.stop','automation','stop','v2 显式权限：automation.stop' WHERE NOT EXISTS(SELECT 1 FROM sys_permission WHERE permission_key='automation.stop');

INSERT INTO sys_permission(permission_key,resource,action,description) SELECT 'bundle.approve','bundle','approve','v2 显式权限：bundle.approve' WHERE NOT EXISTS(SELECT 1 FROM sys_permission WHERE permission_key='bundle.approve');

INSERT INTO sys_permission(permission_key,resource,action,description) SELECT 'bundle.request','bundle','request','v2 显式权限：bundle.request' WHERE NOT EXISTS(SELECT 1 FROM sys_permission WHERE permission_key='bundle.request');

INSERT INTO sys_permission(permission_key,resource,action,description) SELECT 'dataset.manage','dataset','manage','v2 显式权限：dataset.manage' WHERE NOT EXISTS(SELECT 1 FROM sys_permission WHERE permission_key='dataset.manage');

INSERT INTO sys_permission(permission_key,resource,action,description) SELECT 'detection.read','detection','read','v2 显式权限：detection.read' WHERE NOT EXISTS(SELECT 1 FROM sys_permission WHERE permission_key='detection.read');

INSERT INTO sys_permission(permission_key,resource,action,description) SELECT 'evaluation.read','evaluation','read','v2 显式权限：evaluation.read' WHERE NOT EXISTS(SELECT 1 FROM sys_permission WHERE permission_key='evaluation.read');

INSERT INTO sys_permission(permission_key,resource,action,description) SELECT 'evaluation.run','evaluation','run','v2 显式权限：evaluation.run' WHERE NOT EXISTS(SELECT 1 FROM sys_permission WHERE permission_key='evaluation.run');

INSERT INTO sys_permission(permission_key,resource,action,description) SELECT 'event.manage','event','manage','v2 显式权限：event.manage' WHERE NOT EXISTS(SELECT 1 FROM sys_permission WHERE permission_key='event.manage');

INSERT INTO sys_permission(permission_key,resource,action,description) SELECT 'feedback.label','feedback','label','v2 显式权限：feedback.label' WHERE NOT EXISTS(SELECT 1 FROM sys_permission WHERE permission_key='feedback.label');

INSERT INTO sys_permission(permission_key,resource,action,description) SELECT 'feedback.review','feedback','review','v2 显式权限：feedback.review' WHERE NOT EXISTS(SELECT 1 FROM sys_permission WHERE permission_key='feedback.review');

INSERT INTO sys_permission(permission_key,resource,action,description) SELECT 'iam.manage','iam','manage','v2 显式权限：iam.manage' WHERE NOT EXISTS(SELECT 1 FROM sys_permission WHERE permission_key='iam.manage');

INSERT INTO sys_permission(permission_key,resource,action,description) SELECT 'machine.command.claim','machine.command','claim','v2 显式权限：machine.command.claim' WHERE NOT EXISTS(SELECT 1 FROM sys_permission WHERE permission_key='machine.command.claim');

INSERT INTO sys_permission(permission_key,resource,action,description) SELECT 'machine.executor.health','machine.executor','health','v2 显式权限：machine.executor.health' WHERE NOT EXISTS(SELECT 1 FROM sys_permission WHERE permission_key='machine.executor.health');

INSERT INTO sys_permission(permission_key,resource,action,description) SELECT 'machine.observation.write','machine.observation','write','v2 显式权限：machine.observation.write' WHERE NOT EXISTS(SELECT 1 FROM sys_permission WHERE permission_key='machine.observation.write');

INSERT INTO sys_permission(permission_key,resource,action,description) SELECT 'machine.receipt.write','machine.receipt','write','v2 显式权限：machine.receipt.write' WHERE NOT EXISTS(SELECT 1 FROM sys_permission WHERE permission_key='machine.receipt.write');

INSERT INTO sys_permission(permission_key,resource,action,description) SELECT 'machine.sensor.health','machine.sensor','health','v2 显式权限：machine.sensor.health' WHERE NOT EXISTS(SELECT 1 FROM sys_permission WHERE permission_key='machine.sensor.health');

INSERT INTO sys_permission(permission_key,resource,action,description) SELECT 'machine.sensor.read','machine.sensor','read','v2 显式权限：machine.sensor.read' WHERE NOT EXISTS(SELECT 1 FROM sys_permission WHERE permission_key='machine.sensor.read');

INSERT INTO sys_permission(permission_key,resource,action,description) SELECT 'machine.target.bind','machine.target','bind','v2 显式权限：machine.target.bind' WHERE NOT EXISTS(SELECT 1 FROM sys_permission WHERE permission_key='machine.target.bind');

INSERT INTO sys_permission(permission_key,resource,action,description) SELECT 'model.manage','model','manage','v2 显式权限：model.manage' WHERE NOT EXISTS(SELECT 1 FROM sys_permission WHERE permission_key='model.manage');

INSERT INTO sys_permission(permission_key,resource,action,description) SELECT 'model.validate','model','validate','v2 显式权限：model.validate' WHERE NOT EXISTS(SELECT 1 FROM sys_permission WHERE permission_key='model.validate');

INSERT INTO sys_permission(permission_key,resource,action,description) SELECT 'ops.read','ops','read','v2 显式权限：ops.read' WHERE NOT EXISTS(SELECT 1 FROM sys_permission WHERE permission_key='ops.read');

INSERT INTO sys_permission(permission_key,resource,action,description) SELECT 'policy.approve','policy','approve','v2 显式权限：policy.approve' WHERE NOT EXISTS(SELECT 1 FROM sys_permission WHERE permission_key='policy.approve');

INSERT INTO sys_permission(permission_key,resource,action,description) SELECT 'policy.draft','policy','draft','v2 显式权限：policy.draft' WHERE NOT EXISTS(SELECT 1 FROM sys_permission WHERE permission_key='policy.draft');

INSERT INTO sys_permission(permission_key,resource,action,description) SELECT 'resource.read','resource','read','v2 显式权限：resource.read' WHERE NOT EXISTS(SELECT 1 FROM sys_permission WHERE permission_key='resource.read');

INSERT INTO sys_permission(permission_key,resource,action,description) SELECT 'sensor.manage','sensor','manage','v2 显式权限：sensor.manage' WHERE NOT EXISTS(SELECT 1 FROM sys_permission WHERE permission_key='sensor.manage');

INSERT INTO sys_role_permission(role_id,permission_id) SELECT r.id,p.id FROM sys_role r CROSS JOIN sys_permission p WHERE r.role_key='platform_admin' AND p.permission_key IN ('resource.read','iam.manage','asset.manage','sensor.manage','authorization.request','ops.read') AND NOT EXISTS(SELECT 1 FROM sys_role_permission rp WHERE rp.role_id=r.id AND rp.permission_id=p.id);

INSERT INTO sys_role_permission(role_id,permission_id) SELECT r.id,p.id FROM sys_role r CROSS JOIN sys_permission p WHERE r.role_key='security_reviewer' AND p.permission_key IN ('resource.read','authorization.approve','bundle.approve','policy.approve','evaluation.read','detection.read','action.read','action.revoke','automation.stop') AND NOT EXISTS(SELECT 1 FROM sys_role_permission rp WHERE rp.role_id=r.id AND rp.permission_id=p.id);

INSERT INTO sys_role_permission(role_id,permission_id) SELECT r.id,p.id FROM sys_role r CROSS JOIN sys_permission p WHERE r.role_key='model_operator' AND p.permission_key IN ('resource.read','dataset.manage','model.manage','model.validate','evaluation.run','evaluation.read','policy.draft','bundle.request') AND NOT EXISTS(SELECT 1 FROM sys_role_permission rp WHERE rp.role_id=r.id AND rp.permission_id=p.id);

INSERT INTO sys_role_permission(role_id,permission_id) SELECT r.id,p.id FROM sys_role r CROSS JOIN sys_permission p WHERE r.role_key='security_analyst' AND p.permission_key IN ('resource.read','detection.read','event.manage','feedback.label','action.read','action.request') AND NOT EXISTS(SELECT 1 FROM sys_role_permission rp WHERE rp.role_id=r.id AND rp.permission_id=p.id);

INSERT INTO sys_role_permission(role_id,permission_id) SELECT r.id,p.id FROM sys_role r CROSS JOIN sys_permission p WHERE r.role_key='evidence_reviewer' AND p.permission_key IN ('resource.read','feedback.review','evaluation.read','detection.read') AND NOT EXISTS(SELECT 1 FROM sys_role_permission rp WHERE rp.role_id=r.id AND rp.permission_id=p.id);

INSERT INTO sys_role_permission(role_id,permission_id) SELECT r.id,p.id FROM sys_role r CROSS JOIN sys_permission p WHERE r.role_key='auditor' AND p.permission_key IN ('resource.read','audit.read','evaluation.read','action.read') AND NOT EXISTS(SELECT 1 FROM sys_role_permission rp WHERE rp.role_id=r.id AND rp.permission_id=p.id);
