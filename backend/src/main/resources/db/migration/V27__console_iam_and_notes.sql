-- B4/DB-11：只追加控制台身份与资料投影，不改已有行的原字段、权限矩阵、冻结清单或已执行迁移。
-- 默认 builtin=TRUE 保护六个 v2 内置角色及三个已停用 v1 角色；新自定义角色必须由应用显式写 FALSE。
ALTER TABLE sys_role
  ADD COLUMN builtin BOOLEAN NOT NULL DEFAULT TRUE COMMENT '内置角色只读，自定义角色由应用显式置为 FALSE',
  ADD COLUMN revision BIGINT NOT NULL DEFAULT 1 COMMENT '角色资料、权限与状态的乐观锁修订号';

ALTER TABLE asset
  ADD COLUMN display_name VARCHAR(128) NULL COMMENT '控制台显示名，不参与授权范围或身份绑定',
  ADD COLUMN notes VARCHAR(1000) NULL COMMENT '控制台资料说明，不存秘密或原始遥测';

ALTER TABLE sensor_agent
  ADD COLUMN display_name VARCHAR(128) NULL COMMENT '控制台显示名，不改变机器身份',
  ADD COLUMN notes VARCHAR(1000) NULL COMMENT '控制台资料说明，不存凭据';

ALTER TABLE guard_executor
  ADD COLUMN display_name VARCHAR(128) NULL COMMENT '控制台显示名，不改变执行器身份',
  ADD COLUMN notes VARCHAR(1000) NULL COMMENT '控制台资料说明，不存凭据',
  ADD COLUMN updated_at DATETIME(6) NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP(6) COMMENT '可变投影更新时间，历史 NULL 按创建时间读取';

-- 原表为不可变清单；状态与修订只管理资料投影，payload 与原件摘要不能修改。
ALTER TABLE guard_dataset
  ADD COLUMN display_name VARCHAR(128) NULL COMMENT '控制台显示名，不参与冻结清单',
  ADD COLUMN notes VARCHAR(1000) NULL COMMENT '控制台资料说明，不参与冻结清单',
  ADD COLUMN status VARCHAR(24) NOT NULL DEFAULT 'active' COMMENT '资料生命周期，active 或 retired',
  ADD COLUMN revision BIGINT NOT NULL DEFAULT 1 COMMENT '资料编辑与退役的乐观锁修订号',
  ADD COLUMN updated_at DATETIME(6) NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP(6) COMMENT '可变投影更新时间，历史 NULL 按创建时间读取',
  ADD CONSTRAINT ck_guard_dataset_status CHECK (status IN ('active','retired'));

ALTER TABLE guard_model
  ADD COLUMN display_name VARCHAR(128) NULL COMMENT '控制台显示名，不参与 manifest 或制品哈希',
  ADD COLUMN notes VARCHAR(1000) NULL COMMENT '控制台资料说明，不参与 manifest 或制品哈希',
  ADD COLUMN revision BIGINT NOT NULL DEFAULT 1 COMMENT '资料、校验与退役共享的乐观锁修订号',
  ADD COLUMN updated_at DATETIME(6) NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP(6) COMMENT '可变投影更新时间，历史 NULL 按创建时间读取';

ALTER TABLE guard_decision_policy
  ADD COLUMN display_name VARCHAR(128) NULL COMMENT '控制台显示名，不改变冻结策略正文',
  ADD COLUMN notes VARCHAR(1000) NULL COMMENT '控制台资料说明，不改变冻结策略正文',
  ADD COLUMN updated_at DATETIME(6) NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP(6) COMMENT '可变投影更新时间，历史 NULL 按创建时间读取';

ALTER TABLE guard_release_bundle
  ADD COLUMN updated_at DATETIME(6) NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP(6) COMMENT '组合投影更新时间，不改变 subject 或封存证据';
