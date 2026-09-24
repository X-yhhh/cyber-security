-- 连接器权限必须绑定明确的数据源与资产组合，避免独立范围形成笛卡尔积。
CREATE TABLE `api_client_source_asset_scope` (
  `client_id` BIGINT UNSIGNED NOT NULL COMMENT '机器主体主键',
  `data_source_id` BIGINT UNSIGNED NOT NULL COMMENT '允许接入的数据源',
  `asset_id` BIGINT UNSIGNED NOT NULL COMMENT '该数据源允许关联的资产',
  `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '授权创建时间，UTC',
  PRIMARY KEY (`client_id`, `data_source_id`, `asset_id`),
  KEY `idx_api_client_source_asset_lookup` (`data_source_id`, `asset_id`, `client_id`),
  CONSTRAINT `fk_client_source_asset_client` FOREIGN KEY (`client_id`) REFERENCES `api_client` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `fk_client_source_asset_source` FOREIGN KEY (`data_source_id`) REFERENCES `data_source` (`id`) ON DELETE RESTRICT,
  CONSTRAINT `fk_client_source_asset_asset` FOREIGN KEY (`asset_id`) REFERENCES `asset` (`id`) ON DELETE RESTRICT
) ENGINE=InnoDB COMMENT='机器主体显式数据源-资产配对授权';
