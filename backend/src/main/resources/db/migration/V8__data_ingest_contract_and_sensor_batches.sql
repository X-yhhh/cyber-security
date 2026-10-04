-- 数据接入模块：为传感器批次增加配置/序号/契约追溯，并隔离 sensor 机器主体。
-- 仅新增可为空追溯列，保证既有 connector 批次和凭据数据可继续读取。
ALTER TABLE `api_client`
  ADD COLUMN `sensor_id` BIGINT UNSIGNED DEFAULT NULL COMMENT 'sensor 机器主体绑定的传感器' AFTER `client_type`,
  ADD KEY `idx_api_client_sensor` (`sensor_id`),
  ADD CONSTRAINT `fk_api_client_sensor` FOREIGN KEY (`sensor_id`) REFERENCES `sensor_agent` (`id`) ON DELETE RESTRICT,
  ADD CONSTRAINT `ck_api_client_sensor_type` CHECK (`sensor_id` IS NULL OR `client_type` = 'sensor');

ALTER TABLE `ingest_batch`
  ADD COLUMN `sensor_id` BIGINT UNSIGNED DEFAULT NULL COMMENT '传感器来源；connector 批次为空' AFTER `data_source_id`,
  ADD COLUMN `config_version` VARCHAR(64) DEFAULT NULL COMMENT '传感器配置版本' AFTER `sensor_id`,
  ADD COLUMN `sequence_no` BIGINT UNSIGNED DEFAULT NULL COMMENT '主体/配置作用域内单调序号' AFTER `config_version`,
  ADD COLUMN `sequence_gap` BOOLEAN NOT NULL DEFAULT FALSE COMMENT '服务端观察到的序号缺口' AFTER `sequence_no`,
  ADD COLUMN `feature_contract_version` VARCHAR(64) DEFAULT NULL COMMENT '服务端复核的特征契约' AFTER `sequence_gap`,
  ADD UNIQUE KEY `uk_ingest_batch_sensor_config_sequence` (`sensor_id`, `config_version`, `sequence_no`),
  ADD CONSTRAINT `fk_ingest_batch_sensor` FOREIGN KEY (`sensor_id`) REFERENCES `sensor_agent` (`id`) ON DELETE RESTRICT,
  ADD CONSTRAINT `ck_ingest_batch_sensor_sequence` CHECK ((`sensor_id` IS NULL AND `sequence_no` IS NULL)
      OR (`sensor_id` IS NOT NULL AND `sequence_no` IS NOT NULL AND `config_version` IS NOT NULL)),
  ADD CONSTRAINT `ck_ingest_batch_contract_version` CHECK (`feature_contract_version` IS NULL OR CHAR_LENGTH(`feature_contract_version`) <= 64);

INSERT INTO `sys_permission` (`permission_key`, `resource`, `action`, `description`)
VALUES
  ('machine.sensor.heartbeat', 'machine.sensor', 'heartbeat', '传感器机器主体提交心跳摘要'),
  ('machine.sensor.config.read', 'machine.sensor', 'config.read', '传感器机器主体读取批准配置'),
  ('machine.sensor.ingest', 'machine.sensor', 'ingest', '传感器机器主体提交契约化流批次');
