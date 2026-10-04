-- V11：路线 B 阶段 3。为来源映射与传感器配置登记“契约版本 + 契约文件 SHA-256”，
-- 证明映射/配置批准时绑定的契约内容与运行时注册表加载的内容一致（路线 B §3.3、§19.1）。
-- 历史行保持 NULL：v3.1 永不在线；服务层对 onlineEnabled 契约要求哈希非空且与注册表一致，
-- 注册表中的契约文件一旦变化，旧配置即视为失效（CONFIG_VERSION_STALE），需重新批准。
-- 哈希由服务端按注册表写入，不接受客户端传入。
-- REGEXP_LIKE 的 'c' 参数强制区分大小写：库默认排序规则 utf8mb4_0900_ai_ci 不区分大小写，
-- 不加该参数时大写十六进制也能通过校验。

ALTER TABLE `sensor_config`
  ADD COLUMN `feature_contract_sha256` CHAR(64) DEFAULT NULL COMMENT '批准时契约文件 SHA-256（小写十六进制）' AFTER `feature_contract_version`,
  ADD CONSTRAINT `ck_sensor_config_contract_sha256`
    CHECK (`feature_contract_sha256` IS NULL OR REGEXP_LIKE(`feature_contract_sha256`, '^[0-9a-f]{64}$', 'c'));

ALTER TABLE `source_mapping`
  ADD COLUMN `feature_contract_version` VARCHAR(64) DEFAULT NULL COMMENT '映射绑定的特征契约版本' AFTER `mapping_json`,
  ADD COLUMN `feature_contract_sha256` CHAR(64) DEFAULT NULL COMMENT '绑定时契约文件 SHA-256（小写十六进制）' AFTER `feature_contract_version`,
  ADD CONSTRAINT `ck_source_mapping_contract_pair`
    CHECK ((`feature_contract_version` IS NULL) = (`feature_contract_sha256` IS NULL)),
  ADD CONSTRAINT `ck_source_mapping_contract_sha256`
    CHECK (`feature_contract_sha256` IS NULL OR REGEXP_LIKE(`feature_contract_sha256`, '^[0-9a-f]{64}$', 'c'));
