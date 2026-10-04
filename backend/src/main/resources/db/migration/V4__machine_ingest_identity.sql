-- 为连接器增加独立机器凭据验证材料和批次幂等内容摘要；历史凭据不被推断或激活。
ALTER TABLE `api_client`
  ADD COLUMN `client_type` VARCHAR(32) NOT NULL DEFAULT 'connector' COMMENT '机器主体类型；仅 connector 可使用本批接入接口' AFTER `client_key`,
  ADD COLUMN `credential_sha256` CHAR(64) DEFAULT NULL COMMENT '高熵一次性机器凭据的 SHA-256 验证值' AFTER `secret_ref`,
  ADD CONSTRAINT `ck_api_client_type` CHECK (`client_type` IN ('connector', 'sensor', 'response_adapter')),
  ADD CONSTRAINT `ck_api_client_credential_sha256` CHECK (`credential_sha256` IS NULL OR `credential_sha256` REGEXP '^[0-9A-Fa-f]{64}$');

ALTER TABLE `ingest_batch`
  ADD COLUMN `request_sha256` CHAR(64) DEFAULT NULL COMMENT '幂等键绑定的规范化请求摘要' AFTER `idempotency_key`,
  ADD CONSTRAINT `ck_ingest_batch_request_sha256` CHECK (`request_sha256` IS NULL OR `request_sha256` REGEXP '^[0-9A-Fa-f]{64}$');

INSERT INTO `sys_permission` (`permission_key`, `resource`, `action`, `description`)
VALUES ('machine.ingest.submit', 'machine.ingest', 'submit', '连接器主体提交授权数据源的规范化批次');
