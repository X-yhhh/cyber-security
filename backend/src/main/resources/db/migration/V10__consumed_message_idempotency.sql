-- 异步消费者幂等台账：MySQL 是消费结果事实源，消息重复投递不会重复提交推理任务。
CREATE TABLE `consumed_message` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '内部主键',
  `consumer` VARCHAR(96) NOT NULL COMMENT '消费者稳定名称',
  `message_key` VARCHAR(255) NOT NULL COMMENT '消息 eventKey 或安全派生键',
  `status` VARCHAR(24) NOT NULL COMMENT 'processing、retrying、consumed 或 dead_lettered',
  `attempts` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '已记录的失败尝试次数',
  `last_error_code` VARCHAR(96) DEFAULT NULL COMMENT '最近一次安全错误码',
  `last_error_message` VARCHAR(500) DEFAULT NULL COMMENT '最近一次脱敏错误摘要',
  `consumed_at` DATETIME(3) DEFAULT NULL COMMENT '业务结果提交完成时间，UTC',
  `updated_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3) COMMENT '更新时间，UTC',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_consumed_message_consumer_key` (`consumer`, `message_key`),
  KEY `idx_consumed_message_status_updated` (`status`, `updated_at`),
  CONSTRAINT `ck_consumed_message_status` CHECK (`status` IN ('processing', 'retrying', 'consumed', 'dead_lettered'))
) ENGINE=InnoDB COMMENT='异步消息消费幂等与失败台账';
