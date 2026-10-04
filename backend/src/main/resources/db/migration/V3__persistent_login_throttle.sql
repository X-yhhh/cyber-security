-- 登录失败节流仅保存 HMAC 键，不持久化用户名、来源 IP 或凭据内容。
CREATE TABLE `auth_login_throttle` (
  `principal_key_hash` CHAR(64) NOT NULL COMMENT '用户名与来源地址的 HMAC-SHA-256 标识',
  `window_started_at` DATETIME(3) NOT NULL COMMENT '当前计数窗口起点，UTC',
  `failed_attempts` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '当前窗口失败次数',
  `blocked_until` DATETIME(3) DEFAULT NULL COMMENT '达到阈值后的冷却截止时间，UTC',
  `updated_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3) COMMENT '更新时间，UTC',
  PRIMARY KEY (`principal_key_hash`),
  KEY `idx_auth_login_throttle_updated` (`updated_at`),
  KEY `idx_auth_login_throttle_blocked` (`blocked_until`),
  CONSTRAINT `ck_auth_login_throttle_failed_attempts` CHECK (`failed_attempts` <= 5)
) ENGINE=InnoDB COMMENT='人工登录失败节流窗口';
