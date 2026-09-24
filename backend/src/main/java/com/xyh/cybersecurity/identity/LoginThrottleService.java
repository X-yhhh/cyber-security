package com.xyh.cybersecurity.identity;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;

/** 跨实例持久化登录失败冷却状态；数据库只保存带密钥的用户名/IP 摘要。 */
@Service
public class LoginThrottleService {

    private static final int MAX_FAILURES = 5;
    private static final Duration WINDOW = Duration.ofMinutes(15);
    private final JdbcTemplate jdbcTemplate;
    private final byte[] hmacKey;
    private final Clock clock;

    public LoginThrottleService(JdbcTemplate jdbcTemplate,
                                @Value("${cyber.security.login-throttle.hmac-key}") String hmacKey,
                                Clock clock) {
        if (hmacKey.getBytes(StandardCharsets.UTF_8).length < 32) {
            throw new IllegalArgumentException("Login throttle HMAC key must contain at least 32 bytes");
        }
        this.jdbcTemplate = jdbcTemplate;
        this.hmacKey = hmacKey.getBytes(StandardCharsets.UTF_8);
        this.clock = clock;
    }

    public boolean isBlocked(String username, String remoteAddress) {
        Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM auth_login_throttle WHERE principal_key_hash=? AND blocked_until > ?",
                Integer.class, key(username, remoteAddress), Timestamp.from(clock.instant()));
        return count != null && count > 0;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordFailure(String username, String remoteAddress) {
        Instant now = clock.instant();
        jdbcTemplate.update("INSERT INTO auth_login_throttle "
                        + "(principal_key_hash, window_started_at, failed_attempts, blocked_until) VALUES (?, ?, 1, NULL) "
                        + "ON DUPLICATE KEY UPDATE "
                        + "failed_attempts=IF(window_started_at < DATE_SUB(VALUES(window_started_at), INTERVAL 15 MINUTE), "
                        + "1, LEAST(failed_attempts + 1, 5)), "
                        + "blocked_until=IF(failed_attempts >= 5, DATE_ADD(VALUES(window_started_at), INTERVAL 15 MINUTE), blocked_until), "
                        + "window_started_at=IF(window_started_at < DATE_SUB(VALUES(window_started_at), INTERVAL 15 MINUTE), "
                        + "VALUES(window_started_at), window_started_at)",
                key(username, remoteAddress), Timestamp.from(now));
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void clearFailures(String username, String remoteAddress) {
        jdbcTemplate.update("DELETE FROM auth_login_throttle WHERE principal_key_hash=?", key(username, remoteAddress));
    }

    private String key(String username, String remoteAddress) {
        String value = username.strip().toLowerCase(java.util.Locale.ROOT) + "\n" + remoteAddress;
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(hmacKey, "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal(value.getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.GeneralSecurityException exception) {
            throw new IllegalStateException("HMAC-SHA-256 is unavailable", exception);
        }
    }
}
