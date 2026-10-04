package com.xyh.cybersecurity.identity;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;

/** 跨实例持久化登录失败冷却状态；数据库只保存带密钥的用户名/IP 摘要。 */
@Service
public class LoginThrottleService {

    private static final int MAX_FAILURES = 5;
    private static final Duration WINDOW = Duration.ofMinutes(15);
    private final IdentityMapper identityMapper;
    private final byte[] hmacKey;
    private final Clock clock;

    public LoginThrottleService(IdentityMapper identityMapper,
                                @Value("${cyber.security.login-throttle.hmac-key}") String hmacKey,
                                Clock clock) {
        if (hmacKey.getBytes(StandardCharsets.UTF_8).length < 32) {
            throw new IllegalArgumentException("Login throttle HMAC key must contain at least 32 bytes");
        }
        this.identityMapper = identityMapper;
        this.hmacKey = hmacKey.getBytes(StandardCharsets.UTF_8);
        this.clock = clock;
    }

    public boolean isBlocked(String username, String remoteAddress) {
        return identityMapper.countBlockedThrottle(key(username, remoteAddress), clock.instant()) > 0;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordFailure(String username, String remoteAddress) {
        Instant now = clock.instant();
        identityMapper.upsertThrottleFailure(key(username, remoteAddress), now);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void clearFailures(String username, String remoteAddress) {
        identityMapper.clearThrottle(key(username, remoteAddress));
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
