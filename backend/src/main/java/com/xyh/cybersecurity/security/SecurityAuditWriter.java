package com.xyh.cybersecurity.security;

import com.xyh.cybersecurity.identity.IdentityPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.sql.Timestamp;
import java.time.Instant;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/** 记录脱敏的认证/授权拒绝，不写请求参数、Cookie 或权限凭据。 */
@Component
public class SecurityAuditWriter {

    private final JdbcTemplate jdbcTemplate;

    public SecurityAuditWriter(JdbcTemplate jdbcTemplate) { this.jdbcTemplate = jdbcTemplate; }

    public void denied(HttpServletRequest request, Authentication authentication, String action, String reason) {
        Long actorId = authentication != null && authentication.getPrincipal() instanceof IdentityPrincipal principal
                ? principal.id() : null;
        Object requestId = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        jdbcTemplate.update("INSERT INTO audit_log "
                        + "(occurred_at, actor_type, actor_id, action, resource_type, resource_id, request_id, outcome, reason) "
                        + "VALUES (?, ?, ?, ?, 'api', ?, ?, 'denied', ?)",
                Timestamp.from(Instant.now()), actorId == null ? "anonymous" : "human",
                actorId == null ? null : actorId.toString(), action, request.getRequestURI(),
                requestId instanceof String value ? value : null, reason);
    }
}
