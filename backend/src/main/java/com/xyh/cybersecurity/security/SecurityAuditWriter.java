package com.xyh.cybersecurity.security;

import com.xyh.cybersecurity.identity.IdentityPrincipal;
import com.xyh.cybersecurity.audit.AuditMapper;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/** 记录脱敏的认证/授权拒绝，不写请求参数、Cookie 或权限凭据。 */
@Component
public class SecurityAuditWriter {

    private final AuditMapper auditMapper;

    public SecurityAuditWriter(AuditMapper auditMapper) { this.auditMapper = auditMapper; }

    /**
     * 拒绝审计必须独立提交；调用方常处于即将回滚的业务事务中，不能让拒绝事实随异常丢失。
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void denied(HttpServletRequest request, Authentication authentication, String action, String reason) {
        Long actorId = authentication != null && authentication.getPrincipal() instanceof IdentityPrincipal principal
                ? principal.id() : null;
        Object requestId = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        auditMapper.insertAudit(new AuditMapper.AuditInsert(LocalDateTime.now(java.time.Clock.systemUTC()),
                actorId == null ? "anonymous" : "human",
                actorId == null ? null : actorId.toString(), action, "api", request.getRequestURI(),
                requestId instanceof String value ? value : null, "denied", reason));
    }
}
