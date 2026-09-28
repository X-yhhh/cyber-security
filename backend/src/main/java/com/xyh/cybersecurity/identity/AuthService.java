package com.xyh.cybersecurity.identity;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import com.xyh.cybersecurity.audit.AuditMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.List;
import com.xyh.cybersecurity.security.AbsoluteSessionFilter;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/** 处理人工登录、权限摘要、退出及追加式身份审计。 */
@Service
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final SecurityContextRepository contextRepository;
    private final IdentityMapper identityMapper;
    private final AuditMapper auditMapper;
    private final LoginThrottleService loginThrottleService;

    public AuthService(AuthenticationManager authenticationManager, SecurityContextRepository contextRepository,
                       IdentityMapper identityMapper, AuditMapper auditMapper, LoginThrottleService loginThrottleService) {
        this.authenticationManager = authenticationManager;
        this.contextRepository = contextRepository;
        this.identityMapper = identityMapper;
        this.auditMapper = auditMapper;
        this.loginThrottleService = loginThrottleService;
    }

    public SessionUser login(String username, String password, HttpServletRequest request,
                             HttpServletResponse response) {
        String remoteAddress = request.getRemoteAddr();
        if (loginThrottleService.isBlocked(username, remoteAddress)) {
            throw new LoginRateLimitException();
        }
        try {
            Authentication authentication = authenticationManager.authenticate(
                    UsernamePasswordAuthenticationToken.unauthenticated(username, password));
            IdentityPrincipal principal = (IdentityPrincipal) authentication.getPrincipal();
            identityMapper.updateLastLogin(principal.id(), Instant.now());
            loginThrottleService.clearFailures(username, remoteAddress);
            identityMapper.deleteSession(principal.getUsername());
            writeAudit(request, principal.id(), "auth.login", "success", "authenticated");

            if (request.getSession(false) == null) {
                request.getSession(true);
            }
            request.changeSessionId();
            request.getSession(false).setAttribute(AbsoluteSessionFilter.CREATED_AT_ATTRIBUTE, Instant.now().toEpochMilli());
            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authentication);
            SecurityContextHolder.setContext(context);
            contextRepository.saveContext(context, request, response);
            return SessionUser.from(principal);
        } catch (org.springframework.security.core.AuthenticationException exception) {
            SecurityContextHolder.clearContext();
            loginThrottleService.recordFailure(username, remoteAddress);
            writeAudit(request, null, "auth.login", "denied", "invalid_credentials");
            throw exception;
        }
    }

    @Transactional
    public void logout(IdentityPrincipal principal, HttpServletRequest request) {
        writeAudit(request, principal.id(), "auth.logout", "success", "session_revoked");
    }

    private void writeAudit(HttpServletRequest request, Long actorId, String action, String outcome, String reason) {
        Object requestId = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        auditMapper.insertAudit(new AuditMapper.AuditInsert(LocalDateTime.now(), "human",
                actorId == null ? null : actorId.toString(), action, "system", null,
                requestId instanceof String value ? value : null, outcome, reason));
    }

    public record SessionUser(long id, String userKey, String username, String displayName,
                              List<String> roles, List<String> permissions) {
        public static SessionUser from(IdentityPrincipal principal) {
            return new SessionUser(principal.id(), principal.userKey(), principal.getUsername(),
                    principal.displayName(), principal.roles(), principal.permissions());
        }
    }

    public static final class LoginRateLimitException extends RuntimeException {
        public LoginRateLimitException() {
            super("Login rate limit exceeded");
        }
    }
}
