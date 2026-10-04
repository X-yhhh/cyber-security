package com.xyh.cybersecurity.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.xyh.cybersecurity.common.api.ApiEnvelope;
import com.xyh.cybersecurity.common.web.RequestIdFilter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;

/** 按登录建立时间实施八小时绝对会话寿命，不受持续访问刷新空闲 TTL 影响。 */
public class AbsoluteSessionFilter extends OncePerRequestFilter {

    public static final String CREATED_AT_ATTRIBUTE = AbsoluteSessionFilter.class.getName() + ".createdAt";
    private static final Duration ABSOLUTE_LIFETIME = Duration.ofHours(8);
    private final Clock clock;
    private final ObjectMapper objectMapper;

    public AbsoluteSessionFilter(Clock clock, ObjectMapper objectMapper) {
        this.clock = clock;
        this.objectMapper = objectMapper;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()
                && !(authentication instanceof org.springframework.security.authentication.AnonymousAuthenticationToken)) {
            var session = request.getSession(false);
            Object createdAt = session == null ? null : session.getAttribute(CREATED_AT_ATTRIBUTE);
            if (!(createdAt instanceof Long timestamp)
                    || clock.millis() - timestamp >= ABSOLUTE_LIFETIME.toMillis()) {
                if (session != null) {
                    session.invalidate();
                }
                SecurityContextHolder.clearContext();
                Object requestId = request.getAttribute(RequestIdFilter.REQUEST_ID_ATTRIBUTE);
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                response.setCharacterEncoding("UTF-8");
                objectMapper.writeValue(response.getOutputStream(), ApiEnvelope.failure(
                        "SESSION_EXPIRED", "登录会话已过期，请重新登录",
                        requestId instanceof String value ? value : "unknown"));
                return;
            }
        }
        filterChain.doFilter(request, response);
    }
}
