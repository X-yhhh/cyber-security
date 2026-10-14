package com.xyh.cybersecurity.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.xyh.cybersecurity.common.api.ApiEnvelope;
import com.xyh.cybersecurity.common.web.RequestIdFilter;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.UUID;
import org.springframework.context.annotation.Profile;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/** 浏览器可不持证书；deploy 的机器路径必须出示由监听器验证过的证书，并继续原 Bearer 鉴权。 */
@Component
@Profile("deploy")
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
public class DeployMachineTlsFilter extends OncePerRequestFilter {
    private final ObjectMapper mapper;
    public DeployMachineTlsFilter(ObjectMapper mapper) { this.mapper = mapper; }
    @Override protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI().substring(request.getContextPath().length());
        return !(path.startsWith("/api/v1/machine/") || path.startsWith("/api/v2/machine/"));
    }
    @Override protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Object certificates = request.getAttribute("jakarta.servlet.request.X509Certificate");
        if (request.isSecure() && certificates instanceof X509Certificate[] values && values.length > 0) {
            chain.doFilter(request, response);
            return;
        }
        Object existing = request.getAttribute(RequestIdFilter.REQUEST_ID_ATTRIBUTE);
        String requestId = existing instanceof String value ? value : UUID.randomUUID().toString();
        response.setStatus(401);
        response.setContentType("application/json");
        response.setHeader("X-Request-Id", requestId);
        mapper.writeValue(response.getOutputStream(), ApiEnvelope.failure("MACHINE_TLS_REQUIRED", "机器接入需要客户端证书", requestId));
    }
}
