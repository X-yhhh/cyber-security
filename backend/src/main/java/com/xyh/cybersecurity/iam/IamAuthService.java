package com.xyh.cybersecurity.iam;

import com.fasterxml.jackson.databind.JsonNode;
import com.xyh.cybersecurity.identity.AuthService;
import com.xyh.cybersecurity.identity.IdentityPrincipal;
import com.xyh.cybersecurity.identity.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Service;
import static com.xyh.cybersecurity.guard.GuardJson.*;
import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/**
 * v2 浏览器会话入口，复用现有登录、限速、CSRF、会话轮换和改密策略。
 * 登录幂等以 CSRF 引导会话中的随机命名空间隔离；幂等缓存绝不重建已注销会话。
 */
@Service
public class IamAuthService {
    private static final String LOGIN_SCOPE=IamAuthService.class.getName()+".loginScope";
    private final AuthService auth;
    private final UserService users;
    private final IamService service;
    private final IamMapper mapper;
    private final IamIdempotency idempotency;
    private final IamAudit audit;
    private final SecurityContextLogoutHandler logout=new SecurityContextLogoutHandler();

    public IamAuthService(AuthService auth,UserService users,IamService service,IamMapper mapper,
                             IamIdempotency idempotency,IamAudit audit) {
        this.auth=auth;this.users=users;this.service=service;this.mapper=mapper;this.idempotency=idempotency;this.audit=audit;
    }

    public JsonNode csrf(CsrfToken token,HttpServletRequest request) {
        loginScope(request);
        return object("headerName",token.getHeaderName(),"parameterName",token.getParameterName(),"token",token.getToken());
    }

    public JsonNode me(HttpServletRequest request) { return service.me(); }

    public JsonNode login(JsonNode body,String key,
                           HttpServletRequest request,HttpServletResponse response) {
        fields(body,"username password","");
        String username=text(body,"username"),password=text(body,"password");
        if(username.isBlank() || username.length()>64 || password.isBlank() || password.length()>128) throw error(400,"INVALID_REQUEST");
        try {
            var result=idempotency.execute("login:"+loginScope(request),request.getRequestURI(),key,body,null,200,() -> { },() -> {
                auth.login(username,password,request,response);
                mapper.scopeAuth((String)request.getAttribute(REQUEST_ID_ATTRIBUTE));
                return service.me();
            });
            // 缓存只供仍然持有成功登录会话的请求读取，不作为认证凭据。
            service.activeHuman();
            return result;
        } catch(AuthService.LoginRateLimitException e) {
            audit.loginDenied("login_rate_limited",request);throw error(429,"LOGIN_RATE_LIMITED");
        } catch(AuthenticationException e) {
            audit.loginDenied("invalid_credentials",request);throw error(401,"AUTHENTICATION_FAILED");
        }
    }

    public JsonNode logout(JsonNode body,String key,
                            IdentityPrincipal principal,HttpServletRequest request,HttpServletResponse response) {
        fields(body,"","");
        long actor=service.activeHuman();
        var result=idempotency.execute("human:"+actor,request.getRequestURI(),key,body,null,200,service::activeHuman,() -> {
            auth.logout(principal,request);mapper.scopeAuth((String)request.getAttribute(REQUEST_ID_ATTRIBUTE));
            return object("status","logged_out");
        });
        logout.logout(request,response,SecurityContextHolder.getContext().getAuthentication());
        return result;
    }

    public JsonNode password(JsonNode body,String key,
                              IdentityPrincipal principal,HttpServletRequest request,HttpServletResponse response) {
        fields(body,"currentPassword newPassword","");
        String current=text(body,"currentPassword");
        if(current.isBlank() || current.length()>128) throw error(400,"INVALID_REQUEST");
        String password=IamService.password(body,"newPassword");
        long actor=service.activeHuman();
        try {
            var result=idempotency.execute("human:"+actor,request.getRequestURI(),key,body,null,200,service::activeHuman,() -> {
                users.changeOwnPassword(principal,current,password,request);
                mapper.touch(actor);mapper.scopeAuth((String)request.getAttribute(REQUEST_ID_ATTRIBUTE));
                return object("status","password_changed");
            });
            logout.logout(request,response,SecurityContextHolder.getContext().getAuthentication());
            return result;
        } catch(com.xyh.cybersecurity.common.api.ApiRequestException failure) {
            mapper.scopeAuth((String)request.getAttribute(REQUEST_ID_ATTRIBUTE));
            throw failure;
        }
    }

    private String loginScope(HttpServletRequest request) {
        var session=request.getSession(true);
        synchronized(session) {
            Object old=session.getAttribute(LOGIN_SCOPE);
            if(old instanceof String value) return value;
            String value=id();session.setAttribute(LOGIN_SCOPE,value);return value;
        }
    }
}
