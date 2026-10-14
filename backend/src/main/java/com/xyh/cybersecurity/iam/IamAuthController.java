package com.xyh.cybersecurity.iam;

import com.fasterxml.jackson.databind.JsonNode;
import com.xyh.cybersecurity.identity.IdentityPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;
import static com.xyh.cybersecurity.guard.GuardJson.parse;
import static com.xyh.cybersecurity.iam.IamController.envelope;

/** v2 认证协议适配；会话、限速、口令、幂等和审计均委托身份应用服务。 */
@RestController
@RequestMapping(value="/api/v2/auth",produces=MediaType.APPLICATION_JSON_VALUE)
public class IamAuthController {
    private final IamAuthService service;
    public IamAuthController(IamAuthService service) { this.service=service; }

    @GetMapping("/csrf")
    public JsonNode csrf(@RequestAttribute(name="_csrf") CsrfToken token,HttpServletRequest request) {
        return envelope(service.csrf(token,request),request);
    }

    @GetMapping("/me")
    public JsonNode me(HttpServletRequest request) { return envelope(service.me(request),request); }

    @PostMapping(value="/login",consumes=MediaType.APPLICATION_JSON_VALUE)
    public JsonNode login(@RequestBody String raw,@RequestHeader("Idempotency-Key") String key,
                           HttpServletRequest request,HttpServletResponse response) {
        return envelope(service.login(parse(raw),key,request,response),request);
    }

    @PostMapping(value="/logout",consumes=MediaType.APPLICATION_JSON_VALUE)
    public JsonNode logout(@RequestBody String raw,@RequestHeader("Idempotency-Key") String key,
                            @AuthenticationPrincipal IdentityPrincipal principal,HttpServletRequest request,HttpServletResponse response) {
        return envelope(service.logout(parse(raw),key,principal,request,response),request);
    }

    @PostMapping(value="/password",consumes=MediaType.APPLICATION_JSON_VALUE)
    public JsonNode password(@RequestBody String raw,@RequestHeader("Idempotency-Key") String key,
                              @AuthenticationPrincipal IdentityPrincipal principal,HttpServletRequest request,HttpServletResponse response) {
        return envelope(service.password(parse(raw),key,principal,request,response),request);
    }
}
