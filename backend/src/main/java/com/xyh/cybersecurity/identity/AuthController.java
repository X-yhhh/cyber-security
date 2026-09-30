package com.xyh.cybersecurity.identity;

import com.xyh.cybersecurity.common.api.ApiEnvelope;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/** 为浏览器提供 JSON 登录、当前身份、CSRF 引导和服务端会话注销接口。 */
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final AuthService authService;
    private final UserService userService;
    private final SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();

    public AuthController(AuthService authService, UserService userService) {
        this.authService = authService;
        this.userService = userService;
    }

    @GetMapping("/csrf")
    public ApiEnvelope<CsrfInfo> csrf(@RequestAttribute(name = "_csrf") CsrfToken token,
                                      HttpServletRequest request) {
        return ApiEnvelope.success(new CsrfInfo(token.getHeaderName(), token.getParameterName(), token.getToken()),
                requestId(request));
    }

    @PostMapping("/login")
    public ResponseEntity<ApiEnvelope<?>> login(@Valid @RequestBody LoginRequest body,
                                                 HttpServletRequest request, HttpServletResponse response) {
        try {
            return ResponseEntity.ok(ApiEnvelope.success(
                    authService.login(body.username(), body.password(), request, response), requestId(request)));
        } catch (AuthService.LoginRateLimitException exception) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(ApiEnvelope.failure(
                    "LOGIN_RATE_LIMITED", "登录尝试过于频繁，请稍后重试", requestId(request)));
        } catch (AuthenticationException exception) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(ApiEnvelope.failure(
                    "AUTHENTICATION_FAILED", "用户名或密码错误", requestId(request)));
        }
    }

    @GetMapping("/me")
    public ApiEnvelope<AuthService.SessionUser> me(@AuthenticationPrincipal IdentityPrincipal principal,
                                                    HttpServletRequest request) {
        return ApiEnvelope.success(AuthService.SessionUser.from(principal), requestId(request));
    }

    @PostMapping("/logout")
    public ApiEnvelope<Map<String, String>> logout(@AuthenticationPrincipal IdentityPrincipal principal,
                                                   HttpServletRequest request, HttpServletResponse response) {
        authService.logout(principal, request);
        logoutHandler.logout(request, response, SecurityContextHolder.getContext().getAuthentication());
        return ApiEnvelope.success(Map.of("status", "logged_out"), requestId(request));
    }

    /**
     * 自助改密：核对当前口令，成功后撤销本人全部会话并使当前会话失效，客户端须重新登录。
     * 当前口令错误 400 {@code CURRENT_PASSWORD_INVALID}，连续失败按登录限速返回 429。
     */
    @PostMapping("/password")
    public ApiEnvelope<Map<String, String>> changePassword(@Valid @RequestBody ChangePasswordRequest body,
                                                           @AuthenticationPrincipal IdentityPrincipal principal,
                                                           HttpServletRequest request, HttpServletResponse response) {
        userService.changeOwnPassword(principal, body.currentPassword(), body.newPassword(), request);
        logoutHandler.logout(request, response, SecurityContextHolder.getContext().getAuthentication());
        return ApiEnvelope.success(Map.of("status", "password_changed"), requestId(request));
    }

    private String requestId(HttpServletRequest request) {
        Object requestId = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        return requestId instanceof String value ? value : "unknown";
    }

    public record LoginRequest(@NotBlank @Size(max = 64) String username,
                               @NotBlank @Size(max = 128) String password) {
    }

    public record ChangePasswordRequest(@NotBlank @Size(max = 128) String currentPassword,
                                        @NotBlank @Size(min = 12, max = 128) String newPassword) {
    }

    public record CsrfInfo(String headerName, String parameterName, String token) {
    }
}
