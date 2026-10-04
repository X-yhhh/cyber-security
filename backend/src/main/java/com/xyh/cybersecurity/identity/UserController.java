package com.xyh.cybersecurity.identity;

import com.xyh.cybersecurity.common.api.ApiEnvelope;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.Valid;
import java.util.List;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/** 公开预定义角色模板及用户管理端点；不提供在线角色权限编辑 API。 */
@RestController
@RequestMapping("/api/v1")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) { this.userService = userService; }

    @GetMapping("/users")
    @PreAuthorize("hasAuthority('iam.user.read')")
    public ApiEnvelope<UserService.Page<UserService.UserSummary>> users(
            @RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "20") int size,
            HttpServletRequest request) {
        return ApiEnvelope.success(userService.listUsers(page, size), requestId(request));
    }

    @PostMapping("/users")
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAuthority('iam.user.manage')")
    public ApiEnvelope<UserService.UserSummary> create(@Valid @RequestBody CreateUserBody body,
                                                        @AuthenticationPrincipal IdentityPrincipal actor,
                                                        HttpServletRequest request) {
        var result = userService.createUser(new UserService.CreateUserRequest(body.username(), body.displayName(),
                body.password()), actor, request);
        return ApiEnvelope.success(result, requestId(request));
    }

    @GetMapping("/users/{id}")
    @PreAuthorize("hasAuthority('iam.user.read')")
    public ApiEnvelope<IdentityMapper.UserDetail> user(@PathVariable long id, HttpServletRequest request) {
        return ApiEnvelope.success(userService.getUser(id), requestId(request));
    }

    /** 修改显示名称；用户名不可改。 */
    @PutMapping("/users/{id}")
    @PreAuthorize("hasAuthority('iam.user.manage')")
    public ApiEnvelope<IdentityMapper.UserDetail> update(@PathVariable long id, @Valid @RequestBody UpdateUserBody body,
                                                         @AuthenticationPrincipal IdentityPrincipal actor,
                                                         HttpServletRequest request) {
        return ApiEnvelope.success(userService.updateProfile(id, body.displayName(), actor, request), requestId(request));
    }

    /** 冻结（disabled）或解冻（active）；冻结撤销该用户全部会话。 */
    @PostMapping("/users/{id}/status")
    @PreAuthorize("hasAuthority('iam.user.manage')")
    public ApiEnvelope<IdentityMapper.UserDetail> status(@PathVariable long id, @Valid @RequestBody StatusBody body,
                                                         @AuthenticationPrincipal IdentityPrincipal actor,
                                                         HttpServletRequest request) {
        return ApiEnvelope.success(userService.changeStatus(id, body.status(), body.reason(), actor, request),
                requestId(request));
    }

    /** 管理员重置他人口令；撤销该用户全部会话。本人改密使用 {@code POST /auth/password}。 */
    @PostMapping("/users/{id}/password-reset")
    @PreAuthorize("hasAuthority('iam.user.manage')")
    public ApiEnvelope<IdentityMapper.UserDetail> resetPassword(@PathVariable long id,
                                                                @Valid @RequestBody PasswordResetBody body,
                                                                @AuthenticationPrincipal IdentityPrincipal actor,
                                                                HttpServletRequest request) {
        return ApiEnvelope.success(userService.resetPassword(id, body.newPassword(), body.reason(), actor, request),
                requestId(request));
    }

    @GetMapping("/roles")
    @PreAuthorize("hasAuthority('iam.role.read')")
    public ApiEnvelope<?> roles(HttpServletRequest request) {
        return ApiEnvelope.success(userService.listRoles(), requestId(request));
    }

    @PutMapping("/users/{id}/roles")
    @PreAuthorize("hasAuthority('iam.role.assign')")
    public ApiEnvelope<?> replaceRoles(@PathVariable long id, @Valid @RequestBody RoleAssignmentsBody body,
                                       @AuthenticationPrincipal IdentityPrincipal actor,
                                       HttpServletRequest request) {
        var assignments = body.assignments().stream().map(row -> new IdentityMapper.RoleBinding(
                row.roleKey(), row.scopeType(), row.scopeId())).toList();
        return ApiEnvelope.success(userService.assignRoles(id, new UserService.RoleAssignments(assignments),
                actor, request), requestId(request));
    }

    private String requestId(HttpServletRequest request) {
        Object value = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        return value instanceof String requestId ? requestId : "unknown";
    }

    public record CreateUserBody(@NotBlank @Size(min = 3, max = 64) String username,
                                 @NotBlank @Size(max = 128) String displayName,
                                 @NotBlank @Size(min = 12, max = 128) String password) { }
    public record UpdateUserBody(@NotBlank @Size(max = 128) String displayName) { }
    public record StatusBody(@NotBlank String status, @NotBlank @Size(max = 1000) String reason) { }
    public record PasswordResetBody(@NotBlank @Size(min = 12, max = 128) String newPassword,
                                    @NotBlank @Size(max = 1000) String reason) { }
    public record RoleAssignmentsBody(@NotNull @Size(min = 1, max = 64) List<@NotNull @Valid RoleBindingBody> assignments) { }
    public record RoleBindingBody(@NotBlank String roleKey, @NotBlank String scopeType, @NotBlank String scopeId) { }
}
