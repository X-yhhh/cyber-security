package com.xyh.cybersecurity.identity;

import com.xyh.cybersecurity.authorization.ResourceScope;
import com.xyh.cybersecurity.audit.AuditMapper;
import com.xyh.cybersecurity.common.api.ApiRequestException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/** 实施用户管理、范围校验、预定义角色分配、会话撤销及不可变审计。 */
@Service
public class UserService {

    private static final Set<String> BUILTIN_ROLES = Set.of("platform_admin", "asset_source_admin",
            "security_analyst", "response_approver", "model_operator", "model_releaser", "auditor");

    static final int MIN_PASSWORD_LENGTH = 12;
    static final int MAX_PASSWORD_LENGTH = 128;

    private final IdentityMapper identityMapper;
    private final AuditMapper auditMapper;
    private final PasswordEncoder passwordEncoder;
    private final LoginThrottleService loginThrottleService;
    private final com.xyh.cybersecurity.security.SecurityAuditWriter securityAuditWriter;

    public UserService(IdentityMapper identityMapper, AuditMapper auditMapper, PasswordEncoder passwordEncoder,
                       LoginThrottleService loginThrottleService,
                       com.xyh.cybersecurity.security.SecurityAuditWriter securityAuditWriter) {
        this.identityMapper = identityMapper;
        this.auditMapper = auditMapper;
        this.passwordEncoder = passwordEncoder;
        this.loginThrottleService = loginThrottleService;
        this.securityAuditWriter = securityAuditWriter;
    }

    public Page<UserSummary> listUsers(int page, int size) {
        int offset = checkedOffset(page, size);
        return new Page<>(identityMapper.countUsers(), page, size, identityMapper.listUsers(offset, size).stream()
                .map(UserSummary::from).toList());
    }

    public List<RoleSummary> listRoles() {
        return identityMapper.listRoles().stream().map(role -> new RoleSummary(role.roleKey(), role.name(),
                role.description(), identityMapper.listRolePermissions(role.id()))).toList();
    }

    @Transactional
    public UserSummary createUser(CreateUserRequest input, IdentityPrincipal actor, HttpServletRequest request) {
        String username = input.username().trim();
        String displayName = input.displayName().trim();
        if (!username.matches("[A-Za-z0-9._-]{3,64}") || displayName.isBlank()) {
            throw ApiRequestException.badRequest("用户名或显示名称格式无效");
        }
        validatePassword(input.password());
        String userKey = "usr_" + java.util.UUID.randomUUID().toString().replace("-", "");
        try {
            identityMapper.insertUser(userKey, username, displayName, passwordEncoder.encode(input.password()));
        } catch (org.springframework.dao.DuplicateKeyException exception) {
            throw ApiRequestException.conflict("用户名已存在");
        }
        long userId = identityMapper.findUserIdByKey(userKey);
        writeAudit(request, actor.id(), "iam.user.create", "user", Long.toString(userId), "success",
                "user created without implicit roles");
        IdentityMapper.UserView created = identityMapper.findUser(userId);
        if (created == null) {
            throw new IllegalStateException("Created user could not be loaded");
        }
        return UserSummary.from(created);
    }

    @Transactional
    public List<IdentityMapper.RoleBinding> assignRoles(long userId, RoleAssignments requestBody,
                                                         IdentityPrincipal actor, HttpServletRequest request) {
        identityMapper.lockPlatformAdminRole();
        requireGlobalUserAdmin(actor);
        if (actor.id() == userId) {
            throw ApiRequestException.conflict("不得修改自身角色或资源范围");
        }
        IdentityMapper.UserView target = identityMapper.lockUser(userId);
        if (target == null) {
            throw ApiRequestException.notFound();
        }
        if (requestBody == null || requestBody.assignments() == null) {
            throw ApiRequestException.badRequest("角色范围集合不能为空");
        }
        if (requestBody.assignments().stream().anyMatch(java.util.Objects::isNull)) {
            throw ApiRequestException.badRequest("角色范围集合包含无效项");
        }
        List<IdentityMapper.RoleBinding> assignments = List.copyOf(requestBody.assignments());
        if (assignments.isEmpty() || assignments.size() > 64) {
            throw ApiRequestException.badRequest("角色范围集合不能为空且最多包含 64 项");
        }
        Set<String> uniqueBindings = new HashSet<>();
        java.util.ArrayList<IdentityMapper.RoleBinding> normalizedAssignments = new java.util.ArrayList<>();
        boolean keepsGlobalAdmin = false;
        for (IdentityMapper.RoleBinding binding : assignments) {
            if (!BUILTIN_ROLES.contains(binding.roleKey())) {
                throw ApiRequestException.badRequest("只能分配平台预定义角色");
            }
            Long roleId = identityMapper.findActiveBuiltinRoleId(binding.roleKey());
            if (roleId == null) {
                throw ApiRequestException.badRequest("指定预定义角色不可用");
            }
            ResourceScope scope = ResourceScope.parse(binding.scopeType(), binding.scopeId(), binding.roleKey());
            if (scope.type() != ResourceScope.Type.GLOBAL
                    && !identityMapper.existsScope(scope.type().key(), scope.id())) {
                throw ApiRequestException.badRequest("授权资源不存在");
            }
            String key = binding.roleKey() + "\u0000" + scope.type().key() + "\u0000" + scope.id();
            if (!uniqueBindings.add(key)) {
                throw ApiRequestException.badRequest("角色范围集合存在重复项");
            }
            normalizedAssignments.add(new IdentityMapper.RoleBinding(binding.roleKey(), scope.type().key(), scope.id()));
            if (binding.roleKey().equals("platform_admin") && scope.type() == ResourceScope.Type.GLOBAL) {
                keepsGlobalAdmin = true;
            }
        }
        boolean currentlyGlobalAdmin = identityMapper.listRoleBindings(userId).stream()
                .anyMatch(binding -> binding.roleKey().equals("platform_admin")
                        && binding.scopeType().equals("global") && binding.scopeId().equals("*"));
        List<Long> lockedPlatformAdmins = currentlyGlobalAdmin && !keepsGlobalAdmin && "active".equals(target.status())
                ? identityMapper.lockActiveGlobalPlatformAdministratorIds() : List.of();
        if (!lockedPlatformAdmins.isEmpty() && lockedPlatformAdmins.size() <= 1) {
            throw ApiRequestException.conflict("不能移除最后一名有效平台管理员");
        }
        if ("admin".equals(target.username()) && (normalizedAssignments.size() != 1 || !keepsGlobalAdmin
                || !normalizedAssignments.getFirst().roleKey().equals("platform_admin")
                || !normalizedAssignments.getFirst().scopeType().equals("global")
                || !normalizedAssignments.getFirst().scopeId().equals("*"))) {
            throw ApiRequestException.conflict("保留 admin 账号的全局平台管理员角色");
        }

        identityMapper.deleteUserRoles(userId);
        for (IdentityMapper.RoleBinding binding : normalizedAssignments) {
            Long roleId = identityMapper.findActiveBuiltinRoleId(binding.roleKey());
            identityMapper.insertUserRole(userId, roleId, binding.scopeType(), binding.scopeId());
        }
        identityMapper.deleteSession(target.username());
        writeAudit(request, actor.id(), "iam.user.roles.replace", "user", Long.toString(userId), "success",
                "replaced with " + normalizedAssignments.size() + " predefined role scope bindings");
        return identityMapper.listRoleBindings(userId);
    }

    /** 用户详情；不返回口令哈希。不存在时 404。 */
    public IdentityMapper.UserDetail getUser(long userId) {
        IdentityMapper.UserDetail user = identityMapper.findUserDetail(userId);
        if (user == null) throw ApiRequestException.notFound();
        return user;
    }

    /**
     * 修改用户资料（当前只有显示名称）。用户名与 user_key 不可修改；不影响会话与权限。
     * 调用方须为全局平台管理员（资源范围二次校验）。
     */
    @Transactional
    public IdentityMapper.UserDetail updateProfile(long userId, String displayName, IdentityPrincipal actor,
                                                   HttpServletRequest request) {
        requireGlobalUserAdmin(actor);
        String name = displayName == null ? "" : displayName.trim();
        if (name.isEmpty() || name.length() > 128) throw ApiRequestException.badRequest("显示名称格式无效");
        if (identityMapper.lockUser(userId) == null) throw ApiRequestException.notFound();
        identityMapper.updateDisplayName(userId, name);
        writeAudit(request, actor.id(), "iam.user.profile.update", "user", Long.toString(userId), "success",
                "display name updated");
        return getUser(userId);
    }

    /**
     * 冻结（{@code disabled}）或解冻（{@code active}）用户。冻结同事务撤销其全部会话；
     * 不能冻结本人，也不能冻结最后一名 active 全局平台管理员（锁定全部管理员行后判定，避免并发冻结两人）。
     *
     * @throws ApiRequestException 409 {@code USER_STATUS_CONFLICT}：状态不允许该迁移或违反上述保护
     */
    @Transactional
    public IdentityMapper.UserDetail changeStatus(long userId, String status, String reason, IdentityPrincipal actor,
                                                  HttpServletRequest request) {
        identityMapper.lockPlatformAdminRole();
        requireGlobalUserAdmin(actor);
        String why = reason(reason);
        if (!"active".equals(status) && !"disabled".equals(status)) throw ApiRequestException.badRequest("用户状态无效");
        if (actor.id() == userId) throw statusConflict("不能变更本人账号状态");
        IdentityMapper.UserView target = identityMapper.lockUser(userId);
        if (target == null) throw ApiRequestException.notFound();
        if (status.equals(target.status())) throw statusConflict("用户已处于该状态");
        if ("disabled".equals(status) && "active".equals(target.status())
                && identityMapper.isGlobalPlatformAdmin(userId)
                && identityMapper.lockActiveGlobalPlatformAdministratorIds().size() <= 1) {
            throw statusConflict("不能冻结最后一名有效平台管理员");
        }
        List<String> from = "disabled".equals(status) ? List.of("active", "locked") : List.of("disabled", "locked");
        if (identityMapper.transitionUserStatus(userId, from, status) != 1) throw statusConflict("用户状态已被其他请求更新");
        identityMapper.deleteSession(target.username());
        writeAudit(request, actor.id(), "disabled".equals(status) ? "iam.user.disabled" : "iam.user.enabled", "user",
                Long.toString(userId), "success", why);
        return getUser(userId);
    }

    /**
     * 管理员重置他人口令：写入新 BCrypt 哈希、记录改密时间并撤销该用户全部会话。本人改密须走
     * {@link #changeOwnPassword}（要求核对当前口令）。口令本身不进入审计或日志。
     */
    @Transactional
    public IdentityMapper.UserDetail resetPassword(long userId, String newPassword, String reason, IdentityPrincipal actor,
                                                   HttpServletRequest request) {
        requireGlobalUserAdmin(actor);
        String why = reason(reason);
        if (actor.id() == userId) throw statusConflict("本人改密请使用自助改密");
        validatePassword(newPassword);
        IdentityMapper.UserView target = identityMapper.lockUser(userId);
        if (target == null) throw ApiRequestException.notFound();
        identityMapper.updatePasswordHash(userId, passwordEncoder.encode(newPassword));
        identityMapper.deleteSession(target.username());
        writeAudit(request, actor.id(), "iam.user.password.reset", "user", Long.toString(userId), "success", why);
        return getUser(userId);
    }

    /**
     * 自助改密：核对当前口令后写入新口令并撤销本人全部会话（含当前会话，调用方须重新登录）。
     * 当前口令错误按登录失败计入限速；被限速时返回 429，错误时返回 400 {@code CURRENT_PASSWORD_INVALID}。
     */
    @Transactional
    public void changeOwnPassword(IdentityPrincipal actor, String currentPassword, String newPassword,
                                  HttpServletRequest request) {
        String remote = request.getRemoteAddr();
        if (loginThrottleService.isBlocked(actor.getUsername(), remote)) {
            throw new ApiRequestException(org.springframework.http.HttpStatus.TOO_MANY_REQUESTS, "LOGIN_RATE_LIMITED",
                    "尝试过于频繁，请稍后重试");
        }
        IdentityMapper.UserView self = identityMapper.lockUser(actor.id());
        String hash = self == null ? null : identityMapper.findPasswordHash(actor.id());
        if (self == null || !"active".equals(self.status()) || hash == null
                || currentPassword == null || utf8Length(currentPassword) > 72 || !passwordEncoder.matches(currentPassword, hash)) {
            // 限速计数与拒绝审计都独立提交，不随本事务回滚。
            loginThrottleService.recordFailure(actor.getUsername(), remote);
            securityAuditWriter.denied(request, org.springframework.security.core.context.SecurityContextHolder
                    .getContext().getAuthentication(), "auth.password.change", "current_password_mismatch");
            throw new ApiRequestException(org.springframework.http.HttpStatus.BAD_REQUEST, "CURRENT_PASSWORD_INVALID",
                    "当前口令不正确");
        }
        validatePassword(newPassword);
        if (passwordEncoder.matches(newPassword, hash)) throw ApiRequestException.badRequest("新口令不能与当前口令相同");
        identityMapper.updatePasswordHash(actor.id(), passwordEncoder.encode(newPassword));
        identityMapper.deleteSession(self.username());
        loginThrottleService.clearFailures(actor.getUsername(), remote);
        writeAudit(request, actor.id(), "auth.password.change", "user", Long.toString(actor.id()), "success",
                "password changed, sessions revoked");
    }

    private void requireGlobalUserAdmin(IdentityPrincipal actor) {
        if (!identityMapper.isGlobalPlatformAdmin(actor.id())) {
            throw new org.springframework.security.access.AccessDeniedException("Global platform administrator required");
        }
    }

    private static void validatePassword(String password) {
        if (password == null || password.length() < MIN_PASSWORD_LENGTH || password.length() > MAX_PASSWORD_LENGTH
                || password.isBlank() || utf8Length(password) > 72) {
            throw ApiRequestException.badRequest("口令须为 12～128 个字符，且 UTF-8 编码不超过 72 字节");
        }
    }

    private static int utf8Length(String value) {
        return value.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
    }

    private static String reason(String reason) {
        if (reason == null || reason.isBlank() || reason.length() > 1000) {
            throw ApiRequestException.badRequest("须填写 1-1000 字的理由");
        }
        return reason.trim();
    }

    private static ApiRequestException statusConflict(String message) {
        return new ApiRequestException(org.springframework.http.HttpStatus.CONFLICT, "USER_STATUS_CONFLICT", message);
    }

    private void writeAudit(HttpServletRequest request, long actorId, String action, String resourceType,
                            String resourceId, String outcome, String reason) {
        Object requestId = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        auditMapper.insertAudit(new AuditMapper.AuditInsert(LocalDateTime.now(ZoneOffset.UTC), "human", Long.toString(actorId),
                action, resourceType, resourceId, requestId instanceof String value ? value : null, outcome, reason));
    }

    private static int checkedOffset(int page, int size) {
        if (page < 0 || size < 1 || size > 100 || (long) page * size > Integer.MAX_VALUE) {
            throw ApiRequestException.badRequest("分页参数超出允许范围");
        }
        return page * size;
    }

    public record CreateUserRequest(String username, String displayName, String password) { }
    public record RoleAssignments(List<IdentityMapper.RoleBinding> assignments) { }
    public record UserSummary(long id, String userKey, String username, String displayName, String status) {
        static UserSummary from(IdentityMapper.UserView user) {
            return new UserSummary(user.id(), user.userKey(), user.username(), user.displayName(), user.status());
        }
    }
    public record RoleSummary(String roleKey, String name, String description, List<String> permissions) { }
    public record Page<T>(long totalElements, int page, int size, List<T> items) { }
}
