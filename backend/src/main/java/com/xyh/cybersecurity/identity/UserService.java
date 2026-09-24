package com.xyh.cybersecurity.identity;

import com.xyh.cybersecurity.authorization.ResourceScope;
import com.xyh.cybersecurity.common.api.ApiRequestException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/** 实施用户管理、范围校验、预定义角色分配、会话撤销及不可变审计。 */
@Service
public class UserService {

    private static final Set<String> BUILTIN_ROLES = Set.of("platform_admin", "asset_source_admin",
            "security_analyst", "response_approver", "model_operator", "model_releaser", "auditor");

    private final IdentityMapper identityMapper;
    private final JdbcTemplate jdbcTemplate;
    private final PasswordEncoder passwordEncoder;

    public UserService(IdentityMapper identityMapper, JdbcTemplate jdbcTemplate, PasswordEncoder passwordEncoder) {
        this.identityMapper = identityMapper;
        this.jdbcTemplate = jdbcTemplate;
        this.passwordEncoder = passwordEncoder;
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
        if (input.password().length() < 12) {
            throw ApiRequestException.badRequest("初始密码至少需要 12 个字符");
        }
        String userKey = "usr_" + java.util.UUID.randomUUID().toString().replace("-", "");
        try {
            jdbcTemplate.update("INSERT INTO sys_user (user_key, username, display_name, status, password_hash) "
                            + "VALUES (?, ?, ?, 'active', ?)",
                    userKey, username, displayName, passwordEncoder.encode(input.password()));
        } catch (org.springframework.dao.DuplicateKeyException exception) {
            throw ApiRequestException.conflict("用户名已存在");
        }
        long userId = jdbcTemplate.queryForObject("SELECT id FROM sys_user WHERE user_key=?", Long.class, userKey);
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
        if (actor.id() == userId) {
            throw ApiRequestException.conflict("不得修改自身角色或资源范围");
        }
        IdentityMapper.UserView target = identityMapper.findUser(userId);
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

        jdbcTemplate.update("DELETE FROM sys_user_role WHERE user_id=?", userId);
        for (IdentityMapper.RoleBinding binding : normalizedAssignments) {
            Long roleId = identityMapper.findActiveBuiltinRoleId(binding.roleKey());
            jdbcTemplate.update("INSERT INTO sys_user_role (user_id, role_id, scope_type, scope_id) VALUES (?, ?, ?, ?)",
                    userId, roleId, binding.scopeType(), binding.scopeId());
        }
        jdbcTemplate.update("DELETE FROM SPRING_SESSION WHERE PRINCIPAL_NAME=?", target.username());
        writeAudit(request, actor.id(), "iam.user.roles.replace", "user", Long.toString(userId), "success",
                "replaced with " + normalizedAssignments.size() + " predefined role scope bindings");
        return identityMapper.listRoleBindings(userId);
    }

    private void writeAudit(HttpServletRequest request, long actorId, String action, String resourceType,
                            String resourceId, String outcome, String reason) {
        Object requestId = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        jdbcTemplate.update("INSERT INTO audit_log "
                        + "(occurred_at, actor_type, actor_id, action, resource_type, resource_id, request_id, outcome, reason) "
                        + "VALUES (?, 'human', ?, ?, ?, ?, ?, ?, ?)", Timestamp.from(Instant.now()),
                Long.toString(actorId), action, resourceType, resourceId,
                requestId instanceof String value ? value : null, outcome, reason);
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
