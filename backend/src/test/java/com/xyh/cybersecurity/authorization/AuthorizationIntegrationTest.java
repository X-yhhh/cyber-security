package com.xyh.cybersecurity.authorization;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import com.xyh.cybersecurity.identity.IdentityMapper;
import com.xyh.cybersecurity.asset.AssetMapper;
import com.xyh.cybersecurity.audit.AuditMapper;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;


import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** 使用专用 MySQL schema 验证角色权限、资源范围和审计可见性。 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@EnabledIfEnvironmentVariable(named = "DB_TEST_BASE_URL", matches = ".+")
class AuthorizationIntegrationTest {

    private static final String TEST_SCHEMA = "cyber_security_backend_authz_20260923";
    private static final String ADMIN_PASSWORD_HASH = new BCryptPasswordEncoder(4).encode("admin");
    private static final String CSRF_HEADER = "X-CSRF-TOKEN";

    @BeforeAll
    static void migrateAuthorizationTestSchema() throws Exception {
        String baseUrl = System.getenv("DB_TEST_BASE_URL");
        String username = System.getenv("DB_TEST_USERNAME");
        String password = System.getenv("DB_TEST_PASSWORD");
        try (java.sql.Connection connection = java.sql.DriverManager.getConnection(baseUrl, username, password);
             java.sql.Statement statement = connection.createStatement()) {
            statement.execute("CREATE DATABASE IF NOT EXISTS " + TEST_SCHEMA
                    + " CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci");
        }
        Flyway.configure().dataSource(baseUrl.replaceFirst("/+$", "") + "/" + TEST_SCHEMA, username, password)
                .locations("classpath:db/migration").baselineOnMigrate(false).load().migrate();
    }

    @DynamicPropertySource
    static void databaseProperties(DynamicPropertyRegistry registry) {
        String baseUrl = System.getenv("DB_TEST_BASE_URL");
        registry.add("spring.datasource.url", () -> baseUrl.replaceFirst("/+$", "") + "/" + TEST_SCHEMA
                + "?connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true");
        registry.add("spring.datasource.username", () -> System.getenv("DB_TEST_USERNAME"));
        registry.add("spring.datasource.password", () -> System.getenv("DB_TEST_PASSWORD"));
        registry.add("spring.flyway.enabled", () -> false);
        registry.add("cyber.security.login-throttle.hmac-key", () -> "test-only-key-with-at-least-thirty-two-bytes");
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private IdentityMapper identityMapper;

    @Autowired
    private AssetMapper assetMapper;

    @Autowired
    private AuditMapper auditMapper;

    private long adminId;
    private long analystId;
    private long auditorId;
    private long visibleAssetId;
    private long hiddenAssetId;

    @BeforeEach
    void seedIsolatedAuthorizationFixtures() {
        jdbcTemplate.update("DELETE FROM SPRING_SESSION");
        jdbcTemplate.update("DELETE FROM audit_resource_scope");
        jdbcTemplate.update("DELETE FROM audit_log WHERE action LIKE 'auth.%' OR action LIKE 'authorization.%' "
                + "OR action LIKE 'iam.%' OR action LIKE 'security.%'");
        jdbcTemplate.update("DELETE FROM sys_user_role");
        jdbcTemplate.update("DELETE FROM asset WHERE asset_key LIKE 'authz-test-%'");
        jdbcTemplate.update("DELETE FROM sys_user WHERE username IN ('authz-admin', 'authz-analyst', 'authz-auditor', 'authz-locked')");
        jdbcTemplate.update("DELETE FROM sys_user WHERE username='new-analyst'");

        createUser("authz-admin", "测试平台管理员", "active");
        Integer preservedAdminCount = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM sys_user WHERE username='admin'", Integer.class);
        if (preservedAdminCount == 0) {
            adminId = createUser("admin", "现有管理员账号", "active");
        } else {
            adminId = jdbcTemplate.queryForObject("SELECT id FROM sys_user WHERE username='admin'", Long.class);
        }
        analystId = createUser("authz-analyst", "测试分析员", "active");
        auditorId = createUser("authz-auditor", "测试审计员", "active");
        createUser("authz-locked", "测试锁定用户", "locked");
        bindRole("authz-admin", "platform_admin", "global", "*");
        if (jdbcTemplate.queryForObject("SELECT COUNT(*) FROM sys_user_role ur JOIN sys_role r ON r.id=ur.role_id "
                        + "WHERE ur.user_id=? AND r.role_key='platform_admin' AND ur.scope_type='global' AND ur.scope_id='*'",
                Integer.class, adminId) == 0) {
            bindRole("admin", "platform_admin", "global", "*");
        }

        hiddenAssetId = createAsset("hidden");
        visibleAssetId = createAsset("visible");
        bindRole("authz-analyst", "security_analyst", "asset", Long.toString(visibleAssetId));
        bindRole("authz-auditor", "auditor", "asset", Long.toString(visibleAssetId));
    }

    @Test
    void analystListsOnlyAuthorizedAssetsBeforeApplyingPagination() throws Exception {
        Cookie session = loginAndGetSession("authz-analyst", "admin");

        mockMvc.perform(get("/api/v1/assets?page=0&size=1").cookie(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.totalElements").value(1))
                .andExpect(jsonPath("$.data.items.length()").value(1))
                .andExpect(jsonPath("$.data.items[0].id").value(visibleAssetId));
    }

    @Test
    void myBatisMappersLoadAndApplyVisibleResourcePredicates() {
        assertThat(identityMapper.findUser(adminId)).isNotNull();
        assertThat(identityMapper.listRoles()).hasSize(7);
        assertThat(assetMapper.countVisible(analystId)).isEqualTo(1);
        assertThat(auditMapper.countVisible(auditorId)).isZero();
    }

    @Test
    void hidesAnOutOfScopeAssetByReturningNotFound() throws Exception {
        Cookie session = loginAndGetSession("authz-analyst", "admin");

        mockMvc.perform(get("/api/v1/assets/{id}", hiddenAssetId).cookie(session))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error.code").value("NOT_FOUND"));
        assertThat(jdbcTemplate.queryForObject("SELECT COUNT(*) FROM audit_log WHERE actor_id=? "
                        + "AND action='authorization.scope.denied' AND outcome='denied'", Integer.class,
                Long.toString(analystId))).isEqualTo(1);
    }

    @Test
    void deniesUserManagementToAnAnalyst() throws Exception {
        Cookie session = loginAndGetSession("authz-analyst", "admin");

        mockMvc.perform(get("/api/v1/users").cookie(session))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error.code").value("FORBIDDEN"));
    }

    @Test
    void exposesDistinctBuiltInRolePermissionTemplatesToAdministrators() throws Exception {
        Cookie adminSession = loginAndGetSession("authz-admin", "admin");
        MvcResult result = mockMvc.perform(get("/api/v1/roles").cookie(adminSession))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode roles = objectMapper.readTree(result.getResponse().getContentAsString()).path("data");
        assertThat(roles).hasSize(7);
        String templates = roles.toString();
        assertThat(templates).contains("security_analyst", "action.request", "response_approver", "approval.decide",
                "model_operator", "model_releaser", "auditor", "audit.read")
                .doesNotContain("response.policy.manage");
    }

    @Test
    void roleAssignmentRevokesTheTargetUsersExistingSessions() throws Exception {
        Cookie adminSession = loginAndGetSession("authz-admin", "admin");
        Cookie analystSession = loginAndGetSession("authz-analyst", "admin");
        CsrfContext csrf = csrf(adminSession);

        mockMvc.perform(put("/api/v1/users/{id}/roles", analystId)
                        .cookie(adminSession)
                        .header(CSRF_HEADER, csrf.token())
                        .contentType(APPLICATION_JSON)
                        .content("{\"assignments\":[{\"roleKey\":\"security_analyst\","
                                + "\"scopeType\":\"asset\",\"scopeId\":\"" + hiddenAssetId + "\"}]}"))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/v1/auth/me").cookie(analystSession))
                .andExpect(status().isUnauthorized());
        assertThat(jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM sys_user_role ur JOIN sys_role r ON r.id=ur.role_id "
                        + "WHERE ur.user_id=? AND r.role_key='security_analyst' AND ur.scope_id=?",
                Integer.class, analystId, Long.toString(hiddenAssetId))).isEqualTo(1);
    }

    @Test
    void revokedAdministratorSessionCannotRemoveLastAdministrator() throws Exception {
        Cookie administratorSession = loginAndGetSession("authz-admin", "admin");
        CsrfContext csrf = csrf(administratorSession);
        jdbcTemplate.update("DELETE ur FROM sys_user_role ur JOIN sys_role r ON r.id=ur.role_id "
                + "WHERE ur.user_id=? AND r.role_key='platform_admin'", identityId("authz-admin"));

        mockMvc.perform(put("/api/v1/users/{id}/roles", adminId)
                        .cookie(administratorSession)
                        .header(CSRF_HEADER, csrf.token())
                        .contentType(APPLICATION_JSON)
                        .content("{\"assignments\":[{\"roleKey\":\"security_analyst\","
                                + "\"scopeType\":\"asset\",\"scopeId\":\"" + visibleAssetId + "\"}]}"))
                .andExpect(status().isForbidden());

        assertThat(jdbcTemplate.queryForObject("SELECT COUNT(*) FROM sys_user_role ur "
                        + "JOIN sys_role r ON r.id=ur.role_id WHERE ur.user_id=? AND r.role_key='platform_admin' "
                        + "AND ur.scope_type='global' AND ur.scope_id='*'", Integer.class, adminId)).isEqualTo(1);
    }

    @Test
    void normalizesNumericResourceScopeIdsBeforePersistingThem() throws Exception {
        Cookie adminSession = loginAndGetSession("authz-admin", "admin");
        CsrfContext csrf = csrf(adminSession);
        String paddedAssetId = "000000" + hiddenAssetId;

        mockMvc.perform(put("/api/v1/users/{id}/roles", analystId)
                        .cookie(adminSession)
                        .header(CSRF_HEADER, csrf.token())
                        .contentType(APPLICATION_JSON)
                        .content("{\"assignments\":[{\"roleKey\":\"security_analyst\","
                                + "\"scopeType\":\"asset\",\"scopeId\":\"" + paddedAssetId + "\"}]}"))
                .andExpect(status().isOk());

        assertThat(jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM sys_user_role ur JOIN sys_role r ON r.id=ur.role_id "
                        + "WHERE ur.user_id=? AND r.role_key='security_analyst' AND ur.scope_id=?",
                Integer.class, analystId, Long.toString(hiddenAssetId))).isEqualTo(1);
    }

    @Test
    void rejectsUnknownScopesAndDoesNotMutateBuiltInPermissionTemplates() throws Exception {
        Cookie adminSession = loginAndGetSession("authz-admin", "admin");
        CsrfContext csrf = csrf(adminSession);
        int permissionCount = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM sys_role_permission", Integer.class);

        mockMvc.perform(put("/api/v1/users/{id}/roles", analystId)
                        .cookie(adminSession)
                        .header(CSRF_HEADER, csrf.token())
                        .contentType(APPLICATION_JSON)
                        .content("{\"assignments\":[{\"roleKey\":\"security_analyst\","
                                + "\"scopeType\":\"asset\",\"scopeId\":\"999999999\"}]}"))
                .andExpect(status().isBadRequest());

        mockMvc.perform(put("/api/v1/users/{id}/roles", analystId)
                        .cookie(adminSession)
                        .header(CSRF_HEADER, csrf.token())
                        .contentType(APPLICATION_JSON)
                        .content("{\"assignments\":[{\"roleKey\":\"security_analyst\","
                                + "\"scopeType\":\"global\",\"scopeId\":\"*\"}]}"))
                .andExpect(status().isBadRequest());

        assertThat(jdbcTemplate.queryForObject("SELECT COUNT(*) FROM sys_role_permission", Integer.class))
                .isEqualTo(permissionCount);
    }

    @Test
    void preservesTheExistingAdminCredentialAndBuiltInAdministratorBinding() throws Exception {
        String originalHash = jdbcTemplate.queryForObject(
                "SELECT password_hash FROM sys_user WHERE username='admin'", String.class);
        Cookie adminSession = loginAndGetSession("authz-admin", "admin");
        CsrfContext csrf = csrf(adminSession);

        mockMvc.perform(put("/api/v1/users/{id}/roles", adminId)
                        .cookie(adminSession)
                        .header(CSRF_HEADER, csrf.token())
                        .contentType(APPLICATION_JSON)
                        .content("{\"assignments\":[{\"roleKey\":\"security_analyst\","
                                + "\"scopeType\":\"asset\",\"scopeId\":\"" + visibleAssetId + "\"}]}"))
                .andExpect(status().isConflict());

        assertThat(jdbcTemplate.queryForObject(
                "SELECT password_hash FROM sys_user WHERE username='admin'", String.class)).isEqualTo(originalHash);
        assertThat(jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM sys_user_role ur JOIN sys_role r ON r.id=ur.role_id "
                        + "WHERE ur.user_id=? AND r.role_key='platform_admin' AND ur.scope_type='global' AND ur.scope_id='*'",
                Integer.class, adminId)).isEqualTo(1);
    }

    @Test
    void createsUsersWithHashedPasswordsAndNoImplicitRole() throws Exception {
        Cookie adminSession = loginAndGetSession("authz-admin", "admin");
        CsrfContext csrf = csrf(adminSession);

        mockMvc.perform(post("/api/v1/users")
                        .cookie(adminSession)
                        .header(CSRF_HEADER, csrf.token())
                        .contentType(APPLICATION_JSON)
                        .content("{\"username\":\"new-analyst\",\"displayName\":\"新分析员\","
                                + "\"password\":\"a-strong-test-password\"}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.data.username").value("new-analyst"));

        String passwordHash = jdbcTemplate.queryForObject(
                "SELECT password_hash FROM sys_user WHERE username='new-analyst'", String.class);
        assertThat(passwordHash).startsWith("$2").isNotEqualTo("a-strong-test-password");
        assertThat(jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM sys_user_role ur JOIN sys_user u ON u.id=ur.user_id "
                        + "WHERE u.username='new-analyst'", Integer.class)).isZero();
    }

    private long createUser(String username, String displayName, String status) {
        jdbcTemplate.update("INSERT INTO sys_user (user_key, username, display_name, status, password_hash) "
                        + "VALUES (?, ?, ?, ?, ?)",
                username, username, displayName, status, ADMIN_PASSWORD_HASH);
        return jdbcTemplate.queryForObject("SELECT id FROM sys_user WHERE username=?", Long.class, username);
    }

    private long identityId(String username) {
        return jdbcTemplate.queryForObject("SELECT id FROM sys_user WHERE username=?", Long.class, username);
    }

    private void bindRole(String username, String roleKey, String scopeType, String scopeId) {
        jdbcTemplate.update("INSERT INTO sys_user_role (user_id, role_id, scope_type, scope_id) "
                        + "SELECT u.id, r.id, ?, ? FROM sys_user u JOIN sys_role r ON r.role_key=? "
                        + "WHERE u.username=?",
                scopeType, scopeId, roleKey, username);
    }

    private long createAsset(String keySuffix) {
        String key = "authz-test-" + keySuffix;
        jdbcTemplate.update("INSERT INTO asset (asset_key, asset_type, environment, criticality, owner, status, labels_json) "
                        + "VALUES (?, 'host', 'lab', 'medium', 'test-team', 'active', '{}')", key);
        return jdbcTemplate.queryForObject("SELECT id FROM asset WHERE asset_key=?", Long.class, key);
    }

    private Cookie loginAndGetSession(String username, String password) throws Exception {
        MvcResult csrfResult = mockMvc.perform(get("/api/v1/auth/csrf")).andExpect(status().isOk()).andReturn();
        Cookie csrfCookie = csrfResult.getResponse().getCookie("SESSION");
        String token = objectMapper.readTree(csrfResult.getResponse().getContentAsString())
                .path("data").path("token").asText();
        MvcResult login = mockMvc.perform(post("/api/v1/auth/login")
                        .cookie(csrfCookie)
                        .header(CSRF_HEADER, token)
                        .contentType(APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"))
                .andExpect(status().isOk()).andReturn();
        return login.getResponse().getCookie("SESSION");
    }

    private CsrfContext csrf(Cookie sessionCookie) throws Exception {
        MvcResult result = mockMvc.perform(get("/api/v1/auth/csrf").cookie(sessionCookie))
                .andExpect(status().isOk()).andReturn();
        return new CsrfContext(objectMapper.readTree(result.getResponse().getContentAsString())
                .path("data").path("token").asText());
    }

    private record CsrfContext(String token) {
    }
}
