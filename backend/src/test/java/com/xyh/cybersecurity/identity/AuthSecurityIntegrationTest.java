package com.xyh.cybersecurity.identity;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.flywaydb.core.Flyway;
import org.springframework.test.web.servlet.MvcResult;
import jakarta.servlet.http.Cookie;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@EnabledIfEnvironmentVariable(named = "DB_TEST_BASE_URL", matches = ".+")
@org.junit.jupiter.api.extension.ExtendWith(com.xyh.cybersecurity.database.IsolatedDatabaseSchemas.class)
class AuthSecurityIntegrationTest {

    private static final String TEST_SCHEMA = com.xyh.cybersecurity.database.IsolatedDatabaseSchemas.name(AuthSecurityIntegrationTest.class, "suite");
    private static final String EXISTING_ADMIN_HASH = "$2a$12$wnH.GRQsjecWDHOvIAnApObHTCWtvrjOKXrQCAdfv0J.6cJnMRzcq";
    private static final String ADMIN_HASH = new BCryptPasswordEncoder(12).encode("admin");
    private static final String CSRF_HEADER = "X-CSRF-TOKEN";

    @BeforeAll
    static void migrateAuthenticationTestSchema() throws Exception {
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

    @BeforeEach
    void createIsolatedIdentityFixtures() {
        jdbcTemplate.update("DELETE FROM SPRING_SESSION");
        jdbcTemplate.update("DELETE FROM auth_login_throttle");
        jdbcTemplate.update("DELETE FROM audit_log WHERE actor_type='human' AND resource_type='system'");
        jdbcTemplate.update("INSERT INTO sys_user (user_key, username, display_name, status, password_hash) "
                        + "VALUES (?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE password_hash=VALUES(password_hash), status='active'",
                "test-admin", "admin", "测试平台管理员", "active", ADMIN_HASH);
        jdbcTemplate.update("INSERT INTO sys_user (user_key, username, display_name, status, password_hash) "
                        + "VALUES (?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE id=id",
                "test-existing-admin", "existing-admin", "原有管理员哈希保留测试", "active", EXISTING_ADMIN_HASH);
        jdbcTemplate.update("INSERT INTO sys_user (user_key, username, display_name, status, password_hash) "
                        + "VALUES (?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE id=id",
                "test-locked", "locked-user", "锁定测试用户", "locked", ADMIN_HASH);
        jdbcTemplate.update("INSERT INTO sys_user_role (user_id, role_id, scope_type, scope_id) "
                        + "SELECT u.id, r.id, 'global', '*' FROM sys_user u JOIN sys_role r "
                        + "ON r.role_key='platform_admin' WHERE u.username='admin' "
                        + "AND NOT EXISTS (SELECT 1 FROM sys_user_role ur WHERE ur.user_id=u.id "
                        + "AND ur.role_id=r.id AND ur.scope_type='global' AND ur.scope_id='*')");
    }

    @Test
    void rejectsAnonymousSessionProfileRequest() throws Exception {
        mockMvc.perform(get("/api/v1/auth/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.error.code").value("UNAUTHENTICATED"));
    }

    @Test
    void rejectsLoginWithoutCsrfToken() throws Exception {
        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(APPLICATION_JSON)
                        .content("{\"username\":\"admin\",\"password\":\"admin\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error.code").value("CSRF_INVALID"));
    }

    @Test
    void loginRotatesSessionAndReturnsOnlyAssignedPermissions() throws Exception {
        MvcResult csrfResult = mockMvc.perform(get("/api/v1/auth/csrf"))
                .andExpect(status().isOk())
                .andReturn();
        Cookie csrfCookie = csrfResult.getResponse().getCookie("SESSION");
        assertThat(csrfCookie).isNotNull();
        String originalSessionCookie = csrfCookie.getValue();
        JsonNode csrf = objectMapper.readTree(csrfResult.getResponse().getContentAsString()).path("data");

        MvcResult login = mockMvc.perform(post("/api/v1/auth/login")
                        .cookie(csrfCookie)
                        .header(CSRF_HEADER, csrf.path("token").asText())
                        .contentType(APPLICATION_JSON)
                        .content("{\"username\":\"admin\",\"password\":\"admin\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.username").value("admin"))
                .andExpect(jsonPath("$.data.roles[0]").value("platform_admin"))
                .andExpect(jsonPath("$.data.permissions").isArray())
                .andReturn();

        Cookie authenticatedCookie = login.getResponse().getCookie("SESSION");
        assertThat(authenticatedCookie).isNotNull();
        assertThat(authenticatedCookie.getValue()).isNotEqualTo(originalSessionCookie);
        JsonNode permissions = objectMapper.readTree(login.getResponse().getContentAsString())
                .path("data").path("permissions");
        assertThat(permissions.toString()).contains("iam.user.manage", "asset.authorization.approve", "audit.read")
                .doesNotContain("approval.decide", "action.request", "model.release.approve", "response.policy.manage");
        assertThat(login.getResponse().getHeader("Set-Cookie"))
                .contains("HttpOnly")
                .containsIgnoringCase("SameSite=Lax");

        mockMvc.perform(get("/api/v1/auth/me").cookie(authenticatedCookie))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.username").value("admin"));

        mockMvc.perform(post("/api/v1/auth/logout")
                        .cookie(authenticatedCookie)
                        .header(CSRF_HEADER, csrf.path("token").asText()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.status").value("logged_out"));
        mockMvc.perform(get("/api/v1/auth/me").cookie(authenticatedCookie))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void throttlesRepeatedFailedAuthenticationAttempts() throws Exception {
        for (int attempt = 0; attempt < 5; attempt++) {
            loginFailure("admin", "wrong-password");
        }
        MvcResult throttled = loginAttempt("admin", "admin");

        assertThat(throttled.getResponse().getStatus()).isEqualTo(429);
        assertThat(throttled.getResponse().getContentAsString()).contains("LOGIN_RATE_LIMITED");
    }

    @Test
    void limitsConcurrentSessionsForTheSameUser() throws Exception {
        Cookie firstSession = loginAndGetSessionCookie("admin", "admin");
        loginAndGetSessionCookie("admin", "admin");

        mockMvc.perform(get("/api/v1/auth/me").cookie(firstSession))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void rejectsUnknownAndLockedUsersWithSameAuthenticationError() throws Exception {
        String unknownBody = loginFailure("missing-user");
        String lockedBody = loginFailure("locked-user");

        assertThat(unknownBody).contains("AUTHENTICATION_FAILED");
        assertThat(lockedBody).contains("AUTHENTICATION_FAILED");
        assertThat(unknownBody).doesNotContain("missing-user");
        assertThat(lockedBody).doesNotContain("locked-user");
    }

    @Test
    void leavesExistingAdminPasswordHashUntouched() {
        assertThat(jdbcTemplate.queryForObject("SELECT password_hash FROM sys_user WHERE username='existing-admin'",
                String.class)).isEqualTo(EXISTING_ADMIN_HASH);
    }

    private String loginFailure(String username) throws Exception {
        return loginFailure(username, "admin");
    }

    private String loginFailure(String username, String password) throws Exception {
        MvcResult csrfResult = mockMvc.perform(get("/api/v1/auth/csrf"))
                .andExpect(status().isOk()).andReturn();
        Cookie csrfCookie = csrfResult.getResponse().getCookie("SESSION");
        String token = objectMapper.readTree(csrfResult.getResponse().getContentAsString())
                .path("data").path("token").asText();
        MvcResult failure = mockMvc.perform(post("/api/v1/auth/login")
                        .cookie(csrfCookie)
                        .header(CSRF_HEADER, token)
                        .contentType(APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error.code").value("AUTHENTICATION_FAILED"))
                .andReturn();
        return failure.getResponse().getContentAsString();
    }

    private Cookie loginAndGetSessionCookie(String username, String password) throws Exception {
        MvcResult csrfResult = mockMvc.perform(get("/api/v1/auth/csrf"))
                .andExpect(status().isOk()).andReturn();
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

    private MvcResult loginAttempt(String username, String password) throws Exception {
        MvcResult csrfResult = mockMvc.perform(get("/api/v1/auth/csrf")).andReturn();
        Cookie csrfCookie = csrfResult.getResponse().getCookie("SESSION");
        String token = objectMapper.readTree(csrfResult.getResponse().getContentAsString())
                .path("data").path("token").asText();
        return mockMvc.perform(post("/api/v1/auth/login")
                        .cookie(csrfCookie)
                        .header(CSRF_HEADER, token)
                        .contentType(APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"))
                .andReturn();
    }
}
