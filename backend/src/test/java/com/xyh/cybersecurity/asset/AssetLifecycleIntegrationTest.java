package com.xyh.cybersecurity.asset;

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

/** 验证资产范围维护及需分离审批人的授权生命周期。 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@EnabledIfEnvironmentVariable(named = "DB_TEST_BASE_URL", matches = ".+")
@org.junit.jupiter.api.extension.ExtendWith(com.xyh.cybersecurity.database.IsolatedDatabaseSchemas.class)
class AssetLifecycleIntegrationTest {

    private static final String TEST_SCHEMA = com.xyh.cybersecurity.database.IsolatedDatabaseSchemas.name(AssetLifecycleIntegrationTest.class, "suite");
    private static final String PASSWORD_HASH = new BCryptPasswordEncoder(4).encode("admin");
    private static final String CSRF_HEADER = "X-CSRF-TOKEN";

    @BeforeAll
    static void migrateTestSchema() throws Exception {
        String base = System.getenv("DB_TEST_BASE_URL");
        String user = System.getenv("DB_TEST_USERNAME");
        String password = System.getenv("DB_TEST_PASSWORD");
        try (var connection = java.sql.DriverManager.getConnection(base, user, password);
             var statement = connection.createStatement()) {
            statement.execute("CREATE DATABASE IF NOT EXISTS " + TEST_SCHEMA
                    + " CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci");
        }
        Flyway.configure().dataSource(base.replaceFirst("/+$", "") + "/" + TEST_SCHEMA, user, password)
                .locations("classpath:db/migration").baselineOnMigrate(false).load().migrate();
    }

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        String base = System.getenv("DB_TEST_BASE_URL");
        registry.add("spring.datasource.url", () -> base.replaceFirst("/+$", "") + "/" + TEST_SCHEMA
                + "?connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true");
        registry.add("spring.datasource.username", () -> System.getenv("DB_TEST_USERNAME"));
        registry.add("spring.datasource.password", () -> System.getenv("DB_TEST_PASSWORD"));
        registry.add("spring.flyway.enabled", () -> false);
        registry.add("cyber.security.login-throttle.hmac-key", () -> "test-only-key-with-at-least-thirty-two-bytes");
    }

    @Autowired private MockMvc mockMvc;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private ObjectMapper objectMapper;

    private long adminId;
    private long assetManagerId;
    private long assetId;

    @BeforeEach
    void seedFixtures() {
        jdbc.update("DELETE FROM SPRING_SESSION");
        jdbc.update("DELETE FROM audit_resource_scope");
        jdbc.update("DELETE FROM audit_log WHERE action LIKE 'asset.%' OR action LIKE 'authorization.%'");
        jdbc.update("DELETE FROM asset_authorization");
        jdbc.update("DELETE FROM asset WHERE asset_key LIKE 'asset-lifecycle-test-%'");
        jdbc.update("DELETE FROM sys_user_role");
        jdbc.update("DELETE FROM sys_user WHERE username IN ('asset-lifecycle-admin', 'asset-lifecycle-manager')");
        adminId = createUser("asset-lifecycle-admin");
        assetManagerId = createUser("asset-lifecycle-manager");
        bindRole("asset-lifecycle-admin", "platform_admin", "global", "*");
        bindRole("asset-lifecycle-manager", "asset_source_admin", "asset", "100000");
        assetId = createAsset("in-scope");
        jdbc.update("DELETE FROM sys_user_role WHERE user_id=?", assetManagerId);
        bindRole("asset-lifecycle-manager", "asset_source_admin", "asset", Long.toString(assetId));
    }

    @Test
    void createsAndUpdatesAssetsWithExplicitPermissionsAndScope() throws Exception {
        Cookie admin = login("asset-lifecycle-admin");
        Csrf csrf = csrf(admin);
        MvcResult created = mockMvc.perform(post("/api/v1/assets")
                        .cookie(admin).header(CSRF_HEADER, csrf.token()).contentType(APPLICATION_JSON)
                        .content("{\"assetKey\":\"asset-lifecycle-test-created\",\"assetType\":\"host\","
                                + "\"environment\":\"lab\",\"criticality\":\"medium\","
                                + "\"owner\":\"test\",\"labels\":{}}"))
                .andExpect(status().isCreated()).andExpect(jsonPath("$.data.status").value("active")).andReturn();
        long createdId = objectMapper.readTree(created.getResponse().getContentAsString()).path("data").path("id").asLong();

        Cookie manager = login("asset-lifecycle-manager");
        Csrf managerCsrf = csrf(manager);
        mockMvc.perform(put("/api/v1/assets/{id}", assetId)
                        .cookie(manager).header(CSRF_HEADER, managerCsrf.token()).contentType(APPLICATION_JSON)
                        .content("{\"criticality\":\"high\",\"owner\":\"blue-team\",\"status\":\"active\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.criticality").value("high"));
        mockMvc.perform(put("/api/v1/assets/{id}", createdId)
                        .cookie(manager).header(CSRF_HEADER, managerCsrf.token()).contentType(APPLICATION_JSON)
                        .content("{\"criticality\":\"low\",\"owner\":\"outside\",\"status\":\"active\"}"))
                .andExpect(status().isNotFound());
        assertThat(jdbc.queryForObject("SELECT criticality FROM asset WHERE id=?", String.class, createdId))
                .isEqualTo("medium");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM audit_resource_scope ars JOIN audit_log al ON al.id=ars.audit_id "
                        + "WHERE ars.scope_type='asset' AND ars.scope_id=? AND al.action='asset.updated'",
                Integer.class, Long.toString(assetId))).isEqualTo(1);
        // 审计时间按 UTC 写入：与数据库 UTC 当前时刻同一口径。JVM 默认时区非 UTC 时（如本机 UTC+8），
        // 按默认时区取时会产生整小时偏差。
        assertThat(jdbc.queryForObject("SELECT MAX(ABS(TIMESTAMPDIFF(SECOND, occurred_at, UTC_TIMESTAMP(3)))) "
                + "FROM audit_log WHERE action IN ('asset.created','asset.updated')", Long.class)).isLessThanOrEqualTo(60L);
    }

    @Test
    void authorizationRequestRequiresSeparateApproverAndCurrentValidity() throws Exception {
        Cookie manager = login("asset-lifecycle-manager");
        Csrf managerCsrf = csrf(manager);
        MvcResult requested = mockMvc.perform(post("/api/v1/assets/{id}/authorizations", assetId)
                        .cookie(manager).header(CSRF_HEADER, managerCsrf.token()).contentType(APPLICATION_JSON)
                        .content("{\"authorizationRef\":\"vault://test/asset-authorization\","
                                + "\"validFrom\":\"2026-09-22T00:00:00Z\","
                        + "\"scope\":{\"purpose\":\"passive-monitoring\",\"interfaces\":[\"en0\"]},"
                                + "\"validUntil\":\"2026-09-25T00:00:00Z\"}"))
                .andExpect(status().isCreated()).andExpect(jsonPath("$.data.status").value("pending")).andReturn();
        long authorizationId = objectMapper.readTree(requested.getResponse().getContentAsString())
                .path("data").path("id").asLong();
        assertThat(jdbc.queryForObject("SELECT requested_by FROM asset_authorization WHERE id=?", Long.class,
                authorizationId)).isEqualTo(assetManagerId);

        mockMvc.perform(post("/api/v1/assets/{assetId}/authorizations/{authorizationId}/approve", assetId, authorizationId)
                        .cookie(manager).header(CSRF_HEADER, managerCsrf.token()))
                .andExpect(status().isForbidden());

        Cookie admin = login("asset-lifecycle-admin");
        Csrf adminCsrf = csrf(admin);
        jdbc.update("UPDATE asset_authorization SET valid_until=UTC_TIMESTAMP(3) - INTERVAL 1 SECOND WHERE id=?",
                authorizationId);
        mockMvc.perform(post("/api/v1/assets/{assetId}/authorizations/{authorizationId}/approve", assetId, authorizationId)
                        .cookie(admin).header(CSRF_HEADER, adminCsrf.token()))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error.code").value("AUTHORIZATION_EXPIRED"));
        assertThat(jdbc.queryForObject("SELECT status FROM asset_authorization WHERE id=?", String.class,
                authorizationId)).isEqualTo("pending");
    }

    private long createUser(String username) {
        jdbc.update("INSERT INTO sys_user (user_key,username,display_name,status,password_hash) VALUES (?,?,?,'active',?)",
                username, username, username, PASSWORD_HASH);
        return jdbc.queryForObject("SELECT id FROM sys_user WHERE username=?", Long.class, username);
    }

    private long createAsset(String suffix) {
        String key = "asset-lifecycle-test-" + suffix;
        jdbc.update("INSERT INTO asset (asset_key,asset_type,environment,criticality,owner,status,labels_json) "
                        + "VALUES (?,'host','lab','medium','test','active','{}')", key);
        return jdbc.queryForObject("SELECT id FROM asset WHERE asset_key=?", Long.class, key);
    }

    private void bindRole(String username, String roleKey, String scopeType, String scopeId) {
        jdbc.update("INSERT INTO sys_user_role (user_id,role_id,scope_type,scope_id) "
                        + "SELECT u.id,r.id,?,? FROM sys_user u JOIN sys_role r ON r.role_key=? WHERE u.username=?",
                scopeType, scopeId, roleKey, username);
    }

    private Cookie login(String username) throws Exception {
        MvcResult csrfResult = mockMvc.perform(get("/api/v1/auth/csrf")).andReturn();
        Cookie cookie = csrfResult.getResponse().getCookie("SESSION");
        String token = objectMapper.readTree(csrfResult.getResponse().getContentAsString()).path("data").path("token").asText();
        return mockMvc.perform(post("/api/v1/auth/login").cookie(cookie).header(CSRF_HEADER, token)
                        .contentType(APPLICATION_JSON).content("{\"username\":\"" + username + "\",\"password\":\"admin\"}"))
                .andExpect(status().isOk()).andReturn().getResponse().getCookie("SESSION");
    }

    private Csrf csrf(Cookie cookie) throws Exception {
        var result = mockMvc.perform(get("/api/v1/auth/csrf").cookie(cookie)).andReturn();
        return new Csrf(objectMapper.readTree(result.getResponse().getContentAsString()).path("data").path("token").asText());
    }

    private record Csrf(String token) { }
}
