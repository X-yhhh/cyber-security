package com.xyh.cybersecurity.query;

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
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/** 控制台只读查询：功能权限拒绝、资产范围过滤、全局管理员可见性与未登录拒绝。 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@EnabledIfEnvironmentVariable(named = "DB_TEST_BASE_URL", matches = ".+")
@org.junit.jupiter.api.extension.ExtendWith(com.xyh.cybersecurity.database.IsolatedDatabaseSchemas.class)
class ConsoleQueryIntegrationTest {

    private static final String TEST_SCHEMA = com.xyh.cybersecurity.database.IsolatedDatabaseSchemas.name(ConsoleQueryIntegrationTest.class, "suite");
    private static final String PASSWORD = "console-query-test-password";
    private static final String HASH = new BCryptPasswordEncoder(4).encode(PASSWORD);

    @Autowired private MockMvc mockMvc;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private ObjectMapper objectMapper;

    @BeforeAll
    static void migrate() throws Exception {
        String baseUrl = System.getenv("DB_TEST_BASE_URL");
        try (var connection = java.sql.DriverManager.getConnection(baseUrl, System.getenv("DB_TEST_USERNAME"),
                System.getenv("DB_TEST_PASSWORD")); var statement = connection.createStatement()) {
            statement.execute("CREATE DATABASE IF NOT EXISTS " + TEST_SCHEMA
                    + " CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci");
        }
        Flyway.configure().dataSource(baseUrl.replaceFirst("/+$", "") + "/" + TEST_SCHEMA,
                System.getenv("DB_TEST_USERNAME"), System.getenv("DB_TEST_PASSWORD"))
                .locations("classpath:db/migration").load().migrate();
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        String baseUrl = System.getenv("DB_TEST_BASE_URL");
        registry.add("spring.datasource.url", () -> baseUrl.replaceFirst("/+$", "") + "/" + TEST_SCHEMA
                + "?connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true");
        registry.add("spring.datasource.username", () -> System.getenv("DB_TEST_USERNAME"));
        registry.add("spring.datasource.password", () -> System.getenv("DB_TEST_PASSWORD"));
        registry.add("spring.flyway.enabled", () -> false);
        registry.add("cyber.security.login-throttle.hmac-key", () -> "test-only-key-with-at-least-thirty-two-bytes");
    }

    private long assetA;
    private long assetB;

    @BeforeEach
    void fixtures() {
        jdbc.update("DELETE FROM SPRING_SESSION");
        jdbc.update("DELETE FROM auth_login_throttle");
        jdbc.update("DELETE FROM sensor_agent WHERE agent_key LIKE 'cq-%'");
        jdbc.update("INSERT IGNORE INTO asset (asset_key, asset_type, environment, criticality, owner, status, labels_json) "
                + "VALUES ('cq-asset-a','host','range','low','test','active','{}'),('cq-asset-b','host','range','low','test','active','{}')");
        assetA = jdbc.queryForObject("SELECT id FROM asset WHERE asset_key='cq-asset-a'", Long.class);
        assetB = jdbc.queryForObject("SELECT id FROM asset WHERE asset_key='cq-asset-b'", Long.class);
        jdbc.update("INSERT INTO sensor_agent (agent_key, asset_id, platform, agent_version, capabilities_json, credential_ref, "
                + "status, registered_at) VALUES ('cq-sensor-a',?,'macos','1','{}','vault://t','active',UTC_TIMESTAMP(3)),"
                + "('cq-sensor-b',?,'windows','1','{}','vault://t','active',UTC_TIMESTAMP(3))", assetA, assetB);
        user("cq-admin", "platform_admin", "global", "*");
        user("cq-analyst", "security_analyst", "asset", Long.toString(assetA));
        user("cq-auditor", "auditor", "asset", Long.toString(assetA));
    }

    @Test
    void sensorsAreFilteredByAssetScope() throws Exception {
        JsonNode analyst = getData(login("cq-analyst"), "/api/v1/sensors");
        assertThat(analyst.findValuesAsText("agentKey")).contains("cq-sensor-a").doesNotContain("cq-sensor-b");
        JsonNode admin = getData(login("cq-admin"), "/api/v1/sensors");
        assertThat(admin.findValuesAsText("agentKey")).contains("cq-sensor-a", "cq-sensor-b");
    }

    @Test
    void missingPermissionIsDeniedAndAnonymousIsRejected() throws Exception {
        Cookie auditor = login("cq-auditor");
        assertThat(mockMvc.perform(get("/api/v1/sensors").cookie(auditor)).andReturn().getResponse().getStatus()).isEqualTo(403);
        assertThat(mockMvc.perform(get("/api/v1/training-jobs").cookie(auditor)).andReturn().getResponse().getStatus()).isEqualTo(403);
        assertThat(mockMvc.perform(get("/api/v1/overview")).andReturn().getResponse().getStatus()).isEqualTo(401);
    }

    @Test
    void overviewAndLedgerReturnOnlyScopedCounts() throws Exception {
        Cookie analyst = login("cq-analyst");
        JsonNode overview = getData(analyst, "/api/v1/overview");
        assertThat(overview.path("quality24h").has("accepted")).isTrue();
        assertThat(getData(analyst, "/api/v1/actions/mine").isArray()).isTrue();
    }

    private void user(String username, String role, String scopeType, String scopeId) {
        jdbc.update("INSERT INTO sys_user (user_key, username, display_name, status, password_hash) VALUES (?,?,?,'active',?) "
                + "ON DUPLICATE KEY UPDATE password_hash=VALUES(password_hash), status='active'", username, username, username, HASH);
        long id = jdbc.queryForObject("SELECT id FROM sys_user WHERE username=?", Long.class, username);
        jdbc.update("DELETE FROM sys_user_role WHERE user_id=?", id);
        jdbc.update("INSERT INTO sys_user_role (user_id, role_id, scope_type, scope_id) "
                + "SELECT ?, id, ?, ? FROM sys_role WHERE role_key=?", id, scopeType, scopeId, role);
    }

    private JsonNode getData(Cookie cookie, String path) throws Exception {
        MvcResult result = mockMvc.perform(get(path).cookie(cookie)).andReturn();
        assertThat(result.getResponse().getStatus()).as(path).isEqualTo(200);
        return objectMapper.readTree(result.getResponse().getContentAsString()).path("data");
    }

    private Cookie login(String username) throws Exception {
        MvcResult bootstrap = mockMvc.perform(get("/api/v1/auth/csrf")).andReturn();
        Cookie cookie = bootstrap.getResponse().getCookie("SESSION");
        String token = objectMapper.readTree(bootstrap.getResponse().getContentAsString()).path("data").path("token").asText();
        MvcResult login = mockMvc.perform(post("/api/v1/auth/login").cookie(cookie).header("X-CSRF-TOKEN", token)
                .contentType(APPLICATION_JSON).content("{\"username\":\"" + username + "\",\"password\":\"" + PASSWORD + "\"}"))
                .andReturn();
        assertThat(login.getResponse().getStatus()).isEqualTo(200);
        return login.getResponse().getCookie("SESSION");
    }
}
