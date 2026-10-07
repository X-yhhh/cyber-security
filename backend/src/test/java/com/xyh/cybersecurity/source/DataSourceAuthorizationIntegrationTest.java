package com.xyh.cybersecurity.source;

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

/** 验证数据源和映射版本只能在角色的显式 data_source 范围内维护。 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@EnabledIfEnvironmentVariable(named = "DB_TEST_BASE_URL", matches = ".+")
@org.junit.jupiter.api.extension.ExtendWith(com.xyh.cybersecurity.database.IsolatedDatabaseSchemas.class)
class DataSourceAuthorizationIntegrationTest {

    private static final String TEST_SCHEMA = com.xyh.cybersecurity.database.IsolatedDatabaseSchemas.name(DataSourceAuthorizationIntegrationTest.class, "suite");
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
    private long sourceManagerId;
    private long visibleSourceId;
    private long hiddenSourceId;

    @BeforeEach
    void seedFixtures() {
        jdbc.update("DELETE FROM SPRING_SESSION");
        jdbc.update("DELETE FROM audit_resource_scope");
        jdbc.update("DELETE FROM audit_log WHERE action LIKE 'source.%'");
        jdbc.update("DELETE FROM source_mapping WHERE data_source_id IN "
                + "(SELECT id FROM data_source WHERE source_key LIKE 'source-authz-test-%')");
        jdbc.update("DELETE FROM data_source WHERE source_key LIKE 'source-authz-test-%'");
        jdbc.update("DELETE FROM sys_user_role");
        jdbc.update("DELETE FROM sys_user WHERE username IN ('source-authz-admin','source-authz-manager')");
        adminId = createUser("source-authz-admin");
        sourceManagerId = createUser("source-authz-manager");
        bindRole("source-authz-admin", "platform_admin", "global", "*");
        visibleSourceId = createSource("visible");
        hiddenSourceId = createSource("hidden");
        bindRole("source-authz-manager", "asset_source_admin", "data_source", Long.toString(visibleSourceId));
    }

    @Test
    void filtersSourceListAndHidesOutOfScopeUpdates() throws Exception {
        Cookie manager = login("source-authz-manager");
        mockMvc.perform(get("/api/v1/data-sources?page=0&size=20").cookie(manager))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.totalElements").value(1))
                .andExpect(jsonPath("$.data.items[0].id").value(visibleSourceId));
        Csrf csrf = csrf(manager);
        mockMvc.perform(put("/api/v1/data-sources/{id}", hiddenSourceId)
                        .cookie(manager).header(CSRF_HEADER, csrf.token()).contentType(APPLICATION_JSON)
                        .content("{\"environment\":\"lab\",\"schemaVersion\":\"v2\",\"status\":\"disabled\"}"))
                .andExpect(status().isNotFound());
    }

    @Test
    void createsVersionedMappingsWithinScopeAndRejectsDuplicateVersions() throws Exception {
        Cookie manager = login("source-authz-manager");
        Csrf csrf = csrf(manager);
        String mapping = "{\"mappingVersion\":\"1.0\",\"sourceSchema\":{\"flow_id\":\"string\"},"
                + "\"mapping\":{\"recordKey\":\"flow_id\"}}";
        mockMvc.perform(post("/api/v1/data-sources/{id}/mappings", visibleSourceId)
                        .cookie(manager).header(CSRF_HEADER, csrf.token()).contentType(APPLICATION_JSON).content(mapping))
                .andExpect(status().isCreated()).andExpect(jsonPath("$.data.status").value("draft"));
        mockMvc.perform(post("/api/v1/data-sources/{id}/mappings", visibleSourceId)
                        .cookie(manager).header(CSRF_HEADER, csrf.token()).contentType(APPLICATION_JSON).content(mapping))
                .andExpect(status().isConflict());
        mockMvc.perform(post("/api/v1/data-sources/{id}/mappings", hiddenSourceId)
                        .cookie(manager).header(CSRF_HEADER, csrf.token()).contentType(APPLICATION_JSON)
                        .content(mapping.replace("1.0", "2.0")))
                .andExpect(status().isNotFound());
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM source_mapping WHERE data_source_id=?", Integer.class,
                visibleSourceId)).isEqualTo(1);
    }

    @Test
    void mappingApprovalRequiresIndependentApproverAndKnownRequester() throws Exception {
        Cookie manager = login("source-authz-manager");
        Csrf managerCsrf = csrf(manager);
        String mapping = "{\"mappingVersion\":\"1.0\",\"sourceSchema\":{\"flow_id\":\"string\"},"
                + "\"mapping\":{\"recordKey\":\"flow_id\"}}";
        MvcResult created = mockMvc.perform(post("/api/v1/data-sources/{id}/mappings", visibleSourceId)
                        .cookie(manager).header(CSRF_HEADER, managerCsrf.token()).contentType(APPLICATION_JSON)
                        .content(mapping))
                .andExpect(status().isCreated()).andExpect(jsonPath("$.data.requestedBy").value(sourceManagerId))
                .andReturn();
        long mappingId = objectMapper.readTree(created.getResponse().getContentAsString()).path("data").path("id").asLong();

        // 登记人（无批准权限）不能批准。
        mockMvc.perform(post("/api/v1/data-sources/{id}/mappings/{mappingId}/approve", visibleSourceId, mappingId)
                        .cookie(manager).header(CSRF_HEADER, managerCsrf.token()))
                .andExpect(status().isForbidden());

        // 他人（全局平台管理员）批准；重复批准 409。
        Cookie admin = login("source-authz-admin");
        Csrf adminCsrf = csrf(admin);
        mockMvc.perform(post("/api/v1/data-sources/{id}/mappings/{mappingId}/approve", visibleSourceId, mappingId)
                        .cookie(admin).header(CSRF_HEADER, adminCsrf.token()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.status").value("approved"))
                .andExpect(jsonPath("$.data.approvedBy").value(adminId))
                .andExpect(jsonPath("$.data.requestedBy").value(sourceManagerId));
        mockMvc.perform(post("/api/v1/data-sources/{id}/mappings/{mappingId}/approve", visibleSourceId, mappingId)
                        .cookie(admin).header(CSRF_HEADER, adminCsrf.token()))
                .andExpect(status().isConflict());
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM audit_log WHERE action='source.mapping.approved' "
                + "AND resource_id=?", Integer.class, Long.toString(mappingId))).isEqualTo(1);

        // 管理员自己登记的映射不能自批。
        MvcResult own = mockMvc.perform(post("/api/v1/data-sources/{id}/mappings", visibleSourceId)
                        .cookie(admin).header(CSRF_HEADER, adminCsrf.token()).contentType(APPLICATION_JSON)
                        .content(mapping.replace("1.0", "2.0")))
                .andExpect(status().isCreated()).andReturn();
        long ownId = objectMapper.readTree(own.getResponse().getContentAsString()).path("data").path("id").asLong();
        mockMvc.perform(post("/api/v1/data-sources/{id}/mappings/{mappingId}/approve", visibleSourceId, ownId)
                        .cookie(admin).header(CSRF_HEADER, adminCsrf.token()))
                .andExpect(status().isForbidden());

        // V14 之前的映射没有登记人：无法证明职责分离，拒绝经接口批准。
        jdbc.update("INSERT INTO source_mapping (data_source_id,mapping_version,source_schema_json,mapping_json,status) "
                + "VALUES (?,'legacy','{}','{}','draft')", visibleSourceId);
        long legacyId = jdbc.queryForObject("SELECT id FROM source_mapping WHERE data_source_id=? AND mapping_version='legacy'",
                Long.class, visibleSourceId);
        mockMvc.perform(post("/api/v1/data-sources/{id}/mappings/{mappingId}/approve", visibleSourceId, legacyId)
                        .cookie(admin).header(CSRF_HEADER, adminCsrf.token()))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error.code").value("MAPPING_REQUESTER_UNKNOWN"));
        assertThat(jdbc.queryForObject("SELECT status FROM source_mapping WHERE id=?", String.class, legacyId))
                .isEqualTo("draft");
    }

    private long createUser(String username) {
        jdbc.update("INSERT INTO sys_user (user_key,username,display_name,status,password_hash) VALUES (?,?,?,'active',?)",
                username, username, username, PASSWORD_HASH);
        return jdbc.queryForObject("SELECT id FROM sys_user WHERE username=?", Long.class, username);
    }

    private long createSource(String suffix) {
        String key = "source-authz-test-" + suffix;
        jdbc.update("INSERT INTO data_source (source_key,source_type,environment,schema_version,scope_json,status) "
                        + "VALUES (?,'file','lab','v1','{}','active')", key);
        return jdbc.queryForObject("SELECT id FROM data_source WHERE source_key=?", Long.class, key);
    }

    private void bindRole(String username, String roleKey, String scopeType, String scopeId) {
        jdbc.update("INSERT INTO sys_user_role (user_id,role_id,scope_type,scope_id) "
                        + "SELECT u.id,r.id,?,? FROM sys_user u JOIN sys_role r ON r.role_key=? WHERE u.username=?",
                scopeType, scopeId, roleKey, username);
    }

    private Cookie login(String username) throws Exception {
        var csrfResult = mockMvc.perform(get("/api/v1/auth/csrf")).andReturn();
        Cookie cookie = csrfResult.getResponse().getCookie("SESSION");
        String token = objectMapper.readTree(csrfResult.getResponse().getContentAsString()).path("data").path("token").asText();
        return mockMvc.perform(post("/api/v1/auth/login").cookie(cookie).header(CSRF_HEADER, token)
                        .contentType(APPLICATION_JSON).content("{\"username\":\"" + username + "\",\"password\":\"admin\"}"))
                .andExpect(status().isOk()).andReturn().getResponse().getCookie("SESSION");
    }

    private Csrf csrf(Cookie cookie) throws Exception {
        MvcResult result = mockMvc.perform(get("/api/v1/auth/csrf").cookie(cookie)).andReturn();
        return new Csrf(objectMapper.readTree(result.getResponse().getContentAsString()).path("data").path("token").asText());
    }

    private record Csrf(String token) { }
}
