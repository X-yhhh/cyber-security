package com.xyh.cybersecurity.ingest;

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
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** 验证连接器专用机器身份、资源范围和幂等接入边界。 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@EnabledIfEnvironmentVariable(named = "DB_TEST_BASE_URL", matches = ".+")
@org.junit.jupiter.api.extension.ExtendWith(com.xyh.cybersecurity.database.IsolatedDatabaseSchemas.class)
class MachineIngestIntegrationTest {

    private static final String TEST_SCHEMA = com.xyh.cybersecurity.database.IsolatedDatabaseSchemas.name(MachineIngestIntegrationTest.class, "suite");
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
    @Autowired private com.xyh.cybersecurity.identity.IdentityMapper identityMapper;

    private long sourceId;
    private long hiddenSourceId;
    private long assetId;
    private long unpairedAssetId;

    @BeforeEach
    void seedFixtures() {
        jdbc.update("DELETE FROM SPRING_SESSION");
        jdbc.update("DELETE FROM audit_resource_scope");
        jdbc.update("DELETE FROM outbox_event WHERE event_key LIKE 'ingest.batch:%'");
        jdbc.update("DELETE FROM ingest_record WHERE batch_id IN (SELECT id FROM ingest_batch WHERE idempotency_key LIKE 'machine-test-%')");
        jdbc.update("DELETE FROM ingest_batch WHERE idempotency_key LIKE 'machine-test-%'");
        jdbc.update("DELETE FROM api_client_source_asset_scope WHERE client_id IN "
                + "(SELECT id FROM api_client WHERE client_key LIKE 'machine-test-%')");
        jdbc.update("DELETE FROM api_client_scope WHERE client_id IN (SELECT id FROM api_client WHERE client_key LIKE 'machine-test-%')");
        jdbc.update("DELETE FROM api_client_permission WHERE client_id IN (SELECT id FROM api_client WHERE client_key LIKE 'machine-test-%')");
        jdbc.update("DELETE FROM api_client WHERE client_key LIKE 'machine-test-%'");
        jdbc.update("DELETE FROM source_mapping WHERE data_source_id IN (SELECT id FROM data_source WHERE source_key LIKE 'machine-test-%')");
        jdbc.update("DELETE FROM data_source WHERE source_key LIKE 'machine-test-%'");
        jdbc.update("DELETE FROM asset WHERE asset_key LIKE 'machine-test-%'");
        jdbc.update("DELETE FROM sys_user_role");
        jdbc.update("DELETE FROM sys_user WHERE username IN ('machine-test-admin','machine-test-source-manager')");

        createUser("machine-test-admin");
        createUser("machine-test-source-manager");
        bindRole("machine-test-admin", "platform_admin", "global", "*");
        assetId = createAsset("visible");
        unpairedAssetId = createAsset("unpaired");
        sourceId = createSource("visible");
        hiddenSourceId = createSource("hidden");
        bindRole("machine-test-source-manager", "asset_source_admin", "data_source", Long.toString(sourceId));
        bindRole("machine-test-source-manager", "asset_source_admin", "asset", Long.toString(assetId));
        jdbc.update("INSERT INTO source_mapping (data_source_id,mapping_version,source_schema_json,mapping_json,status,approved_by) "
                + "SELECT ?, '1.0', '{\"flow_id\":\"string\"}', '{\"recordKey\":\"flow_id\"}', 'approved', id "
                + "FROM sys_user WHERE username='machine-test-admin'", sourceId);
    }

    @Test
    void browserSessionCannotCallMachineIngest() throws Exception {
        Cookie browser = login("machine-test-admin");
        Csrf csrf = csrf(browser);
        mockMvc.perform(post("/api/v1/machine/ingest/batches").cookie(browser)
                        .header(CSRF_HEADER, csrf.token()).header("Idempotency-Key", "machine-test-browser")
                        .contentType(APPLICATION_JSON).content(batch(sourceId, assetId, "browser-flow", "42")))
                .andExpect(status().isUnauthorized());
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM ingest_batch WHERE idempotency_key='machine-test-browser'",
                Integer.class)).isZero();
    }

    @Test
    void machineCredentialIsScopedAndIdempotentWithAtomicOutbox() throws Exception {
        // 旧登记接口已下线；夹具只在随机隔离库生成机器身份，继续验证实际机器安全链。
        var issued = LegacyMachineFixtures.connector(jdbc, identityMapper, sourceId, assetId, unpairedAssetId);
        String credential = issued.credential();
        long clientId = issued.id();

        String body = batch(sourceId, assetId, "machine-flow-1", "42");
        MvcResult accepted = mockMvc.perform(post("/api/v1/machine/ingest/batches")
                        .header("Authorization", "Machine " + credential).header("Idempotency-Key", "machine-test-replay")
                        .contentType(APPLICATION_JSON).content(body))
                .andExpect(status().isCreated()).andExpect(jsonPath("$.data.status").value("received")).andReturn();
        long batchId = objectMapper.readTree(accepted.getResponse().getContentAsString()).path("data").path("id").asLong();
        mockMvc.perform(post("/api/v1/machine/ingest/batches")
                        .header("Authorization", "Machine " + credential).header("Idempotency-Key", "machine-test-replay")
                        .contentType(APPLICATION_JSON).content(body))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.id").value(batchId));
        mockMvc.perform(post("/api/v1/machine/ingest/batches")
                        .header("Authorization", "Machine " + credential).header("Idempotency-Key", "machine-test-replay")
                        .contentType(APPLICATION_JSON).content(batch(sourceId, assetId, "machine-flow-1", "43")))
                .andExpect(status().isConflict());
        mockMvc.perform(post("/api/v1/machine/ingest/batches")
                        .header("Authorization", "Machine " + credential).header("Idempotency-Key", "machine-test-duplicate-record")
                        .contentType(APPLICATION_JSON).content(duplicateRecordBatch(sourceId, assetId)))
                .andExpect(status().isBadRequest());
        mockMvc.perform(post("/api/v1/machine/ingest/batches")
                        .header("Authorization", "Machine " + credential).header("Idempotency-Key", "machine-test-outside")
                        .contentType(APPLICATION_JSON).content(batch(hiddenSourceId, assetId, "outside-flow", "42")))
                .andExpect(status().isNotFound());
        var unpaired = mockMvc.perform(post("/api/v1/machine/ingest/batches")
                        .header("Authorization", "Machine " + credential).header("Idempotency-Key", "machine-test-unpaired")
                        .contentType(APPLICATION_JSON).content(batch(sourceId, unpairedAssetId, "unpaired-flow", "42")))
                .andReturn();
        assertThat(unpaired.getResponse().getStatus()).isEqualTo(404);
        var oversized = mockMvc.perform(post("/api/v1/machine/ingest/batches")
                        .header("Authorization", "Machine " + credential).header("Idempotency-Key", "machine-test-oversized")
                        .contentType(APPLICATION_JSON).content(body + " ".repeat(1_048_577)))
                .andReturn();
        assertThat(oversized.getResponse().getStatus()).isEqualTo(413);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM ingest_batch WHERE idempotency_key='machine-test-oversized'",
                Integer.class)).isZero();

        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM ingest_record WHERE batch_id=?", Integer.class, batchId)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM outbox_event WHERE event_key=?", Integer.class,
                "ingest.batch:" + batchId)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT credential_sha256 FROM api_client WHERE id=?", String.class, clientId))
                .hasSize(64).doesNotContain(credential);
        jdbc.update("UPDATE api_client SET expires_at=UTC_TIMESTAMP(3)-INTERVAL 1 SECOND WHERE id=?", clientId);
        mockMvc.perform(post("/api/v1/machine/ingest/batches")
                        .header("Authorization", "Machine " + credential).header("Idempotency-Key", "machine-test-expired")
                        .contentType(APPLICATION_JSON).content(body))
                .andExpect(status().isUnauthorized());
    }

    private String batch(long source, long asset, String recordKey, String bytes) {
        return "{\"dataSourceId\":" + source + ",\"mappingVersion\":\"1.0\",\"records\":[{"
                + "\"recordKey\":\"" + recordKey + "\",\"eventType\":\"network_flow\","
                + "\"eventTime\":\"2026-09-23T12:00:00Z\",\"assetId\":" + asset
                + ",\"payload\":{\"bytes\":" + bytes + "}}]}";
    }

    private String duplicateRecordBatch(long source, long asset) {
        String row = "{\"recordKey\":\"duplicate-flow\",\"eventType\":\"network_flow\","
                + "\"eventTime\":\"2026-09-23T12:00:00Z\",\"assetId\":" + asset
                + ",\"payload\":{\"bytes\":42}}";
        return "{\"dataSourceId\":" + source + ",\"mappingVersion\":\"1.0\",\"records\":[" + row + "," + row + "]}";
    }

    private long createUser(String username) {
        jdbc.update("INSERT INTO sys_user (user_key,username,display_name,status,password_hash) VALUES (?,?,?,'active',?)",
                username, username, username, PASSWORD_HASH);
        return jdbc.queryForObject("SELECT id FROM sys_user WHERE username=?", Long.class, username);
    }

    private long createAsset(String suffix) {
        String key = "machine-test-" + suffix;
        jdbc.update("INSERT INTO asset (asset_key,asset_type,environment,criticality,owner,status,labels_json) "
                + "VALUES (?,'host','lab','medium','test','active','{}')", key);
        return jdbc.queryForObject("SELECT id FROM asset WHERE asset_key=?", Long.class, key);
    }

    private long createSource(String suffix) {
        String key = "machine-test-" + suffix;
        jdbc.update("INSERT INTO data_source (source_key,source_type,environment,schema_version,scope_json,status) "
                + "VALUES (?,'connector','lab','v1','{}','active')", key);
        return jdbc.queryForObject("SELECT id FROM data_source WHERE source_key=?", Long.class, key);
    }

    private void bindRole(String username, String roleKey, String scopeType, String scopeId) {
        jdbc.update("INSERT INTO sys_user_role (user_id,role_id,scope_type,scope_id) "
                        + "SELECT u.id,r.id,?,? FROM sys_user u JOIN sys_role r ON r.role_key=? WHERE u.username=?",
                scopeType, scopeId, roleKey, username);
    }

    private Cookie login(String username) throws Exception {
        MvcResult csrfResult = mockMvc.perform(get("/api/v2/auth/csrf")).andReturn();
        Cookie cookie = csrfResult.getResponse().getCookie("SESSION");
        String token = objectMapper.readTree(csrfResult.getResponse().getContentAsString()).path("data").path("token").asText();
        return mockMvc.perform(post("/api/v2/auth/login").header("Idempotency-Key", java.util.UUID.randomUUID().toString()).cookie(cookie).header(CSRF_HEADER, token)
                        .contentType(APPLICATION_JSON).content("{\"username\":\"" + username + "\",\"password\":\"admin\"}"))
                .andExpect(status().isOk()).andReturn().getResponse().getCookie("SESSION");
    }

    private Csrf csrf(Cookie cookie) throws Exception {
        var result = mockMvc.perform(get("/api/v2/auth/csrf").cookie(cookie)).andReturn();
        return new Csrf(objectMapper.readTree(result.getResponse().getContentAsString()).path("data").path("token").asText());
    }

    private record Csrf(String token) { }
}
