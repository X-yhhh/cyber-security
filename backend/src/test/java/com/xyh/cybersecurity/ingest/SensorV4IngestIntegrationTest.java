package com.xyh.cybersecurity.ingest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.xyh.cybersecurity.ingest.contract.FeatureContractRegistry;
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

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 路线 B 阶段 3 验收（§9.3）：传感器按 v4 契约上报时，合格记录进入 outbox、拒绝原因可查询；
 * 映射未绑定契约、配置契约哈希过期时整批拒绝；v3.1 在线路径仍 fail-closed。地址不出现在记录中，特征为合成值。
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@EnabledIfEnvironmentVariable(named = "DB_TEST_BASE_URL", matches = ".+")
class SensorV4IngestIntegrationTest {
    private static final String TEST_SCHEMA = "cyber_security_backend_sensor_v4_ingest_20260929";
    private static final String PASSWORD_HASH = new BCryptPasswordEncoder(4).encode("admin");
    private static final String CSRF_HEADER = "X-CSRF-TOKEN";
    private static final String V4 = "unsw-nb15-flow-v4";
    private static final String V31 = "unsw-nb15-flow-v3.1";

    @BeforeAll
    static void migrateTestSchema() throws Exception {
        String base = System.getenv("DB_TEST_BASE_URL");
        try (var connection = java.sql.DriverManager.getConnection(base, System.getenv("DB_TEST_USERNAME"), System.getenv("DB_TEST_PASSWORD"));
             var statement = connection.createStatement()) {
            statement.execute("CREATE DATABASE IF NOT EXISTS " + TEST_SCHEMA + " CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci");
        }
        Flyway.configure().dataSource(base.replaceFirst("/+$", "") + "/" + TEST_SCHEMA, System.getenv("DB_TEST_USERNAME"),
                System.getenv("DB_TEST_PASSWORD")).locations("classpath:db/migration").baselineOnMigrate(false).load().migrate();
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

    private long assetId;
    private long sourceId;

    @BeforeEach
    void seed() {
        // 专用测试 schema：按外键依赖顺序清空本测试涉及的表。
        for (String table : java.util.List.of("SPRING_SESSION", "audit_resource_scope", "outbox_event", "ingest_record",
                "ingest_batch", "sensor_health_window", "sensor_config", "api_client_source_asset_scope", "api_client_scope",
                "api_client_permission", "api_client", "sensor_agent", "source_mapping", "data_source", "asset_authorization",
                "asset", "sys_user_role")) {
            jdbc.update("DELETE FROM " + table);
        }
        jdbc.update("DELETE FROM sys_user WHERE username='sensor-v4-admin'");
        jdbc.update("INSERT INTO sys_user (user_key,username,display_name,status,password_hash) VALUES "
                + "('sensor-v4-admin','sensor-v4-admin','sensor-v4-admin','active',?)", PASSWORD_HASH);
        jdbc.update("INSERT INTO sys_user_role (user_id,role_id,scope_type,scope_id) SELECT u.id,r.id,'global','*' "
                + "FROM sys_user u JOIN sys_role r ON r.role_key='platform_admin' WHERE u.username='sensor-v4-admin'");
        jdbc.update("INSERT INTO asset (asset_key,asset_type,environment,criticality,owner,status,labels_json) "
                + "VALUES ('sensor-v4-host','host','lab','medium','test','active','{}')");
        assetId = jdbc.queryForObject("SELECT id FROM asset WHERE asset_key='sensor-v4-host'", Long.class);
        jdbc.update("INSERT INTO asset_authorization (asset_id,authorization_ref,scope_json,valid_from,valid_until,status,approved_by) "
                + "SELECT ?, 'test://authorization', '{}', UTC_TIMESTAMP(3) - INTERVAL 1 DAY, UTC_TIMESTAMP(3) + INTERVAL 1 DAY, "
                + "'active', id FROM sys_user WHERE username='sensor-v4-admin'", assetId);
        jdbc.update("INSERT INTO data_source (source_key,source_type,environment,schema_version,scope_json,status) "
                + "VALUES ('sensor-v4-source','sensor','lab','v1','{}','active')");
        sourceId = jdbc.queryForObject("SELECT id FROM data_source WHERE source_key='sensor-v4-source'", Long.class);
        String v4Sha = FeatureContractRegistry.fromClasspath().require(V4).fileSha256();
        // 1.0 绑定 v4 契约；2.0 为未绑定契约的历史映射。
        jdbc.update("INSERT INTO source_mapping (data_source_id,mapping_version,source_schema_json,mapping_json,"
                + "feature_contract_version,feature_contract_sha256,status,approved_by) SELECT ?, '1.0', '{}', '{}', ?, ?, "
                + "'approved', id FROM sys_user WHERE username='sensor-v4-admin'", sourceId, V4, v4Sha);
        jdbc.update("INSERT INTO source_mapping (data_source_id,mapping_version,source_schema_json,mapping_json,status,approved_by) "
                + "SELECT ?, '2.0', '{}', '{}', 'approved', id FROM sys_user WHERE username='sensor-v4-admin'", sourceId);
    }

    @Test
    void v4RecordsReachOutboxAndBindingViolationsFailClosed() throws Exception {
        Sensor sensor = register("sensor-v4-a", V4);
        assertThat(jdbc.queryForObject("SELECT last_success_at FROM data_source WHERE id=?", java.sql.Timestamp.class, sourceId)).isNull();
        assertThat(jdbc.queryForObject("SELECT feature_contract_sha256 FROM sensor_config WHERE sensor_id=?", String.class,
                sensor.id())).isEqualTo(FeatureContractRegistry.fromClasspath().require(V4).fileSha256());

        MvcResult accepted = submit(sensor, "v4-ok", 1, "1.0", V4, record("r-ok", true)).andExpect(status().isCreated()).andReturn();
        long batchId = data(accepted).path("id").asLong();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM outbox_event WHERE event_key=?", Integer.class,
                "sensor.ingest.batch:" + batchId)).isEqualTo(1);
        String issues = jdbc.queryForObject("SELECT quality_issues_json FROM ingest_record WHERE batch_id=?", String.class, batchId);
        assertThat(issues).contains("VOCABULARY_UNAVAILABLE");
        // 有记录通过门禁即刷新数据源最近成功时间，口径为 UTC。
        assertThat(jdbc.queryForObject("SELECT TIMESTAMPDIFF(SECOND, last_success_at, UTC_TIMESTAMP(3)) FROM data_source WHERE id=?",
                Long.class, sourceId)).isBetween(0L, 60L);
        jdbc.update("UPDATE data_source SET last_success_at=NULL WHERE id=?", sourceId);
        assertThat(jdbc.queryForObject("SELECT JSON_UNQUOTE(JSON_EXTRACT(normalized_payload,'$.metadata.viewpoint')) "
                + "FROM ingest_record WHERE batch_id=?", String.class, batchId)).isEqualTo("responder");

        MvcResult missing = submit(sensor, "v4-missing-metadata", 2, "1.0", V4, record("r-missing", false))
                .andExpect(status().isUnprocessableEntity()).andReturn();
        long rejectedBatch = data(missing).path("id").asLong();
        assertThat(jdbc.queryForObject("SELECT quality_status FROM ingest_record WHERE batch_id=?", String.class, rejectedBatch))
                .isEqualTo("rejected");
        assertThat(jdbc.queryForObject("SELECT quality_issues_json FROM ingest_record WHERE batch_id=?", String.class, rejectedBatch))
                .contains("RECORD_METADATA_INVALID");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM outbox_event WHERE event_key=?", Integer.class,
                "sensor.ingest.batch:" + rejectedBatch)).isZero();
        assertThat(jdbc.queryForObject("SELECT last_success_at FROM data_source WHERE id=?", java.sql.Timestamp.class, sourceId)).isNull();

        submit(sensor, "v4-unbound-mapping", 3, "2.0", V4, record("r-unbound", true)).andExpect(status().isConflict());
        jdbc.update("UPDATE sensor_config SET feature_contract_sha256=? WHERE sensor_id=?", "0".repeat(64), sensor.id());
        submit(sensor, "v4-stale-config", 3, "1.0", V4, record("r-stale", true)).andExpect(status().isConflict());
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM ingest_batch WHERE sensor_id=?", Integer.class, sensor.id())).isEqualTo(2);
    }

    @Test
    void v31OnlineIngestStaysFailClosed() throws Exception {
        Sensor sensor = register("sensor-v31-a", V31);
        MvcResult result = submit(sensor, "v31-online", 1, "2.0", V31, record("r-v31", false))
                .andExpect(status().isUnprocessableEntity()).andReturn();
        long batchId = data(result).path("id").asLong();
        assertThat(jdbc.queryForObject("SELECT quality_issues_json FROM ingest_record WHERE batch_id=?", String.class, batchId))
                .contains("FEATURE_CONTRACT_MISMATCH");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM outbox_event", Integer.class)).isZero();
    }

    /**
     * 回归：序号 0 违反 {@code @Positive}。该接口参数上直接声明了约束，Spring 走方法级校验并抛
     * HandlerMethodValidationException；此前落到 500，传感器把 5xx 当作可重试而无限重发。必须是 400 且不写批次。
     */
    @Test
    void nonPositiveSequenceIsBadRequestNotServerError() throws Exception {
        Sensor sensor = register("sensor-v4-seq0", V4);
        MvcResult result = submit(sensor, "v4-seq0", 0, "1.0", V4, record("r-seq0", true))
                .andExpect(status().isBadRequest()).andReturn();
        assertThat(objectMapper.readTree(result.getResponse().getContentAsString()).path("error").path("code").asText())
                .isEqualTo("INVALID_REQUEST");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM ingest_batch WHERE sensor_id=?", Integer.class, sensor.id())).isZero();
    }

    /**
     * 回归：健康窗口列为 DATETIME(3)，MySQL 默认对亚毫秒四舍五入。上一窗口结束（.840512345 → .841）进位后大于
     * 本窗口开始，相邻窗口被误判为重叠（409）；本机冒烟中多个窗口因此丢失。服务端按毫秒截断后再判重叠与写入。
     */
    @Test
    void adjacentHealthWindowsWithSubMillisecondBoundaryDoNotOverlap() throws Exception {
        Sensor sensor = register("sensor-v4-health", V4);
        String boundary = "2026-09-29T20:02:02.840512345Z";
        health(sensor, "2026-09-29T20:01:02.654Z", boundary).andExpect(status().isNoContent());
        health(sensor, boundary, "2026-09-29T20:03:03.024Z").andExpect(status().isNoContent());
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM sensor_health_window WHERE sensor_id=?", Integer.class,
                sensor.id())).isEqualTo(2);
    }

    private org.springframework.test.web.servlet.ResultActions health(Sensor sensor, String start, String end) throws Exception {
        return mockMvc.perform(post("/api/v1/machine/sensors/{id}/health-windows", sensor.id())
                .header("Authorization", "Machine " + sensor.credential()).contentType(APPLICATION_JSON)
                .content("{\"windowStart\":\"" + start + "\",\"windowEnd\":\"" + end + "\",\"flowsSeen\":10,"
                        + "\"flowsEmitted\":5,\"flowsDropped\":0,\"queueDepthMax\":1,\"errors\":{}}"));
    }

    private Sensor register(String agentKey, String contract) throws Exception {
        Cookie admin = login();
        String token = csrf(admin);
        MvcResult issued = mockMvc.perform(post("/api/v1/sensors").cookie(admin).header(CSRF_HEADER, token)
                        .contentType(APPLICATION_JSON).content("{\"agentKey\":\"" + agentKey + "\",\"assetId\":" + assetId
                                + ",\"dataSourceId\":" + sourceId + ",\"platform\":\"macos\",\"agentVersion\":\"0.1.0\","
                                + "\"capabilities\":{},\"config\":{\"configVersion\":\"cfg-1\",\"interfaceScope\":{},"
                                + "\"filterPolicy\":{},\"flowWindowSeconds\":60,\"featureContractVersion\":\"" + contract
                                + "\",\"samplingPolicy\":{}}}"))
                .andExpect(status().isCreated()).andReturn();
        JsonNode body = data(issued);
        return new Sensor(body.path("sensorId").asLong(), body.path("credential").asText());
    }

    private org.springframework.test.web.servlet.ResultActions submit(Sensor sensor, String key, long sequence, String mapping,
                                                                     String contract, String record) throws Exception {
        String body = "{\"dataSourceId\":" + sourceId + ",\"configVersion\":\"cfg-1\",\"sequence\":" + sequence
                + ",\"observedAt\":\"" + Instant.now() + "\",\"sourceMappingVersion\":\"" + mapping
                + "\",\"featureContractVersion\":\"" + contract + "\",\"records\":[" + record + "]}";
        return mockMvc.perform(post("/api/v1/machine/sensors/{id}/flow-batches", sensor.id())
                .header("Authorization", "Machine " + sensor.credential()).header("Idempotency-Key", key)
                .contentType(APPLICATION_JSON).content(body));
    }

    /** 满足 v4 契约全部边界规则的一条入站 TCP 流；{@code withMetadata=false} 时不带 v4 元数据。 */
    private static String record(String recordKey, boolean withMetadata) {
        Instant end = Instant.now().minusSeconds(120);
        String metadata = withMetadata ? ",\"viewpoint\":\"responder\",\"addressFamily\":\"ipv4\",\"handshakeSeen\":true" : "";
        return "{\"recordKey\":\"" + recordKey + "\",\"flowStartAt\":\"" + end.minusSeconds(1) + "\",\"flowEndAt\":\"" + end
                + "\",\"observedAt\":\"" + end.plusSeconds(1) + "\",\"directionBasis\":\"initiator_to_responder\"" + metadata
                + ",\"features\":{\"dur\":1.0,\"sbytes\":100,\"dbytes\":200,\"sload\":400.0,\"dload\":800.0,\"tcprtt\":0.0003,"
                + "\"ackdat\":0.0001,\"synack\":0.0002,\"smean\":50,\"dmean\":100,\"spkts\":2,\"dpkts\":2,\"ct_srv_src\":5,"
                + "\"ct_srv_dst\":5,\"ct_dst_ltm\":100,\"ct_src_ltm\":5,\"ct_src_dport_ltm\":1,\"proto\":\"tcp\",\"service\":\"http\"}}";
    }

    private JsonNode data(MvcResult result) throws Exception {
        return objectMapper.readTree(result.getResponse().getContentAsString()).path("data");
    }

    private Cookie login() throws Exception {
        MvcResult csrfResult = mockMvc.perform(get("/api/v1/auth/csrf")).andReturn();
        Cookie cookie = csrfResult.getResponse().getCookie("SESSION");
        String token = objectMapper.readTree(csrfResult.getResponse().getContentAsString()).path("data").path("token").asText();
        return mockMvc.perform(post("/api/v1/auth/login").cookie(cookie).header(CSRF_HEADER, token).contentType(APPLICATION_JSON)
                        .content("{\"username\":\"sensor-v4-admin\",\"password\":\"admin\"}"))
                .andExpect(status().isOk()).andReturn().getResponse().getCookie("SESSION");
    }

    private String csrf(Cookie cookie) throws Exception {
        var result = mockMvc.perform(get("/api/v1/auth/csrf").cookie(cookie)).andReturn();
        return objectMapper.readTree(result.getResponse().getContentAsString()).path("data").path("token").asText();
    }

    private record Sensor(long id, String credential) { }
}
