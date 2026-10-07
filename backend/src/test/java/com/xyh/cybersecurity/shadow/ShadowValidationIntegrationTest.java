package com.xyh.cybersecurity.shadow;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.xyh.cybersecurity.drift.DriftMetricService;
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

import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 路线 B 阶段 7：告警级人工标注与第二人复核、M8 漂移窗口任务、影子验证汇总与 G3 判定。
 * 数据为合成值：一个数据源、一个传感器、一批 5 条记录（3 条推理成功、1 条范围外、1 条接入拒绝），2 条模型告警。
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@EnabledIfEnvironmentVariable(named = "DB_TEST_BASE_URL", matches = ".+")
@org.junit.jupiter.api.extension.ExtendWith(com.xyh.cybersecurity.database.IsolatedDatabaseSchemas.class)
class ShadowValidationIntegrationTest {
    private static final String TEST_SCHEMA = com.xyh.cybersecurity.database.IsolatedDatabaseSchemas.name(ShadowValidationIntegrationTest.class, "suite");
    private static final String HASH = new BCryptPasswordEncoder(4).encode("shadow-password");
    private static final String CSRF_HEADER = "X-CSRF-TOKEN";
    private static final String V4 = "unsw-nb15-flow-v4";
    /** 最小 manifest：一个数值字段 dur、一个类别字段 proto，基线 min_samples=200。 */
    private static final String MANIFEST = "{\"model_version\":\"shadow-test-1\",\"feature_contract\":{\"inputs\":{"
            + "\"flow_numeric\":[{\"name\":\"dur\",\"unit\":\"秒\"}],\"flow_categorical\":[\"proto\"]}},"
            + "\"feature_baseline_stats\":{\"schema_version\":\"baseline-v1\",\"method\":\"train_partition_decile_bins\","
            + "\"categorical_other\":\"__other__\",\"source\":{\"partition\":\"train\",\"split_fingerprint\":\"f\"},"
            + "\"psi\":{\"epsilon\":0.0001,\"warning\":0.2,\"alert\":0.3,\"min_samples\":200},"
            + "\"numeric\":{\"dur\":{\"edges\":[1.0],\"proportions\":[0.5,0.5],\"counts\":[100,100],\"count\":200}},"
            + "\"categorical\":{\"proto\":{\"proportions\":{\"tcp\":0.6,\"udp\":0.4,\"__other__\":0.0},"
            + "\"counts\":{\"tcp\":120,\"udp\":80,\"__other__\":0},\"count\":200}}}}";
    private static final String SHA = "a".repeat(64);

    @BeforeAll
    static void migrate() throws Exception {
        String base = System.getenv("DB_TEST_BASE_URL");
        String username = System.getenv("DB_TEST_USERNAME");
        String password = System.getenv("DB_TEST_PASSWORD");
        try (var connection = java.sql.DriverManager.getConnection(base, username, password);
             var statement = connection.createStatement()) {
            statement.execute("CREATE DATABASE IF NOT EXISTS " + TEST_SCHEMA
                    + " CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci");
        }
        Flyway.configure().dataSource(base.replaceFirst("/+$", "") + "/" + TEST_SCHEMA, username, password)
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
    @Autowired private DriftMetricService drift;

    /** 固定为 3 小时前的整点，保证漂移窗口已结束且在回看范围内。 */
    private Instant base;
    private long assetId;
    private long sourceId;
    private long sensorId;
    private long modelId;
    private long batchId;
    private long alertA;
    private long alertB;

    @BeforeEach
    void seed() {
        // 专用测试 schema：按外键依赖顺序清空本测试涉及的表。
        for (String table : java.util.List.of("SPRING_SESSION", "audit_resource_scope", "feedback_sample",
                "drift_metric_window", "event_alert_link", "detection_alert", "inference_request", "sensor_health_window",
                "ingest_record", "ingest_batch", "sensor_agent", "model_version", "data_source", "asset", "sys_user_role")) {
            jdbc.update("DELETE FROM " + table);
        }
        jdbc.update("DELETE FROM sys_user WHERE username LIKE 'shadow-%'");
        base = Instant.now().truncatedTo(ChronoUnit.HOURS).minus(3, ChronoUnit.HOURS);

        jdbc.update("INSERT INTO asset (asset_key,asset_type,environment,criticality,owner,status,labels_json) "
                + "VALUES ('shadow-host','host','lab','medium','test','active','{}'),('shadow-other','host','lab','low','test','active','{}')");
        assetId = jdbc.queryForObject("SELECT id FROM asset WHERE asset_key='shadow-host'", Long.class);
        long otherAsset = jdbc.queryForObject("SELECT id FROM asset WHERE asset_key='shadow-other'", Long.class);
        jdbc.update("INSERT INTO data_source (source_key,source_type,environment,schema_version,scope_json,status) "
                + "VALUES ('shadow-source','sensor','lab','v1','{}','active'),('shadow-other-source','sensor','lab','v1','{}','active')");
        sourceId = jdbc.queryForObject("SELECT id FROM data_source WHERE source_key='shadow-source'", Long.class);
        long otherSource = jdbc.queryForObject("SELECT id FROM data_source WHERE source_key='shadow-other-source'", Long.class);

        user("shadow-labeler", "security_analyst", assetId, sourceId);
        user("shadow-reviewer", "security_analyst", assetId, sourceId);
        user("shadow-outsider", "security_analyst", otherAsset, otherSource);
        user("shadow-admin", "platform_admin", null, null);

        jdbc.update("INSERT INTO sensor_agent (agent_key,asset_id,platform,agent_version,capabilities_json,credential_ref,status,registered_at) "
                + "VALUES ('shadow-sensor',?,'darwin/arm64','test','{}','keychain://test','active',UTC_TIMESTAMP(3))", assetId);
        sensorId = jdbc.queryForObject("SELECT id FROM sensor_agent WHERE agent_key='shadow-sensor'", Long.class);
        jdbc.update("INSERT INTO model_version (model_key,version,task_type,manifest_version,manifest_json,artifact_ref,"
                + "artifact_sha256,feature_contract_version,approval_status) VALUES ('shadow-test','1','binary_flow_classification',"
                + "'1.0',?,'model://shadow-test-1/model.onnx',?,?,'candidate')", MANIFEST, SHA, V4);
        modelId = jdbc.queryForObject("SELECT id FROM model_version WHERE model_key='shadow-test'", Long.class);

        jdbc.update("INSERT INTO ingest_batch (batch_key,data_source_id,sensor_id,config_version,sequence_no,feature_contract_version,"
                + "idempotency_key,status,total_count,accepted_count,rejected_count,started_at) "
                + "VALUES ('shadow-batch',?,?,'cfg-shadow',1,?,'shadow-batch','completed_with_errors',5,4,1,?)",
                sourceId, sensorId, V4, ts(base.plusSeconds(600)));
        batchId = jdbc.queryForObject("SELECT id FROM ingest_batch WHERE batch_key='shadow-batch'", Long.class);
        long r1 = record("r1", "accepted", "{\"dur\":0.5,\"proto\":\"tcp\"}", null);
        long r2 = record("r2", "accepted", "{\"dur\":2.0,\"proto\":\"udp\"}", null);
        long r3 = record("r3", "accepted", "{\"dur\":3.0,\"proto\":\"proto-253\"}",
                "[{\"code\":\"CATEGORY_OUT_OF_VOCABULARY\",\"field\":\"proto\",\"expected\":\"model vocabulary\",\"actual\":\"out_of_vocabulary\"}]");
        long r4 = record("r4", "accepted", "{\"dur\":1.0,\"proto\":\"tcp\"}", null);
        record("r5", "rejected", "{\"dur\":-1,\"proto\":\"tcp\"}",
                "[{\"code\":\"FEATURE_VALUE_INVALID\",\"field\":\"dur\",\"expected\":\"≥ 0\",\"actual\":\"negative\"}]");
        alertA = alert("a", r1, scored(r1, 0.9, "Attack"));
        alertB = alert("b", r2, scored(r2, 0.8, "Attack"));
        scored(r3, 0.1, "Normal");
        jdbc.update("INSERT INTO inference_request (request_key,ingest_record_id,model_version_id,contract_version,deployment_mode,"
                + "status,reject_reason,requested_at,completed_at) VALUES ('shadow-req-r4',?,?,?,'local','not_in_model_scope',"
                + "'not_in_model_scope',?,?)", r4, modelId, V4, ts(base.plusSeconds(600)), ts(base.plusMillis(600_020)));
        // 健康窗口覆盖 [base-1h, base+2h)，每段 1 小时，首尾相接。
        for (int i = -1; i < 2; i++) {
            jdbc.update("INSERT INTO sensor_health_window (sensor_id,window_start,window_end,flows_seen,flows_emitted,flows_dropped,"
                    + "queue_depth_max) VALUES (?,?,?,10,5,0,1)", sensorId, ts(base.plusSeconds(3600L * i)),
                    ts(base.plusSeconds(3600L * (i + 1))));
        }
    }

    // ---------------------------------------------------------------- 夹具

    private void user(String username, String role, Long asset, Long source) {
        jdbc.update("INSERT INTO sys_user (user_key,username,display_name,status,password_hash) VALUES (?,?,?,'active',?)",
                username, username, username, HASH);
        long id = jdbc.queryForObject("SELECT id FROM sys_user WHERE username=?", Long.class, username);
        if (asset == null) {
            jdbc.update("INSERT INTO sys_user_role (user_id,role_id,scope_type,scope_id) SELECT ?,id,'global','*' "
                    + "FROM sys_role WHERE role_key=?", id, role);
            return;
        }
        jdbc.update("INSERT INTO sys_user_role (user_id,role_id,scope_type,scope_id) SELECT ?,id,'asset',? "
                + "FROM sys_role WHERE role_key=?", id, Long.toString(asset), role);
        jdbc.update("INSERT INTO sys_user_role (user_id,role_id,scope_type,scope_id) SELECT ?,id,'data_source',? "
                + "FROM sys_role WHERE role_key=?", id, Long.toString(source), role);
    }

    private long record(String key, String quality, String features, String issues) {
        jdbc.update("INSERT INTO ingest_record (batch_id,source_record_key,event_type,event_time,asset_id,normalized_payload,"
                        + "quality_status,quality_issues_json,mapping_version) VALUES (?,?,'network_flow',?,?,"
                        + "JSON_OBJECT('features',CAST(? AS JSON),'metadata',JSON_OBJECT('viewpoint','responder','addressFamily','ipv4')),"
                        + "?,CAST(? AS JSON),'1.0')",
                batchId, "shadow-" + key, ts(base.plusSeconds(590)), assetId, features, quality, issues);
        return jdbc.queryForObject("SELECT id FROM ingest_record WHERE source_record_key=?", Long.class, "shadow-" + key);
    }

    /** 推理成功：请求在批次开始时刻，完成于 20 ms 后（端到端延迟 20 ms）。 */
    private long scored(long recordId, double probability, String label) {
        jdbc.update("INSERT INTO inference_request (request_key,ingest_record_id,model_version_id,contract_version,contract_sha256,"
                        + "deployment_mode,status,attack_probability,binary_label,decision_threshold,threshold_policy_version,"
                        + "latency_ms,requested_at,completed_at) VALUES (?,?,?,?,?,'local','succeeded',?,?,0.5,'threshold-v1',3,?,?)",
                "shadow-req-" + recordId, recordId, modelId, V4, SHA, probability, label,
                ts(base.plusSeconds(600)), ts(base.plusMillis(600_020)));
        return jdbc.queryForObject("SELECT id FROM inference_request WHERE request_key=?", Long.class, "shadow-req-" + recordId);
    }

    private long alert(String key, long recordId, long inferenceId) {
        jdbc.update("INSERT INTO detection_alert (alert_key,ingest_record_id,inference_request_id,model_version_id,contract_version,"
                        + "contract_sha256,alert_type,severity,severity_policy_version,score,threshold_version,basis_json,status,detected_at) "
                        + "VALUES (?,?,?,?,?,?,'model','medium','severity-v1',0.9,'threshold-v1','{}','new',?)",
                "shadow-alert-" + key, recordId, inferenceId, modelId, V4, SHA, ts(base.plusSeconds(600)));
        return jdbc.queryForObject("SELECT id FROM detection_alert WHERE alert_key=?", Long.class, "shadow-alert-" + key);
    }

    private static Timestamp ts(Instant instant) { return Timestamp.from(instant); }

    private Cookie login(String username) throws Exception {
        MvcResult bootstrap = mockMvc.perform(get("/api/v1/auth/csrf")).andReturn();
        Cookie cookie = bootstrap.getResponse().getCookie("SESSION");
        String token = objectMapper.readTree(bootstrap.getResponse().getContentAsString()).path("data").path("token").asText();
        return mockMvc.perform(post("/api/v1/auth/login").cookie(cookie).header(CSRF_HEADER, token)
                        .contentType(APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"password\":\"shadow-password\"}"))
                .andExpect(status().isOk()).andReturn().getResponse().getCookie("SESSION");
    }

    private String csrf(Cookie session) throws Exception {
        MvcResult result = mockMvc.perform(get("/api/v1/auth/csrf").cookie(session)).andReturn();
        return objectMapper.readTree(result.getResponse().getContentAsString()).path("data").path("token").asText();
    }

    private org.springframework.test.web.servlet.ResultActions postJson(Cookie session, String path, String body,
                                                                        Object... vars) throws Exception {
        return mockMvc.perform(post(path, vars).cookie(session).header(CSRF_HEADER, csrf(session))
                .contentType(APPLICATION_JSON).content(body));
    }

    @Test
    void labelThenSecondPersonReviewWithSeparationOfDuties() throws Exception {
        Cookie labeler = login("shadow-labeler");
        Cookie reviewer = login("shadow-reviewer");
        Cookie outsider = login("shadow-outsider");

        postJson(labeler, "/api/v1/alerts/{id}/feedback", "{\"label\":\"false_positive\",\"note\":\"本机同步流量\"}", alertA)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.label").value("false_positive"))
                .andExpect(jsonPath("$.data.reviewStatus").value("pending"))
                .andExpect(jsonPath("$.data.trainingEligible").value(false));
        assertThat(jdbc.queryForObject("SELECT status FROM detection_alert WHERE id=?", String.class, alertA))
                .isEqualTo("false_positive");
        long feedbackId = jdbc.queryForObject("SELECT id FROM feedback_sample WHERE alert_id=?", Long.class, alertA);

        // 已结案告警不能再标注；越权告警 404；非法取值 400。
        postJson(labeler, "/api/v1/alerts/{id}/feedback", "{\"label\":\"true_positive\",\"note\":\"again\"}", alertA)
                .andExpect(status().isConflict());
        postJson(outsider, "/api/v1/alerts/{id}/feedback", "{\"label\":\"true_positive\",\"note\":\"x\"}", alertB)
                .andExpect(status().isNotFound());
        postJson(labeler, "/api/v1/alerts/{id}/feedback", "{\"label\":\"maybe\",\"note\":\"x\"}", alertB)
                .andExpect(status().isBadRequest());

        // 标注人不能复核本人标注，待复核列表也不包含本人标注。
        mockMvc.perform(get("/api/v1/feedback-reviews").cookie(labeler))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.totalElements").value(0));
        postJson(labeler, "/api/v1/feedback-samples/{id}/review", "{\"decision\":\"approve\",\"reason\":\"self\"}", feedbackId)
                .andExpect(status().isForbidden());
        postJson(outsider, "/api/v1/feedback-samples/{id}/review", "{\"decision\":\"approve\",\"reason\":\"x\"}", feedbackId)
                .andExpect(status().isNotFound());

        // 第二人驳回：标注失效，告警退回 acknowledged，可重新标注。
        mockMvc.perform(get("/api/v1/feedback-reviews").cookie(reviewer))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.totalElements").value(1))
                .andExpect(jsonPath("$.data.items[0].id").value(feedbackId));
        postJson(reviewer, "/api/v1/feedback-samples/{id}/review", "{\"decision\":\"reject\",\"reason\":\"依据不足\"}", feedbackId)
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.reviewStatus").value("rejected"));
        assertThat(jdbc.queryForObject("SELECT status FROM detection_alert WHERE id=?", String.class, alertA))
                .isEqualTo("acknowledged");
        postJson(reviewer, "/api/v1/feedback-samples/{id}/review", "{\"decision\":\"approve\",\"reason\":\"x\"}", feedbackId)
                .andExpect(status().isConflict());

        postJson(labeler, "/api/v1/alerts/{id}/feedback", "{\"label\":\"true_positive\",\"note\":\"复查后确认\"}", alertA)
                .andExpect(status().isOk());
        long second = jdbc.queryForObject("SELECT id FROM feedback_sample WHERE active_alert_id=?", Long.class, alertA);
        postJson(reviewer, "/api/v1/feedback-samples/{id}/review", "{\"decision\":\"approve\",\"reason\":\"同意\"}", second)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.reviewStatus").value("training_approved"))
                .andExpect(jsonPath("$.data.trainingEligible").value(true));
        assertThat(jdbc.queryForObject("SELECT status FROM detection_alert WHERE id=?", String.class, alertA))
                .isEqualTo("acknowledged");

        mockMvc.perform(get("/api/v1/alerts/{id}/feedback", alertA).cookie(labeler))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.length()").value(2));
        mockMvc.perform(get("/api/v1/alerts/{id}/feedback", alertA).cookie(outsider)).andExpect(status().isNotFound());
        // 数据库兜底：复核人与标注人相同的行写不进去。
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> jdbc.update(
                "UPDATE feedback_sample SET second_reviewed_by=reviewed_by WHERE id=?", second))
                .isInstanceOf(org.springframework.dao.DataAccessException.class);
    }

    @Test
    void shadowReportAggregatesAndGradesAgainstG3() throws Exception {
        String range = "?from=" + base.minusSeconds(3600) + "&to=" + base.plusSeconds(7200) + "&zone=Asia/Shanghai";
        Cookie analyst = login("shadow-labeler");
        MvcResult result = mockMvc.perform(get("/api/v1/data-sources/{id}/shadow-report" + range, sourceId).cookie(analyst))
                .andExpect(status().isOk()).andReturn();
        JsonNode report = objectMapper.readTree(result.getResponse().getContentAsString()).path("data");

        assertThat(report.at("/coverage/sensors").asInt()).isEqualTo(1);
        assertThat(report.at("/coverage/coverageRatio").asDouble()).isEqualTo(1.0);
        assertThat(report.at("/records/total").asLong()).isEqualTo(5);
        assertThat(report.at("/records/ingestRejected").asLong()).isEqualTo(1);
        assertThat(report.at("/records/ingestIssueCodes/FEATURE_VALUE_INVALID").asLong()).isEqualTo(1);
        assertThat(report.at("/records/scored").asLong()).isEqualTo(3);
        assertThat(report.at("/records/scoredAttack").asLong()).isEqualTo(2);
        assertThat(report.at("/records/notInModelScope").asLong()).isEqualTo(1);
        assertThat(report.at("/records/contractRejectRate").asDouble()).isEqualTo(0.2);
        assertThat(report.at("/records/outOfVocabulary/proto").asLong()).isEqualTo(1);
        assertThat(report.at("/alerts/modelAlerts").asLong()).isEqualTo(2);
        assertThat(report.at("/review/population").asLong()).isEqualTo(2);
        assertThat(report.at("/review/sample").size()).isEqualTo(2);
        assertThat(report.at("/drift/status").asText()).isEqualTo("insufficient_samples");
        assertThat(report.at("/drift/samples").asLong()).isEqualTo(3);
        assertThat(report.at("/drift/baselineModelVersionId").asLong()).isEqualTo(modelId);
        assertThat(report.at("/performance/p95Ms").asLong()).isEqualTo(20);
        assertThat(report.at("/performance/deadLetters").asLong()).isZero();

        assertThat(criterion(report, "run_duration")).isEqualTo("pending");
        assertThat(criterion(report, "alert_volume")).isEqualTo("fail");
        assertThat(criterion(report, "manual_fp_rate")).isEqualTo("pending");
        assertThat(criterion(report, "scope_attack_ratio")).isEqualTo("fail");
        assertThat(criterion(report, "contract_reject_rate")).isEqualTo("fail");
        assertThat(criterion(report, "psi")).isEqualTo("not_evaluable");
        assertThat(criterion(report, "latency_p95")).isEqualTo("pass");
        assertThat(criterion(report, "dead_letters")).isEqualTo("pass");
        assertThat(report.path("verdict").asText()).isEqualTo("fail");
        assertThat(report.path("limitations").size()).isGreaterThanOrEqualTo(3);

        // 标注后抽检计数随之变化。
        postJson(analyst, "/api/v1/alerts/{id}/feedback", "{\"label\":\"false_positive\",\"note\":\"n\"}", alertA)
                .andExpect(status().isOk());
        postJson(analyst, "/api/v1/alerts/{id}/feedback", "{\"label\":\"true_positive\",\"note\":\"n\"}", alertB)
                .andExpect(status().isOk());
        JsonNode labeled = objectMapper.readTree(mockMvc.perform(get("/api/v1/data-sources/{id}/shadow-report" + range,
                sourceId).cookie(analyst)).andReturn().getResponse().getContentAsString()).path("data");
        assertThat(labeled.at("/review/labeled").asInt()).isEqualTo(2);
        assertThat(labeled.at("/review/falsePositiveRate").asDouble()).isEqualTo(0.5);
        assertThat(criterion(labeled, "manual_fp_rate")).isEqualTo("fail");

        // 范围外数据源 404；平台管理员全局可读；非法范围 400。
        mockMvc.perform(get("/api/v1/data-sources/{id}/shadow-report" + range, sourceId).cookie(login("shadow-outsider")))
                .andExpect(status().isNotFound());
        Cookie admin = login("shadow-admin");
        mockMvc.perform(get("/api/v1/data-sources/{id}/shadow-report" + range, sourceId).cookie(admin))
                .andExpect(status().isOk());
        mockMvc.perform(get("/api/v1/data-sources/{id}/shadow-report?from=2026-01-01T00:00:00Z&to=2026-03-01T00:00:00Z",
                sourceId).cookie(admin)).andExpect(status().isBadRequest());
        mockMvc.perform(get("/api/v1/data-sources/{id}/shadow-report?zone=Mars/Base", sourceId).cookie(admin))
                .andExpect(status().isBadRequest());
    }

    @Test
    void driftJobWritesEachFinishedHourOnce() throws Exception {
        assertThat(drift.computeDueWindows()).isEqualTo(1);
        var row = jdbc.queryForMap("SELECT sample_count, request_count, drift_status, quality_reject_rate, baseline_ref, "
                + "CAST(feature_stats_json AS CHAR) features, CAST(label_feedback_stats_json AS CHAR) feedback "
                + "FROM drift_metric_window WHERE data_source_id=? AND model_version_id=? AND window_start=?",
                sourceId, modelId, ts(base));
        assertThat(((Number) row.get("sample_count")).longValue()).isEqualTo(3);
        assertThat(((Number) row.get("request_count")).longValue()).isEqualTo(4);
        assertThat(row.get("drift_status")).isEqualTo("insufficient_samples");
        assertThat(((Number) row.get("quality_reject_rate")).doubleValue()).isZero();
        assertThat((String) row.get("baseline_ref")).contains("baseline-v1");
        JsonNode features = objectMapper.readTree((String) row.get("features"));
        assertThat(features.has("psi")).isTrue();
        assertThat(features.has("otherRatio")).isTrue();
        // MySQL JSON 列会规范化空白，按解析后的值断言。
        assertThat(objectMapper.readTree((String) row.get("feedback")).path("alerts").asLong()).isEqualTo(2);
        // 重跑不重复写入。
        assertThat(drift.computeDueWindows()).isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM drift_metric_window", Integer.class)).isEqualTo(1);
    }

    private static String criterion(JsonNode report, String key) {
        for (JsonNode item : report.path("criteria")) {
            if (key.equals(item.path("key").asText())) return item.path("status").asText();
        }
        throw new AssertionError("criterion missing: " + key);
    }
}
