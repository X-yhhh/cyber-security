package com.xyh.cybersecurity.inference;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.xyh.cybersecurity.ingest.contract.FeatureContractRegistry;
import com.xyh.cybersecurity.ingest.feature.FeatureBuilder;
import com.xyh.cybersecurity.ingest.feature.V4Fixtures;
import com.xyh.cybersecurity.ingest.outbox.IngestBatchEvent;
import com.xyh.cybersecurity.ingest.outbox.IngestBatchProcessingService;
import jakarta.servlet.http.Cookie;
import org.flywaydb.core.Flyway;
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
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;

/**
 * 路线 B 阶段 4 端到端验收（§10.2）：真实交付包 unsw-binary-2026.10.0 走候选登记 → 制品校验 → 发布申请 →
 * 他人批准 → 本机激活；传感器 v4 批次经 M2 消费事务推理并写 inference_request。覆盖无激活模型拒绝、
 * 概率与训练端 expected-outputs 误差 ≤ 1e-5、范围外视角、重复投递不重复推理、按数据源范围查询、
 * dry-run 不落库且仅限回放数据源、接入后配置失效即拒绝。模型制品不入库，由 MODEL_DELIVERY_V4_DIR 指定。
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@EnabledIfEnvironmentVariable(named = "DB_TEST_BASE_URL", matches = ".+")
@EnabledIfEnvironmentVariable(named = "MODEL_DELIVERY_V4_DIR", matches = ".+")
class LocalInferenceIntegrationTest {
    private static final String TEST_SCHEMA = "cyber_security_backend_local_inference_20260929";
    private static final String LOGIN_PHRASE = "local-inference-test-password";
    private static final String HASH = new BCryptPasswordEncoder(4).encode(LOGIN_PHRASE);
    private static final String CSRF_HEADER = "X-CSRF-TOKEN";
    private static final String V4 = "unsw-nb15-flow-v4";
    private static final String MODEL_KEY = "unsw-binary";
    private static final int FIXTURE_ROWS = 50;

    @BeforeAll
    static void migrateAndClean() throws Exception {
        String base = System.getenv("DB_TEST_BASE_URL");
        String username = System.getenv("DB_TEST_USERNAME");
        String dbCredential = System.getenv("DB_TEST_PASSWORD");
        try (var connection = java.sql.DriverManager.getConnection(base, username, dbCredential);
             var statement = connection.createStatement()) {
            statement.execute("CREATE DATABASE IF NOT EXISTS " + TEST_SCHEMA
                    + " CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci");
        }
        String url = base.replaceFirst("/+$", "") + "/" + TEST_SCHEMA;
        Flyway.configure().dataSource(url, username, dbCredential).locations("classpath:db/migration")
                .baselineOnMigrate(false).load().migrate();
        // 上下文启动时会恢复 active 部署；必须在上下文加载前清空，保证“无激活模型”步骤可重复执行。
        try (var connection = java.sql.DriverManager.getConnection(url, username, dbCredential);
             var statement = connection.createStatement()) {
            for (String table : List.of("SPRING_SESSION", "audit_resource_scope", "event_timeline", "event_alert_link",
                    "event_asset_link", "security_event", "detection_alert", "detection_rule", "inference_request", "consumed_message",
                    "outbox_event", "ingest_record", "ingest_batch", "sensor_health_window", "sensor_config",
                    "api_client_source_asset_scope", "api_client_scope", "api_client_permission", "api_client",
                    "sensor_agent", "source_mapping", "data_source", "asset_authorization", "asset", "model_deployment",
                    "model_release_record", "model_version", "sys_user_role")) {
                statement.executeUpdate("DELETE FROM " + table);
            }
            statement.executeUpdate("DELETE FROM sys_user WHERE username LIKE 'm3-%'");
        }
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        String base = System.getenv("DB_TEST_BASE_URL");
        registry.add("spring.datasource.url", () -> base.replaceFirst("/+$", "") + "/" + TEST_SCHEMA
                + "?connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true");
        registry.add("spring.datasource.username", () -> System.getenv("DB_TEST_USERNAME"));
        registry.add("spring.datasource.password", () -> System.getenv("DB_TEST_PASSWORD"));
        registry.add("spring.flyway.enabled", () -> false);
        registry.add("cyber.security.login-throttle.hmac-key", () -> "local-inference-it-key-with-at-least-32-bytes");
        registry.add("cyber.model-artifact.root", () -> delivery().getParent().toString());
    }

    @Autowired private MockMvc mockMvc;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private IngestBatchProcessingService processing;

    private long sourceId;

    @Test
    void consumedBatchesAreInferredOnceWithSnapshotsAndDryRunStaysReadOnly() throws Exception {
        long assetId = seedAssetAndSource();
        long operator = user("m3-operator");
        long releaser = user("m3-releaser");
        long analyst = user("m3-analyst");
        long outsider = user("m3-outsider");
        long admin = user("m3-admin");
        bindRole(admin, "platform_admin", "global", "*");
        bindRole(operator, "model_operator", "model_registry", MODEL_KEY);
        bindRole(operator, "model_operator", "data_source", Long.toString(sourceId));
        bindRole(releaser, "model_releaser", "model_registry", MODEL_KEY);
        bindRole(analyst, "security_analyst", "data_source", Long.toString(sourceId));
        bindRole(analyst, "security_analyst", "asset", Long.toString(assetId));
        // 范围外用户：资产在范围内但数据源不在，事件须整体不可见（不返回部分结果）。
        bindRole(outsider, "security_analyst", "data_source", Long.toString(sourceId + 1000));
        bindRole(outsider, "security_analyst", "asset", Long.toString(assetId));
        Sensor sensor = registerSensor(login("m3-admin"), assetId);

        Map<Long, FeatureBuilder.BuildResult> built = V4Fixtures.buildAll();
        List<JsonNode> expected = V4Fixtures.jsonl("expected-outputs.jsonl").subList(0, FIXTURE_ROWS);
        JsonNode firstFeatures = built.get(expected.getFirst().get("seq").asLong()).features();

        // 1. 无激活模型：记录照常接入，推理显式 rejected，不写模型引用或分数，不回退。
        long early = submit(sensor, 1, List.of(flow("early-1", firstFeatures, "responder")));
        process(early, 1);
        assertThat(jdbc.queryForMap("SELECT status,error_code,model_version_id,attack_probability FROM inference_request"))
                .containsEntry("status", "rejected").containsEntry("error_code", "ACTIVE_MODEL_UNAVAILABLE")
                .containsEntry("model_version_id", null).containsEntry("attack_probability", null);

        // 2. 走既有发布流程激活真实交付包：候选登记 → 制品校验 → 发布申请 → 他人批准 → 本机激活。
        long modelId = activate(login("m3-operator"), login("m3-releaser"));

        // 确定性规则经接口登记与他人批准后才生效（只命中 initiator 视角记录）：
        // 分析员登记为 pending；受限条件外的运算符 400；分析员无批准权限 403；审批人批准后 active。
        long approver = jdbc.queryForObject("SELECT id FROM sys_user WHERE username='m3-approver'", Long.class);
        bindRole(approver, "response_approver", "asset", Long.toString(assetId));
        Cookie ruleAuthor = login("m3-analyst");
        String ruleBody = "{\"ruleKey\":\"m4-initiator-watch\",\"version\":\"1\",\"severity\":\"low\","
                + "\"scope\":{\"featureContractVersion\":\"" + V4 + "\"},"
                + "\"condition\":{\"all\":[{\"field\":\"metadata.viewpoint\",\"op\":\"eq\",\"value\":\"initiator\"}]},"
                + "\"reason\":\"watch initiator-side records\"}";
        assertThat(send(post("/api/v1/detection-rules"), ruleAuthor, ruleBody.replace("\"eq\"", "\"regex\""))
                .getResponse().getStatus()).isEqualTo(400);
        MvcResult createdRule = send(post("/api/v1/detection-rules"), ruleAuthor, ruleBody);
        assertThat(createdRule.getResponse().getStatus()).as(createdRule.getResponse().getContentAsString()).isEqualTo(201);
        long ruleId = data(createdRule).path("id").asLong();
        assertThat(data(createdRule).path("status").asText()).isEqualTo("pending");
        String approve = "{\"decision\":\"approve\",\"reason\":\"independent review\"}";
        assertThat(send(post("/api/v1/detection-rules/{id}/decision", ruleId), ruleAuthor, approve)
                .getResponse().getStatus()).isEqualTo(403);
        MvcResult decided = send(post("/api/v1/detection-rules/{id}/decision", ruleId), login("m3-approver"), approve);
        assertThat(decided.getResponse().getStatus()).as(decided.getResponse().getContentAsString()).isEqualTo(200);
        assertThat(jdbc.queryForMap("SELECT status,requested_by,approved_by FROM detection_rule WHERE id=?", ruleId))
                .containsEntry("status", "active");
        assertThat(((Number) jdbc.queryForObject("SELECT requested_by FROM detection_rule WHERE id=?", Long.class,
                ruleId)).longValue()).isEqualTo(analyst);
        assertThat(jdbc.queryForObject("SELECT approved_by FROM detection_rule WHERE id=?", Long.class, ruleId))
                .isEqualTo(approver);

        // 3. 50 条 golden fixture（Java Feature Builder 输出）+ 1 条 initiator 视角记录，经 M2 消费事务推理。
        List<String> records = new ArrayList<>();
        for (JsonNode row : expected) {
            records.add(flow("fx-" + row.get("seq").asLong(), built.get(row.get("seq").asLong()).features(), "responder"));
        }
        records.add(flow("initiator-1", firstFeatures, "initiator"));
        long main = submit(sensor, 2, records);
        assertThat(process(main, FIXTURE_ROWS + 1)).isEqualTo(IngestBatchProcessingService.ProcessResult.PROCESSED);
        String contractSha = FeatureContractRegistry.fromClasspath().require(V4).fileSha256();
        for (JsonNode row : expected) {
            Map<String, Object> got = jdbc.queryForMap("SELECT ir.status,ir.attack_probability,ir.binary_label,"
                    + "ir.model_version_id,ir.threshold_policy_version,ir.contract_sha256 FROM inference_request ir "
                    + "JOIN ingest_record r ON r.id=ir.ingest_record_id WHERE r.source_record_key=?",
                    "fx-" + row.get("seq").asLong());
            assertThat(got.get("status")).as("seq %s", row.get("seq")).isEqualTo("succeeded");
            assertThat(((Number) got.get("attack_probability")).doubleValue())
                    .isCloseTo(row.get("attack_probability").asDouble(), within(1e-5));
            assertThat(got.get("binary_label")).isEqualTo(row.get("is_attack").asBoolean() ? "Attack" : "Normal");
            assertThat(((Number) got.get("model_version_id")).longValue()).isEqualTo(modelId);
            assertThat(got.get("threshold_policy_version")).isEqualTo("fixed:unsw-binary-2026.10.0");
            assertThat(got.get("contract_sha256")).isEqualTo(contractSha);
        }
        assertThat(statusOf("initiator-1")).isEqualTo("not_in_model_scope");

        // 3a. 阶段 5（M4）：Attack 结论生成模型告警、initiator 记录命中规则告警，同资产同窗口并入一个事件。
        int attacks = 0;
        for (JsonNode row : expected) if (row.get("is_attack").asBoolean()) attacks++;
        assertThat(attacks).isPositive();
        assertThat(alertCount("model")).isEqualTo(attacks);
        assertThat(alertCount("rule")).isEqualTo(1);
        for (Map<String, Object> alert : jdbc.queryForList("SELECT severity,score,model_version_id,contract_sha256,"
                + "severity_policy_version,inference_request_id FROM detection_alert WHERE alert_type='model'")) {
            double score = ((Number) alert.get("score")).doubleValue();
            assertThat(alert.get("severity")).isEqualTo(score >= 0.9 ? "critical" : score >= 0.7 ? "high" : "medium");
            assertThat(((Number) alert.get("model_version_id")).longValue()).isEqualTo(modelId);
            assertThat(alert.get("contract_sha256")).isEqualTo(contractSha);
            assertThat(alert.get("severity_policy_version")).isEqualTo("severity-v1");
            assertThat(alert.get("inference_request_id")).isNotNull();
        }
        Map<String, Object> event = jdbc.queryForMap("SELECT correlation_key,correlation_policy_version,risk_rule_version,"
                + "risk_score,status FROM security_event");
        assertThat(event).containsEntry("correlation_key", "asset:" + assetId).containsEntry("status", "open")
                .containsEntry("correlation_policy_version", "correlation-v1").containsEntry("risk_rule_version", "risk-v1");
        assertThat(event.get("risk_score")).isNotNull();
        assertThat(linkCount()).isEqualTo(attacks + 1);

        // 4. 重复投递：消费台账去重；台账被人为清掉后重放，request_key 仍保证不重复推理。
        assertThat(process(main, FIXTURE_ROWS + 1)).isEqualTo(IngestBatchProcessingService.ProcessResult.DUPLICATE);
        jdbc.update("DELETE FROM consumed_message WHERE message_key=?", "sensor.ingest.batch:" + main);
        assertThat(process(main, FIXTURE_ROWS + 1)).isEqualTo(IngestBatchProcessingService.ProcessResult.PROCESSED);
        assertThat(count()).isEqualTo(FIXTURE_ROWS + 2);
        // 重复投递（含台账被清后重放）不产生重复告警、事件或关联。
        assertThat(alertCount("model") + alertCount("rule")).isEqualTo(attacks + 1);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM security_event", Integer.class)).isEqualTo(1);
        assertThat(linkCount()).isEqualTo(attacks + 1);

        // 5. 台账只读查询按数据源范围过滤；参数类型错误返回 400。
        Cookie analystSession = login("m3-analyst");
        assertThat(list(analystSession, "dataSourceId", Long.toString(sourceId)).path("totalElements").asLong())
                .isEqualTo(FIXTURE_ROWS + 2);
        assertThat(list(analystSession, "status", "succeeded").path("totalElements").asLong()).isEqualTo(FIXTURE_ROWS);
        assertThat(list(login("m3-outsider")).path("totalElements").asLong()).isZero();
        assertThat(mockMvc.perform(get("/api/v1/inference-requests").param("size", "abc").cookie(analystSession))
                .andReturn().getResponse().getStatus()).isEqualTo(400);

        // 5a. 事件范围：资产与数据源都在范围内的分析员可见，并能看到告警来源、契约与评分依据；
        //     数据源不在范围内的用户看不到事件和告警。
        JsonNode events = read(analystSession, "/api/v1/events");
        assertThat(events.path("totalElements").asLong()).isEqualTo(1);
        assertThat(read(analystSession, "/api/v1/alerts").path("totalElements").asLong()).isEqualTo(attacks + 1);
        long eventId = events.path("items").get(0).path("id").asLong();
        JsonNode detail = read(analystSession, "/api/v1/events/" + eventId);
        // 详情只内嵌第一页；全部关联告警经分页子资源读取（单页上限 100，本用例告警数更少）。
        assertThat(detail.path("alerts").path("totalElements").asLong()).isEqualTo(attacks + 1);
        assertThat(detail.path("event").path("riskBasisJson").asText()).contains("formula");
        JsonNode allAlerts = read(analystSession, "/api/v1/events/" + eventId + "/alerts?page=0&size=100");
        assertThat(allAlerts.path("items")).hasSize(attacks + 1);
        for (JsonNode alert : allAlerts.path("items")) {
            if ("model".equals(alert.path("alertType").asText())) {
                assertThat(alert.path("modelKey").asText()).isEqualTo(MODEL_KEY);
                assertThat(alert.path("contractVersion").asText()).isEqualTo(V4);
                assertThat(alert.path("basisJson").asText()).contains("attackProbability");
            } else {
                assertThat(alert.path("ruleKey").asText()).isEqualTo("m4-initiator-watch");
                assertThat(alert.path("basisJson").asText()).contains("metadata.viewpoint");
            }
        }
        Cookie outsiderSession = login("m3-outsider");
        assertThat(read(outsiderSession, "/api/v1/events").path("totalElements").asLong()).isZero();
        assertThat(read(outsiderSession, "/api/v1/alerts").path("totalElements").asLong()).isZero();

        // 6. dry-run：同一推理路径，只写审计不写 inference_request；需 model.replay.run，且仅限回放数据源。
        Cookie operatorSession = login("m3-operator");
        String dryRunBody = "{\"dataSourceId\":" + sourceId + ",\"batchId\":" + main + "}";
        MvcResult dry = send(post("/api/v1/inference/dry-run"), operatorSession, dryRunBody);
        assertThat(dry.getResponse().getStatus()).as(dry.getResponse().getContentAsString()).isEqualTo(200);
        JsonNode results = data(dry).path("results");
        assertThat(results).hasSize(FIXTURE_ROWS + 1);
        long scored = 0;
        for (JsonNode result : results) if ("succeeded".equals(result.path("status").asText())) scored++;
        assertThat(scored).isEqualTo(FIXTURE_ROWS);
        assertThat(count()).isEqualTo(FIXTURE_ROWS + 2);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM audit_log WHERE action='inference.dry_run' AND actor_id=?",
                Integer.class, Long.toString(operator))).isEqualTo(1);
        assertThat(send(post("/api/v1/inference/dry-run"), analystSession, dryRunBody).getResponse().getStatus())
                .isEqualTo(403);
        jdbc.update("UPDATE data_source SET source_type='sensor' WHERE id=?", sourceId);
        MvcResult notReplay = send(post("/api/v1/inference/dry-run"), operatorSession, dryRunBody);
        assertThat(notReplay.getResponse().getStatus()).isEqualTo(409);
        assertThat(notReplay.getResponse().getContentAsString()).contains("DRY_RUN_REPLAY_SOURCE_REQUIRED");

        // 7. 接入后配置被撤销：消费时按 config_not_active 拒绝，不推理。
        long late = submit(sensor, 3, List.of(flow("late-1", firstFeatures, "responder")));
        jdbc.update("UPDATE sensor_config SET status='retired' WHERE sensor_id=?", sensor.id());
        process(late, 1);
        assertThat(jdbc.queryForMap("SELECT ir.status,ir.reject_reason FROM inference_request ir JOIN ingest_record r "
                + "ON r.id=ir.ingest_record_id WHERE r.source_record_key='late-1'"))
                .containsEntry("status", "rejected").containsEntry("reject_reason", "config_not_active");
    }

    private long seedAssetAndSource() {
        long approver = user("m3-approver");
        jdbc.update("INSERT INTO asset (asset_key,asset_type,environment,criticality,owner,status,labels_json) "
                + "VALUES ('m3-host','host','lab','medium','test','active','{}')");
        long assetId = jdbc.queryForObject("SELECT id FROM asset WHERE asset_key='m3-host'", Long.class);
        jdbc.update("INSERT INTO asset_authorization (asset_id,authorization_ref,scope_json,valid_from,valid_until,status,"
                + "approved_by) VALUES (?,'test://authorization','{}',UTC_TIMESTAMP(3)-INTERVAL 1 DAY,"
                + "UTC_TIMESTAMP(3)+INTERVAL 1 DAY,'active',?)", assetId, approver);
        jdbc.update("INSERT INTO data_source (source_key,source_type,environment,schema_version,scope_json,status) "
                + "VALUES ('m3-replay','replay','lab','v1','{}','active')");
        sourceId = jdbc.queryForObject("SELECT id FROM data_source WHERE source_key='m3-replay'", Long.class);
        jdbc.update("INSERT INTO source_mapping (data_source_id,mapping_version,source_schema_json,mapping_json,"
                + "feature_contract_version,feature_contract_sha256,status,approved_by) "
                + "VALUES (?,'1.0','{}','{}',?,?,'approved',?)",
                sourceId, V4, FeatureContractRegistry.fromClasspath().require(V4).fileSha256(), approver);
        return assetId;
    }

    private long activate(Cookie operator, Cookie releaser) throws Exception {
        Path delivery = delivery();
        JsonNode manifest = objectMapper.readTree(delivery.resolve("model_manifest.json").toFile());
        ObjectNode candidate = objectMapper.createObjectNode().put("modelKey", MODEL_KEY)
                .put("version", manifest.path("version").asText()).put("taskType", "binary_flow_classification")
                .put("manifestVersion", manifest.path("manifest_version").asText())
                .put("artifactRef", "model://" + delivery.getFileName() + "/model.onnx")
                .put("artifactSha256", manifest.at("/artifact/sha256").asText()).put("featureContractVersion", V4);
        candidate.set("manifest", manifest);
        MvcResult registered = send(post("/api/v1/models"), operator, candidate.toString());
        assertThat(registered.getResponse().getStatus()).as(registered.getResponse().getContentAsString()).isEqualTo(201);
        long modelId = data(registered).path("id").asLong();
        MvcResult validated = send(post("/api/v1/models/{id}/validate", modelId), operator, "{}");
        assertThat(validated.getResponse().getStatus()).as(validated.getResponse().getContentAsString()).isEqualTo(200);
        MvcResult release = send(post("/api/v1/models/{id}/release-requests", modelId), operator,
                "{\"reason\":\"stage 4 end-to-end acceptance\"}");
        assertThat(release.getResponse().getStatus()).isEqualTo(201);
        MvcResult decision = send(post("/api/v1/model-release-requests/{id}/decision", data(release).path("id").asLong()),
                releaser, "{\"decision\":\"approve\",\"reason\":\"independent approval\"}");
        assertThat(decision.getResponse().getStatus()).isEqualTo(200);
        MvcResult activated = send(put("/api/v1/model-deployments/active"), operator,
                "{\"modelVersionId\":" + modelId + ",\"reason\":\"local activation\"}");
        assertThat(activated.getResponse().getStatus()).as(activated.getResponse().getContentAsString()).isEqualTo(200);
        return modelId;
    }

    private Sensor registerSensor(Cookie admin, long assetId) throws Exception {
        MvcResult issued = send(post("/api/v1/sensors"), admin, "{\"agentKey\":\"m3-sensor\",\"assetId\":" + assetId
                + ",\"dataSourceId\":" + sourceId + ",\"platform\":\"macos\",\"agentVersion\":\"0.1.0\",\"capabilities\":{},"
                + "\"config\":{\"configVersion\":\"cfg-1\",\"interfaceScope\":{},\"filterPolicy\":{},\"flowWindowSeconds\":60,"
                + "\"featureContractVersion\":\"" + V4 + "\",\"samplingPolicy\":{}}}");
        assertThat(issued.getResponse().getStatus()).as(issued.getResponse().getContentAsString()).isEqualTo(201);
        return new Sensor(data(issued).path("sensorId").asLong(), data(issued).path("credential").asText());
    }

    private long submit(Sensor sensor, long sequence, List<String> records) throws Exception {
        String body = "{\"dataSourceId\":" + sourceId + ",\"configVersion\":\"cfg-1\",\"sequence\":" + sequence
                + ",\"observedAt\":\"" + Instant.now() + "\",\"sourceMappingVersion\":\"1.0\",\"featureContractVersion\":\""
                + V4 + "\",\"records\":[" + String.join(",", records) + "]}";
        MvcResult result = mockMvc.perform(post("/api/v1/machine/sensors/{id}/flow-batches", sensor.id())
                .header("Authorization", "Machine " + sensor.credential()).header("Idempotency-Key", "m3-" + sequence)
                .contentType(APPLICATION_JSON).content(body)).andReturn();
        assertThat(result.getResponse().getStatus()).as(result.getResponse().getContentAsString()).isEqualTo(201);
        assertThat(data(result).path("rejectedCount").asLong()).isZero();
        return data(result).path("id").asLong();
    }

    private IngestBatchProcessingService.ProcessResult process(long batchId, int accepted) {
        return processing.process(new IngestBatchEvent("sensor.ingest.batch:" + batchId, "ingest.batch.received",
                batchId, sourceId, accepted));
    }

    /** v4 流记录；时间窗按 dur 取整，地址不出现在记录中。 */
    private String flow(String key, JsonNode features, String viewpoint) {
        Instant end = Instant.now().minusSeconds(120);
        ObjectNode node = objectMapper.createObjectNode().put("recordKey", key)
                .put("flowStartAt", end.minusMillis(Math.round(features.path("dur").asDouble() * 1000)).toString())
                .put("flowEndAt", end.toString()).put("observedAt", end.plusSeconds(1).toString())
                .put("directionBasis", "initiator_to_responder").put("viewpoint", viewpoint).put("addressFamily", "ipv4")
                .put("handshakeSeen", "tcp".equals(features.path("proto").asText()));
        node.set("features", features.deepCopy());
        return node.toString();
    }

    private String statusOf(String recordKey) {
        return jdbc.queryForObject("SELECT ir.status FROM inference_request ir JOIN ingest_record r "
                + "ON r.id=ir.ingest_record_id WHERE r.source_record_key=?", String.class, recordKey);
    }

    private int count() { return jdbc.queryForObject("SELECT COUNT(*) FROM inference_request", Integer.class); }

    private int alertCount(String type) {
        return jdbc.queryForObject("SELECT COUNT(*) FROM detection_alert WHERE alert_type=?", Integer.class, type);
    }

    private int linkCount() { return jdbc.queryForObject("SELECT COUNT(*) FROM event_alert_link", Integer.class); }

    private JsonNode read(Cookie session, String path) throws Exception {
        MvcResult result = mockMvc.perform(get(path).cookie(session)).andReturn();
        assertThat(result.getResponse().getStatus()).as(result.getResponse().getContentAsString()).isEqualTo(200);
        return data(result);
    }

    private JsonNode list(Cookie session, String... params) throws Exception {
        MockHttpServletRequestBuilder request = get("/api/v1/inference-requests").cookie(session);
        for (int i = 0; i + 1 < params.length; i += 2) request.param(params[i], params[i + 1]);
        MvcResult result = mockMvc.perform(request).andReturn();
        assertThat(result.getResponse().getStatus()).as(result.getResponse().getContentAsString()).isEqualTo(200);
        return data(result);
    }

    private MvcResult send(MockHttpServletRequestBuilder request, Cookie session, String body) throws Exception {
        return mockMvc.perform(request.cookie(session).header(CSRF_HEADER, csrf(session))
                .contentType(APPLICATION_JSON).content(body)).andReturn();
    }

    private long user(String username) {
        jdbc.update("INSERT INTO sys_user (user_key,username,display_name,status,password_hash) VALUES (?,?,?,'active',?)",
                username, username, username, HASH);
        return jdbc.queryForObject("SELECT id FROM sys_user WHERE username=?", Long.class, username);
    }

    private void bindRole(long userId, String roleKey, String scopeType, String scopeId) {
        jdbc.update("INSERT INTO sys_user_role (user_id,role_id,scope_type,scope_id) SELECT ?,id,?,? FROM sys_role "
                + "WHERE role_key=?", userId, scopeType, scopeId, roleKey);
    }

    private Cookie login(String username) throws Exception {
        MvcResult bootstrap = mockMvc.perform(get("/api/v1/auth/csrf")).andReturn();
        Cookie cookie = bootstrap.getResponse().getCookie("SESSION");
        String csrfValue = objectMapper.readTree(bootstrap.getResponse().getContentAsString()).path("data").path("token").asText();
        MvcResult login = mockMvc.perform(post("/api/v1/auth/login").cookie(cookie).header(CSRF_HEADER, csrfValue)
                .contentType(APPLICATION_JSON)
                .content("{\"username\":\"" + username + "\",\"password\":\"" + LOGIN_PHRASE + "\"}")).andReturn();
        assertThat(login.getResponse().getStatus()).isEqualTo(200);
        return login.getResponse().getCookie("SESSION");
    }

    private String csrf(Cookie cookie) throws Exception {
        MvcResult result = mockMvc.perform(get("/api/v1/auth/csrf").cookie(cookie)).andReturn();
        return objectMapper.readTree(result.getResponse().getContentAsString()).path("data").path("token").asText();
    }

    private JsonNode data(MvcResult result) throws Exception {
        return objectMapper.readTree(result.getResponse().getContentAsString()).path("data");
    }

    private static Path delivery() {
        try { return Path.of(System.getenv("MODEL_DELIVERY_V4_DIR")).toRealPath(); }
        catch (java.io.IOException exception) { throw new IllegalStateException(exception); }
    }

    private record Sensor(long id, String credential) { }
}
