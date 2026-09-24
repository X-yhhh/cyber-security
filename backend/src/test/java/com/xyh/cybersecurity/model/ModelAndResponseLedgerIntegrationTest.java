package com.xyh.cybersecurity.model;

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

import java.sql.Timestamp;
import java.time.Instant;
import java.util.HexFormat;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/** 验证候选模型/响应只登记元数据和审批，不运行推理或外部动作。 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@EnabledIfEnvironmentVariable(named = "DB_TEST_BASE_URL", matches = ".+")
class ModelAndResponseLedgerIntegrationTest {

    private static final String TEST_SCHEMA = "cyber_security_backend_model_response_20260923";
    private static final String PASSWORD = "model-response-test-password";
    private static final String HASH = new BCryptPasswordEncoder(4).encode(PASSWORD);
    private static final String CSRF_HEADER = "X-CSRF-TOKEN";
    private static final String MODEL_KEY = "ledger-test-model";
    private static final String MODEL_SHA = HexFormat.of().formatHex(new byte[32]);

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

    private long modelOperatorId;
    private long modelReleaserId;
    private long analystId;
    private long responseApproverId;
    private long assetId;
    private long sourceId;
    private long eventId;
    private long authorizationId;
    private long policyId;

    @BeforeEach
    void seed() {
        jdbc.update("DELETE FROM SPRING_SESSION");
        jdbc.update("DELETE FROM audit_resource_scope WHERE audit_id IN (SELECT id FROM audit_log WHERE actor_id IN "
                + "(SELECT CAST(id AS CHAR) FROM sys_user WHERE username LIKE 'ledger-test-%'))");
        jdbc.update("DELETE FROM audit_log WHERE actor_id IN "
                + "(SELECT CAST(id AS CHAR) FROM sys_user WHERE username LIKE 'ledger-test-%')");
        jdbc.update("DELETE FROM approval_task WHERE event_id IN "
                + "(SELECT id FROM security_event WHERE event_key LIKE 'ledger-test-%')");
        jdbc.update("DELETE FROM response_policy WHERE policy_key LIKE 'ledger-test-%'");
        jdbc.update("DELETE FROM model_release_record WHERE model_version_id IN "
                + "(SELECT id FROM model_version WHERE model_key LIKE 'ledger-test-%')");
        jdbc.update("DELETE FROM model_version WHERE model_key LIKE 'ledger-test-%'");
        jdbc.update("DELETE FROM event_timeline WHERE event_id IN (SELECT id FROM security_event WHERE event_key LIKE 'ledger-test-%')");
        jdbc.update("DELETE FROM event_asset_link WHERE event_id IN (SELECT id FROM security_event WHERE event_key LIKE 'ledger-test-%')");
        jdbc.update("DELETE FROM event_alert_link WHERE event_id IN (SELECT id FROM security_event WHERE event_key LIKE 'ledger-test-%')");
        jdbc.update("DELETE FROM security_event WHERE event_key LIKE 'ledger-test-%'");
        jdbc.update("DELETE FROM detection_alert WHERE alert_key LIKE 'ledger-test-%'");
        jdbc.update("DELETE FROM ingest_record WHERE source_record_key LIKE 'ledger-test-%'");
        jdbc.update("DELETE FROM ingest_batch WHERE batch_key LIKE 'ledger-test-%'");
        jdbc.update("DELETE FROM asset_authorization WHERE asset_id IN (SELECT id FROM asset WHERE asset_key LIKE 'ledger-test-%')");
        jdbc.update("DELETE FROM data_source WHERE source_key LIKE 'ledger-test-%'");
        jdbc.update("DELETE FROM asset WHERE asset_key LIKE 'ledger-test-%'");
        jdbc.update("DELETE FROM sys_user_role");
        jdbc.update("DELETE FROM sys_user WHERE username LIKE 'ledger-test-%'");

        modelOperatorId = user("model-operator");
        modelReleaserId = user("model-releaser");
        analystId = user("analyst");
        responseApproverId = user("response-approver");
        bindRole(modelOperatorId, "model_operator", "model_registry", MODEL_KEY);
        bindRole(modelReleaserId, "model_releaser", "model_registry", MODEL_KEY);
        assetId = createAsset();
        sourceId = createSource();
        bindRole(analystId, "security_analyst", "asset", Long.toString(assetId));
        bindRole(analystId, "security_analyst", "data_source", Long.toString(sourceId));
        bindRole(responseApproverId, "response_approver", "asset", Long.toString(assetId));
        eventId = createEvent();
        authorizationId = createAuthorization();
        policyId = createResponsePolicy();
    }

    @Test
    void modelCandidateIsImmutableAndReleaseDecisionRequiresAnotherScopedUser() throws Exception {
        Cookie operator = login("ledger-test-model-operator");
        String candidate = modelCandidate(MODEL_SHA);
        MvcResult badHash = postJson("/api/v1/models", operator, csrf(operator), modelCandidate("invalid"));
        assertThat(badHash.getResponse().getStatus()).isEqualTo(400);

        MvcResult created = postJson("/api/v1/models", operator, csrf(operator), candidate);
        assertThat(created.getResponse().getStatus()).isEqualTo(201);
        JsonNode model = data(created);
        long modelId = model.path("id").asLong();
        assertThat(model.path("artifactSha256").asText()).isEqualTo(MODEL_SHA);
        MvcResult overwrite = postJson("/api/v1/models", operator, csrf(operator),
                modelCandidate("f".repeat(64)));
        assertThat(overwrite.getResponse().getStatus()).isEqualTo(409);
        assertThat(jdbc.queryForObject("SELECT artifact_sha256 FROM model_version WHERE id=?", String.class, modelId))
                .isEqualTo(MODEL_SHA);
        Cookie analyst = login("ledger-test-analyst");
        assertThat(mockMvc.perform(get("/api/v1/models/{id}", modelId).cookie(analyst)).andReturn()
                .getResponse().getStatus()).isEqualTo(403);

        MvcResult release = postJson("/api/v1/models/" + modelId + "/release-requests", operator,
                csrf(operator), "{\"reason\":\"request release review\"}");
        assertThat(release.getResponse().getStatus()).isEqualTo(201);
        long releaseId = data(release).path("id").asLong();
        Cookie releaser = login("ledger-test-model-releaser");
        MvcResult selfDecision = postJson("/api/v1/model-release-requests/" + releaseId + "/decision",
                operator, csrf(operator), "{\"decision\":\"approve\",\"reason\":\"self\"}");
        assertThat(selfDecision.getResponse().getStatus()).isEqualTo(403);

        MvcResult decision = postJson("/api/v1/model-release-requests/" + releaseId + "/decision",
                releaser, csrf(releaser), "{\"decision\":\"approve\",\"reason\":\"reviewed metadata\"}");
        assertThat(decision.getResponse().getStatus()).isEqualTo(200);
        assertThat(jdbc.queryForObject("SELECT requested_by FROM model_release_record WHERE id=?", Long.class, releaseId))
                .isEqualTo(modelOperatorId);
        assertThat(jdbc.queryForObject("SELECT approved_by FROM model_release_record WHERE id=?", Long.class, releaseId))
                .isEqualTo(modelReleaserId);
        assertThat(jdbc.queryForObject("SELECT approval_status FROM model_version WHERE id=?", String.class, modelId))
                .isEqualTo("candidate");
        assertThat(jdbc.queryForObject("SELECT artifact_sha256 FROM model_version WHERE id=?", String.class, modelId))
                .isEqualTo(MODEL_SHA);
    }

    @Test
    void releaseDecisionRejectsModelScopeRevokedAfterInitialAuthorizationCheck() throws Exception {
        Cookie operator = login("ledger-test-model-operator");
        MvcResult created = postJson("/api/v1/models", operator, csrf(operator), modelCandidate(MODEL_SHA));
        long modelId = data(created).path("id").asLong();
        MvcResult release = postJson("/api/v1/models/" + modelId + "/release-requests", operator,
                csrf(operator), "{\"reason\":\"request release review\"}");
        long releaseId = data(release).path("id").asLong();
        Cookie releaser = login("ledger-test-model-releaser");
        try (var blocker = openTestConnection(); ExecutorService executor = Executors.newSingleThreadExecutor()) {
            blocker.setAutoCommit(false);
            try (var lock = blocker.prepareStatement("SELECT role_id FROM sys_user_role WHERE user_id=? "
                    + "AND scope_type='model_registry' AND scope_id=? FOR UPDATE")) {
                lock.setLong(1, modelReleaserId);
                lock.setString(2, MODEL_KEY);
                lock.executeQuery().close();
            }
            Future<MvcResult> pendingDecision = executor.submit(() -> postJson(
                    "/api/v1/model-release-requests/" + releaseId + "/decision", releaser, csrf(releaser),
                    "{\"decision\":\"approve\",\"reason\":\"scope was revoked\"}"));
            awaitDatabaseLockWait("sys_user_role", pendingDecision);
            try (var update = blocker.prepareStatement("UPDATE sys_user_role SET scope_id=? WHERE user_id=? "
                    + "AND scope_type='model_registry'")) {
                update.setString(1, "ledger-test-other-model");
                update.setLong(2, modelReleaserId);
                update.executeUpdate();
            }
            blocker.commit();

            MvcResult decision = pendingDecision.get(5, TimeUnit.SECONDS);
            assertThat(decision.getResponse().getStatus())
                    .as("resolved exception: %s", decision.getResolvedException()).isEqualTo(404);
            assertThat(jdbc.queryForObject("SELECT review_status FROM model_release_record WHERE id=?", String.class,
                    releaseId)).isEqualTo("pending");
            assertThat(jdbc.queryForObject("SELECT approved_by FROM model_release_record WHERE id=?", Long.class,
                    releaseId)).isNull();
        }
    }

    @Test
    void responseRequestIsIdempotentApprovalIsSeparatedAndExecutionFailsClosed() throws Exception {
        Cookie analyst = login("ledger-test-analyst");
        assertThat(mockMvc.perform(get("/api/v1/events/{id}", eventId).cookie(analyst)).andReturn()
                .getResponse().getStatus()).isEqualTo(200);
        String body = actionBody(assetId, "initial review");
        String idemKey = "ledger-test-action-1";
        jdbc.update("UPDATE response_policy SET status='retired' WHERE id=?", policyId);
        MvcResult noPolicy = postAction(analyst, csrf(analyst), idemKey, body);
        assertThat(noPolicy.getResponse().getStatus()).isEqualTo(409);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM approval_task", Integer.class)).isZero();
        jdbc.update("UPDATE response_policy SET status='active' WHERE id=?", policyId);
        MvcResult created = postAction(analyst, csrf(analyst), idemKey, body);
        assertThat(created.getResponse().getStatus()).isEqualTo(201);
        long approvalId = data(created).path("id").asLong();
        assertThat(data(created).path("executionSupported").asBoolean()).isFalse();
        MvcResult action = mockMvc.perform(get("/api/v1/actions/{id}", approvalId).cookie(analyst)).andReturn();
        assertThat(action.getResponse().getStatus()).isEqualTo(200);
        assertThat(data(action).path("executionSupported").asBoolean()).isFalse();
        assertThat(mockMvc.perform(get("/api/v1/approvals").cookie(analyst)).andReturn()
                .getResponse().getStatus()).isEqualTo(403);

        MvcResult replay = postAction(analyst, csrf(analyst), idemKey, body);
        assertThat(replay.getResponse().getStatus()).isEqualTo(200);
        assertThat(data(replay).path("id").asLong()).isEqualTo(approvalId);
        MvcResult conflict = postAction(analyst, csrf(analyst), idemKey, actionBody(assetId, "different content"));
        assertThat(conflict.getResponse().getStatus()).isEqualTo(409);

        Cookie approver = login("ledger-test-response-approver");
        jdbc.update("UPDATE asset_authorization SET valid_until=UTC_TIMESTAMP(3)-INTERVAL 1 SECOND WHERE id=?",
                authorizationId);
        MvcResult expired = postJson("/api/v1/approvals/" + approvalId + "/decision", approver, csrf(approver),
                "{\"decision\":\"approve\",\"reason\":\"authorization expired\"}");
        assertThat(expired.getResponse().getStatus()).isEqualTo(409);
        assertThat(jdbc.queryForObject("SELECT status FROM approval_task WHERE id=?", String.class, approvalId))
                .isEqualTo("pending");

        jdbc.update("UPDATE asset_authorization SET valid_until=UTC_TIMESTAMP(3)+INTERVAL 1 HOUR WHERE id=?",
                authorizationId);
        MvcResult decision = postJson("/api/v1/approvals/" + approvalId + "/decision", approver, csrf(approver),
                "{\"decision\":\"approve\",\"reason\":\"reviewed request\"}");
        assertThat(decision.getResponse().getStatus()).isEqualTo(200);
        assertThat(jdbc.queryForObject("SELECT requested_by FROM approval_task WHERE id=?", Long.class, approvalId))
                .isEqualTo(analystId);
        assertThat(jdbc.queryForObject("SELECT reviewed_by FROM approval_task WHERE id=?", Long.class, approvalId))
                .isEqualTo(responseApproverId);

        MvcResult execution = postJson("/api/v1/actions/" + approvalId + "/execute", analyst, csrf(analyst), "{}");
        assertThat(execution.getResponse().getStatus()).isEqualTo(503);
        assertThat(objectMapper.readTree(execution.getResponse().getContentAsString()).path("error").path("code").asText())
                .isEqualTo("ACTION_EXECUTION_UNAVAILABLE");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM action_execution WHERE status='succeeded'",
                Integer.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM action_execution", Integer.class)).isZero();
    }

    @Test
    void responseDecisionRejectsActionScopeRevokedAfterAuthorizationCheck() throws Exception {
        Cookie analyst = login("ledger-test-analyst");
        MvcResult created = postAction(analyst, csrf(analyst), "ledger-test-action-scope-race",
                actionBody(assetId, "initial review"));
        long approvalId = data(created).path("id").asLong();
        Cookie approver = login("ledger-test-response-approver");
        try (var blocker = openTestConnection(); ExecutorService executor = Executors.newSingleThreadExecutor()) {
            blocker.setAutoCommit(false);
            try (var lock = blocker.prepareStatement("SELECT id FROM asset_authorization WHERE id=? FOR UPDATE")) {
                lock.setLong(1, authorizationId);
                lock.executeQuery().close();
            }
            Future<MvcResult> pendingDecision = executor.submit(() -> postJson(
                    "/api/v1/approvals/" + approvalId + "/decision", approver, csrf(approver),
                    "{\"decision\":\"approve\",\"reason\":\"action scope was narrowed\"}"));
            awaitDatabaseLockWait("asset_authorization", pendingDecision);
            try (var update = blocker.prepareStatement("UPDATE asset_authorization SET scope_json=? WHERE id=?")) {
                update.setString(1, "{\"actionTypes\":[\"other_action\"]}");
                update.setLong(2, authorizationId);
                update.executeUpdate();
            }
            blocker.commit();

            MvcResult decision = pendingDecision.get(5, TimeUnit.SECONDS);
            assertThat(decision.getResponse().getStatus()).isEqualTo(409);
            assertThat(jdbc.queryForObject("SELECT status FROM approval_task WHERE id=?", String.class, approvalId))
                    .isEqualTo("pending");
            assertThat(jdbc.queryForObject("SELECT reviewed_by FROM approval_task WHERE id=?", Long.class, approvalId))
                    .isNull();
        }
    }

    private long user(String suffix) {
        String username = "ledger-test-" + suffix;
        jdbc.update("INSERT INTO sys_user (user_key,username,display_name,status,password_hash) VALUES (?,?,?,'active',?)",
                username, username, username, HASH);
        return jdbc.queryForObject("SELECT id FROM sys_user WHERE username=?", Long.class, username);
    }

    private java.sql.Connection openTestConnection() throws Exception {
        String base = System.getenv("DB_TEST_BASE_URL").replaceFirst("/+$", "") + "/" + TEST_SCHEMA;
        return java.sql.DriverManager.getConnection(base, System.getenv("DB_TEST_USERNAME"),
                System.getenv("DB_TEST_PASSWORD"));
    }

    private void awaitDatabaseLockWait(String table, Future<?> pendingWork) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
        int waitingLocks = 0;
        while (System.nanoTime() < deadline && !pendingWork.isDone()) {
            waitingLocks = jdbc.queryForObject("SELECT COUNT(*) FROM performance_schema.data_lock_waits w "
                            + "JOIN performance_schema.data_locks requested "
                            + "ON requested.ENGINE_LOCK_ID=w.REQUESTING_ENGINE_LOCK_ID "
                            + "WHERE requested.OBJECT_SCHEMA=? AND requested.OBJECT_NAME=?", Integer.class,
                    TEST_SCHEMA, table);
            if (waitingLocks > 0) return;
            Thread.sleep(10);
        }
        assertThat(waitingLocks).as("request must wait for the authorization row lock").isPositive();
    }

    private long createAsset() {
        jdbc.update("INSERT INTO asset (asset_key,asset_type,environment,criticality,owner,status,labels_json) "
                        + "VALUES ('ledger-test-asset','host','lab','medium','test','active','{}')");
        return jdbc.queryForObject("SELECT id FROM asset WHERE asset_key='ledger-test-asset'", Long.class);
    }

    private long createSource() {
        jdbc.update("INSERT INTO data_source (source_key,source_type,environment,schema_version,scope_json,status) "
                + "VALUES ('ledger-test-source','connector','lab','v1','{}','active')");
        return jdbc.queryForObject("SELECT id FROM data_source WHERE source_key='ledger-test-source'", Long.class);
    }

    private long createEvent() {
        jdbc.update("INSERT INTO ingest_batch (batch_key,data_source_id,idempotency_key,status,total_count,accepted_count,rejected_count) "
                        + "VALUES ('ledger-test-batch',?,'ledger-test-batch','completed',1,1,0)", sourceId);
        long batchId = jdbc.queryForObject("SELECT id FROM ingest_batch WHERE batch_key='ledger-test-batch'", Long.class);
        jdbc.update("INSERT INTO ingest_record (batch_id,source_record_key,event_type,event_time,asset_id,normalized_payload,quality_status,mapping_version) "
                        + "VALUES (?,'ledger-test-record','network_flow',UTC_TIMESTAMP(3),?,JSON_OBJECT('bytes',42),'accepted','v1')",
                batchId, assetId);
        long recordId = jdbc.queryForObject("SELECT id FROM ingest_record WHERE source_record_key='ledger-test-record'", Long.class);
        jdbc.update("INSERT INTO detection_alert (alert_key,ingest_record_id,alert_type,severity,status,detected_at) "
                + "VALUES ('ledger-test-alert',?,'rule','medium','new',UTC_TIMESTAMP(3))", recordId);
        long alertId = jdbc.queryForObject("SELECT id FROM detection_alert WHERE alert_key='ledger-test-alert'", Long.class);
        jdbc.update("INSERT INTO security_event (event_key,title,category,severity,status,first_seen_at,last_seen_at) "
                + "VALUES ('ledger-test-event','Ledger test event','network','medium','open',UTC_TIMESTAMP(3),UTC_TIMESTAMP(3))");
        long event = jdbc.queryForObject("SELECT id FROM security_event WHERE event_key='ledger-test-event'", Long.class);
        jdbc.update("INSERT INTO event_alert_link (event_id,alert_id,link_type) VALUES (?,?,'correlated')", event, alertId);
        jdbc.update("INSERT INTO event_asset_link (event_id,asset_id,relation_type) VALUES (?,?,'affected')", event, assetId);
        return event;
    }

    private long createAuthorization() {
        jdbc.update("INSERT INTO asset_authorization (asset_id,authorization_ref,scope_json,valid_from,valid_until,status,requested_by,approved_by) "
                        + "VALUES (?,'controlled://ledger-test','{\"actionTypes\":[\"temporary_block\"]}',"
                        + "UTC_TIMESTAMP(3)-INTERVAL 1 HOUR,UTC_TIMESTAMP(3)+INTERVAL 1 HOUR,'active',?,?)",
                assetId, analystId, responseApproverId);
        return jdbc.queryForObject("SELECT id FROM asset_authorization WHERE asset_id=? ORDER BY id DESC LIMIT 1",
                Long.class, assetId);
    }

    private long createResponsePolicy() {
        jdbc.update("INSERT INTO response_policy (policy_key,version,environment,match_json,action_type,"
                        + "action_params_json,auto_execute,approval_required,max_duration_seconds,status,approved_by) "
                        + "VALUES ('ledger-test-policy','1','lab',JSON_OBJECT('environment','lab'),"
                        + "'temporary_block',JSON_OBJECT('maxTtlSeconds',120,'allowedTargets',JSON_ARRAY('192.0.2.25'))," 
                        + "FALSE,TRUE,120,'active',?)",
                responseApproverId);
        return jdbc.queryForObject("SELECT id FROM response_policy WHERE policy_key='ledger-test-policy'",
                Long.class);
    }

    private void bindRole(long userId, String roleKey, String scopeType, String scopeId) {
        jdbc.update("INSERT INTO sys_user_role (user_id,role_id,scope_type,scope_id) "
                        + "SELECT ?,id,?,? FROM sys_role WHERE role_key=?",
                userId, scopeType, scopeId, roleKey);
    }

    private String modelCandidate(String sha) {
        return "{\"modelKey\":\"" + MODEL_KEY + "\",\"version\":\"1.0.0\",\"taskType\":\"flow_classification\","
                + "\"manifestVersion\":\"1\",\"manifest\":{\"featureContract\":\"flow-v1\",\"labels\":[\"normal\",\"attack\"]},"
                + "\"artifactRef\":\"model://ledger-test/1.0.0/model.onnx\",\"artifactSha256\":\"" + sha
                + "\",\"featureContractVersion\":\"flow-v1\"}";
    }

    private String actionBody(long targetAsset, String reason) {
        return "{\"assetId\":" + targetAsset + ",\"policyId\":" + policyId
                + ",\"actionType\":\"temporary_block\","
                + "\"parameters\":{\"targetAddress\":\"192.0.2.25\",\"ttlSeconds\":60},"
                + "\"reason\":\"" + reason + "\"}";
    }

    private MvcResult postAction(Cookie cookie, String csrf, String key, String body) throws Exception {
        return mockMvc.perform(post("/api/v1/events/{id}/actions", eventId).cookie(cookie)
                        .header(CSRF_HEADER, csrf).header("Idempotency-Key", key)
                        .contentType(APPLICATION_JSON).content(body)).andReturn();
    }

    private MvcResult postJson(String path, Cookie cookie, String csrf, String body) throws Exception {
        return mockMvc.perform(post(path).cookie(cookie).header(CSRF_HEADER, csrf)
                        .contentType(APPLICATION_JSON).content(body)).andReturn();
    }

    private JsonNode data(MvcResult result) throws Exception {
        return objectMapper.readTree(result.getResponse().getContentAsString()).path("data");
    }

    private Cookie login(String username) throws Exception {
        MvcResult bootstrap = mockMvc.perform(get("/api/v1/auth/csrf")).andReturn();
        Cookie cookie = bootstrap.getResponse().getCookie("SESSION");
        String token = objectMapper.readTree(bootstrap.getResponse().getContentAsString()).path("data").path("token").asText();
        MvcResult login = postJson("/api/v1/auth/login", cookie, token,
                "{\"username\":\"" + username + "\",\"password\":\"" + PASSWORD + "\"}");
        assertThat(login.getResponse().getStatus()).isEqualTo(200);
        return login.getResponse().getCookie("SESSION");
    }

    private String csrf(Cookie cookie) throws Exception {
        MvcResult result = mockMvc.perform(get("/api/v1/auth/csrf").cookie(cookie)).andReturn();
        return objectMapper.readTree(result.getResponse().getContentAsString()).path("data").path("token").asText();
    }
}
