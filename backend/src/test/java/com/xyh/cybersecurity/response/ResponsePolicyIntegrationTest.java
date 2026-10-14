package com.xyh.cybersecurity.response;

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
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * M6 响应策略管理端到端：起草 → 提交 → 他人批准 → active；新版本取代旧版本；退役后不能再被申请或审批引用；
 * 自审、越权、非白名单、自动执行与 TTL 上限一律拒绝；每次迁移写带内容哈希的审计。
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@EnabledIfEnvironmentVariable(named = "DB_TEST_BASE_URL", matches = ".+")
@org.junit.jupiter.api.extension.ExtendWith(com.xyh.cybersecurity.database.IsolatedDatabaseSchemas.class)
class ResponsePolicyIntegrationTest {
    private static final String TEST_SCHEMA = com.xyh.cybersecurity.database.IsolatedDatabaseSchemas.name(ResponsePolicyIntegrationTest.class, "suite");
    private static final String PASSWORD = "response-policy-test-password";
    private static final String HASH = new BCryptPasswordEncoder(4).encode(PASSWORD);
    private static final String CSRF = "X-CSRF-TOKEN";

    @BeforeAll
    static void migrate() throws Exception {
        String base = System.getenv("DB_TEST_BASE_URL");
        try (var c = java.sql.DriverManager.getConnection(base, System.getenv("DB_TEST_USERNAME"), System.getenv("DB_TEST_PASSWORD"));
             var s = c.createStatement()) {
            s.execute("CREATE DATABASE IF NOT EXISTS " + TEST_SCHEMA + " CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci");
        }
        Flyway.configure().dataSource(base.replaceFirst("/+$", "") + "/" + TEST_SCHEMA, System.getenv("DB_TEST_USERNAME"),
                System.getenv("DB_TEST_PASSWORD")).locations("classpath:db/migration").baselineOnMigrate(false).target("25") /* v1 兼容断言固定在权限停用前；V26 由 IAM/guard 套件验收。 */.load().migrate();
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

    @Autowired private MockMvc mvc;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private ObjectMapper json;

    private long analystId;
    private long approverId;
    private long assetId;
    private long eventId;

    @BeforeEach
    void seed() {
        jdbc.update("DELETE FROM SPRING_SESSION");
        jdbc.update("DELETE FROM audit_resource_scope WHERE audit_id IN (SELECT id FROM audit_log WHERE actor_id IN "
                + "(SELECT CAST(id AS CHAR) FROM sys_user WHERE username LIKE 'rp-test-%'))");
        jdbc.update("DELETE FROM audit_log WHERE actor_id IN (SELECT CAST(id AS CHAR) FROM sys_user WHERE username LIKE 'rp-test-%')");
        jdbc.update("DELETE FROM approval_task WHERE event_id IN (SELECT id FROM security_event WHERE event_key LIKE 'rp-test-%')");
        jdbc.update("UPDATE response_policy SET based_on_policy_id=NULL WHERE policy_key LIKE 'rp-test-%'");
        jdbc.update("DELETE FROM response_policy WHERE policy_key LIKE 'rp-test-%'");
        for (String table : new String[] {"event_timeline", "event_asset_link", "event_alert_link"}) {
            jdbc.update("DELETE FROM " + table + " WHERE event_id IN (SELECT id FROM security_event WHERE event_key LIKE 'rp-test-%')");
        }
        jdbc.update("DELETE FROM security_event WHERE event_key LIKE 'rp-test-%'");
        jdbc.update("DELETE FROM detection_alert WHERE alert_key LIKE 'rp-test-%'");
        jdbc.update("DELETE FROM ingest_record WHERE source_record_key LIKE 'rp-test-%'");
        jdbc.update("DELETE FROM ingest_batch WHERE batch_key LIKE 'rp-test-%'");
        jdbc.update("DELETE FROM asset_authorization WHERE asset_id IN (SELECT id FROM asset WHERE asset_key LIKE 'rp-test-%')");
        jdbc.update("DELETE FROM data_source WHERE source_key LIKE 'rp-test-%'");
        jdbc.update("DELETE FROM asset WHERE asset_key LIKE 'rp-test-%'");
        jdbc.update("DELETE FROM sys_user_role");
        jdbc.update("DELETE FROM sys_user WHERE username LIKE 'rp-test-%'");

        analystId = user("analyst");
        approverId = user("approver");
        long secondAnalyst = user("analyst2");
        jdbc.update("INSERT INTO asset (asset_key,asset_type,environment,criticality,owner,status,labels_json) "
                + "VALUES ('rp-test-asset','host','lab','medium','test','active','{}')");
        assetId = jdbc.queryForObject("SELECT id FROM asset WHERE asset_key='rp-test-asset'", Long.class);
        jdbc.update("INSERT INTO data_source (source_key,source_type,environment,schema_version,scope_json,status) "
                + "VALUES ('rp-test-source','connector','lab','v1','{}','active')");
        long sourceId = jdbc.queryForObject("SELECT id FROM data_source WHERE source_key='rp-test-source'", Long.class);
        for (long u : new long[] {analystId, secondAnalyst}) {
            bindRole(u, "security_analyst", "asset", Long.toString(assetId));
            bindRole(u, "security_analyst", "data_source", Long.toString(sourceId));
        }
        bindRole(approverId, "response_approver", "asset", Long.toString(assetId));
        eventId = createEvent(sourceId);
        jdbc.update("INSERT INTO asset_authorization (asset_id,authorization_ref,scope_json,valid_from,valid_until,status,requested_by,approved_by) "
                + "VALUES (?,'controlled://rp-test','{\"actionTypes\":[\"temporary_block\"]}',"
                + "UTC_TIMESTAMP(3)-INTERVAL 1 HOUR,UTC_TIMESTAMP(3)+INTERVAL 1 HOUR,'active',?,?)", assetId, analystId, approverId);
    }

    @Test
    void draftSubmitApproveThenSupersedeAndRetire() throws Exception {
        Cookie analyst = login("rp-test-analyst");
        Cookie approver = login("rp-test-approver");

        MvcResult created = send(analyst, "/api/v1/response-policies", draft("rp-test-block", 120, "192.0.2.25"));
        assertThat(created.getResponse().getStatus()).isEqualTo(201);
        JsonNode v1 = data(created);
        long id1 = v1.path("id").asLong();
        assertThat(v1.path("status").asText()).isEqualTo("draft");
        assertThat(v1.path("version").asText()).isEqualTo("1");
        assertThat(v1.path("contentSha256").asText()).matches("[0-9a-f]{64}");
        assertThat(v1.path("createdBy").asLong()).isEqualTo(analystId);

        // 同一策略键不能再用 POST 新建；草稿未提交前不能被审批。
        assertThat(send(analyst, "/api/v1/response-policies", draft("rp-test-block", 120, "192.0.2.25"))
                .getResponse().getStatus()).isEqualTo(409);
        assertThat(decide(approver, id1, "approve").getResponse().getStatus()).isEqualTo(409);
        // 起草人不能批准；审批人无起草权限，起草人无审批权限。
        assertThat(send(approver, "/api/v1/response-policies", draft("rp-test-other", 60, "192.0.2.26"))
                .getResponse().getStatus()).isEqualTo(403);
        assertThat(send(analyst, "/api/v1/response-policies/" + id1 + "/submit", "{}").getResponse().getStatus()).isEqualTo(200);
        assertThat(decide(analyst, id1, "approve").getResponse().getStatus()).isEqualTo(403);
        // 只有起草人能提交/撤回：他人撤回 403。
        Cookie other = login("rp-test-analyst2");
        assertThat(send(other, "/api/v1/response-policies/" + id1 + "/withdraw", "{}").getResponse().getStatus()).isEqualTo(403);

        MvcResult approved = decide(approver, id1, "approve");
        assertThat(approved.getResponse().getStatus()).isEqualTo(200);
        assertThat(data(approved).path("status").asText()).isEqualTo("active");
        assertThat(data(approved).path("approvedBy").asLong()).isEqualTo(approverId);

        // active 策略可被动作申请引用。
        assertThat(action(analyst, id1, "rp-test-key-0001").getResponse().getStatus()).isEqualTo(201);

        // 新版本：沿用未给出的字段，TTL 收紧到 60 秒；有未决版本时不能再开第三个版本。
        MvcResult v2Created = send(analyst, "/api/v1/response-policies/" + id1 + "/versions",
                "{\"maxDurationSeconds\":60,\"actionParams\":{\"maxTtlSeconds\":60,\"allowedTargets\":[\"192.0.2.25\"]},"
                        + "\"reason\":\"缩短 TTL\"}");
        assertThat(v2Created.getResponse().getStatus()).isEqualTo(201);
        JsonNode v2 = data(v2Created);
        long id2 = v2.path("id").asLong();
        assertThat(v2.path("version").asText()).isEqualTo("2");
        assertThat(v2.path("basedOnPolicyId").asLong()).isEqualTo(id1);
        assertThat(v2.path("environment").asText()).isEqualTo("lab");
        assertThat(send(analyst, "/api/v1/response-policies/" + id1 + "/versions", "{\"reason\":\"并发版本\"}")
                .getResponse().getStatus()).isEqualTo(409);
        assertThat(send(analyst, "/api/v1/response-policies/" + id2 + "/submit", "{}").getResponse().getStatus()).isEqualTo(200);
        assertThat(decide(approver, id2, "approve").getResponse().getStatus()).isEqualTo(200);
        assertThat(status(id1)).isEqualTo("retired");
        assertThat(status(id2)).isEqualTo("active");
        assertThat(jdbc.queryForObject("SELECT retired_by FROM response_policy WHERE id=?", Long.class, id1)).isEqualTo(approverId);

        // 已退役版本不能再被申请引用；引用它的待审批动作也不能被批准。
        assertThat(action(analyst, id1, "rp-test-key-0002").getResponse().getStatus()).isEqualTo(409);
        long pendingTask = jdbc.queryForObject("SELECT id FROM approval_task WHERE policy_id=? AND status='pending'", Long.class, id1);
        assertThat(send(approver, "/api/v1/approvals/" + pendingTask + "/decision",
                "{\"decision\":\"approve\",\"reason\":\"策略已退役\"}").getResponse().getStatus()).isEqualTo(409);

        // 审批人退役 active 版本；已退役不能重复退役。
        assertThat(send(approver, "/api/v1/response-policies/" + id2 + "/retire", "{\"reason\":\"停用\"}")
                .getResponse().getStatus()).isEqualTo(200);
        assertThat(send(approver, "/api/v1/response-policies/" + id2 + "/retire", "{\"reason\":\"重复\"}")
                .getResponse().getStatus()).isEqualTo(409);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM response_policy WHERE policy_key='rp-test-block' AND status='active'",
                Integer.class)).isZero();

        // 追加审计：起草×2、提交×2、批准×2、取代×1、退役×1，均带内容哈希。
        Integer audits = jdbc.queryForObject("SELECT COUNT(*) FROM audit_log WHERE resource_type='response_policy' "
                + "AND resource_id IN (?,?) AND after_hash REGEXP '^[0-9a-f]{64}$'", Integer.class,
                Long.toString(id1), Long.toString(id2));
        assertThat(audits).isEqualTo(8);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM audit_log WHERE action='response.policy.superseded' AND resource_id=?",
                Integer.class, Long.toString(id1))).isEqualTo(1);

        // 列表与筛选。
        MvcResult listed = mvc.perform(get("/api/v1/response-policies").param("policyKey", "rp-test-block").cookie(analyst)).andReturn();
        assertThat(listed.getResponse().getStatus()).isEqualTo(200);
        assertThat(data(listed).size()).isEqualTo(2);
        assertThat(mvc.perform(get("/api/v1/response-policies").param("status", "bogus").cookie(analyst)).andReturn()
                .getResponse().getStatus()).isEqualTo(400);
    }

    @Test
    void rejectsUnsafeDefinitionsAndSupportsRejectAndWithdraw() throws Exception {
        Cookie analyst = login("rp-test-analyst");
        Cookie approver = login("rp-test-approver");
        assertThat(code(send(analyst, "/api/v1/response-policies", draft("rp-test-a", 120, "192.0.2.25")
                .replace("\"temporary_block\"", "\"rate_limit\"")))).isEqualTo("ACTION_NOT_WHITELISTED");
        assertThat(code(send(analyst, "/api/v1/response-policies", draft("rp-test-b", 120, "192.0.2.25")
                .replace("\"autoExecute\":false,\"approvalRequired\":true", "\"autoExecute\":true,\"approvalRequired\":false"))))
                .isEqualTo("AUTO_EXECUTE_NOT_ALLOWED");
        assertThat(code(send(analyst, "/api/v1/response-policies", draft("rp-test-c", 7200, "192.0.2.25"))))
                .isEqualTo("POLICY_TTL_EXCEEDED");
        assertThat(code(send(analyst, "/api/v1/response-policies", draft("rp-test-d", 120, "127.0.0.1"))))
                .isEqualTo("POLICY_DEFINITION_INVALID");
        assertThat(code(send(analyst, "/api/v1/response-policies", draft("rp-test-e", 120, "192.0.2.25")
                .replace("{\"environment\":\"lab\"}", "{\"environment\":\"lab\",\"url\":\"https://x\"}"))))
                .isEqualTo("POLICY_DEFINITION_INVALID");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM response_policy WHERE policy_key LIKE 'rp-test-%'", Integer.class)).isZero();

        long id = data(send(analyst, "/api/v1/response-policies", draft("rp-test-f", 120, "192.0.2.25"))).path("id").asLong();
        send(analyst, "/api/v1/response-policies/" + id + "/submit", "{}");
        MvcResult rejected = decide(approver, id, "reject");
        assertThat(data(rejected).path("status").asText()).isEqualTo("rejected");
        assertThat(data(rejected).path("reviewedBy").asLong()).isEqualTo(approverId);
        assertThat(data(rejected).path("approvedBy").isNull()).isTrue();
        assertThat(send(analyst, "/api/v1/response-policies/" + id + "/submit", "{}").getResponse().getStatus()).isEqualTo(409);

        long draftId = data(send(analyst, "/api/v1/response-policies/" + id + "/versions", "{\"reason\":\"重拟\"}")).path("id").asLong();
        assertThat(data(send(analyst, "/api/v1/response-policies/" + draftId + "/withdraw", "{}")).path("status").asText())
                .isEqualTo("retired");
        // 被拒版本不能被退役接口激活或重复处理。
        assertThat(send(approver, "/api/v1/response-policies/" + id + "/retire", "{\"reason\":\"x\"}").getResponse().getStatus())
                .isEqualTo(409);
    }

    @Test
    void databaseEnforcesSeparationAndSingleActive() {
        jdbc.update("INSERT INTO response_policy (policy_key,version,environment,match_json,action_type,action_params_json,"
                + "auto_execute,approval_required,max_duration_seconds,status,created_by,approved_by) VALUES "
                + "('rp-test-db','1','lab',JSON_OBJECT('environment','lab'),'temporary_block',JSON_OBJECT(),FALSE,TRUE,60,'active',?,?)",
                analystId, approverId);
        assertThatThrownBy(() -> jdbc.update("INSERT INTO response_policy (policy_key,version,environment,match_json,action_type,"
                + "action_params_json,auto_execute,approval_required,max_duration_seconds,status,created_by,approved_by) VALUES "
                + "('rp-test-db','2','lab',JSON_OBJECT('environment','lab'),'temporary_block',JSON_OBJECT(),FALSE,TRUE,60,'active',?,?)",
                analystId, approverId)).hasMessageContaining("uk_response_policy_active");
        assertThatThrownBy(() -> jdbc.update("INSERT INTO response_policy (policy_key,version,environment,match_json,action_type,"
                + "action_params_json,auto_execute,approval_required,max_duration_seconds,status,created_by,approved_by) VALUES "
                + "('rp-test-db2','1','lab',JSON_OBJECT('environment','lab'),'temporary_block',JSON_OBJECT(),FALSE,TRUE,60,'active',?,?)",
                analystId, analystId)).hasMessageContaining("ck_response_policy_separation");
        assertThatThrownBy(() -> jdbc.update("INSERT INTO response_policy (policy_key,version,environment,match_json,action_type,"
                + "action_params_json,auto_execute,approval_required,max_duration_seconds,status,created_by) VALUES "
                + "('rp-test-db3','1','lab',JSON_OBJECT('environment','lab'),'temporary_block',JSON_OBJECT(),FALSE,TRUE,60,'active',?)",
                analystId)).hasMessageContaining("ck_response_policy_active_approved");
    }

    private static String draft(String key, int maxDuration, String target) {
        return "{\"policyKey\":\"" + key + "\",\"environment\":\"lab\",\"match\":{\"environment\":\"lab\"},"
                + "\"actionType\":\"temporary_block\",\"actionParams\":{\"maxTtlSeconds\":" + Math.min(maxDuration, 3600)
                + ",\"allowedTargets\":[\"" + target + "\"]},\"autoExecute\":false,\"approvalRequired\":true,"
                + "\"maxDurationSeconds\":" + maxDuration + ",\"reason\":\"实验室临时阻断策略\"}";
    }

    private MvcResult decide(Cookie cookie, long id, String decision) throws Exception {
        return send(cookie, "/api/v1/response-policies/" + id + "/decision",
                "{\"decision\":\"" + decision + "\",\"reason\":\"复核通过\"}");
    }

    private MvcResult action(Cookie cookie, long policyId, String key) throws Exception {
        return mvc.perform(post("/api/v1/events/{id}/actions", eventId).cookie(cookie).header(CSRF, csrf(cookie))
                .header("Idempotency-Key", key).contentType(APPLICATION_JSON)
                .content("{\"assetId\":" + assetId + ",\"policyId\":" + policyId + ",\"actionType\":\"temporary_block\","
                        + "\"parameters\":{\"targetAddress\":\"192.0.2.25\",\"ttlSeconds\":60},\"reason\":\"阻断可疑来源\"}"))
                .andReturn();
    }

    private String status(long id) {
        return jdbc.queryForObject("SELECT status FROM response_policy WHERE id=?", String.class, id);
    }

    private String code(MvcResult result) throws Exception {
        return json.readTree(result.getResponse().getContentAsString()).path("error").path("code").asText();
    }

    private long createEvent(long sourceId) {
        jdbc.update("INSERT INTO ingest_batch (batch_key,data_source_id,idempotency_key,status,total_count,accepted_count,rejected_count) "
                + "VALUES ('rp-test-batch',?,'rp-test-batch','completed',1,1,0)", sourceId);
        long batchId = jdbc.queryForObject("SELECT id FROM ingest_batch WHERE batch_key='rp-test-batch'", Long.class);
        jdbc.update("INSERT INTO ingest_record (batch_id,source_record_key,event_type,event_time,asset_id,normalized_payload,quality_status,mapping_version) "
                + "VALUES (?,'rp-test-record','network_flow',UTC_TIMESTAMP(3),?,JSON_OBJECT('bytes',42),'accepted','v1')", batchId, assetId);
        long recordId = jdbc.queryForObject("SELECT id FROM ingest_record WHERE source_record_key='rp-test-record'", Long.class);
        jdbc.update("INSERT INTO detection_alert (alert_key,ingest_record_id,alert_type,severity,status,detected_at) "
                + "VALUES ('rp-test-alert',?,'rule','medium','new',UTC_TIMESTAMP(3))", recordId);
        long alertId = jdbc.queryForObject("SELECT id FROM detection_alert WHERE alert_key='rp-test-alert'", Long.class);
        jdbc.update("INSERT INTO security_event (event_key,title,category,severity,status,first_seen_at,last_seen_at) "
                + "VALUES ('rp-test-event','Policy test event','network','medium','open',UTC_TIMESTAMP(3),UTC_TIMESTAMP(3))");
        long event = jdbc.queryForObject("SELECT id FROM security_event WHERE event_key='rp-test-event'", Long.class);
        jdbc.update("INSERT INTO event_alert_link (event_id,alert_id,link_type) VALUES (?,?,'correlated')", event, alertId);
        jdbc.update("INSERT INTO event_asset_link (event_id,asset_id,relation_type) VALUES (?,?,'affected')", event, assetId);
        return event;
    }

    private long user(String suffix) {
        String username = "rp-test-" + suffix;
        jdbc.update("INSERT INTO sys_user (user_key,username,display_name,status,password_hash) VALUES (?,?,?,'active',?)",
                username, username, username, HASH);
        return jdbc.queryForObject("SELECT id FROM sys_user WHERE username=?", Long.class, username);
    }

    private void bindRole(long userId, String roleKey, String scopeType, String scopeId) {
        jdbc.update("INSERT INTO sys_user_role (user_id,role_id,scope_type,scope_id) SELECT ?,id,?,? FROM sys_role WHERE role_key=?",
                userId, scopeType, scopeId, roleKey);
    }

    private MvcResult send(Cookie cookie, String path, String body) throws Exception {
        return mvc.perform(post(path).cookie(cookie).header(CSRF, csrf(cookie)).contentType(APPLICATION_JSON).content(body)).andReturn();
    }

    private JsonNode data(MvcResult result) throws Exception {
        return json.readTree(result.getResponse().getContentAsString()).path("data");
    }

    private Cookie login(String username) throws Exception {
        MvcResult bootstrap = mvc.perform(get("/api/v1/auth/csrf")).andReturn();
        Cookie cookie = bootstrap.getResponse().getCookie("SESSION");
        String token = json.readTree(bootstrap.getResponse().getContentAsString()).path("data").path("token").asText();
        MvcResult login = mvc.perform(post("/api/v1/auth/login").cookie(cookie).header(CSRF, token).contentType(APPLICATION_JSON)
                .content("{\"username\":\"" + username + "\",\"password\":\"" + PASSWORD + "\"}")).andReturn();
        assertThat(login.getResponse().getStatus()).isEqualTo(200);
        return login.getResponse().getCookie("SESSION");
    }

    private String csrf(Cookie cookie) throws Exception {
        MvcResult result = mvc.perform(get("/api/v1/auth/csrf").cookie(cookie)).andReturn();
        return json.readTree(result.getResponse().getContentAsString()).path("data").path("token").asText();
    }
}
