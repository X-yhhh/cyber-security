package com.xyh.cybersecurity.incident;

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

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** 验证告警/事件范围过滤、全关联可见和事件状态机。 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@EnabledIfEnvironmentVariable(named = "DB_TEST_BASE_URL", matches = ".+")
@org.junit.jupiter.api.extension.ExtendWith(com.xyh.cybersecurity.database.IsolatedDatabaseSchemas.class)
class IncidentAuthorizationIntegrationTest {

    private static final String TEST_SCHEMA = com.xyh.cybersecurity.database.IsolatedDatabaseSchemas.name(IncidentAuthorizationIntegrationTest.class, "suite");
    private static final String HASH = new BCryptPasswordEncoder(4).encode("analyst-password");
    private static final String CSRF_HEADER = "X-CSRF-TOKEN";

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
                .locations("classpath:db/migration").baselineOnMigrate(false).target("25") /* v1 兼容断言固定在权限停用前；V26 由 IAM/guard 套件验收。 */.load().migrate();
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

    private long visibleAssetId;
    private long hiddenAssetId;
    private long visibleSourceId;
    private long hiddenSourceId;
    private long visibleAlertId;
    private long hiddenAlertId;
    private long visibleEventId;
    private long mixedEventId;

    @BeforeEach
    void seed() {
        jdbc.update("DELETE FROM SPRING_SESSION");
        jdbc.update("DELETE FROM event_timeline");
        jdbc.update("DELETE FROM event_asset_link");
        jdbc.update("DELETE FROM event_alert_link");
        jdbc.update("DELETE FROM security_event WHERE event_key LIKE 'incident-test-%'");
        jdbc.update("DELETE FROM detection_alert WHERE alert_key LIKE 'incident-test-%'");
        jdbc.update("DELETE FROM ingest_record WHERE source_record_key LIKE 'incident-test-%'");
        jdbc.update("DELETE FROM ingest_batch WHERE batch_key LIKE 'incident-test-%'");
        jdbc.update("DELETE FROM source_mapping WHERE data_source_id IN (SELECT id FROM data_source WHERE source_key LIKE 'incident-test-%')");
        jdbc.update("DELETE FROM data_source WHERE source_key LIKE 'incident-test-%'");
        jdbc.update("DELETE FROM asset WHERE asset_key LIKE 'incident-test-%'");
        jdbc.update("DELETE FROM sys_user_role");
        jdbc.update("DELETE FROM sys_user WHERE username='incident-test-analyst'");

        jdbc.update("INSERT INTO sys_user (user_key,username,display_name,status,password_hash) VALUES "
                + "('incident-test-analyst','incident-test-analyst','Incident Analyst','active',?)", HASH);
        long userId = jdbc.queryForObject("SELECT id FROM sys_user WHERE username='incident-test-analyst'", Long.class);
        visibleAssetId = asset("visible");
        hiddenAssetId = asset("hidden");
        visibleSourceId = source("visible");
        hiddenSourceId = source("hidden");
        jdbc.update("INSERT INTO sys_user_role (user_id,role_id,scope_type,scope_id) SELECT ?,id,'asset',? FROM sys_role WHERE role_key='security_analyst'",
                userId, Long.toString(visibleAssetId));
        jdbc.update("INSERT INTO sys_user_role (user_id,role_id,scope_type,scope_id) SELECT ?,id,'data_source',? FROM sys_role WHERE role_key='security_analyst'",
                userId, Long.toString(visibleSourceId));
        visibleAlertId = alert("visible", visibleSourceId, visibleAssetId);
        hiddenAlertId = alert("hidden", hiddenSourceId, hiddenAssetId);
        visibleEventId = event("visible", visibleAlertId, visibleAssetId);
        mixedEventId = event("mixed", visibleAlertId, visibleAssetId);
        jdbc.update("INSERT INTO event_alert_link (event_id,alert_id,link_type) VALUES (?,?,'correlated')",
                mixedEventId, hiddenAlertId);
    }

    @Test
    void alertListIsScopedInSqlBeforePaginationAndMixedEventsAreHidden() throws Exception {
        Cookie session = login();
        mockMvc.perform(get("/api/v1/alerts?page=0&size=1").cookie(session))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.totalElements").value(1))
                .andExpect(jsonPath("$.data.items[0].id").value(visibleAlertId));
        mockMvc.perform(get("/api/v1/alerts/{id}", hiddenAlertId).cookie(session))
                .andExpect(status().isNotFound());
        mockMvc.perform(get("/api/v1/events?page=0&size=20").cookie(session))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.totalElements").value(1))
                .andExpect(jsonPath("$.data.items[0].id").value(visibleEventId));
        mockMvc.perform(get("/api/v1/events/{id}", mixedEventId).cookie(session))
                .andExpect(status().isNotFound());
    }

    @Test
    void assignmentRequiresActiveFullyScopedInvestigatorAndWritesTimeline() throws Exception {
        Cookie session=login(); Csrf csrfValue=csrf(session);
        long userId=jdbc.queryForObject("SELECT id FROM sys_user WHERE username='incident-test-analyst'",Long.class);
        var operation=org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put("/api/v1/events/{id}/assignee",visibleEventId)
                .cookie(session).header(CSRF_HEADER,csrfValue.token()).contentType(APPLICATION_JSON);
        mockMvc.perform(operation.content("{\"assigneeId\":"+userId+",\"reason\":\"本人处理\"}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.event.assigneeId").value(userId));
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM event_timeline WHERE entry_type='assignee_changed'",Integer.class)).isEqualTo(1);
        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put("/api/v1/events/{id}/assignee",mixedEventId)
                .cookie(session).header(CSRF_HEADER,csrfValue.token()).contentType(APPLICATION_JSON)
                .content("{\"assigneeId\":"+userId+",\"reason\":\"隐藏证据事件\"}"))
                .andExpect(status().isNotFound());
        mockMvc.perform(operation.content("{\"assigneeId\":9999999,\"reason\":\"未知用户\"}"))
                .andExpect(status().isBadRequest());
        mockMvc.perform(operation.content("{\"assigneeId\":null,\"reason\":\"取消指派\"}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.event.assigneeId").isEmpty());
        jdbc.update("UPDATE security_event SET status='closed' WHERE id=?",visibleEventId);
        mockMvc.perform(operation.content("{\"assigneeId\":"+userId+",\"reason\":\"已关闭\"}"))
                .andExpect(status().isConflict());
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM audit_log WHERE resource_id=? AND action='event.assignee.changed'",Integer.class,Long.toString(visibleEventId))).isEqualTo(2);
    }

    @Test
    void eventTransitionsAreValidatedAndTimelineIsAppendOnly() throws Exception {
        Cookie session = login();
        Csrf csrf = csrf(session);
        mockMvc.perform(post("/api/v1/events/{id}/transitions", visibleEventId).cookie(session)
                        .header(CSRF_HEADER, csrf.token()).contentType(APPLICATION_JSON).content("{\"status\":\"closed\",\"reason\":\"premature\"}"))
                .andExpect(status().isConflict());
        assertThat(jdbc.queryForObject("SELECT status FROM security_event WHERE id=?", String.class, visibleEventId)).isEqualTo("open");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM event_timeline WHERE event_id=?", Integer.class, visibleEventId)).isZero();

        mockMvc.perform(post("/api/v1/events/{id}/transitions", visibleEventId).cookie(session)
                        .header(CSRF_HEADER, csrf.token()).contentType(APPLICATION_JSON).content("{\"status\":\"investigating\",\"reason\":\"triage started\"}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.event.status").value("investigating"));
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM event_timeline WHERE event_id=? AND entry_type='status_transition'",
                Integer.class, visibleEventId)).isEqualTo(1);
        mockMvc.perform(post("/api/v1/events/{id}/transitions", visibleEventId).cookie(session)
                        .header(CSRF_HEADER, csrf.token()).contentType(APPLICATION_JSON).content("{\"status\":\"investigating\",\"reason\":\"repeat\"}"))
                .andExpect(status().isConflict());
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM event_timeline WHERE event_id=?", Integer.class, visibleEventId)).isEqualTo(1);
    }

    @Test
    void eventDetailEmbedsOnlyTheFirstPageAndPagesEvidenceNewestFirst() throws Exception {
        // 可见事件再挂 24 条告警（共 25 条）与 25 条时间线，均在范围内；时间递增，id 递增。
        Instant base = Instant.parse("2026-09-29T10:00:00Z");
        for (int i = 1; i <= 24; i++) {
            long alertId = alert("page-" + i, visibleSourceId, visibleAssetId, base.plusSeconds(i));
            jdbc.update("INSERT INTO event_alert_link (event_id,alert_id,link_type) VALUES (?,?,'correlated')",
                    visibleEventId, alertId);
        }
        for (int i = 1; i <= 25; i++) {
            jdbc.update("INSERT INTO event_timeline (event_id,occurred_at,entry_type,actor_type,summary) "
                    + "VALUES (?,?,'alert_linked','system',?)", visibleEventId, Timestamp.from(base.plusSeconds(i)), "entry-" + i);
        }
        Cookie session = login();

        // 详情内嵌第一页 20 条并带总数；最新在前。
        mockMvc.perform(get("/api/v1/events/{id}", visibleEventId).cookie(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.alerts.totalElements").value(25))
                .andExpect(jsonPath("$.data.alerts.size").value(20))
                .andExpect(jsonPath("$.data.alerts.items.length()").value(20))
                .andExpect(jsonPath("$.data.timeline.totalElements").value(25))
                .andExpect(jsonPath("$.data.timeline.items.length()").value(20))
                .andExpect(jsonPath("$.data.timeline.items[0].summary").value("entry-25"))
                .andExpect(jsonPath("$.data.assets.length()").value(1));

        // 子资源分页：第二页只剩 5 条，顺序接续且不重叠。
        mockMvc.perform(get("/api/v1/events/{id}/timeline?page=1&size=20", visibleEventId).cookie(session))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.page").value(1))
                .andExpect(jsonPath("$.data.items.length()").value(5))
                .andExpect(jsonPath("$.data.items[0].summary").value("entry-5"))
                .andExpect(jsonPath("$.data.items[4].summary").value("entry-1"));
        mockMvc.perform(get("/api/v1/events/{id}/alerts?page=0&size=10", visibleEventId).cookie(session))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.totalElements").value(25))
                .andExpect(jsonPath("$.data.items.length()").value(10))
                // 初始可见告警检测时间为当前时刻，最新；其后是 page-24。
                .andExpect(jsonPath("$.data.items[0].alertKey").value("incident-test-visible"))
                .andExpect(jsonPath("$.data.items[1].alertKey").value("incident-test-page-24"));
        mockMvc.perform(get("/api/v1/events/{id}/alerts?page=2&size=10", visibleEventId).cookie(session))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.items.length()").value(5));

        // 含越权告警的事件、不存在的事件都返回 404，而不是空页。
        mockMvc.perform(get("/api/v1/events/{id}/alerts", mixedEventId).cookie(session)).andExpect(status().isNotFound());
        mockMvc.perform(get("/api/v1/events/{id}/timeline", mixedEventId).cookie(session)).andExpect(status().isNotFound());
        mockMvc.perform(get("/api/v1/events/{id}/timeline", Long.MAX_VALUE).cookie(session)).andExpect(status().isNotFound());

        // 分页参数越界 400。
        mockMvc.perform(get("/api/v1/events/{id}/alerts?size=101", visibleEventId).cookie(session)).andExpect(status().isBadRequest());
        mockMvc.perform(get("/api/v1/events/{id}/timeline?size=0", visibleEventId).cookie(session)).andExpect(status().isBadRequest());
        mockMvc.perform(get("/api/v1/events/{id}/timeline?page=-1", visibleEventId).cookie(session)).andExpect(status().isBadRequest());
    }

    private long asset(String suffix) {
        jdbc.update("INSERT INTO asset (asset_key,asset_type,environment,criticality,owner,status,labels_json) VALUES (?,'host','lab','low','test','active','{}')",
                "incident-test-" + suffix);
        return jdbc.queryForObject("SELECT id FROM asset WHERE asset_key=?", Long.class, "incident-test-" + suffix);
    }

    private long source(String suffix) {
        jdbc.update("INSERT INTO data_source (source_key,source_type,environment,schema_version,scope_json,status) VALUES (?,'connector','lab','v1','{}','active')",
                "incident-test-" + suffix);
        return jdbc.queryForObject("SELECT id FROM data_source WHERE source_key=?", Long.class, "incident-test-" + suffix);
    }

    private long alert(String suffix, long sourceId, long assetId) {
        return alert(suffix, sourceId, assetId, Instant.now());
    }

    private long alert(String suffix, long sourceId, long assetId, Instant detectedAt) {
        jdbc.update("INSERT INTO ingest_batch (batch_key,data_source_id,idempotency_key,status,total_count,accepted_count,rejected_count) VALUES (?,?,?,'completed',1,1,0)",
                "incident-test-" + suffix, sourceId, "incident-test-" + suffix);
        long batchId = jdbc.queryForObject("SELECT id FROM ingest_batch WHERE batch_key=?", Long.class, "incident-test-" + suffix);
        jdbc.update("INSERT INTO ingest_record (batch_id,source_record_key,event_type,event_time,asset_id,normalized_payload,quality_status,mapping_version) "
                        + "VALUES (?,?,'network_flow',?,?,JSON_OBJECT('bytes',42),'accepted','v1')",
                batchId, "incident-test-" + suffix, Timestamp.from(Instant.now()), assetId);
        long recordId = jdbc.queryForObject("SELECT id FROM ingest_record WHERE source_record_key=?", Long.class, "incident-test-" + suffix);
        jdbc.update("INSERT INTO detection_alert (alert_key,ingest_record_id,alert_type,severity,status,detected_at) VALUES (?,?,'rule','medium','new',?)",
                "incident-test-" + suffix, recordId, Timestamp.from(detectedAt));
        return jdbc.queryForObject("SELECT id FROM detection_alert WHERE alert_key=?", Long.class, "incident-test-" + suffix);
    }

    private long event(String suffix, long alertId, long assetId) {
        jdbc.update("INSERT INTO security_event (event_key,title,category,severity,status,first_seen_at,last_seen_at) VALUES (?,?,'network','medium','open',?,?)",
                "incident-test-" + suffix, "Incident " + suffix, Timestamp.from(Instant.now()), Timestamp.from(Instant.now()));
        long eventId = jdbc.queryForObject("SELECT id FROM security_event WHERE event_key=?", Long.class, "incident-test-" + suffix);
        jdbc.update("INSERT INTO event_alert_link (event_id,alert_id,link_type) VALUES (?,?,'correlated')", eventId, alertId);
        jdbc.update("INSERT INTO event_asset_link (event_id,asset_id,relation_type) VALUES (?,?,'affected')", eventId, assetId);
        return eventId;
    }

    private Cookie login() throws Exception {
        MvcResult bootstrap = mockMvc.perform(get("/api/v1/auth/csrf")).andReturn();
        Cookie cookie = bootstrap.getResponse().getCookie("SESSION");
        String token = objectMapper.readTree(bootstrap.getResponse().getContentAsString()).path("data").path("token").asText();
        return mockMvc.perform(post("/api/v1/auth/login").cookie(cookie).header(CSRF_HEADER, token)
                        .contentType(APPLICATION_JSON).content("{\"username\":\"incident-test-analyst\",\"password\":\"analyst-password\"}"))
                .andExpect(status().isOk()).andReturn().getResponse().getCookie("SESSION");
    }

    private Csrf csrf(Cookie cookie) throws Exception {
        MvcResult result = mockMvc.perform(get("/api/v1/auth/csrf").cookie(cookie)).andReturn();
        return new Csrf(objectMapper.readTree(result.getResponse().getContentAsString()).path("data").path("token").asText());
    }

    private record Csrf(String token) { }
}
