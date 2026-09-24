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
class IncidentAuthorizationIntegrationTest {

    private static final String TEST_SCHEMA = "cyber_security_backend_incident_20260923";
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
        jdbc.update("INSERT INTO ingest_batch (batch_key,data_source_id,idempotency_key,status,total_count,accepted_count,rejected_count) VALUES (?,?,?,'completed',1,1,0)",
                "incident-test-" + suffix, sourceId, "incident-test-" + suffix);
        long batchId = jdbc.queryForObject("SELECT id FROM ingest_batch WHERE batch_key=?", Long.class, "incident-test-" + suffix);
        jdbc.update("INSERT INTO ingest_record (batch_id,source_record_key,event_type,event_time,asset_id,normalized_payload,quality_status,mapping_version) "
                        + "VALUES (?,?,'network_flow',?,?,JSON_OBJECT('bytes',42),'accepted','v1')",
                batchId, "incident-test-" + suffix, Timestamp.from(Instant.now()), assetId);
        long recordId = jdbc.queryForObject("SELECT id FROM ingest_record WHERE source_record_key=?", Long.class, "incident-test-" + suffix);
        jdbc.update("INSERT INTO detection_alert (alert_key,ingest_record_id,alert_type,severity,status,detected_at) VALUES (?,?,'rule','medium','new',?)",
                "incident-test-" + suffix, recordId, Timestamp.from(Instant.now()));
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
