package com.xyh.cybersecurity.detection;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.xyh.cybersecurity.ingest.IngestMapper;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.support.TransactionTemplate;

import java.io.InputStream;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 时间窗规则的数据库路径（开发路线 §4.2）：窗口上下文从已落库记录读取（跨批次、按契约过滤），
 * 告警抑制读取已有规则告警，重放不产生重复告警；告警照常并入同资产事件。
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@EnabledIfEnvironmentVariable(named = "DB_TEST_BASE_URL", matches = ".+")
class WindowRuleIntegrationTest {
    private static final String TEST_SCHEMA = "cyber_security_backend_window_rule_20261001";
    private static final String V4 = "unsw-nb15-flow-v4";
    private static final Instant T0 = Instant.parse("2026-09-30T11:14:00Z");
    private static final String FAILED_HANDSHAKE = "{\"features\":{\"proto\":\"tcp\",\"service\":\"-\",\"synack\":0,"
            + "\"tcprtt\":0,\"dur\":0,\"spkts\":1},\"metadata\":{\"viewpoint\":\"responder\",\"addressFamily\":\"ipv4\","
            + "\"handshakeSeen\":true}}";

    @BeforeAll
    static void migrate() throws Exception {
        String base = System.getenv("DB_TEST_BASE_URL");
        try (var connection = java.sql.DriverManager.getConnection(base, System.getenv("DB_TEST_USERNAME"),
                System.getenv("DB_TEST_PASSWORD")); var statement = connection.createStatement()) {
            statement.execute("CREATE DATABASE IF NOT EXISTS " + TEST_SCHEMA + " CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci");
        }
        Flyway.configure().dataSource(base.replaceFirst("/+$", "") + "/" + TEST_SCHEMA, System.getenv("DB_TEST_USERNAME"),
                System.getenv("DB_TEST_PASSWORD")).locations("classpath:db/migration").baselineOnMigrate(false).load().migrate();
    }

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        String base = System.getenv("DB_TEST_BASE_URL");
        registry.add("spring.datasource.url", () -> base.replaceFirst("/+$", "") + "/" + TEST_SCHEMA);
        registry.add("spring.datasource.username", () -> System.getenv("DB_TEST_USERNAME"));
        registry.add("spring.datasource.password", () -> System.getenv("DB_TEST_PASSWORD"));
        registry.add("spring.flyway.enabled", () -> false);
        registry.add("cyber.security.login-throttle.hmac-key", () -> "test-only-key-with-at-least-thirty-two-bytes");
    }

    @Autowired private DetectionService detection;
    @Autowired private IngestMapper ingestMapper;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private TransactionTemplate transactions;
    @Autowired private ObjectMapper json;

    private long assetId;
    private long sourceId;
    private long ruleId;
    private int batchSeq;

    @BeforeEach
    void seed() throws Exception {
        for (String table : List.of("event_timeline", "event_alert_link", "event_asset_link", "security_event",
                "detection_alert", "detection_rule", "ingest_record", "ingest_batch", "data_source", "asset_authorization",
                "asset", "sys_user_role", "sys_user")) {
            jdbc.update("DELETE FROM " + table);
        }
        jdbc.update("INSERT INTO sys_user (user_key,username,display_name,status,password_hash) VALUES "
                + "('wr-a','wr-a','wr-a','active',NULL),('wr-b','wr-b','wr-b','active',NULL)");
        jdbc.update("INSERT INTO asset (asset_key,asset_type,environment,criticality,owner,status,labels_json) "
                + "VALUES ('wr-host','host','lab','medium','test','active','{}')");
        assetId = jdbc.queryForObject("SELECT id FROM asset WHERE asset_key='wr-host'", Long.class);
        jdbc.update("INSERT INTO data_source (source_key,source_type,environment,schema_version,scope_json,status) "
                + "VALUES ('wr-source','sensor','lab','v1','{}','active')");
        sourceId = jdbc.queryForObject("SELECT id FROM data_source WHERE source_key='wr-source'", Long.class);
        // 登记仓库内定义的端口扫描规则（30 条 / 60 秒），由不同用户批准为 active。
        JsonNode rule;
        try (InputStream in = getClass().getResourceAsStream("/detection-rules/window-rules-v1.json")) {
            rule = json.readTree(in).get(0);
        }
        assertThat(rule.path("ruleKey").asText()).isEqualTo("tcp-port-scan");
        jdbc.update("INSERT INTO detection_rule (rule_key,version,scope_json,condition_json,severity,status,requested_by,"
                + "approved_by) SELECT ?,?,CAST(? AS JSON),CAST(? AS JSON),?,'active',a.id,b.id FROM sys_user a, sys_user b "
                + "WHERE a.username='wr-a' AND b.username='wr-b'", rule.path("ruleKey").asText(), rule.path("version").asText(),
                rule.path("scope").toString(), rule.path("condition").toString(), rule.path("severity").asText());
        ruleId = jdbc.queryForObject("SELECT id FROM detection_rule", Long.class);
        batchSeq = 0;
    }

    @Test
    void burstAcrossBatchesAlertsOnceAndReplayIsIdempotent() {
        // 第一批 20 条（未达阈值），第二批 15 条：窗口含上一批次记录，在第 30 条上告警一次。
        long first = batch(V4, 0, 20, FAILED_HANDSHAKE);
        assertThat(process(first).alertsCreated()).isZero();
        long second = batch(V4, 20, 15, FAILED_HANDSHAKE);
        assertThat(process(second).alertsCreated()).isEqualTo(1);
        var alert = jdbc.queryForMap("SELECT da.alert_key, da.severity, da.detection_rule_id, r.source_record_key, "
                + "CAST(da.basis_json AS CHAR) basis FROM detection_alert da JOIN ingest_record r ON r.id=da.ingest_record_id");
        assertThat(alert.get("source_record_key")).isEqualTo("rec-29");
        assertThat(alert.get("severity")).isEqualTo("high");
        assertThat(((Number) alert.get("detection_rule_id")).longValue()).isEqualTo(ruleId);
        assertThat((String) alert.get("basis")).contains("\"records\": 30").contains("\"groupBy\": \"asset\"");

        // 重放两个批次：告警键与抑制保证不重复；同一资产事件只有一个。
        assertThat(process(first).alertsCreated()).isZero();
        assertThat(process(second).alertsCreated()).isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM detection_alert", Integer.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM security_event", Integer.class)).isEqualTo(1);

        // 抑制期后的新一轮突发再告警一次（第 200 秒起 40 条）。
        long later = batch(V4, 200, 40, FAILED_HANDSHAKE);
        assertThat(process(later).alertsCreated()).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM detection_alert WHERE alert_type='rule'", Integer.class))
                .isEqualTo(2);
    }

    @Test
    void recordsOfOtherContractsAndNonMatchingFlowsDoNotCount() {
        // 其他契约的批次不计入窗口；握手完整的流不满足过滤条件。
        long legacy = batch("unsw-nb15-flow-v3.1", 0, 25, FAILED_HANDSHAKE);
        process(legacy);
        long benign = batch(V4, 0, 25, FAILED_HANDSHAKE.replace("\"synack\":0", "\"synack\":0.01"));
        long mixed = batch(V4, 25, 25, FAILED_HANDSHAKE);
        assertThat(process(benign).alertsCreated()).isZero();
        assertThat(process(mixed).alertsCreated()).isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM detection_alert", Integer.class)).isZero();
    }

    @Test
    void windowReadsSeeCommittedAlertsEvenAfterRepeatableReadSnapshot() {
        long first = batch(V4, 0, 30, FAILED_HANDSHAKE);
        long second = batch(V4, 30, 5, FAILED_HANDSHAKE);
        transactions.executeWithoutResult(status -> {
            // 消费事务在推理阶段已经建立快照；其他消费者随后提交同资产告警。
            assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM detection_alert", Integer.class)).isZero();
            try (var executor = java.util.concurrent.Executors.newSingleThreadExecutor()) {
                try {
                    assertThat(executor.submit(() -> process(first)).get(10, java.util.concurrent.TimeUnit.SECONDS)
                            .alertsCreated()).isEqualTo(1);
                } catch (Exception exception) { throw new AssertionError(exception); }
            }
            assertThat(detection.processBatch(second, ingestMapper.findAcceptedRecords(second)).alertsCreated()).isZero();
        });
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM detection_alert", Integer.class)).isEqualTo(1);
    }

    private DetectionService.Summary process(long batchId) {
        return transactions.execute(status -> detection.processBatch(batchId, ingestMapper.findAcceptedRecords(batchId)));
    }

    /** 插入一个批次：{@code count} 条记录，第 i 条事件时间为 T0 + (offset + i) 秒，记录键 {@code rec-<offset+i>}。 */
    private long batch(String contract, int offset, int count, String payload) {
        String key = "wr-batch-" + (++batchSeq);
        jdbc.update("INSERT INTO ingest_batch (batch_key,data_source_id,idempotency_key,request_sha256,status,total_count,"
                        + "accepted_count,rejected_count,started_at,feature_contract_version) VALUES (?,?,?,?,'received',?,?,0,?,?)",
                key, sourceId, key, "0".repeat(64), count, count, Timestamp.from(T0), contract);
        long batchId = jdbc.queryForObject("SELECT id FROM ingest_batch WHERE batch_key=?", Long.class, key);
        for (int i = 0; i < count; i++) {
            int second = offset + i;
            jdbc.update("INSERT INTO ingest_record (batch_id,source_record_key,event_type,event_time,asset_id,normalized_payload,"
                            + "quality_status,mapping_version) VALUES (?,?,'network_flow',?,?,CAST(? AS JSON),'accepted','1.0')",
                    batchId, "rec-" + second, Timestamp.from(T0.plusSeconds(second)), assetId, payload);
        }
        return batchId;
    }
}
