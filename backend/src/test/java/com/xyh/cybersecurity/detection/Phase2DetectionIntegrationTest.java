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

import static org.assertj.core.api.Assertions.*;
import com.xyh.cybersecurity.identity.IdentityPrincipal;
import com.xyh.cybersecurity.incident.IncidentService;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.web.servlet.MockMvc;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.*;

/**
 * 时间窗规则的数据库路径（开发路线 §4.2）：窗口上下文从已落库记录读取（跨批次、按契约过滤），
 * 告警抑制读取已有规则告警，重放不产生重复告警；告警照常并入同资产事件。
 */
@org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@EnabledIfEnvironmentVariable(named = "DB_TEST_BASE_URL", matches = ".+")
@org.junit.jupiter.api.extension.ExtendWith(com.xyh.cybersecurity.database.IsolatedDatabaseSchemas.class)
class Phase2DetectionIntegrationTest {
    private static final String TEST_SCHEMA = com.xyh.cybersecurity.database.IsolatedDatabaseSchemas.name(Phase2DetectionIntegrationTest.class, "suite");
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

    @Autowired private DetectionPolicyService policies;
    @Autowired private DetectionRuleService rules;
    @Autowired private IncidentService incidents;
    @Autowired private MockMvc mvc;
    private long assetId, sourceId, modelId, authorId, reviewerId;
    private int sequence;
    private final MockHttpServletRequest request = new MockHttpServletRequest();
    private static final String CONFIG = "{\"model\":[{\"minScore\":0.9,\"severity\":\"critical\"},{\"minScore\":0,\"severity\":\"medium\"}],"
            + "\"modelSignal\":{\"enabled\":true,\"countThreshold\":3,\"highScore\":0.99}}";

    @BeforeEach
    void seed() {
        jdbc.update("DELETE FROM SPRING_SESSION");
        for (String table : List.of("audit_resource_scope", "audit_log", "event_timeline", "event_alert_link", "event_asset_link",
                "security_event", "detection_alert", "detection_rule", "inference_request", "ingest_record", "ingest_batch",
                "model_version", "data_source", "asset", "sys_user_role")) jdbc.update("DELETE FROM " + table);
        for (Long id:jdbc.queryForList("SELECT id FROM detection_policy WHERE created_by IS NOT NULL ORDER BY id DESC",Long.class))
            jdbc.update("DELETE FROM detection_policy WHERE id=?",id);
        jdbc.update("DELETE FROM detection_policy WHERE created_by IS NOT NULL");
        jdbc.update("UPDATE detection_policy SET status='active',retired_by=NULL,retired_at=NULL");
        jdbc.update("DELETE FROM sys_user");
        for (String key : List.of("p2-author", "p2-reviewer")) jdbc.update("INSERT INTO sys_user (user_key,username,display_name,status,password_hash) VALUES (?,?,?,'active','test-hash')",key,key,key);
        authorId=id("sys_user","username","p2-author"); reviewerId=id("sys_user","username","p2-reviewer");
        jdbc.update("INSERT INTO asset (asset_key,asset_type,environment,criticality,owner,status,labels_json) VALUES ('p2-asset','host','lab','medium','test','active','{}')");
        assetId=id("asset","asset_key","p2-asset");
        jdbc.update("INSERT INTO data_source (source_key,source_type,environment,schema_version,scope_json,status) VALUES ('p2-source','sensor','lab','v1','{}','active')");
        sourceId=id("data_source","source_key","p2-source");
        for (String type:List.of("asset","data_source")) jdbc.update("INSERT INTO sys_user_role(user_id,role_id,scope_type,scope_id) SELECT ?,id,?,? FROM sys_role WHERE role_key='security_analyst'",authorId,type,Long.toString(type.equals("asset")?assetId:sourceId));
        jdbc.update("INSERT INTO model_version (model_key,version,task_type,manifest_version,manifest_json,artifact_ref,artifact_sha256,feature_contract_version,approval_status) VALUES ('p2-model','1','binary_flow_classification','1.0','{}','model://test/model.onnx',?,?,'candidate')","0".repeat(64),V4);
        modelId=id("model_version","model_key","p2-model");
        request.setAttribute("requestId","phase2-test"); sequence=0;
    }
    @Test
    void policyLifecycleIsImmutableIndependentAndAudited() throws Exception {
        var p=draft();
        assertThat(p.status()).isEqualTo("draft");
        assertThatThrownBy(()->policies.submit(p.id(),actor(reviewerId),request)).isInstanceOf(org.springframework.security.access.AccessDeniedException.class);
        policies.submit(p.id(),actor(authorId),request);
        assertThatThrownBy(()->policies.decide(p.id(),"approve","自审",actor(authorId),request)).isInstanceOf(org.springframework.security.access.AccessDeniedException.class);
        policies.decide(p.id(),"approve","独立审核",actor(reviewerId),request);
        assertThat(policies.get(p.id()).status()).isEqualTo("active");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM detection_policy WHERE policy_type='severity_mapping' AND status='active'",Integer.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM audit_log WHERE action LIKE 'detection.policy.%' AND after_hash REGEXP '^[0-9a-f]{64}$'",Integer.class)).isEqualTo(4);
        assertThatThrownBy(()->policies.decide(p.id(),"approve","重复审核",actor(reviewerId),request)).isInstanceOf(com.xyh.cybersecurity.common.api.ApiRequestException.class);
        policies.retire(p.id(),"停用",false,actor(reviewerId),request);
        assertThatThrownBy(()->process(batch(0,1,0.8))).isInstanceOf(DetectionUnavailableException.class);
    }
    @Test
    void concurrentPolicyDecisionsOnlyOneSucceeds() throws Exception {
        var p=draft();policies.submit(p.id(),actor(authorId),request);
        try(var pool=java.util.concurrent.Executors.newFixedThreadPool(2)) {
            var start=new java.util.concurrent.CountDownLatch(1);
            java.util.concurrent.Callable<Boolean> decide=()->{
                start.await();
                try {policies.decide(p.id(),"approve","并发独立审批",actor(reviewerId),request);return true;}
                catch(com.xyh.cybersecurity.common.api.ApiRequestException e){return false;}
            };
            var a=pool.submit(decide);var b=pool.submit(decide);start.countDown();
            assertThat(List.of(a.get(10,java.util.concurrent.TimeUnit.SECONDS),b.get(10,java.util.concurrent.TimeUnit.SECONDS)))
                    .containsExactlyInAnyOrder(true,false);
        }
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM audit_log WHERE action='detection.policy.approved'",Integer.class)).isEqualTo(1);
    }

    @Test
    void changedPolicyDoesNotRetroactivelyPromoteOldSignals() throws Exception {
        enable(); assertThat(process(batch(0,1,0.8)).alertsCreated()).isZero();
        var config=json.readTree(CONFIG);
        ((com.fasterxml.jackson.databind.node.ObjectNode)config.path("modelSignal")).put("highScore",0.7);
        long base=jdbc.queryForObject("SELECT id FROM detection_policy WHERE policy_type='severity_mapping' AND status='active'",Long.class);
        var next=policies.create(base,new DetectionPolicyService.Draft(null,config,"新参数"),actor(authorId),request);
        policies.submit(next.id(),actor(authorId),request);policies.decide(next.id(),"approve","新版本",actor(reviewerId),request);
        assertThat(process(batch(1,1,0.8)).alertsCreated()).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM detection_alert WHERE alert_layer='signal'",Integer.class)).isEqualTo(1);
    }

    @Test
    void invalidConfigsAndContentTamperingFailClosed() throws Exception {
        var bad=json.readTree(CONFIG); ((com.fasterxml.jackson.databind.node.ObjectNode)bad).put("script","arbitrary");
        assertThatThrownBy(()->policies.create(null,new DetectionPolicyService.Draft("severity_mapping",bad,"测试"),actor(authorId),request)).isInstanceOf(com.xyh.cybersecurity.common.api.ApiRequestException.class);
        var p=draft();
        jdbc.update("UPDATE detection_policy SET config_json=JSON_SET(config_json,'$.modelSignal.highScore',0.95) WHERE id=?",p.id());
        assertThatThrownBy(()->policies.submit(p.id(),actor(authorId),request)).isInstanceOf(com.xyh.cybersecurity.common.api.ApiRequestException.class).hasMessageContaining("哈希");
        policies.retire(p.id(),"撤回异常草稿",true,actor(authorId),request);
    }
    @Test
    void signalCountAcrossBatchesPromotesOnlyEligibleRecordsAndReplayDoesNotDuplicate() throws Exception {
        enable();
        long first=batch(0,2,0.8);
        assertThat(process(first).alertsCreated()).isZero();
        assertThat(incidents.alerts(authorId,0,20).totalElements()).isZero();
        assertThat(incidents.alerts(authorId,0,20,"signal").totalElements()).isEqualTo(2);
        long next=batch(2,1,0.8);
        assertThat(process(next).alertsCreated()).isEqualTo(1);
        assertThat(incidents.alerts(authorId,0,20).totalElements()).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM security_event",Integer.class)).isEqualTo(1);
        assertThat(process(first).alertsCreated()).isZero(); assertThat(process(next).alertsCreated()).isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM detection_alert",Integer.class)).isEqualTo(3);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM event_alert_link",Integer.class)).isEqualTo(1);
    }
    @Test
    void highScorePromotesAndLateRulePromotesPriorSignalWithoutRewritingOtherPolicy() throws Exception {
        enable();
        assertThat(process(batch(0,1,0.995)).alertsCreated()).isEqualTo(1);
        assertThat(process(batch(2000,1,0.8)).alertsCreated()).isZero();
        var rule=rules.create(new DetectionRuleService.CreateRule("phase2-tcp","1","high",
                json.readTree("{\"all\":[{\"field\":\"features.proto\",\"op\":\"eq\",\"value\":\"tcp\"}]}"),null,"确定规则"),actor(authorId),request);
        rules.decide(rule.id(),"approve","独立审批",actor(reviewerId),request);
        assertThat(process(batch(2001,1,0.1)).alertsCreated()).isEqualTo(2);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM detection_alert WHERE alert_layer='signal'",Integer.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM detection_alert WHERE JSON_EXTRACT(basis_json,'$.promotion.reason')='rule_corroboration'",Integer.class)).isEqualTo(1);
        rules.retire(rule.id(),"结束",actor(reviewerId),request);
        var version=rules.createVersion(rule.id(),new DetectionRuleService.CreateRule(null,"2",null,null,null,"复用"),actor(authorId),request);
        assertThat(version.status()).isEqualTo("pending"); assertThat(version.conditionJson()).isEqualTo(rule.conditionJson());
    }
    @Test
    void outOfOrderCommittedSignalsAreVisibleBeyondRepeatableReadSnapshot() throws Exception {
        enable();
        long late=batch(2,1,0.8), early=batch(0,2,0.8);
        assertThat(process(late).alertsCreated()).isZero();
        transactions.executeWithoutResult(tx->{
            jdbc.queryForObject("SELECT COUNT(*) FROM detection_alert",Integer.class);
            try(var pool=java.util.concurrent.Executors.newSingleThreadExecutor()) {
                assertThat(pool.submit(()->process(early)).get(10,java.util.concurrent.TimeUnit.SECONDS).alertsCreated()).isEqualTo(1);
            }catch(Exception e){throw new AssertionError(e);}
            assertThat(detection.processBatch(late,ingestMapper.findAcceptedRecords(late)).alertsCreated()).isZero();
        });
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM event_alert_link",Integer.class)).isEqualTo(1);
    }
    @Test
    void policyHttpEndpointsRequireAuthorityAndCsrf() throws Exception {
        String hash=new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder(4).encode("phase2-test-password");
        jdbc.update("UPDATE sys_user SET password_hash=?",hash);
        var bootstrap=mvc.perform(get("/api/v1/auth/csrf")).andReturn();
        var cookie=bootstrap.getResponse().getCookie("SESSION");
        String csrfValue=json.readTree(bootstrap.getResponse().getContentAsString()).path("data").path("token").asText();
        var login=mvc.perform(post("/api/v1/auth/login").cookie(cookie).header("X-CSRF-TOKEN",csrfValue)
                .contentType("application/json").content("{\"username\":\"p2-author\",\"password\":\"phase2-test-password\"}"))
                .andExpect(status().isOk()).andReturn();
        cookie=login.getResponse().getCookie("SESSION");
        mvc.perform(get("/api/v1/detection-policies").cookie(cookie)).andExpect(status().isOk());
        mvc.perform(post("/api/v1/detection-policies").cookie(cookie).contentType("application/json").content("{}"))
                .andExpect(status().isForbidden());
        var csrfResult=mvc.perform(get("/api/v1/auth/csrf").cookie(cookie)).andReturn();
        csrfValue=json.readTree(csrfResult.getResponse().getContentAsString()).path("data").path("token").asText();
        var created=mvc.perform(post("/api/v1/detection-policies").cookie(cookie).header("X-CSRF-TOKEN",csrfValue).contentType("application/json")
                .content("{\"policyType\":\"severity_mapping\",\"config\":"+CONFIG+",\"reason\":\"新版本\"}"))
                .andExpect(status().isCreated()).andExpect(jsonPath("$.data.status").value("draft")).andReturn();
        long id=json.readTree(created.getResponse().getContentAsString()).path("data").path("id").asLong();
        mvc.perform(post("/api/v1/detection-policies/{id}/decision",id).cookie(cookie).header("X-CSRF-TOKEN",csrfValue)
                .contentType("application/json").content("{\"decision\":\"approve\",\"reason\":\"越权\"}"))
                .andExpect(status().isForbidden());
    }
    private DetectionPolicyMapper.Row draft() throws Exception { return policies.create(null,new DetectionPolicyService.Draft("severity_mapping",json.readTree(CONFIG),"分层验证"),actor(authorId),request); }
    private void enable() throws Exception {var p=draft();policies.submit(p.id(),actor(authorId),request);policies.decide(p.id(),"approve","独立批准",actor(reviewerId),request);}
    private IdentityPrincipal actor(long id) {return new IdentityPrincipal(id,"u"+id,"u"+id,"u","hash","active",List.of(),List.of());}
    private long id(String table,String field,String value){return jdbc.queryForObject("SELECT id FROM "+table+" WHERE "+field+"=?",Long.class,value);}
    private DetectionService.Summary process(long batch){return transactions.execute(tx->detection.processBatch(batch,ingestMapper.findAcceptedRecords(batch)));}
    private long batch(int offset,int count,double score){
        String key="phase2-"+(++sequence);
        jdbc.update("INSERT INTO ingest_batch (batch_key,data_source_id,idempotency_key,status,total_count,accepted_count,rejected_count,started_at,feature_contract_version) VALUES (?,?,?,'received',?,?,0,?,?)",key,sourceId,key,count,count,Timestamp.from(T0),V4);
        long batch=id("ingest_batch","batch_key",key);
        for(int i=0;i<count;i++){
            jdbc.update("INSERT INTO ingest_record (batch_id,source_record_key,event_type,event_time,asset_id,normalized_payload,quality_status,mapping_version) VALUES (?,?,'network_flow',?,?,?,'accepted','1')",batch,key+"-"+i,Timestamp.from(T0.plusSeconds(offset+i)),assetId,FAILED_HANDSHAKE);
            long record=id("ingest_record","source_record_key",key+"-"+i);
            jdbc.update("INSERT INTO inference_request (request_key,ingest_record_id,model_version_id,contract_version,contract_sha256,deployment_mode,status,attack_probability,binary_label,decision_threshold,threshold_policy_version,requested_at,completed_at) VALUES (?,?,?,?,?,'local','succeeded',?,?,0.5,'fixed:1',?,?)",key+"-"+i,record,modelId,V4,"0".repeat(64),score,score>=0.5?"Attack":"Normal",Timestamp.from(T0),Timestamp.from(T0));
        }
        return batch;
    }
}
