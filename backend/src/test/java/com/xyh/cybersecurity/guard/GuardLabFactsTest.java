package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.*;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

/** 对照既有不可变观察/命令/回执验证关联边界，不以客户端的成功标记代替核验。 */
class GuardLabFactsTest {
    GuardStore store;
    GuardLabMapper mapper;
    GuardLabFacts facts;
    ObjectNode p,o,proof,command;
    JsonNode scenario,mapping;
    Map<String,Object> receipt;
    String observationId,commandId,receiptId;
    Instant at=Instant.parse("2026-10-11T00:00:10Z");
    @BeforeEach void setup() throws Exception {
        store=mock(GuardStore.class);mapper=mock(GuardLabMapper.class);facts=new GuardLabFacts(store,mock(GuardArtifacts.class),mock(GuardSignatures.class),mapper);
        p=(ObjectNode)parse(Files.readString(Path.of("../docs/contracts/examples/lab-session.json")));
        scenario=parse(Files.readString(Path.of("../docs/contracts/examples/lab-scenarios.json"))).at("/scenarios/0");
        mapping=parse(Files.readString(Path.of("../docs/contracts/examples/lab-mapping.json"))).at("/entries/0");
        o=(ObjectNode)parse(Files.readString(Path.of("../docs/contracts/examples/observation.json")));observationId=id();commandId=id();receiptId=id();
        o.put("observationId",observationId).put("environment","lab").put("assetId",text(p,"assetId")).put("sensorId",text(p,"sensorId")).put("bootId",text(p,"bootId"))
                .put("peerKey",text(mapping,"peerKey")).put("captureScopeId",text(mapping,"captureScopeId")).put("targetRef",text(mapping,"targetRef"))
                .put("targetExpiresAt",at.plusSeconds(60).toString()).put("asOf",at.toString());
        when(store.now()).thenReturn(at.plusSeconds(100));updateObservation();
        var target=map("budget_target_id",10L,"scope_digest","fixed-scope","sensor_id",1L,"executor_id",4L,"collector_boot_id",text(p,"bootId"),
                "executor_boot_id",text(p,"executorBootId"),"expires_at",db(at.plusSeconds(60)));
        when(store.external("guard_target_binding",text(mapping,"targetBindingId"),false)).thenReturn(target);
        when(store.one(eq("guard_target_binding"),anyMap(),eq(false))).thenReturn(target);
        proof=object("bundleId",p.get("bundleId"),"bundleSubjectSha256",p.get("subjectSha256"),"environment","lab","family","port_scan","source","model","ruleId",null,
                "triggerObservationId",observationId,"selectedObservations",List.of(object("observationId",observationId,"contentSha256",hash(o))));updateDecision();
        var action=map("public_id",id(),"decision_id",2L,"block_until",db(at.plusSeconds(40)));
        when(store.get("guard_action",6L)).thenReturn(action);
        command=object("executorId",p.get("executorId"),"targetRef",mapping.get("targetRef"),"authorizationId",p.get("authorizationId"),"authorizationRevision",1);
        when(store.get("guard_command",3L)).thenAnswer(i->map("public_id",commandId,"action_id",6L,"executor_boot_id",text(p,"executorBootId"),
                "payload_json",canonical(command),"payload_sha256",hash(command),"issued_at",db(at.plusSeconds(1))));
        receipt=map("command_id",3L,"executor_id",4L,"status","applied","observed_at",db(at.plusSeconds(2)),"state_digest","a".repeat(64),"projected",false,
                "payload_json",canonical(object("errorCode",null)));
        when(store.external("guard_action_receipt",receiptId,false)).thenReturn(receipt);
        when(store.external("guard_executor",text(p,"executorId"),false)).thenReturn(map("id",4L));
    }
    void updateObservation() {when(store.external("guard_observation",observationId,false)).thenAnswer(i->map("public_id",observationId,"as_of",db(at),"payload_json",canonical(o),"content_sha256",hash(o)));}
    void updateDecision() {when(store.get("guard_decision",2L)).thenAnswer(i->map("public_id",id(),"evidence_json",canonical(proof),"evidence_sha256",hash(proof),"decision","block_candidate","reason_code",null,"decided_at",db(at)));}
    JsonNode resolve(String kind,String ref) {return facts.resolve(p,scenario,mapping,object("eventId",id(),"scenarioId",text(scenario,"scenarioId"),"kind",kind,"referenceId",ref));}
    @Test void unprojectedReceiptCannotClaimApplied() {
        var event=resolve("receipt",receiptId);assertThat(event.path("verification").asText()).isEqualTo("unverified");
        assertThatThrownBy(()->resolve("verified_receipt",receiptId)).hasMessageContaining("LAB_RECEIPT_UNVERIFIED");
    }
    @Test void onlyVerifiedReconciliationSuppliesApplicationTime() {
        receipt.put("projected",true);
        when(store.one(eq("guard_reconciliation"),anyMap(),eq(false))).thenReturn(map("public_id",id(),"error_count",0,"observed_at",db(at.plusSeconds(3))));
        assertThat(resolve("verified_receipt",receiptId).path("occurredAt").asText()).isEqualTo(at.plusSeconds(3).toString());
        when(store.one(eq("guard_reconciliation"),anyMap(),eq(false))).thenReturn(map("public_id",id(),"error_count",1,"observed_at",db(at.plusSeconds(3))));
        assertThatThrownBy(()->resolve("verified_receipt",receiptId)).hasMessageContaining("LAB_RECEIPT_UNVERIFIED");
    }
    @Test void wrongBootAssetOrPeerCannotEnterTimeline() {
        for(String field:List.of("bootId","assetId","peerKey")) {
            var saved=o.get(field);o.put(field,"wrong");assertThatThrownBy(()->resolve("observation",observationId)).hasMessageContaining("LAB_FACT_MISMATCH");o.set(field,saved);
        }
    }
    @Test void crossBundleAndWrongSourceCannotReuseExistingDecision() {
        proof.put("bundleId",id());assertThatThrownBy(()->resolve("receipt",receiptId)).hasMessageContaining("LAB_FACT_MISMATCH");
        proof.set("bundleId",p.get("bundleId"));proof.put("source","rule");assertThatThrownBy(()->resolve("receipt",receiptId)).hasMessageContaining("LAB_FACT_MISMATCH");
    }
    @Test void expiredLeaseIsRejected() {
        when(store.one(eq("guard_target_binding"),anyMap(),eq(false))).thenReturn(map("budget_target_id",10L,"scope_digest","fixed-scope","sensor_id",1L,"executor_id",4L,
                "collector_boot_id",text(p,"bootId"),"executor_boot_id",text(p,"executorBootId"),"expires_at",db(at.minusSeconds(1))));
        assertThatThrownBy(()->resolve("observation",observationId)).hasMessageContaining("LAB_LEASE_MISMATCH");
    }
    @Test void futureEventTimeIsRejected() {
        when(store.now()).thenReturn(at.minusSeconds(1));
        assertThatThrownBy(()->resolve("observation",observationId)).hasMessageContaining("LAB_TIME_INVALID");
    }
    JsonNode quality(Instant received) {
        when(mapper.observations(anyMap())).thenReturn(List.of(map("payload_json",canonical(o),"created_at",db(received))));
        return facts.quality(p,scenario,mapping,10L,1L);
    }
    @Test void nullReferenceRemainsCaptureQualityButNeverExecutionEvidence() {
        o.putNull("targetRef").putNull("targetExpiresAt");var q=quality(at.plusSeconds(1));
        assertThat(q.path("snapshots").asInt()).isEqualTo(1);assertThat(q.path("qualified").asInt()).isEqualTo(1);
        assertThat(q.path("executionQualified").asInt()).isZero();assertThat(q.path("missingTargetRef").asInt()).isEqualTo(1);
        assertThat(q.path("nonExecutable").asInt()).isEqualTo(1);
        verify(store,never()).one(eq("guard_target_binding"),anyMap(),eq(false));
    }
    @Test void expiredReferenceIsCountedRatherThanAbortingTheReport() {
        o.put("targetExpiresAt",at.plusSeconds(1).toString());var q=quality(at.plusSeconds(2));
        assertThat(q.path("expiredTargetRef").asInt()).isEqualTo(1);assertThat(q.path("qualified").asInt()).isEqualTo(1);
        assertThat(q.path("executionQualified").asInt()).isZero();
    }
    @Test void freshnessUsesIngestTimeAndKeepsTheTenSecondBoundary() {
        assertThat(quality(at.plusMillis(10000)).path("executionQualified").asInt()).isEqualTo(1);
        var stale=quality(at.plusMillis(10001));assertThat(stale.path("staleEvidence").asInt()).isEqualTo(1);
        assertThat(stale.path("executionQualified").asInt()).isZero();
        when(store.now()).thenReturn(at.plusSeconds(86400));
        assertThat(quality(at.plusSeconds(1)).path("executionQualified").asInt()).isEqualTo(1);
    }
    @Test void missingIngestTimeIsUnknownAndDoesNotUseNowAsAReplacement() {
        var q=quality(null);assertThat(q.path("invalidTiming").asInt()).isEqualTo(1);
        assertThat(q.path("executionQualified").asInt()).isZero();
    }
    @Test void warmupQualityIsSeparateFromTheScoringPopulation() {
        ((ObjectNode)scenario).put("sourceStart","2020-01-01T00:01:00Z");o.putNull("targetRef").putNull("targetExpiresAt");
        var q=quality(at.plusSeconds(1));assertThat(q.path("snapshots").asInt()).isZero();
        assertThat(q.at("/outsideScoringWindow/snapshots").asInt()).isEqualTo(1);
        assertThat(q.at("/outsideScoringWindow/executionQualified").asInt()).isZero();
    }
    @Test void nonNullCrossTargetAndBootRemainHardFailuresEvenForQuality() {
        var foreign=map("budget_target_id",99L,"scope_digest","fixed-scope","sensor_id",1L,"executor_id",4L,
                "collector_boot_id",text(p,"bootId"),"executor_boot_id",text(p,"executorBootId"),"expires_at",db(at.plusSeconds(60)));
        when(store.one(eq("guard_target_binding"),anyMap(),eq(false))).thenReturn(foreign);
        assertThatThrownBy(()->quality(at.plusSeconds(1))).hasMessageContaining("LAB_LEASE_MISMATCH");
        foreign.put("budget_target_id",10L);foreign.put("collector_boot_id",id());
        assertThatThrownBy(()->quality(at.plusSeconds(1))).hasMessageContaining("LAB_LEASE_MISMATCH");
    }
    @Test void warmupObservationIsNotAcceptedAsScoringEvidence() {
        ((ObjectNode)scenario).put("sourceStart","2020-01-01T00:01:00Z");
        assertThatThrownBy(()->resolve("observation",observationId)).hasMessageContaining("LAB_FACT_MISMATCH");
    }
}
