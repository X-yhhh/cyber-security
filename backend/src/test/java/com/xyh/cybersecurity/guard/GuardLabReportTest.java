package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import java.nio.file.*;
import java.util.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;
import static org.assertj.core.api.Assertions.*;

/** 共享合成向量覆盖时长边界、乱序、缺失和双端 JCS；不依赖数据库或真实 PF。 */
class GuardLabReportTest {
    static ObjectNode fixture() throws Exception {return (ObjectNode)parse(Files.readString(Path.of("../docs/contracts/examples/lab-report-input.json")));}
    static ObjectNode live() throws Exception {var n=fixture();((ObjectNode)n.get("session")).put("evidenceKind","lab");n.put("sessionSha256",hash(n.get("session")));return n;}
    @Test void matchesPythonGoldenBytesAndNeverPassesSynthetic() throws Exception {
        var actual=GuardLabReport.generate(fixture());var expected=parse(Files.readString(Path.of("../docs/contracts/examples/lab-report-expected.json")));
        assertThat(canonical(actual)).isEqualTo(canonical(expected));assertThat(actual.path("passed").asBoolean()).isFalse();
        assertThat(actual.path("computedStatus").asText()).isEqualTo("passed");
    }
    @Test void thirtyMinutesConcurrentDoesNotPretendContinuousAndLatencyIsOnlyReport() throws Exception {
        var r=GuardLabReport.generate(live());assertThat(r.path("passed").asBoolean()).isTrue();
        assertThat(r.at("/normal/cumulativeMs").asLong()).isEqualTo(1800000);
        assertThat(r.at("/normal/singleAssetUnionMs").asLong()).isEqualTo(900000);
        assertThat(r.at("/scenarios/0/alertLatencyMs").asLong()).isEqualTo(30000);
    }
    @ParameterizedTest @ValueSource(strings={"command","verified_receipt","scenario_result"})
    void missingFactsDoNotBecomeSuccess(String kind) throws Exception {
        var n=live();var events=(ArrayNode)n.get("events");var keep=JSON.createArrayNode();
        for(var e:events)if(!kind.equals(e.path("kind").asText()))keep.add(e);
        n.set("events",keep);
        // 缺签发事件但有实际回执仍可证明 OS 发生过动作；时间线必须保留 issuedAt=null。
        var r=GuardLabReport.generate(n);
        if(kind.equals("command"))assertThat(r.at("/scenarios/0/commands/0/issuedAt").isNull()).isTrue();
        else assertThat(r.path("passed").asBoolean()).isFalse();
    }
    @Test void expiryWithoutApplicationProofIsUnverified() throws Exception {
        var n=live();var keep=JSON.createArrayNode();for(var e:n.path("events"))if(!"applied".equals(e.path("status").asText()))keep.add(e);n.set("events",keep);
        assertThat(GuardLabReport.generate(n).path("status").asText()).isEqualTo("unverified");
    }
    @Test void unlinkedCommandAndUnknownQualityBlockACompleteReport() throws Exception {
        var n=live();((ArrayNode)n.get("unlinkedCommandIds")).add(id());assertThat(GuardLabReport.generate(n).path("passed").asBoolean()).isFalse();
        n=live();((ObjectNode)n.at("/scenarios/0/quality")).put("snapshots",0).put("qualified",0).put("executionQualified",0);
        assertThat(GuardLabReport.generate(n).path("passed").asBoolean()).isFalse();
    }
    @Test void falseBlockIsDeduplicatedAndHalfHourRateIsTwo() throws Exception {
        var n=live();String cid=id(),sid=n.at("/scenarios/4/scenarioId").asText();var events=(ArrayNode)n.get("events");
        var applied=object("scenarioId",sid,"commandId",cid,"kind","verified_receipt","verification","verified","status","applied","occurredAt","2026-10-11T00:00:10Z");
        events.add(applied);events.add(applied.deepCopy());events.add(object("scenarioId",sid,"commandId",cid,"kind","verified_receipt","verification","verified","status","expired","occurredAt","2026-10-11T00:00:20Z"));
        var report=GuardLabReport.generate(n);assertThat(report.at("/normal/verifiedFalseBlocks").asInt()).isEqualTo(1);
        assertThat(report.at("/normal/perHour").asDouble()).isEqualTo(2);assertThat(report.path("passed").asBoolean()).isFalse();
    }
    @Test void outOfOrderDoesNotInventOrReverseTimes() throws Exception {
        var n=live();var all=new ArrayList<JsonNode>();n.path("events").forEach(all::add);Collections.reverse(all);n.set("events",node(all));
        var r=GuardLabReport.generate(n);assertThat(r.path("passed").asBoolean()).isTrue();assertThat(r.at("/scenarios/0/firstAppliedAt").asText()).endsWith("00:00:32Z");
    }
    @Test void manualCleanupDoesNotProveNormalTtlRecovery() throws Exception {
        var n=live();for(int i:List.of(4,5))((ObjectNode)n.at("/scenarios/"+i)).put("sourceEnd","2020-01-01T00:30:00Z");
        String sid=n.at("/scenarios/4/scenarioId").asText(),cid=id();var events=(ArrayNode)n.get("events");
        events.add(object("scenarioId",sid,"commandId",cid,"kind","command","occurredAt","2026-10-11T00:00:01Z"));
        events.add(object("scenarioId",sid,"commandId",cid,"kind","verified_receipt","verification","verified","status","applied","occurredAt","2026-10-11T00:00:02Z"));
        events.add(object("scenarioId",sid,"commandId",cid,"kind","verified_receipt","verification","verified","status","revoked","occurredAt","2026-10-11T00:00:03Z"));
        var r=GuardLabReport.generate(n);assertThat(r.at("/normal/perHour").asDouble()).isEqualTo(1);
        assertThat(r.at("/normal/falseBlocksTtlRestored").asBoolean()).isFalse();assertThat(r.path("passed").asBoolean()).isFalse();
    }
    @Test void wrongSessionDigestIsRejected() throws Exception {
        var n=live();n.put("sessionSha256","f".repeat(64));assertThatThrownBy(()->GuardLabReport.generate(n)).hasMessageContaining("LAB_REPORT_MISMATCH");
    }
    /** 第 9 节：逐类结果、全链路五个时刻与未验证项；缺类、未结束运行和合成证据都进入未验证项。 */
    @Test void perClassResultsTimelineAndUnverifiedItems() throws Exception {
        assertThat(GuardLabReport.generate(live()).path("unverifiedItems").size()).isZero();
        var n=live();var kept=JSON.createArrayNode();for(int i=1;i<n.path("scenarios").size();i++)kept.add(n.path("scenarios").get(i));n.set("scenarios",kept);
        var r=GuardLabReport.generate(n);
        var families=new ArrayList<String>();for(var c:r.path("classes"))families.add(c.path("family").asText());
        assertThat(families).containsExactly("brute_force","dos_flood","dos_slow","port_scan");
        assertThat(r.at("/classes/3/status").asText()).isEqualTo("not_evaluated");assertThat(r.at("/classes/3/scenarioIds").size()).isZero();
        assertThat(r.at("/classes/0/firstApplicationLatencyMs").asLong()).isEqualTo(32000);
        assertThat(r.path("unverifiedItems").toString()).contains("class:port_scan:no_scenario");
        var row=r.at("/scenarios/0");
        assertThat(List.of(row.path("labStart").asText(),row.path("firstAlertAt").asText(),row.path("firstIssuedAt").asText(),row.path("firstAppliedAt").asText(),row.path("lastClearedAt").asText()))
                .containsExactly("2026-10-11T00:00:00Z","2026-10-11T00:00:30Z","2026-10-11T00:00:31Z","2026-10-11T00:00:32Z","2026-10-11T00:01:02Z");
        assertThat(row.path("issueLatencyMs").asLong()).isEqualTo(31000);assertThat(row.path("cleanupLatencyMs").asLong()).isEqualTo(62000);
        var interrupted=live();interrupted.put("runStatus","interrupted");
        assertThat(GuardLabReport.generate(interrupted).path("unverifiedItems").toString()).contains("run:interrupted");
        assertThat(GuardLabReport.generate(fixture()).path("unverifiedItems").toString()).contains("evidence:synthetic");
    }
    @Test void contractRejectsClockRewriteAndMappingReuse() throws Exception {
        var n=fixture();var p=(ObjectNode)n.get("session");((ObjectNode)p.get("time")).put("offsetMicros",1);
        assertThatThrownBy(()->GuardLabContract.manifest(p)).hasMessageContaining("LAB_OFFSET_INVALID");
        var valid=fixture().get("session");var scenarios=parse(Files.readString(Path.of("../docs/contracts/examples/lab-scenarios.json")));
        var mappings=parse(Files.readString(Path.of("../docs/contracts/examples/lab-mapping.json")));
        GuardLabContract.manifest(valid);GuardLabContract.scenarios(valid,scenarios);GuardLabContract.mapping(valid,scenarios,mappings);
        ((ObjectNode)mappings.at("/entries/1")).set("targetRef",mappings.at("/entries/0/targetRef"));
        assertThatThrownBy(()->GuardLabContract.mapping(valid,scenarios,mappings)).hasMessageContaining("LAB_MAPPING_MISMATCH");
    }
    @Test void captureQualityCannotReplaceUsableExecutionEvidence() throws Exception {
        var n=live();((ObjectNode)n.at("/scenarios/0/quality")).put("executionQualified",0).put("missingTargetRef",10).put("nonExecutable",10);
        var r=GuardLabReport.generate(n);assertThat(r.at("/scenarios/0/qualifiedCoverage").asDouble()).isEqualTo(1.0);
        assertThat(r.at("/scenarios/0/executionQualifiedCoverage").asDouble()).isZero();assertThat(r.path("passed").asBoolean()).isFalse();
    }
    @Test void onlyKnownOutsideScoringDecisionsCanLeaveTheRequiredPopulation() throws Exception {
        var n=fixture();var scenarios=object("scenarios",n.get("scenarios"));
        var mapping=parse(Files.readString(Path.of("../docs/contracts/examples/lab-mapping.json")));
        var row=map("as_of",db(java.time.Instant.parse("2026-10-10T23:59:59Z")),"peer_key",mapping.at("/entries/0/peerKey").asText(),"key_epoch",1L);
        assertThat(GuardLabSessions.outsideScoring(n.get("session"),scenarios,mapping,row)).isTrue();
        row.put("peer_key","unknown");assertThat(GuardLabSessions.outsideScoring(n.get("session"),scenarios,mapping,row)).isFalse();
        row.put("as_of",null);assertThat(GuardLabSessions.outsideScoring(n.get("session"),scenarios,mapping,row)).isFalse();
        row.put("peer_key",mapping.at("/entries/0/peerKey").asText());row.put("as_of",db(java.time.Instant.parse("2026-10-11T00:00:10Z")));
        ((ObjectNode)scenarios.at("/scenarios/0")).put("sourceStart","2020-01-01T00:01:00Z");
        var second=(ObjectNode)mapping.at("/entries/0").deepCopy();second.put("scenarioId",scenarios.at("/scenarios/1/scenarioId").asText());
        ((ArrayNode)mapping.get("entries")).insert(1,second);
        assertThat(GuardLabSessions.outsideScoring(n.get("session"),scenarios,mapping,row)).isFalse();
    }
}
