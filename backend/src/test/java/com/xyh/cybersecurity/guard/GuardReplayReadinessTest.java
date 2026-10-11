package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;
import java.time.Instant;
import java.util.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;
import static org.assertj.core.api.Assertions.*;

/** 研究旁路不可改变冻结策略，不能用 final、重复 parent、坏质量或过期证据凑数。 */
class GuardReplayReadinessTest {
    private final Instant now=Instant.parse("2026-10-10T00:00:10Z");
    JsonNode policy(){return object("profile","flow-prefix-v1","maxEvidenceAgeMs",10000,"minEvidenceSpanMs",500,
            "contextWindowSeconds",1,"minPeerFlowStarts",2,"familyPolicies",List.of(object("family","dos_slow",
            "alertThreshold",0.9,"autoThreshold",0.95,"minDistinctFlows",2,"autoEligible",false,"modelAutoEligible",false)),"rulePolicies",List.of());}
    JsonNode closeout(){return object("completed",true,"gates",object("G1",true,"G2",true),"classEligibility",
            object("dos_slow",object("offlineEligible",true,"modelOnly",object("offlineEligible",true))));}
    JsonNode manifest(){return object("profiles",List.of("flow-prefix-v1"),"supportedScope",List.of(object(
            "addressFamily","ipv4","transport","tcp","direction","inbound","coverageWindowSeconds",1,"minimumCoverageMs",1000)));}
    GuardDecisionEngine.Evidence evidence(String parent,int ago,String profile){var o=object("observationId",id(),
            "parentConnectionId",parent,"asOf",now.minusSeconds(ago).toString(),"profile",profile,"addressFamily","ipv4",
            "transport","tcp","direction","inbound","quality",object("clockSkewMs",0),
            "contexts",List.of(object("windowSeconds",1,"coverageMs",1000,"peerFlowStarts",2)));
        return new GuardDecisionEngine.Evidence(o,0.99,"dos_slow","model","",false,hash(o));}
    @Test void frozenSwitchesAndParametersRemainUnchanged(){var p=policy();var before=p.deepCopy();var projection=GuardReplayReadiness.policy(p,closeout());
        assertThat(p).isEqualTo(before);assertThat(projection.at("/familyPolicies/0/modelAutoEligible").asBoolean()).isTrue();
        assertThat(projection.at("/familyPolicies/0/autoThreshold")).isEqualTo(p.at("/familyPolicies/0/autoThreshold"));
        var outcome=GuardReplayReadiness.evaluate(projection,manifest(),List.of(evidence("a",1,"flow-prefix-v1"),evidence("b",2,"flow-prefix-v1")),now,"dos_slow","model","");
        assertThat(outcome.decision()).isEqualTo("block_candidate");assertThat(GuardReplayReadiness.proof(outcome).path("actionable").asBoolean()).isFalse();}
    @Test void finalReplacementRejectsWholeGroup(){var p=GuardReplayReadiness.policy(policy(),closeout());
        var outcome=GuardReplayReadiness.evaluate(p,manifest(),List.of(evidence("a",1,"flow-prefix-v1"),evidence("b",2,"flow-final-v1")),now,"dos_slow","model","");
        assertThat(outcome.reason()).isEqualTo("CAPABILITY_NOT_SUPPORTED");assertThat(outcome.decision()).isEqualTo("alert");}
    /** acceptedProfiles 显式列出两种快照时，prefix/final 混组按同一门槛计数；未列出的 profile 仍整组拒绝。 */
    @Test void acceptedProfilesAdmitFinalSnapshots(){var base=policy();((com.fasterxml.jackson.databind.node.ObjectNode)base).set("acceptedProfiles",node(List.of("flow-prefix-v1","flow-final-v1")));
        var p=GuardReplayReadiness.policy(base,closeout());var both=object("profiles",List.of("flow-prefix-v1","flow-final-v1"),"supportedScope",manifest().get("supportedScope"));
        var mixed=List.of(evidence("a",1,"flow-prefix-v1"),evidence("b",2,"flow-final-v1"));
        assertThat(GuardReplayReadiness.evaluate(p,both,mixed,now,"dos_slow","model","").decision()).isEqualTo("block_candidate");
        assertThat(GuardEligibility.profileAccepted(policy(),evidence("b",2,"flow-final-v1").observation())).isFalse();
        assertThat(GuardEligibility.profileAccepted(base,evidence("b",2,"flow-final-v1").observation())).isTrue();}
    @Test void sameParentAndExpiredEvidenceCannotMeetCount(){var p=GuardReplayReadiness.policy(policy(),closeout());
        for(var group:List.of(List.of(evidence("a",1,"flow-prefix-v1"),evidence("a",2,"flow-prefix-v1")),
                List.of(evidence("a",1,"flow-prefix-v1"),evidence("b",11,"flow-prefix-v1"))))
            assertThat(GuardReplayReadiness.evaluate(p,manifest(),group,now,"dos_slow","model","").reason()).isEqualTo("EVIDENCE_INSUFFICIENT");}
    @Test void defectiveSnapshotCannotBeCounted(){var p=GuardReplayReadiness.policy(policy(),closeout());var e=evidence("a",1,"flow-prefix-v1");
        ((com.fasterxml.jackson.databind.node.ObjectNode)e.observation().path("quality")).put("offloadSuspected",true);
        assertThat(GuardReplayReadiness.evaluate(p,manifest(),List.of(e,evidence("b",2,"flow-prefix-v1")),now,"dos_slow","model","").reason()).isEqualTo("QUALITY_UNSUPPORTED");}
    @Test void ruleHitRetainsAlertButFailedModelCannotProduceCandidate(){var p=GuardReplayReadiness.policy(policy(),closeout());
        ((com.fasterxml.jackson.databind.node.ObjectNode)p).set("rulePolicies",node(List.of(object("ruleId","slow","family","dos_slow","autoEligible",true))));
        var o=evidence("a",1,"flow-prefix-v1").observation();
        var hit=new GuardDecisionEngine.Evidence(o,null,"dos_slow","rule","slow",true,hash(o));
        var outcome=GuardReplayReadiness.evaluate(p,manifest(),List.of(hit),now,"dos_slow","rule","slow",false);
        assertThat(outcome.decision()).isEqualTo("alert");assertThat(outcome.reason()).isEqualTo("CAPABILITY_NOT_SUPPORTED");}
}
