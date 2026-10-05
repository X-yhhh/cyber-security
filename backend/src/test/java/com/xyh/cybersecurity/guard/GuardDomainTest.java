package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;
import static org.assertj.core.api.Assertions.*;

class GuardDomainTest {
    static JsonNode example(String name)throws Exception{return parse(Files.readString(Path.of("../docs/contracts/examples/"+name+".json")));}
    static ObjectNode observation(Instant now)throws Exception{
        ObjectNode o=(ObjectNode)example("observation");o.put("firstSeenAt",now.minusSeconds(5).toString());o.put("asOf",now.toString());o.put("lastPacketAt",now.minusMillis(1).toString());o.put("emittedAt",now.toString());((ObjectNode)o.get("features")).put("elapsedMs",5000);
        for(var c:o.get("contexts")){((ObjectNode)c).put("coverageMs",Math.min(5000,c.get("windowSeconds").asLong()*1000));((ObjectNode)c).put("peerFlowStarts",3);}
        return o;
    }
    @Test void canonicalizationUsesRfc8785NumbersAndRejectsDuplicateProperties(){assertThat(canonical(parse("{\"z\":-0.0,\"b\":1e30,\"a\":1e-7}"))).isEqualTo("{\"a\":1e-7,\"b\":1e+30,\"z\":0}");assertThatThrownBy(()->parse("{\"a\":1,\"a\":2}")).isInstanceOf(com.xyh.cybersecurity.common.api.ApiRequestException.class);}
    @Test void schemaPlusCausalInvariantsRejectUnknownFutureOrWrongProfileData()throws Exception{
        var c=new GuardContracts();ObjectNode o=observation(Instant.parse("2026-10-05T00:00:00Z"));c.observation(o);
        o.put("healthy",true);assertThatThrownBy(()->c.observation(o)).hasMessageContaining("CONTRACT_INVALID");o.remove("healthy");
        o.put("lastPacketAt",time(o,"asOf").plusSeconds(1).toString());assertThatThrownBy(()->c.observation(o)).hasMessageContaining("INVALID_OBSERVATION_TIME");
        ObjectNode bad=observation(Instant.parse("2026-10-05T00:00:00Z"));((ObjectNode)bad.get("features")).put("elapsedMs",5001);assertThatThrownBy(()->c.observation(bad)).hasMessageContaining("INVALID_ELAPSED_TIME");
    }
    @Test void refusalOrderIsFixedAndNeverUsesExpiredHighScores()throws Exception{
        Instant now=Instant.parse("2026-10-05T00:00:00Z");ObjectNode o=observation(now);JsonNode policy=example("decision-policy");var es=List.of(new GuardDecisionEngine.Evidence(o,1d,"a".repeat(64)));
        assertThat(GuardDecisionEngine.evaluate(policy,es,now,new GuardDecisionEngine.Gates(false,false,false,false,"blocked")).reason()).isEqualTo("CAPABILITY_NOT_SUPPORTED");
        ((ObjectNode)o.get("quality")).put("captureGap",true);assertThat(GuardDecisionEngine.evaluate(policy,es,now,new GuardDecisionEngine.Gates(true,true,false,false,"blocked")).reason()).isEqualTo("QUALITY_UNSUPPORTED");
        ((ObjectNode)o.get("quality")).put("captureGap",false).putNull("clockSkewMs");assertThat(GuardDecisionEngine.evaluate(policy,es,now,new GuardDecisionEngine.Gates(true,true,false,false,"blocked")).reason()).isEqualTo("CLOCK_UNTRUSTED");
        ((ObjectNode)o.get("quality")).put("clockSkewMs",0);assertThat(GuardDecisionEngine.evaluate(policy,es,now.plusSeconds(11),new GuardDecisionEngine.Gates(true,true,true,true,null)).reason()).isEqualTo("EVIDENCE_STALE");
        assertThat(GuardDecisionEngine.evaluate(policy,es,now.minusSeconds(1),new GuardDecisionEngine.Gates(true,true,true,true,null)).reason()).isEqualTo("EVIDENCE_STALE");
        assertThat(GuardDecisionEngine.evaluate(policy,es,now,new GuardDecisionEngine.Gates(true,true,true,true,null)).reason()).isEqualTo("EVIDENCE_INSUFFICIENT");
    }
    @Test void singleParentHasZeroSpanAndBudgetRejectionStillQualifiesEvidence()throws Exception{
        Instant now=Instant.parse("2026-10-05T00:00:00Z");var o=observation(now);ObjectNode p=(ObjectNode)example("decision-policy");p.put("minDistinctFlows",1).put("minEvidenceSpanMs",0);
        var result=GuardDecisionEngine.evaluate(p,List.of(new GuardDecisionEngine.Evidence(o,1d,"a".repeat(64))),now,new GuardDecisionEngine.Gates(true,true,true,true,"TARGET_CONTINUOUS_BUDGET"));assertThat(result.reason()).isEqualTo("PROTECTION_OR_BUDGET_BLOCKED");assertThat(result.qualifiedEvidence()).isTrue();
        p.put("minEvidenceSpanMs",1);assertThat(GuardDecisionEngine.evaluate(p,List.of(new GuardDecisionEngine.Evidence(o,1d,"a".repeat(64))),now,new GuardDecisionEngine.Gates(true,true,true,true,null)).reason()).isEqualTo("EVIDENCE_INSUFFICIENT");
    }
    @Test void intervalUnionDoesNotChargeRetriesTwice(){Instant t=Instant.EPOCH;assertThat(GuardBudget.unionMillis(List.of(new GuardBudget.Interval(t,t.plusSeconds(30)),new GuardBudget.Interval(t,t.plusSeconds(30)),new GuardBudget.Interval(t.plusSeconds(20),t.plusSeconds(50)),new GuardBudget.Interval(t.plusSeconds(60),t.plusSeconds(80))))).isEqualTo(70000);}
    static ObjectNode health(Instant end,long sequence,String previous){return object("healthVersion",HEALTH,"healthWindowId",id(),"assetId",id(),"sensorId",id(),"captureScopeId",id(),"observerSessionId",id(),"sequence",sequence,"intervalStart",end.minusSeconds(5).toString(),"intervalEnd",end.toString(),"previousSha256",previous,"counterStart",object("packetsSeen",0,"kernelDrops",0,"capacityDrops",0),"counterEnd",object("packetsSeen",0,"kernelDrops",0,"capacityDrops",0),"captureGap",false,"clockSkewMs",0,"configSha256","a".repeat(64),"buildSha256","b".repeat(64));}
    @Test void unknownDropsDelayedWindowsAndHashGapsNeverProveHealth(){Instant now=Instant.parse("2026-10-05T00:00:00Z");var b=health(now,1,null);assertThat(GuardHealth.verify(b,null,null,now)).isEqualTo("healthy");((ObjectNode)b.get("counterEnd")).putNull("kernelDrops");assertThat(GuardHealth.verify(b,null,null,now)).isEqualTo("COUNTER_UNKNOWN");((ObjectNode)b.get("counterEnd")).put("kernelDrops",0);assertThat(GuardHealth.verify(b,null,null,now.plusMillis(10001))).isEqualTo("HEALTH_DELAY_EXCEEDED");b.put("sequence",2);assertThat(GuardHealth.verify(b,null,null,now)).isEqualTo("HEALTH_CHAIN_INCOMPLETE");}
    @Test void missingMaskPreservesObservedZeroAndCategoryUnknown()throws Exception{
        var m=example("model-manifest");var o=observation(Instant.parse("2026-10-05T00:00:00Z"));((ObjectNode)o.get("features")).putNull("iatMeanUs");var pre=object("vocabularies",List.of(List.of("tcp"),List.of("inbound"),List.of("web")));var t=GuardModelRuntime.tensors(o,m,pre);assertThat(t.values()).hasSize(43);assertThat(t.missing()[9]).isEqualTo(1);assertThat(t.values()[9]).isZero();assertThat(t.missing()[14]).isZero();assertThat(t.codes()).containsExactly(1,0,1);}
}
