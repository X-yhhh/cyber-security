package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import java.time.Instant;
import java.util.*;
import java.util.function.Function;
import static com.xyh.cybersecurity.guard.GuardJson.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

/** 文件回放只证明回放完整性，不能提供现场健康或预算恢复证明。 */
class GuardHealthTest {
    final Instant now=Instant.parse("2026-10-12T00:00:00Z");
    static ObjectNode replay(Instant end,long sequence,String previous){
        var b=GuardDomainTest.health(end,sequence,previous);
        b.put("healthVersion",HEALTH_REPLAY).put("captureSource","file_replay");
        ((ObjectNode)b.get("counterStart")).putNull("kernelDrops");
        ((ObjectNode)b.get("counterEnd")).putNull("kernelDrops");return b;
    }
    @Test void replayAcceptsOnlyKnownMonotonicPacketsAndUnchangedCapacity(){
        var b=replay(now,1,null);GuardHealth.windowFields(b);
        assertThat(GuardHealth.verify(b,null,null,now)).isEqualTo("replay_healthy");
        for(String endpoint:List.of("counterStart","counterEnd")){
            var invalid=b.deepCopy();((ObjectNode)invalid.get(endpoint)).put("kernelDrops",0);
            assertThat(GuardHealth.verify(invalid,null,null,now)).isEqualTo("REPLAY_KERNEL_DROPS_INVALID");
        }
        ((ObjectNode)b.get("counterEnd")).put("capacityDrops",1);
        assertThat(GuardHealth.verify(b,null,null,now)).isEqualTo("CAPTURE_DROPS");
        ((ObjectNode)b.get("counterEnd")).put("capacityDrops",0);
        ((ObjectNode)b.get("counterStart")).put("packetsSeen",1);
        assertThat(GuardHealth.verify(b,null,null,now)).isEqualTo("CAPTURE_DROPS");
        ((ObjectNode)b.get("counterStart")).putNull("packetsSeen");
        assertThat(GuardHealth.verify(b,null,null,now)).isEqualTo("COUNTER_UNKNOWN");
    }
    @Test void versionRequiresExplicitSourceAndRejectsOldVersionExtension(){
        var missing=replay(now,1,null);missing.remove("captureSource");
        assertThatThrownBy(()->GuardHealth.windowFields(missing)).hasMessageContaining("MISSING_FIELD");
        var invalid=replay(now,1,null).put("captureSource","unknown");
        assertThatThrownBy(()->GuardHealth.windowFields(invalid)).hasMessageContaining("CAPTURE_SOURCE_INVALID");
        var old=replay(now,1,null).put("healthVersion",HEALTH);
        assertThatThrownBy(()->GuardHealth.windowFields(old)).hasMessageContaining("UNKNOWN_FIELD");
    }
    @Test void replayRetainsGapClockDelayAndIdentityChecks(){
        var b=replay(now,1,null).put("captureGap",true);
        assertThat(GuardHealth.verify(b,null,null,now)).isEqualTo("CAPTURE_GAP");
        b.put("captureGap",false).put("clockSkewMs",1001);
        assertThat(GuardHealth.verify(b,null,null,now)).isEqualTo("CLOCK_UNTRUSTED");
        b.put("clockSkewMs",1000);
        assertThat(GuardHealth.verify(b,null,null,now.plusSeconds(10))).isEqualTo("replay_healthy");
        assertThat(GuardHealth.verify(b,null,null,now.plusMillis(10001))).isEqualTo("HEALTH_DELAY_EXCEEDED");
        var next=next(b);assertThat(GuardHealth.verify(next,b,hash(b),now.plusSeconds(5))).isEqualTo("replay_healthy");
        next.put("sensorId",id());assertThat(GuardHealth.verify(next,b,hash(b),now.plusSeconds(5))).isEqualTo("HEALTH_IDENTITY_CHANGED");
        next=next(b);((ObjectNode)next.get("counterStart")).put("packetsSeen",1);
        ((ObjectNode)next.get("counterEnd")).put("packetsSeen",1);
        assertThat(GuardHealth.verify(next,b,hash(b),now.plusSeconds(5))).isEqualTo("HEALTH_CHAIN_INCOMPLETE");
    }
    ObjectNode next(ObjectNode previous){
        var b=previous.deepCopy();b.put("healthWindowId",id()).put("sequence",previous.path("sequence").asLong()+1)
                .put("previousSha256",hash(previous)).put("intervalStart",previous.path("intervalEnd").asText())
                .put("intervalEnd",time(previous,"intervalEnd").plusSeconds(5).toString());return b;
    }
    @Test void liveV11HasTheSameCounterSemanticsAsV10(){
        var old=GuardDomainTest.health(now,1,null);var live=old.deepCopy().put("healthVersion",HEALTH_REPLAY).put("captureSource","live");
        GuardHealth.windowFields(old);GuardHealth.windowFields(live);
        for(String variant:List.of("healthy","unknown","drops","gap","clock")){
            var a=old.deepCopy();var b=live.deepCopy();
            for(var w:List.of(a,b))switch(variant){
                case "unknown"->((ObjectNode)w.get("counterEnd")).putNull("kernelDrops");
                case "drops"->((ObjectNode)w.get("counterEnd")).put("kernelDrops",1);
                case "gap"->w.put("captureGap",true);case "clock"->w.putNull("clockSkewMs");
            }
            assertThat(GuardHealth.verify(b,null,null,now)).isEqualTo(GuardHealth.verify(a,null,null,now));
        }
    }
    @Test void replayCurrentRequiresOptInAndExpiresAtTheSameBoundary(){
        var store=mock(GuardStore.class);var health=new GuardHealth(store,mock(GuardAccess.class));
        var row=map("verification_status","replay_healthy","interval_end",db(now));
        when(store.one(eq("guard_capture_health_window"),anyMap(),eq(false))).thenReturn(row);
        assertThat(health.current(1,now)).isFalse();assertThat(health.current(1,now,true)).isTrue();
        assertThat(health.current(1,now.plusSeconds(10),true)).isTrue();
        assertThat(health.current(1,now.plusMillis(10001),true)).isFalse();
        assertThat(health.current(1,now.minusMillis(1),true)).isFalse();
    }
    @Test void replayBreaksBudgetProofEvenBetweenHealthyWindows(){
        var store=mock(GuardStore.class);var health=new GuardHealth(store,mock(GuardAccess.class));
        var first=GuardDomainTest.health(now,1,null);var replay=next(first).put("healthVersion",HEALTH_REPLAY).put("captureSource","file_replay");
        var last=next(replay).put("healthVersion",HEALTH);last.remove("captureSource");
        var rows=List.of(row(last,"healthy"),row(replay,"replay_healthy"),row(first,"healthy"));
        when(store.rows(eq("guard_capture_health_window"),anyMap(),eq(false),eq(10000))).thenReturn(rows);
        assertThatThrownBy(()->health.proof(1,now.minusSeconds(5),now.plusSeconds(10),now.plusSeconds(10)))
                .hasMessageContaining("HEALTH_CHAIN_INCOMPLETE");
    }
    Map<String,Object> row(JsonNode b,String status){return map("public_id",b.path("healthWindowId").asText(),"content_sha256",hash(b),"payload_json",canonical(b),"verification_status",status);}
    @Test void machineHealthIngestDoesNotTriggerRecoveryForReplay(){
        var access=mock(GuardAccess.class);var idem=mock(GuardIdempotency.class);var health=mock(GuardHealth.class);
        var budget=mock(GuardBudget.class);var store=mock(GuardStore.class);String sensor=id();
        when(access.sensor(sensor,"machine.sensor.health")).thenReturn(map("asset_id",1L));
        when(idem.executeWithDigest(anyString(),anyString(),any(),eq(200),eq(false),any()))
                .thenAnswer(invocation->invocation.<Function<String,JsonNode>>getArgument(5).apply("a".repeat(64)));
        when(health.accept(eq(sensor),any())).thenReturn(object("verificationStatus","replay_healthy"));
        var controller=new GuardMachineController(access,idem,null,health,budget,null,null,store,null,null);
        var request=new MockHttpServletRequest("POST","/api/v2/machine/sensors/"+sensor+"/health-windows");
        controller.write("sensors",sensor,"health-windows",id(),canonical(replay(now,1,null)),request);
        verifyNoInteractions(budget);verify(store,never()).rows(eq("guard_budget_target"),anyMap(),anyBoolean(),anyInt());
        when(health.accept(eq(sensor),any())).thenReturn(object("verificationStatus","healthy"));
        when(store.rows(eq("guard_budget_target"),anyMap(),eq(false),eq(10000))).thenReturn(List.of(map("id",2L)));
        when(store.now()).thenReturn(now);
        controller.write("sensors",sensor,"health-windows",id(),canonical(GuardDomainTest.health(now,1,null)),request);
        verify(budget).recover(1,2,now);
    }
}
