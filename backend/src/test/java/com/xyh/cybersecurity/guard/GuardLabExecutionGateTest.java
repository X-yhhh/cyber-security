package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.*;
import java.time.Instant;
import java.util.Map;
import static com.xyh.cybersecurity.guard.GuardJson.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

/** 真实 lab 资格仍需现有 T1—T9；本测试只核对新增会话门，不执行动作。 */
class GuardLabExecutionGateTest {
    GuardStore store;GuardLabMapper mapper;GuardLabExecutionGate gate;
    ObjectNode observation,manifest;Map<String,Object> session,run,auth,bundle;
    Instant now=Instant.parse("2030-01-01T00:00:00Z");
    @BeforeEach void fixture() {
        store=mock(GuardStore.class);mapper=mock(GuardLabMapper.class);gate=new GuardLabExecutionGate(store,mapper);
        String sensor=id(),boot=id(),target=id(),initial=id(),capture=id();
        observation=object("environment","lab","sensorId",sensor,"bootId",boot,"targetRef",target,"peerKey","a".repeat(64),"keyEpoch",1,"captureScopeId",capture);
        manifest=object("evidenceKind","lab","validFrom",now.minusSeconds(1).toString(),"validUntil",now.plusSeconds(100).toString(),"timeoutSeconds",60,"authorizationRevision",1);
        session=map("status","active","asset_id",10L,"bundle_id",20L,"authorization_id",30L);bundle=map("id",20L);
        run=map("status","running","manifest_jcs",canonical(manifest),"last_activity_at",db(now),"mapping_jcs",canonical(object("entries",java.util.List.of(object("targetBindingId",initial,"peerKey","a".repeat(64),"keyEpoch",1,"captureScopeId",capture)))));
        auth=map("status","active","revision",1L,"valid_from",db(now.minusSeconds(1)),"valid_until",db(now.plusSeconds(100)));
        when(store.external("sensor_agent",sensor,false)).thenReturn(map("id",1L,"asset_id",10L));when(mapper.owner(1L,boot)).thenReturn(2L);
        when(store.get("guard_validation_session",2L)).thenReturn(session);when(mapper.run(2L)).thenReturn(run);when(store.get("asset_authorization",30L)).thenReturn(auth);
        var binding=map("budget_target_id",40L,"scope_digest","a");
        when(store.one(eq("guard_target_binding"),anyMap(),eq(false))).thenReturn(binding);when(store.external("guard_target_binding",initial,false)).thenReturn(binding);
    }
    @Test void eligibleLabPassesOnlyThisAdditionalGate() {assertThat(gate.permits(observation,bundle,now)).isTrue();}
    @Test void syntheticOrExpiredSessionIsDenied() {
        manifest.put("evidenceKind","synthetic");run.put("manifest_jcs",canonical(manifest));assertThat(gate.permits(observation,bundle,now)).isFalse();
        manifest.put("evidenceKind","lab");run.put("manifest_jcs",canonical(manifest));assertThat(gate.permits(observation,bundle,now.plusSeconds(100))).isFalse();
    }
    @Test void revocationAndAuthorizationRevisionAreImmediate() {
        session.put("status","revoked");assertThat(gate.permits(observation,bundle,now)).isFalse();
        session.put("status","active");auth.put("revision",2L);assertThat(gate.permits(observation,bundle,now)).isFalse();
    }
    @Test void endedInterruptedAndTimedOutCannotIssueNewCommands() {
        for(String state:java.util.List.of("completed","failed","interrupted","cancelled","expired")) {run.put("status",state);assertThat(gate.permits(observation,bundle,now)).isFalse();}
        run.put("status","running");assertThat(gate.permits(observation,bundle,now.plusSeconds(60))).isFalse();
    }
    @Test void changedBootCannotFallBackToLegacyPlatformPath() {
        when(mapper.owner(anyLong(),anyString())).thenReturn(null);when(mapper.managedSensor(1L)).thenReturn(1);
        assertThat(gate.permits(observation,bundle,now)).isFalse();when(mapper.managedSensor(1L)).thenReturn(0);
        assertThat(gate.permits(observation,bundle,now)).isTrue();
    }
    @Test void wrongTargetAndWrongBundleAreDenied() {
        when(store.one(eq("guard_target_binding"),anyMap(),eq(false))).thenReturn(map("budget_target_id",99L,"scope_digest","a"));
        assertThat(gate.permits(observation,bundle,now)).isFalse();assertThat(gate.permits(observation,map("id",99L),now)).isFalse();
    }
    @Test void replayRequiresV11RunningFormalOwnerWithMatchingAssetAndBundle() {
        ObjectNode versions=(ObjectNode)versions();versions.put("health",HEALTH_REPLAY);bundle.put("subject_json",canonical(object("protocolVersions",versions)));
        assertThat(gate.replayAllowed(observation,bundle)).isTrue();
        versions.put("health",HEALTH);bundle.put("subject_json",canonical(object("protocolVersions",versions)));
        assertThat(gate.replayAllowed(observation,bundle)).isFalse();
        versions.put("health",HEALTH_REPLAY);bundle.put("subject_json",canonical(object("protocolVersions",versions)));
        observation.put("environment","research");assertThat(gate.replayAllowed(observation,bundle)).isFalse();observation.put("environment","lab");
        when(mapper.owner(anyLong(),anyString())).thenReturn(null);assertThat(gate.replayAllowed(observation,bundle)).isFalse();
        when(mapper.owner(anyLong(),anyString())).thenReturn(2L);
        for(String state:java.util.List.of("queued","completed","interrupted","failed","cancelled","expired")) {
            run.put("status",state);assertThat(gate.replayAllowed(observation,bundle)).isFalse();
        }
        run.put("status","running");manifest.put("evidenceKind","synthetic");run.put("manifest_jcs",canonical(manifest));
        assertThat(gate.replayAllowed(observation,bundle)).isFalse();
        manifest.put("evidenceKind","lab");run.put("manifest_jcs",canonical(manifest));
        session.put("asset_id",99L);assertThat(gate.replayAllowed(observation,bundle)).isFalse();session.put("asset_id",10L);
        session.put("bundle_id",99L);assertThat(gate.replayAllowed(observation,bundle)).isFalse();
    }
    @Test void sharedEligibilityControlsT2ForDecisionAndClaimEvidence()throws Exception {
        ObjectNode versions=(ObjectNode)versions();versions.put("health",HEALTH_REPLAY);bundle.put("subject_json",canonical(object("protocolVersions",versions)));
        var eligibility=new GuardEligibility(store,true,"");eligibility.labGate(gate);
        var health=new GuardHealth(store,mock(GuardAccess.class));
        when(store.one(eq("guard_capture_health_window"),anyMap(),eq(false)))
                .thenReturn(map("verification_status","replay_healthy","interval_end",db(now)));
        var o=GuardDomainTest.observation(now);o.put("environment","lab").put("sensorId",observation.path("sensorId").asText()).put("bootId",observation.path("bootId").asText());
        var policy=GuardDomainTest.autoPolicy(1);policy.put("minEvidenceSpanMs",0);
        var evidence=java.util.List.of(new GuardDecisionEngine.Evidence(o,1d,"a".repeat(64)));
        assertThat(GuardDecisionEngine.evaluate(policy,evidence,now,new GuardDecisionEngine.Gates(true,health.current(1,now,eligibility.replayAllowed(o,bundle)),true,true,null)).decision()).isEqualTo("block_candidate");
        run.put("status","completed");
        assertThat(GuardDecisionEngine.evaluate(policy,evidence,now,new GuardDecisionEngine.Gates(true,health.current(1,now,eligibility.replayAllowed(o,bundle)),true,true,null)).reason()).isEqualTo("QUALITY_UNSUPPORTED");
    }
}
