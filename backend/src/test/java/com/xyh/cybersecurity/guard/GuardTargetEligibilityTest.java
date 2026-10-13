package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import java.time.Instant;
import java.util.Map;
import static com.xyh.cybersecurity.guard.GuardJson.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

/** D6 的目标身份与触发租约分离；跨目标证据在 T4 拒绝，禁止由有效的最后一条代替。 */
class GuardTargetEligibilityTest {
    final Instant now=Instant.parse("2030-01-01T00:00:00Z");
    GuardEligibility eligibility;
    ObjectNode observation,policy,payload;
    Map<String,Object> target;
    @BeforeEach void fixture()throws Exception{
        var store=mock(GuardStore.class);eligibility=new GuardEligibility(store,true,"");
        observation=GuardDomainTest.observation(now).put("environment","lab").put("targetRef",id()).put("targetExpiresAt",now.plusSeconds(15).toString());
        policy=GuardDomainTest.autoPolicy(1);payload=observation.deepCopy().put("scope","peer_service");
        String boot=observation.path("bootId").asText(),executorBoot=id();
        target=map("target_ref",observation.path("targetRef").asText(),"expires_at",db(now.plusSeconds(15)),"sensor_id",1L,"executor_id",2L,"budget_target_id",3L,
                "collector_boot_id",boot,"executor_boot_id",executorBoot,"payload_json",canonical(payload));
        when(store.get("sensor_agent",1L)).thenReturn(map("guard_boot_id",boot));
        when(store.get("guard_executor",2L)).thenReturn(map("boot_id",executorBoot));
        when(store.get("guard_budget_target",3L)).thenReturn(map("identity_status","verified","environment","lab"));
        assertThat(eligibility.target(target,observation,now,policy,"dos_slow")).isTrue();
    }
    @ParameterizedTest
    @ValueSource(strings={"missing_reference","different_reference","expired_reference","binding_expired","old_packet"})
    void historicalIdentityDoesNotDependOnItsLeaseButTriggerMustHaveOne(String change){
        switch(change){
            case "missing_reference"->observation.putNull("targetRef").putNull("targetExpiresAt");
            case "different_reference"->observation.put("targetRef",id());
            case "expired_reference"->observation.put("targetExpiresAt",now.toString());
            case "binding_expired"->target.put("expires_at",db(now));
            case "old_packet"->observation.put("lastPacketAt",now.minusSeconds(15).toString());
        }
        assertThat(eligibility.sameTarget(target,observation,policy,"dos_slow")).isTrue();
        assertThat(eligibility.target(target,observation,now,policy,"dos_slow")).isFalse();
    }
    @ParameterizedTest
    @ValueSource(strings={"sensorId","captureScopeId","peerKey","keyEpoch","direction","transport","addressFamily","servicePort"})
    void everyTargetIdentityDimensionMustMatch(String field){
        if(field.equals("keyEpoch")||field.equals("servicePort"))observation.put(field,observation.path(field).asInt()+1);
        else observation.put(field,"other-identity");
        assertThat(eligibility.sameTarget(target,observation,policy,"dos_slow")).isFalse();
        assertThat(eligibility.target(target,observation,now,policy,"dos_slow")).isFalse();
    }
    @Test void inboundScopeAllowsDifferentPortsButRequiresInboundAndNullBindingPort(){
        ((ObjectNode)GuardDecisionEngine.familyPolicy(policy,"dos_slow")).put("scope","peer_inbound");
        observation.put("direction","inbound").put("servicePort",80);
        payload.put("scope","peer_inbound").put("direction","inbound").putNull("servicePort");target.put("payload_json",canonical(payload));
        assertThat(eligibility.sameTarget(target,observation,policy,"dos_slow")).isTrue();
        observation.put("servicePort",443);assertThat(eligibility.sameTarget(target,observation,policy,"dos_slow")).isTrue();
        payload.put("servicePort",443);target.put("payload_json",canonical(payload));assertThat(eligibility.sameTarget(target,observation,policy,"dos_slow")).isFalse();
    }
}
