package com.xyh.cybersecurity.response;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.xyh.cybersecurity.response.domain.ActionSnapshotFactory;
import com.xyh.cybersecurity.response.domain.ApprovalStateMachine;
import com.xyh.cybersecurity.response.domain.AuthorizationGuard;
import com.xyh.cybersecurity.response.domain.PolicyGuard;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

class ResponseDomainTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void policyGuardRejectsWrongEnvironmentTtlAndUnlistedTarget() throws Exception {
        PolicyGuard guard = new PolicyGuard(mapper);
        PolicyGuard.Policy policy = new PolicyGuard.Policy("active", 7L, false, true,
                "temporary_block", "lab", "{\"environment\":\"lab\"}",
                "{\"maxTtlSeconds\":600,\"allowedTargets\":[\"192.0.2.10\"]}", 600);
        var asset = new PolicyGuard.Asset("lab");

        assertThat(guard.matches(policy, "temporary_block", asset,
                mapper.readTree("{\"targetAddress\":\"192.0.2.10\",\"ttlSeconds\":60}"))).isTrue();
        assertThat(guard.matches(policy, "temporary_block", asset,
                mapper.readTree("{\"targetAddress\":\"192.0.2.11\",\"ttlSeconds\":60}"))).isFalse();
        assertThat(guard.matches(policy, "temporary_block", asset,
                mapper.readTree("{\"targetAddress\":\"192.0.2.10\",\"ttlSeconds\":601}"))).isFalse();
    }

    @Test
    void authorizationGuardFailsClosedForMalformedScope() {
        AuthorizationGuard guard = new AuthorizationGuard(mapper);
        assertThat(guard.scopeAllows("{\"actionTypes\":[\"temporary_block\"]}", "temporary_block")).isTrue();
        assertThat(guard.scopeAllows("{\"actionTypes\":[\"other\"]}", "temporary_block")).isFalse();
        assertThat(guard.scopeAllows("not-json", "temporary_block")).isFalse();
    }

    @Test
    void stateMachineAllowsOnlyPendingAndSeparatesDecisions() {
        assertThat(ApprovalStateMachine.decide("pending", "approve")).isEqualTo("approved");
        assertThat(ApprovalStateMachine.decide("pending", "reject")).isEqualTo("rejected");
        assertThatIllegalStateException().isThrownBy(() -> ApprovalStateMachine.decide("approved", "approve"));
        assertThatIllegalArgumentException().isThrownBy(() -> ApprovalStateMachine.decide("pending", "delete"));
    }

    @Test
    void snapshotContainsPolicyVersionAndActionIdentity() throws Exception {
        String snapshot = new ActionSnapshotFactory(mapper).create(4, 8, 12, "temporary_block",
                mapper.readTree("{\"targetAddress\":\"192.0.2.10\",\"ttlSeconds\":60}"), "review",
                new ActionSnapshotFactory.PolicySnapshot("policy-a", "v1", "lab", 600));
        var json = mapper.readTree(snapshot);
        assertThat(json.path("eventId").asLong()).isEqualTo(4);
        assertThat(json.path("policyKey").asText()).isEqualTo("policy-a");
        assertThat(json.path("policyVersion").asText()).isEqualTo("v1");
    }
}
