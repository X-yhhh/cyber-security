package com.xyh.cybersecurity.model.runtime;

import com.xyh.cybersecurity.ingest.contract.FeatureContract;
import com.xyh.cybersecurity.ingest.contract.FeatureContractRegistry;
import com.xyh.cybersecurity.ingest.contract.RecordMetadata;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** 推理入口契约一致性门禁（路线 B §3.2、§9.2「版本一致性」）。 */
class FeatureContractModelGateTest {
    private static final String V4 = "unsw-nb15-flow-v4";
    private static final String V31 = "unsw-nb15-flow-v3.1";
    private static final RecordMetadata INBOUND = new RecordMetadata("responder", "ipv4", true);

    private final FeatureContractRegistry registry = FeatureContractRegistry.fromClasspath();
    private final FeatureContractModelGate gate = new FeatureContractModelGate(registry);
    private final FeatureContract v4 = registry.require(V4);
    private final String v4Sha = v4.fileSha256();

    @Test
    void consistentV4RecordConfigAndModelIsAccepted() {
        FeatureContractModelGate.Decision decision = gate.check(V4, V4, v4Sha, model(V4, v4.specSha256()), INBOUND);
        assertThat(decision.accepted()).isTrue();
        assertThat(decision.errorCode()).isNull();
    }

    @Test
    void v4RecordWithV31ModelIsRejected() {
        assertRejected(gate.check(V4, V4, v4Sha, model(V31, null), INBOUND), "record_model_mismatch");
    }

    @Test
    void v31RecordIsRejectedOnline() {
        String v31Sha = registry.require(V31).fileSha256();
        assertRejected(gate.check(V31, V31, v31Sha, model(V31, null), null), "contract_not_online");
    }

    @Test
    void configAndRecordContractMismatchIsRejected() {
        assertRejected(gate.check(V4, V31, v4Sha, model(V4, v4.specSha256()), INBOUND), "record_config_mismatch");
        assertRejected(gate.check(null, V4, v4Sha, model(V4, v4.specSha256()), INBOUND), "record_config_mismatch");
    }

    @Test
    void staleConfigHashAndSpecHashMismatchAreRejected() {
        assertRejected(gate.check(V4, V4, "0".repeat(64), model(V4, v4.specSha256()), INBOUND), "config_contract_hash_mismatch");
        assertRejected(gate.check(V4, V4, null, model(V4, v4.specSha256()), INBOUND), "config_contract_hash_mismatch");
        assertRejected(gate.check(V4, V4, v4Sha, model(V4, "1".repeat(64)), INBOUND), "model_spec_hash_mismatch");
    }

    @Test
    void missingModelOrMetadataIsRejected() {
        assertRejected(gate.check(V4, V4, v4Sha, null, INBOUND), "model_unavailable");
        assertRejected(gate.check(V4, V4, v4Sha, model(V4, v4.specSha256()), null), "record_metadata_missing");
    }

    @Test
    void outboundAndIpv6AreNotInModelScopeRatherThanRejected() {
        ModelInputContract model = model(V4, v4.specSha256());
        FeatureContractModelGate.Decision outbound = gate.check(V4, V4, v4Sha, model, new RecordMetadata("initiator", "ipv4", true));
        assertThat(outbound.outcome()).isEqualTo(FeatureContractModelGate.Outcome.NOT_IN_MODEL_SCOPE);
        assertThat(outbound.errorCode()).isNull();
        FeatureContractModelGate.Decision ipv6 = gate.check(V4, V4, v4Sha, model, new RecordMetadata("responder", "ipv6", false));
        assertThat(ipv6.outcome()).isEqualTo(FeatureContractModelGate.Outcome.NOT_IN_MODEL_SCOPE);
    }

    private static void assertRejected(FeatureContractModelGate.Decision decision, String reason) {
        assertThat(decision.outcome()).isEqualTo(FeatureContractModelGate.Outcome.REJECT);
        assertThat(decision.errorCode()).isEqualTo("FEATURE_CONTRACT_MODEL_MISMATCH");
        assertThat(decision.reason()).isEqualTo(reason);
    }

    private ModelInputContract model(String version, String specSha) {
        FeatureContract contract = registry.require(version);
        boolean scoped = contract.requiresRecordMetadata();
        return new ModelInputContract(version, specSha, contract.numericFieldNames(), contract.categoricalFieldNames(),
                java.util.Set.of(), Map.of(), scoped ? List.of("responder") : List.of(), scoped ? List.of("ipv4") : List.of());
    }
}
