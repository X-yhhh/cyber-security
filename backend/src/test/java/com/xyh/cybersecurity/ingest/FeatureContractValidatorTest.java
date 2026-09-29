package com.xyh.cybersecurity.ingest;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.xyh.cybersecurity.ingest.contract.ActiveModelInputs;
import com.xyh.cybersecurity.ingest.contract.FeatureContract;
import com.xyh.cybersecurity.ingest.contract.FeatureContractRegistry;
import com.xyh.cybersecurity.ingest.contract.FeatureContractValidator;
import com.xyh.cybersecurity.ingest.contract.FeatureValidationResult;
import com.xyh.cybersecurity.ingest.contract.RecordMetadata;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/** 校验器按注册契约判定阻断问题与非阻断遥测；覆盖 v3.1 历史契约与 v4 在线契约（路线 B §9.1 第 2 项、§9.2）。 */
class FeatureContractValidatorTest {
    private static final String V31 = "unsw-nb15-flow-v3.1";
    private static final String V4 = "unsw-nb15-flow-v4";
    private static final RecordMetadata INBOUND = new RecordMetadata("responder", "ipv4", true);

    private final ObjectMapper mapper = new ObjectMapper();
    private final FeatureContractRegistry registry = FeatureContractRegistry.fromClasspath();
    private final FeatureContractValidator validator = new FeatureContractValidator(registry, ActiveModelInputs.NONE);

    @Test
    void v31AcceptsAllRawFieldsAndAllowsOnlyHttpMethodNull() {
        ObjectNode features = mapper.createObjectNode();
        registry.require(V31).numericFieldNames().forEach(field -> features.put(field, 0.0));
        features.putNull("ct_flw_http_mthd");
        features.put("proto", "tcp");
        features.put("service", "http");
        FeatureValidationResult result = validator.validate(V31, features);
        assertThat(result.valid()).isTrue();
        assertThat(result.issues()).isEmpty();
        assertThat(result.advisories()).extracting("code").containsExactly("VOCABULARY_UNAVAILABLE");
    }

    @Test
    void v31RejectsMissingNegativeAndNonFiniteValues() {
        ObjectNode features = mapper.createObjectNode();
        registry.require(V31).numericFieldNames().forEach(field -> features.put(field, 1.0));
        features.remove("sbytes");
        features.put("dbytes", -1);
        features.put("sload", Double.NaN);
        features.put("sttl", (String) null);
        features.put("proto", "TCP");
        features.put("service", "http");
        FeatureValidationResult result = validator.validate(V31, features);
        assertThat(result.valid()).isFalse();
        assertThat(result.issues()).extracting("field").contains("sbytes", "dbytes", "sload", "sttl", "proto");
    }

    @Test
    void unknownContractFailsClosed() {
        FeatureValidationResult result = validator.validate("future-contract", mapper.createObjectNode());
        assertThat(result.valid()).isFalse();
        assertThat(result.issues().getFirst().code()).isEqualTo("FEATURE_CONTRACT_MISMATCH");
    }

    @Test
    void v4AcceptsValidRecordAndReportsMissingVocabularyAsAdvisory() {
        FeatureValidationResult result = validator.validate(V4, v4Features(), INBOUND);
        assertThat(result.valid()).isTrue();
        assertThat(result.issues()).isEmpty();
        assertThat(result.advisories()).extracting("code").containsExactly("VOCABULARY_UNAVAILABLE");
    }

    @Test
    void v4RequiresRecordMetadata() {
        FeatureValidationResult missing = validator.validate(V4, v4Features(), null);
        assertThat(missing.valid()).isFalse();
        assertThat(missing.issues()).extracting("code").containsOnly("RECORD_METADATA_INVALID");
        assertThat(missing.issues()).extracting("field").containsExactlyInAnyOrder("viewpoint", "addressFamily", "handshakeSeen");

        FeatureValidationResult invalid = validator.validate(V4, v4Features(), new RecordMetadata("observer", "ipx", false));
        assertThat(invalid.issues()).extracting("field").containsExactlyInAnyOrder("viewpoint", "addressFamily");
    }

    @Test
    void v4RejectsUnknownRemovedAndMissingFields() {
        ObjectNode features = v4Features();
        features.put("sttl", 64);
        features.remove("ct_src_ltm");
        FeatureValidationResult result = validator.validate(V4, features, INBOUND);
        assertThat(result.valid()).isFalse();
        assertThat(result.issues()).extracting("code", "field").contains(
                org.assertj.core.groups.Tuple.tuple("FEATURE_CONTRACT_MISMATCH", "sttl"),
                org.assertj.core.groups.Tuple.tuple("REQUIRED_FIELD_MISSING", "ct_src_ltm"));
    }

    @Test
    void v4RejectsNullNegativeFractionalAndOutOfRangeValues() {
        ObjectNode features = v4Features();
        features.putNull("dur");
        features.put("sbytes", -1);
        features.put("spkts", 0);
        features.put("dpkts", 1.5);
        features.put("ct_srv_src", 101);
        features.put("ct_dst_ltm", 0);
        features.put("dload", Double.POSITIVE_INFINITY);
        FeatureValidationResult result = validator.validate(V4, features, INBOUND);
        assertThat(result.valid()).isFalse();
        assertThat(result.issues()).extracting("field")
                .contains("dur", "sbytes", "spkts", "dpkts", "ct_srv_src", "ct_dst_ltm", "dload");
    }

    @Test
    void v4RejectsCategoriesNotProducedByContractRules() {
        ObjectNode features = v4Features();
        features.put("proto", "TCP");
        features.put("service", "https");
        FeatureValidationResult result = validator.validate(V4, features, INBOUND);
        assertThat(result.issues()).extracting("field").containsExactlyInAnyOrder("proto", "service");

        ObjectNode unknownProtocol = v4Features();
        unknownProtocol.put("proto", "proto-253");
        unknownProtocol.put("service", "-");
        assertThat(validator.validate(V4, zeroHandshake(unknownProtocol), INBOUND).valid()).isTrue();
    }

    @Test
    void v4EnforcesBoundaryConsistencyRules() {
        ObjectNode udpWithHandshake = v4Features();
        udpWithHandshake.put("proto", "udp");
        udpWithHandshake.put("service", "dns");
        assertThat(validator.validate(V4, udpWithHandshake, INBOUND).issues()).extracting("field").containsExactly("synack");

        ObjectNode noReverse = v4Features();
        noReverse.put("dpkts", 0);
        noReverse.put("dload", 0);
        assertThat(validator.validate(V4, noReverse, INBOUND).issues()).extracting("field").containsExactly("dbytes");

        ObjectNode zeroDuration = v4Features();
        zeroDuration.put("dur", 0.0);
        assertThat(validator.validate(V4, zeroDuration, INBOUND).issues()).extracting("field")
                .containsExactlyInAnyOrder("sload", "dload");

        ObjectNode singleSourcePacket = v4Features();
        singleSourcePacket.put("spkts", 1);
        assertThat(validator.validate(V4, singleSourcePacket, INBOUND).issues()).extracting("field").containsExactly("sload");
    }

    @Test
    void partialHandshakeIsAcceptedBecauseTrainingDataContainsIt() {
        ObjectNode features = v4Features();
        features.put("ackdat", 0.0);
        assertThat(validator.validate(V4, features, INBOUND).valid()).isTrue();
    }

    @Test
    void activeModelScopeProducesNonBlockingDriftAndScopeAdvisories() {
        ActiveModelInputs model = version -> V4.equals(version)
                ? Optional.of(new ActiveModelInputs.Scope("model-1", Map.of("proto", Set.of("tcp", "udp"),
                        "service", Set.of("-", "dns", "http")), List.of("responder"), List.of("ipv4")))
                : Optional.empty();
        FeatureContractValidator withModel = new FeatureContractValidator(registry, model);

        assertThat(withModel.validate(V4, v4Features(), INBOUND).advisories()).isEmpty();

        ObjectNode oov = zeroHandshake(v4Features());
        oov.put("proto", "sctp");
        oov.put("service", "-");
        FeatureValidationResult drift = withModel.validate(V4, oov, INBOUND);
        assertThat(drift.valid()).isTrue();
        assertThat(drift.advisories()).extracting("code", "field")
                .containsExactly(org.assertj.core.groups.Tuple.tuple("CATEGORY_OUT_OF_VOCABULARY", "proto"));
        assertThat(drift.advisories()).extracting("actual").doesNotContain("sctp");

        FeatureValidationResult outbound = withModel.validate(V4, v4Features(), new RecordMetadata("initiator", "ipv4", true));
        assertThat(outbound.valid()).isTrue();
        assertThat(outbound.advisories()).extracting("code").containsExactly("NOT_IN_MODEL_SCOPE");

        FeatureValidationResult ipv6 = withModel.validate(V4, v4Features(), new RecordMetadata("responder", "ipv6", false));
        assertThat(ipv6.advisories()).extracting("code").containsExactly("NOT_IN_MODEL_SCOPE");
    }

    @Test
    void v4ContractIsOnlineAndV31StaysOffline() {
        FeatureContract v4 = registry.require(V4);
        FeatureContract v31 = registry.require(V31);
        assertThat(v4.onlineEnabled()).isTrue();
        assertThat(v31.onlineEnabled()).isFalse();
        assertThat(v4.numericFieldNames()).hasSize(17);
        assertThat(v31.numericFieldNames()).hasSize(26);
    }

    /** 满足契约全部边界规则的一条 TCP 入站流（逐流值互相一致，ct_* 在 1～100 内）。 */
    private ObjectNode v4Features() {
        ObjectNode node = mapper.createObjectNode();
        node.put("dur", 1.0);
        node.put("sbytes", 100);
        node.put("dbytes", 200);
        node.put("sload", 400.0);
        node.put("dload", 800.0);
        node.put("tcprtt", 0.0003);
        node.put("ackdat", 0.0001);
        node.put("synack", 0.0002);
        node.put("smean", 50);
        node.put("dmean", 100);
        node.put("spkts", 2);
        node.put("dpkts", 2);
        node.put("ct_srv_src", 5);
        node.put("ct_srv_dst", 5);
        node.put("ct_dst_ltm", 100);
        node.put("ct_src_ltm", 5);
        node.put("ct_src_dport_ltm", 1);
        node.put("proto", "tcp");
        node.put("service", "http");
        return node;
    }

    private static ObjectNode zeroHandshake(ObjectNode node) {
        node.put("tcprtt", 0.0);
        node.put("ackdat", 0.0);
        node.put("synack", 0.0);
        return node;
    }
}
