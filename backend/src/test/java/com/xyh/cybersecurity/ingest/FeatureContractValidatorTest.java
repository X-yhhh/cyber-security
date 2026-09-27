package com.xyh.cybersecurity.ingest;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.xyh.cybersecurity.ingest.contract.FeatureContract;
import com.xyh.cybersecurity.ingest.contract.FeatureContractRegistry;
import com.xyh.cybersecurity.ingest.contract.FeatureContractValidator;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class FeatureContractValidatorTest {
    private final ObjectMapper mapper = new ObjectMapper();
    private final FeatureContractValidator validator = new FeatureContractValidator(new FeatureContractRegistry());

    @Test
    void validatesAllRawFieldsInFixedOrderAndAllowsOnlyHttpMethodNull() {
        ObjectNode features = mapper.createObjectNode();
        FeatureContract.UNSW_NB15_V3_1.numericFields().forEach(field -> features.put(field, 0.0));
        features.putNull("ct_flw_http_mthd");
        features.put("proto", "tcp");
        features.put("service", "http");
        var result = validator.validate(FeatureContract.V3_1, features);
        assertThat(result.valid()).isTrue();
        assertThat(result.issues()).isEmpty();
    }

    @Test
    void rejectsMissingNegativeAndNonFiniteValues() {
        ObjectNode features = mapper.createObjectNode();
        FeatureContract.UNSW_NB15_V3_1.numericFields().forEach(field -> features.put(field, 1.0));
        features.remove("sbytes");
        features.put("dbytes", -1);
        features.put("sload", Double.NaN);
        features.put("proto", "TCP");
        features.put("service", "unknown");
        var result = validator.validate(FeatureContract.V3_1, features);
        assertThat(result.valid()).isFalse();
        assertThat(result.issues()).extracting("field").contains("sbytes", "dbytes", "sload", "proto");
        assertThat(result.categoryDrift()).contains("service=out_of_vocabulary");
    }

    @Test
    void unknownContractFailsClosed() {
        var result = validator.validate("future-contract", mapper.createObjectNode());
        assertThat(result.valid()).isFalse();
        assertThat(result.issues().getFirst().code()).isEqualTo("FEATURE_CONTRACT_MISMATCH");
    }
}
