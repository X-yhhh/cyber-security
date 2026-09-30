package com.xyh.cybersecurity.model.runtime;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.xyh.cybersecurity.ingest.contract.FeatureContract;
import com.xyh.cybersecurity.ingest.contract.FeatureContractRegistry;
import com.xyh.cybersecurity.model.validation.ModelContractException;
import org.junit.jupiter.api.Test;

import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * 模型输入契约三方交叉核对（路线 B §9.1 第 4 项、§9.2「运行时」）。manifest 与 preprocessing.json 由注册契约合成，
 * 不依赖仓库外的交付包；真实交付包的核对由 {@code ModelReplayCli} 与环境变量门控测试覆盖。
 */
class ModelInputContractTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private final FeatureContractRegistry registry = FeatureContractRegistry.fromClasspath();
    private final FeatureContract v4 = registry.require("unsw-nb15-flow-v4");

    @Test
    void validV4ManifestProducesContractDrivenDimensionsAndScope() {
        ModelInputContract inputs = ModelInputContract.from(manifest(), preprocessing(), v4);
        assertThat(inputs.numericCount()).isEqualTo(17);
        assertThat(inputs.categoricalCount()).isEqualTo(2);
        assertThat(inputs.numericFields()).containsExactlyElementsOf(v4.numericFieldNames());
        assertThat(inputs.supportedViewpoints()).containsExactly("responder");
        assertThat(inputs.supportedAddressFamilies()).containsExactly("ipv4");
        assertThat(inputs.vocabularies().get("proto")).contains("tcp", "udp");
        assertThat(inputs.specSha256()).isEqualTo(v4.specSha256());
    }

    @Test
    void unitMismatchIsRejected() {
        // manifest 与 preprocessing 自洽（都写毫秒），但与注册契约的「秒」不符。
        assertCode("MODEL_INPUT_UNIT_MISMATCH", m -> ((ObjectNode) numeric(m).get(0)).put("unit", "毫秒"),
                p -> ((ObjectNode) p.at("/inputs/flow_numeric/fields").get(0)).put("unit", "毫秒"));
        // 只改 manifest 时，先被 manifest ↔ preprocessing 核对拦下。
        assertCode("MODEL_PREPROCESSING_CONTRACT_MISMATCH", m -> ((ObjectNode) numeric(m).get(0)).put("unit", "毫秒"), p -> { });
    }

    @Test
    void fieldOrderMismatchIsRejected() {
        assertCode("MODEL_INPUT_CONTRACT_MISMATCH", m -> {
            ArrayNode fields = numeric(m);
            var first = fields.get(0).deepCopy();
            fields.set(0, fields.get(1).deepCopy());
            fields.set(1, first);
        }, p -> {
            ArrayNode fields = (ArrayNode) p.at("/inputs/flow_numeric/fields");
            var first = fields.get(0).deepCopy();
            ((ObjectNode) first).put("index", 1);
            ObjectNode second = fields.get(1).deepCopy();
            second.put("index", 0);
            fields.set(0, second);
            fields.set(1, first);
        });
    }

    @Test
    void dimensionMismatchWithPreprocessingIsRejected() {
        assertCode("MODEL_PREPROCESSING_CONTRACT_MISMATCH", m -> { },
                p -> ((ArrayNode) p.at("/inputs/flow_numeric/shape")).set(1, 26));
        assertCode("MODEL_PREPROCESSING_CONTRACT_MISMATCH", m -> numeric(m).remove(16), p -> { });
    }

    @Test
    void specHashMismatchIsRejected() {
        assertCode("MODEL_SPEC_HASH_MISMATCH", m -> ((ObjectNode) m.get("feature_contract"))
                .put("spec_sha256", "0".repeat(64)), p -> { });
    }

    @Test
    void v4ModelMustDeclareScopeWithinContract() {
        assertCode("MODEL_SCOPE_CONTRACT_MISMATCH", m -> ((ObjectNode) m.get("feature_contract")).remove("supported_viewpoints"), p -> { });
        assertCode("MODEL_SCOPE_CONTRACT_MISMATCH", m -> ((ObjectNode) m.get("feature_contract"))
                .putArray("supported_address_families").add("ipx"), p -> { });
    }

    @Test
    void unregisteredOrMismatchedContractIsRejected() {
        assertThatThrownBy(() -> ModelInputContract.from(manifest(), preprocessing(), null))
                .isInstanceOf(ModelContractException.class).hasMessage("MODEL_FEATURE_CONTRACT_UNREGISTERED");
        // 记录 v4 + 模型 v3.1：同一 manifest 不能套用另一份契约。
        assertThatThrownBy(() -> ModelInputContract.from(manifest(), preprocessing(), registry.require("unsw-nb15-flow-v3.1")))
                .isInstanceOf(ModelContractException.class).hasMessage("MODEL_FEATURE_CONTRACT_UNREGISTERED");
    }

    @Test
    void v31ManifestWithPlainNamesStillParsesForOfflineReplay() {
        FeatureContract v31 = registry.require("unsw-nb15-flow-v3.1");
        ObjectNode m = JSON.createObjectNode();
        ObjectNode fc = m.putObject("feature_contract");
        fc.put("version", v31.version());
        ArrayNode numeric = fc.putObject("inputs").putArray("flow_numeric");
        v31.numericFieldNames().forEach(numeric::add);
        ArrayNode categorical = ((ObjectNode) fc.get("inputs")).putArray("flow_categorical");
        v31.categoricalFieldNames().forEach(categorical::add);
        ObjectNode p = preprocessingFor(v31, false);
        ModelInputContract inputs = ModelInputContract.from(m, p, v31);
        assertThat(inputs.numericCount()).isEqualTo(26);
        assertThat(inputs.supportedViewpoints()).isEmpty();
        assertThat(inputs.nullableNumericFields()).containsExactly("ct_flw_http_mthd");
        assertThat(inputs.numericNullable(v31.numericFieldNames().indexOf("ct_flw_http_mthd"))).isTrue();
        assertThat(inputs.numericNullable(0)).isFalse();
    }

    @Test
    void preprocessingCannotWidenNullableFields() {
        assertCode("MODEL_PREPROCESSING_CONTRACT_MISMATCH", m -> { },
                p -> ((ObjectNode) p.at("/inputs/flow_numeric/fields").get(0)).put("nullable", true));
    }

    private void assertCode(String code, Consumer<ObjectNode> manifestMutation, Consumer<ObjectNode> prepMutation) {
        ObjectNode m = manifest();
        ObjectNode p = preprocessing();
        manifestMutation.accept(m);
        prepMutation.accept(p);
        assertThatThrownBy(() -> ModelInputContract.from(m, p, v4))
                .isInstanceOf(ModelContractException.class).hasMessage(code);
    }

    private static ArrayNode numeric(ObjectNode manifest) {
        return (ArrayNode) manifest.at("/feature_contract/inputs/flow_numeric");
    }

    /** 与 unsw-binary-2026.10.0 manifest 同构的最小 v4 manifest。 */
    private ObjectNode manifest() {
        ObjectNode m = JSON.createObjectNode();
        ObjectNode fc = m.putObject("feature_contract");
        fc.put("version", v4.version());
        fc.put("spec_sha256", v4.specSha256());
        ObjectNode inputs = fc.putObject("inputs");
        ArrayNode numeric = inputs.putArray("flow_numeric");
        v4.numericFields().forEach(f -> numeric.addObject().put("name", f.name()).put("unit", f.unit().manifestLabel()));
        ArrayNode categorical = inputs.putArray("flow_categorical");
        v4.categoricalFieldNames().forEach(categorical::add);
        fc.putArray("supported_viewpoints").add("responder");
        fc.putArray("supported_address_families").add("ipv4");
        return m;
    }

    private ObjectNode preprocessing() {
        return preprocessingFor(v4, true);
    }

    private static ObjectNode preprocessingFor(FeatureContract contract, boolean units) {
        ObjectNode p = JSON.createObjectNode();
        p.put("contract_version", contract.version());
        ObjectNode numeric = p.putObject("inputs").putObject("flow_numeric");
        numeric.putArray("shape").add("N").add(contract.numericFields().size());
        ArrayNode fields = numeric.putArray("fields");
        for (int i = 0; i < contract.numericFields().size(); i++) {
            FeatureContract.NumericField f = contract.numericFields().get(i);
            ObjectNode field = fields.addObject().put("index", i).put("name", f.name());
            if (units && f.unit() != null) field.put("unit", f.unit().manifestLabel());
        }
        ObjectNode categorical = ((ObjectNode) p.get("inputs")).putObject("flow_categorical");
        categorical.putArray("shape").add("N").add(contract.categoricalFields().size());
        ArrayNode cats = categorical.putArray("fields");
        for (int i = 0; i < contract.categoricalFieldNames().size(); i++) {
            ObjectNode field = cats.addObject().put("index", i).put("name", contract.categoricalFieldNames().get(i));
            ArrayNode vocabulary = field.putArray("vocabulary");
            if (i == 0) vocabulary.add("tcp").add("udp"); else vocabulary.add("-").add("dns").add("http");
        }
        return p;
    }
}
