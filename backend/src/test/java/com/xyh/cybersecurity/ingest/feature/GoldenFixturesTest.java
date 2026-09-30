package com.xyh.cybersecurity.ingest.feature;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.xyh.cybersecurity.ingest.contract.ActiveModelInputs;
import com.xyh.cybersecurity.ingest.contract.FeatureContract;
import com.xyh.cybersecurity.ingest.contract.FeatureContractRegistry;
import com.xyh.cybersecurity.ingest.contract.FeatureContractValidator;
import com.xyh.cybersecurity.ingest.contract.FeatureValidationResult;
import com.xyh.cybersecurity.ingest.contract.RecordMetadata;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * golden fixtures 逐字段对拍（路线 B §9.2「Golden fixtures」）：{@code raw-flows → expected-features}。
 *
 * <p>比对口径：计数类（{@code ct_*}、字节、包、均值）与类别必须完全相等；逐流连续值原样透传，也要求完全相等
 * （fixtures 本身由训练端 float32 口径导出，Builder 不做任何换算）。{@code window_not_ready} 不输出特征；
 * {@code not_in_model_scope} 的 {@code ct_*} 在 fixtures 中隐藏，只比对逐流字段与类别。</p>
 */
class GoldenFixturesTest {
    private static FeatureContract contract;
    private static Map<Long, FeatureBuilder.BuildResult> results;
    private static List<JsonNode> expected;

    @BeforeAll
    static void build() {
        V4Fixtures.verifyChecksums();
        contract = V4Fixtures.contract();
        results = V4Fixtures.buildAll();
        expected = V4Fixtures.jsonl("expected-features.jsonl");
    }

    @Test
    void fixtureSummaryMatchesContract() {
        JsonNode info = V4Fixtures.fixtureInfo();
        assertThat(info.get("window").asInt()).isEqualTo(contract.window().size());
        assertThat(info.get("flows").asInt()).isEqualTo(results.size()).isEqualTo(expected.size());
    }

    @Test
    void everyFlowMatchesExpectedStatusAndFields() {
        Map<String, Integer> statusCounts = new HashMap<>();
        for (JsonNode row : expected) {
            long seq = row.get("seq").asLong();
            String status = row.get("status").asText();
            FeatureBuilder.BuildResult result = results.get(seq);
            statusCounts.merge(status, 1, Integer::sum);
            switch (status) {
                case "window_not_ready" -> assertThat(result.status()).as("seq %d", seq)
                        .isEqualTo(FeatureBuilder.Status.WINDOW_NOT_READY);
                case "not_in_model_scope" -> {
                    assertThat(result.status()).as("seq %d", seq).isEqualTo(FeatureBuilder.Status.READY);
                    assertThat(result.viewpoint()).as("seq %d", seq).isEqualTo("initiator");
                    assertFields(seq, row, result.features(), false);
                }
                case "scored" -> {
                    assertThat(result.status()).as("seq %d", seq).isEqualTo(FeatureBuilder.Status.READY);
                    assertThat(result.viewpoint()).as("seq %d", seq).isEqualTo("responder");
                    assertThat(result.addressFamily()).isEqualTo("ipv4");
                    assertFields(seq, row, result.features(), true);
                }
                default -> throw new AssertionError("未知 fixtures 状态: " + status);
            }
        }
        JsonNode declared = V4Fixtures.fixtureInfo().get("status_counts");
        declared.fields().forEachRemaining(entry ->
                assertThat(statusCounts.get(entry.getKey())).as(entry.getKey()).isEqualTo(entry.getValue().asInt()));
    }

    @Test
    void builderOutputPassesContractValidationWithoutFalseRejects() {
        FeatureContractValidator validator = new FeatureContractValidator(FeatureContractRegistry.fromClasspath(),
                ActiveModelInputs.NONE);
        Map<Long, JsonNode> raw = new HashMap<>();
        V4Fixtures.jsonl("raw-flows.jsonl").forEach(row -> raw.put(row.get("seq").asLong(), row));
        results.forEach((seq, result) -> {
            if (!result.ready()) return;
            FeatureValidationResult check = validator.validate(contract.version(), result.features(),
                    new RecordMetadata(result.viewpoint(), result.addressFamily(), handshakeSeen(raw.get(seq))));
            assertThat(check.issues()).as("seq %d", seq).isEmpty();
        });
    }

    @Test
    void outOfVocabularyProtocolIsScoredWithDriftAdvisory() {
        long oovSeq = V4Fixtures.fixtureInfo().get("oov_seq").asLong();
        String oovValue = V4Fixtures.fixtureInfo().get("oov_value").asText();
        FeatureBuilder.BuildResult result = results.get(oovSeq);
        assertThat(result.ready()).isTrue();
        assertThat(result.features().get("proto").asText()).isEqualTo(oovValue);
        assertThat(result.features().get("service").asText()).isEqualTo("-");

        ActiveModelInputs model = version -> Optional.of(new ActiveModelInputs.Scope("fixture-model",
                Map.of("proto", Set.of("tcp", "udp"), "service", Set.of("-", "dns", "http")),
                List.of("responder"), List.of("ipv4")));
        FeatureValidationResult check = new FeatureContractValidator(FeatureContractRegistry.fromClasspath(), model)
                .validate(contract.version(), result.features(), new RecordMetadata("responder", "ipv4", false));
        assertThat(check.valid()).isTrue();
        assertThat(check.advisories()).extracting("code").contains("CATEGORY_OUT_OF_VOCABULARY");
    }

    private void assertFields(long seq, JsonNode expectedRow, ObjectNode actual, boolean withWindow) {
        for (FeatureContract.NumericField field : contract.numericFields()) {
            if (!withWindow && field.source() == FeatureContract.FieldSource.WINDOW) continue;
            JsonNode want = expectedRow.get(field.name());
            assertThat(want).as("seq %d 缺少期望字段 %s", seq, field.name()).isNotNull();
            assertThat(want.isNull()).as("seq %d 期望字段 %s 为空", seq, field.name()).isFalse();
            assertThat(actual.get(field.name()).asDouble()).as("seq %d %s", seq, field.name())
                    .isEqualTo(want.asDouble());
        }
        for (String field : contract.categoricalFieldNames()) {
            assertThat(actual.get(field).asText()).as("seq %d %s", seq, field).isEqualTo(expectedRow.get(field).asText());
        }
    }

    /** fixtures 没有包级握手信息；按握手字段是否完整近似（只影响元数据，不影响模型输入）。 */
    static boolean handshakeSeen(JsonNode raw) {
        return "tcp".equals(raw.get("proto").asText()) && raw.get("synack").asDouble() > 0 && raw.get("ackdat").asDouble() > 0;
    }
}
