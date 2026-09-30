package com.xyh.cybersecurity.drift;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.xyh.cybersecurity.model.validation.ModelContractException;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.within;

/**
 * 基线解析、分箱语义与 PSI：分箱须与训练端 {@code numpy.searchsorted(edges, v, side="left")} 一致；
 * 结构不合规的基线拒绝（MODEL_BASELINE_STATS_INVALID），缺失时为空。
 */
class FeatureBaselineTest {
    private static final ObjectMapper JSON = new ObjectMapper();

    /** 两个数值字段（dur 3 条边界、sbytes 空边界）与一个类别字段 proto。 */
    static ObjectNode manifest() {
        ObjectNode root = JSON.createObjectNode();
        ObjectNode inputs = root.putObject("feature_contract").putObject("inputs");
        inputs.putArray("flow_numeric").add(JSON.createObjectNode().put("name", "dur").put("unit", "秒"))
                .add(JSON.createObjectNode().put("name", "sbytes").put("unit", "字节"));
        inputs.putArray("flow_categorical").add("proto");
        ObjectNode stats = root.putObject("feature_baseline_stats");
        stats.put("schema_version", "baseline-v1").put("method", "train_partition_decile_bins")
                .put("categorical_other", "__other__");
        stats.putObject("source").put("partition", "train").put("split_fingerprint", "f".repeat(64));
        stats.putObject("psi").put("epsilon", 0.0001).put("warning", 0.2).put("alert", 0.3).put("min_samples", 200);
        ObjectNode numeric = stats.putObject("numeric");
        ObjectNode dur = numeric.putObject("dur");
        dur.putArray("edges").add(0.0).add(1.0).add(10.0);
        dur.putArray("proportions").add(0.25).add(0.25).add(0.25).add(0.25);
        dur.put("count", 400);
        ObjectNode sbytes = numeric.putObject("sbytes");
        sbytes.putArray("edges");
        sbytes.putArray("proportions").add(1.0);
        sbytes.put("count", 400);
        ObjectNode proto = stats.putObject("categorical").putObject("proto");
        proto.putObject("proportions").put("tcp", 0.7).put("udp", 0.3).put("__other__", 0.0);
        proto.put("count", 400);
        return root;
    }

    private static FeatureBaseline parse(ObjectNode manifest) {
        return FeatureBaseline.fromManifestInputs(manifest).orElseThrow();
    }

    @Test
    void binCountsEdgesStrictlyLessThanValue() {
        FeatureBaseline.NumericField dur = parse(manifest()).numeric().get("dur");
        assertThat(dur.bins()).isEqualTo(4);
        assertThat(dur.bin(-1)).isZero();
        assertThat(dur.bin(0.0)).isZero();          // 等于首条边界：严格小于它的边界 0 个
        assertThat(dur.bin(0.5)).isEqualTo(1);
        assertThat(dur.bin(1.0)).isEqualTo(1);
        assertThat(dur.bin(10.0)).isEqualTo(2);
        assertThat(dur.bin(10.0001)).isEqualTo(3);
        assertThat(parse(manifest()).numeric().get("sbytes").bin(123)).isZero();
    }

    @Test
    void unknownCategoriesFallIntoOther() {
        FeatureBaseline.CategoricalField proto = parse(manifest()).categorical().get("proto");
        assertThat(proto.bucket("tcp")).isEqualTo("tcp");
        assertThat(proto.bucket("sctp")).isEqualTo(FeatureBaseline.OTHER);
        assertThat(proto.bucket(null)).isEqualTo(FeatureBaseline.OTHER);
    }

    @Test
    void missingBlockIsEmptyNotError() {
        ObjectNode manifest = manifest();
        manifest.remove("feature_baseline_stats");
        assertThat(FeatureBaseline.fromManifestInputs(manifest)).isEmpty();
    }

    @Test
    void malformedBaselinesAreRejected() {
        List<Consumer<ObjectNode>> breakers = List.of(
                s -> s.put("schema_version", "baseline-v0"),
                s -> ((ArrayNode) s.at("/numeric/dur/edges")).set(2, JSON.getNodeFactory().numberNode(0.5)),
                s -> ((ArrayNode) s.at("/numeric/dur/proportions")).set(0, JSON.getNodeFactory().numberNode(0.5)),
                s -> ((ArrayNode) s.at("/numeric/dur/proportions")).remove(0),
                s -> ((ObjectNode) s.path("numeric")).remove("sbytes"),
                s -> ((ObjectNode) s.at("/categorical/proto/proportions")).remove("__other__"),
                s -> ((ObjectNode) s.path("source")).put("partition", "holdout"),
                s -> ((ObjectNode) s.path("psi")).put("warning", 0.5),
                s -> ((ObjectNode) s.at("/numeric/dur")).put("count", 0));
        for (Consumer<ObjectNode> breaker : breakers) {
            ObjectNode manifest = manifest();
            breaker.accept((ObjectNode) manifest.path("feature_baseline_stats"));
            assertThatThrownBy(() -> FeatureBaseline.fromManifestInputs(manifest))
                    .isInstanceOf(ModelContractException.class).hasMessage("MODEL_BASELINE_STATS_INVALID");
        }
    }

    @Test
    void psiIsZeroForIdenticalDistributionAndMatchesHandComputation() {
        assertThat(Psi.of(new double[]{0.5, 0.5}, new long[]{50, 50}, 1e-4)).isCloseTo(0.0, within(1e-12));
        // e = (0.5, 0.5)，a = (0.9, 0.1)：0.4·ln(1.8) + (−0.4)·ln(0.2)
        double expected = 0.4 * Math.log(1.8) - 0.4 * Math.log(0.2);
        assertThat(Psi.of(new double[]{0.5, 0.5}, new long[]{90, 10}, 1e-4)).isCloseTo(expected, within(1e-12));
        assertThat(Psi.of(new double[]{0.5, 0.5}, new long[]{0, 0}, 1e-4)).isNull();
        // 空箱按 epsilon 截底，不产生无穷。
        assertThat(Psi.of(new double[]{1.0, 0.0}, new long[]{0, 10}, 1e-4)).isFinite().isPositive();
    }

    @Test
    void distributionCountsRoundTripAndInvalidValuesAreSeparated() throws Exception {
        FeatureBaseline baseline = parse(manifest());
        FeatureDistribution first = new FeatureDistribution(baseline);
        first.add(JSON.readTree("{\"dur\":0.5,\"sbytes\":10,\"proto\":\"tcp\"}"));
        first.add(JSON.readTree("{\"dur\":20,\"sbytes\":10,\"proto\":\"sctp\"}"));
        first.add(JSON.readTree("{\"dur\":\"x\",\"proto\":7}"));
        assertThat(first.samples()).isEqualTo(3);
        assertThat(first.invalid()).containsEntry("dur", 1L).containsEntry("sbytes", 1L).containsEntry("proto", 1L);
        assertThat(first.otherRatio().get("proto")).isEqualTo(0.5);

        FeatureDistribution merged = new FeatureDistribution(baseline);
        merged.addCounts(JSON.valueToTree(first.countsJson()));
        merged.addCounts(JSON.valueToTree(first.countsJson()));
        assertThat(merged.samples()).isEqualTo(6);
        @SuppressWarnings("unchecked")
        Map<String, Object> dur = (Map<String, Object>) ((Map<String, Object>) merged.countsJson().get("fields")).get("dur");
        assertThat((long[]) dur.get("counts")).containsExactly(0, 2, 0, 2);
        assertThat(merged.psi().get("dur")).isEqualTo(first.psi().get("dur"));
    }

    @Test
    void driftStatusFollowsSamplesAndThresholds() {
        FeatureBaseline baseline = parse(manifest());
        assertThat(DriftMetricService.status(baseline, 199, Map.of("dur", 0.0))).isEqualTo("insufficient_samples");
        java.util.HashMap<String, Double> withNull = new java.util.HashMap<>();
        withNull.put("dur", null);
        assertThat(DriftMetricService.status(baseline, 500, withNull)).isEqualTo("insufficient_samples");
        assertThat(DriftMetricService.status(baseline, 500, Map.of("dur", 0.2))).isEqualTo("ok");
        assertThat(DriftMetricService.status(baseline, 500, Map.of("dur", 0.25))).isEqualTo("warning");
        assertThat(DriftMetricService.status(baseline, 500, Map.of("dur", 0.31))).isEqualTo("alert");
    }
}
