package com.xyh.cybersecurity.drift;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

/**
 * 按基线分箱累计的运行时特征分布，可跨窗口相加后再算 PSI（影子报告汇总整段时间，见 V16 迁移说明）。
 *
 * <p>只保存箱计数，不保存原始值或记录标识。字段缺失或数值无效（非数值、NaN、无穷）的记录计入 {@code invalid}，
 * 不参与分箱，也不静默当作 0，便于在报告中暴露传感器实现缺陷。</p>
 */
public final class FeatureDistribution {
    private final FeatureBaseline baseline;
    private final Map<String, long[]> numeric = new LinkedHashMap<>();
    private final Map<String, Map<String, Long>> categorical = new LinkedHashMap<>();
    private final Map<String, Long> invalid = new LinkedHashMap<>();
    private long samples;

    public FeatureDistribution(FeatureBaseline baseline) {
        this.baseline = baseline;
        baseline.numeric().forEach((field, stats) -> {
            numeric.put(field, new long[stats.bins()]);
            invalid.put(field, 0L);
        });
        baseline.categorical().forEach((field, stats) -> {
            Map<String, Long> buckets = new TreeMap<>();
            stats.proportions().keySet().forEach(key -> buckets.put(key, 0L));
            categorical.put(field, buckets);
            invalid.put(field, 0L);
        });
    }

    /** 累计一条记录的 {@code features} 对象（后端 normalized_payload.features）。 */
    public void add(JsonNode features) {
        samples++;
        baseline.numeric().forEach((field, stats) -> {
            JsonNode value = features == null ? null : features.get(field);
            if (value == null || !value.isNumber() || !Double.isFinite(value.asDouble())) {
                invalid.merge(field, 1L, Long::sum);
            } else {
                numeric.get(field)[stats.bin(value.asDouble())]++;
            }
        });
        baseline.categorical().forEach((field, stats) -> {
            JsonNode value = features == null ? null : features.get(field);
            if (value == null || !value.isTextual()) {
                invalid.merge(field, 1L, Long::sum);
            } else {
                categorical.get(field).merge(stats.bucket(value.asText()), 1L, Long::sum);
            }
        });
    }

    /** 累计另一窗口保存的计数（{@link #countsJson()} 的输出）；箱数或键与本基线不一致时抛异常。 */
    public void addCounts(JsonNode stored) {
        JsonNode fields = stored.path("fields");
        samples += stored.path("samples").asLong(0);
        numeric.forEach((field, counts) -> {
            JsonNode array = fields.path(field).path("counts");
            if (!array.isArray() || array.size() != counts.length) throw new IllegalArgumentException("DRIFT_COUNTS_INCOMPATIBLE");
            for (int i = 0; i < counts.length; i++) counts[i] += array.get(i).asLong();
            invalid.merge(field, fields.path(field).path("invalid").asLong(0), Long::sum);
        });
        categorical.forEach((field, counts) -> {
            JsonNode object = fields.path(field).path("counts");
            if (!object.isObject()) throw new IllegalArgumentException("DRIFT_COUNTS_INCOMPATIBLE");
            object.fields().forEachRemaining(entry -> {
                if (!counts.containsKey(entry.getKey())) throw new IllegalArgumentException("DRIFT_COUNTS_INCOMPATIBLE");
                counts.merge(entry.getKey(), entry.getValue().asLong(), Long::sum);
            });
            invalid.merge(field, fields.path(field).path("invalid").asLong(0), Long::sum);
        });
    }

    public long samples() { return samples; }

    /** 每字段 PSI；有效样本为 0 的字段不给出数值（null）。 */
    public Map<String, Double> psi() {
        Map<String, Double> result = new LinkedHashMap<>();
        baseline.numeric().forEach((field, stats) -> result.put(field, Psi.of(stats.proportions(), numeric.get(field),
                baseline.epsilon())));
        baseline.categorical().forEach((field, stats) -> {
            Map<String, Long> counts = categorical.get(field);
            double[] expected = new double[counts.size()];
            long[] actual = new long[counts.size()];
            int i = 0;
            for (var entry : counts.entrySet()) {
                expected[i] = stats.proportions().getOrDefault(entry.getKey(), 0.0);
                actual[i++] = entry.getValue();
            }
            result.put(field, Psi.of(expected, actual, baseline.epsilon()));
        });
        return result;
    }

    /** 类别字段落入 {@link FeatureBaseline#OTHER} 的比例（训练中未出现或占比过低的取值），有效样本为 0 时为 null。 */
    public Map<String, Double> otherRatio() {
        Map<String, Double> result = new LinkedHashMap<>();
        categorical.forEach((field, counts) -> {
            long total = counts.values().stream().mapToLong(Long::longValue).sum();
            result.put(field, total == 0 ? null : counts.getOrDefault(FeatureBaseline.OTHER, 0L) / (double) total);
        });
        return result;
    }

    public Map<String, Long> invalid() { return Map.copyOf(invalid); }

    /** 可持久化的计数视图：{@code {samples, fields: {field: {counts, invalid}}}}，不含原始值。 */
    public Map<String, Object> countsJson() {
        Map<String, Object> fields = new LinkedHashMap<>();
        numeric.forEach((field, counts) -> fields.put(field, Map.of("counts", counts.clone(), "invalid", invalid.get(field))));
        categorical.forEach((field, counts) -> fields.put(field, Map.of("counts", new TreeMap<>(counts),
                "invalid", invalid.get(field))));
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("samples", samples);
        result.put("fields", fields);
        return result;
    }
}
