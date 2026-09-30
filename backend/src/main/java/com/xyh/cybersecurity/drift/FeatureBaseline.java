package com.xyh.cybersecurity.drift;

import com.fasterxml.jackson.databind.JsonNode;
import com.xyh.cybersecurity.model.validation.ModelContractException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * manifest {@code feature_baseline_stats}（schema {@code baseline-v1}）的只读视图：训练切分上 v4 原始输入字段的分布基线，
 * 供 M8 漂移窗口与阶段 7 影子报告计算 PSI（路线 B §13.2、§15）。基线由训练端离线写入 manifest，后端不在线更新。
 *
 * <p>数值字段分箱规则与训练端一致：值 v 的箱号 = {@code edges} 中严格小于 v 的元素个数（{@code bins = edges.length + 1}），
 * 等价于 {@code numpy.searchsorted(edges, v, side="left")}。类别字段不在基线键中的取值（含训练中占比过低被归并的取值）
 * 计入 {@link #OTHER}。</p>
 *
 * <p>解析失败语义：manifest 不含该块时返回 {@link Optional#empty()}（漂移记为 {@code baseline_unavailable}，不阻断推理）；
 * 含该块但结构不合规时抛 {@code MODEL_BASELINE_STATS_INVALID}，由制品校验拒绝激活，避免用错的基线得出“无漂移”。</p>
 */
public record FeatureBaseline(String schemaVersion, String method, String sourceRef, double epsilon,
                              double warningThreshold, double alertThreshold, long minSamples,
                              Map<String, NumericField> numeric, Map<String, CategoricalField> categorical) {

    public static final String SCHEMA_VERSION = "baseline-v1";
    public static final String OTHER = "__other__";
    private static final String INVALID = "MODEL_BASELINE_STATS_INVALID";
    private static final double PROPORTION_TOLERANCE = 1e-6;

    public FeatureBaseline {
        numeric = Collections.unmodifiableMap(new LinkedHashMap<>(numeric));
        categorical = Collections.unmodifiableMap(new LinkedHashMap<>(categorical));
    }

    /** 数值字段基线：{@code edges} 严格递增且有限，{@code proportions.length == edges.length + 1}。 */
    public record NumericField(double[] edges, double[] proportions, long count) {
        /** 按训练端规则求箱号：严格小于 v 的边界个数。NaN 与无穷不应出现在 v4 输入中，调用方须先行拒绝。 */
        public int bin(double value) {
            int low = 0;
            int high = edges.length;
            while (low < high) {
                int mid = (low + high) >>> 1;
                if (edges[mid] < value) low = mid + 1; else high = mid;
            }
            return low;
        }

        public int bins() { return edges.length + 1; }
    }

    /** 类别字段基线：键为训练取值（含 {@link #OTHER}），值为占比。 */
    public record CategoricalField(Map<String, Double> proportions, long count) {
        public CategoricalField {
            proportions = Collections.unmodifiableMap(new LinkedHashMap<>(proportions));
        }

        /** 运行时取值映射到基线键：不在基线中的取值一律归 {@link #OTHER}。 */
        public String bucket(String value) {
            return value != null && !OTHER.equals(value) && proportions.containsKey(value) ? value : OTHER;
        }
    }

    /**
     * 从 manifest 解析基线，并核对字段集合与模型输入契约一致。
     *
     * @param manifest          已校验的 model_manifest.json
     * @param numericFields     模型输入契约的数值字段（顺序无关，集合必须完全一致）
     * @param categoricalFields 模型输入契约的类别字段
     */
    public static Optional<FeatureBaseline> fromManifest(JsonNode manifest, List<String> numericFields,
                                                         List<String> categoricalFields) {
        JsonNode node = manifest == null ? null : manifest.get("feature_baseline_stats");
        if (node == null || node.isNull() || node.isMissingNode()) return Optional.empty();
        if (!node.isObject() || !SCHEMA_VERSION.equals(node.path("schema_version").asText())) throw invalid();
        JsonNode psi = node.path("psi");
        double epsilon = positive(psi.path("epsilon"));
        double warning = positive(psi.path("warning"));
        double alert = positive(psi.path("alert"));
        JsonNode minSamplesNode = psi.path("min_samples");
        if (!minSamplesNode.canConvertToLong() || minSamplesNode.asLong() < 1 || epsilon >= 0.01 || warning >= alert) {
            throw invalid();
        }
        if (!OTHER.equals(node.path("categorical_other").asText())) throw invalid();

        JsonNode numericNode = node.path("numeric");
        JsonNode categoricalNode = node.path("categorical");
        if (!numericNode.isObject() || numericNode.size() != numericFields.size()
                || !categoricalNode.isObject() || categoricalNode.size() != categoricalFields.size()) {
            throw invalid();
        }
        Map<String, NumericField> numeric = new LinkedHashMap<>();
        for (String field : numericFields) numeric.put(field, numericField(numericNode.get(field)));
        Map<String, CategoricalField> categorical = new LinkedHashMap<>();
        for (String field : categoricalFields) categorical.put(field, categoricalField(categoricalNode.get(field)));

        JsonNode source = node.path("source");
        String sourceRef = source.path("partition").asText("") + ":" + source.path("split_fingerprint").asText("");
        if (!"train".equals(source.path("partition").asText())) throw invalid();
        return Optional.of(new FeatureBaseline(SCHEMA_VERSION, node.path("method").asText(""), sourceRef, epsilon,
                warning, alert, minSamplesNode.asLong(), numeric, categorical));
    }

    /**
     * 字段集合取自 manifest 自身的 {@code feature_contract.inputs}；仅用于已通过制品校验（与输入契约交叉核对过）的模型版本。
     */
    public static Optional<FeatureBaseline> fromManifestInputs(JsonNode manifest) {
        List<String> numericFields = new ArrayList<>();
        manifest.at("/feature_contract/inputs/flow_numeric").forEach(field -> numericFields.add(field.path("name").asText()));
        List<String> categoricalFields = new ArrayList<>();
        manifest.at("/feature_contract/inputs/flow_categorical").forEach(field -> categoricalFields.add(field.asText()));
        return fromManifest(manifest, numericFields, categoricalFields);
    }

    private static NumericField numericField(JsonNode node) {
        if (node == null || !node.isObject()) throw invalid();
        JsonNode edgesNode = node.path("edges");
        JsonNode proportionsNode = node.path("proportions");
        if (!edgesNode.isArray() || !proportionsNode.isArray() || proportionsNode.size() != edgesNode.size() + 1) {
            throw invalid();
        }
        double[] edges = new double[edgesNode.size()];
        for (int i = 0; i < edges.length; i++) {
            JsonNode edge = edgesNode.get(i);
            if (!edge.isNumber() || !Double.isFinite(edge.asDouble())) throw invalid();
            edges[i] = edge.asDouble();
            if (i > 0 && !(edges[i] > edges[i - 1])) throw invalid();
        }
        double[] proportions = proportions(proportionsNode);
        return new NumericField(edges, proportions, count(node.path("count")));
    }

    private static CategoricalField categoricalField(JsonNode node) {
        if (node == null || !node.isObject()) throw invalid();
        JsonNode proportionsNode = node.path("proportions");
        if (!proportionsNode.isObject() || !proportionsNode.has(OTHER)) throw invalid();
        Map<String, Double> proportions = new LinkedHashMap<>();
        List<Double> values = new ArrayList<>();
        var fields = proportionsNode.fields();
        while (fields.hasNext()) {
            var entry = fields.next();
            if (entry.getKey().isEmpty() || entry.getKey().length() > 64) throw invalid();
            double value = proportion(entry.getValue());
            proportions.put(entry.getKey(), value);
            values.add(value);
        }
        checkSum(values.stream().mapToDouble(Double::doubleValue).sum());
        return new CategoricalField(proportions, count(node.path("count")));
    }

    private static double[] proportions(JsonNode array) {
        double[] values = new double[array.size()];
        double sum = 0;
        for (int i = 0; i < values.length; i++) {
            values[i] = proportion(array.get(i));
            sum += values[i];
        }
        checkSum(sum);
        return values;
    }

    private static double proportion(JsonNode node) {
        if (!node.isNumber()) throw invalid();
        double value = node.asDouble();
        if (!Double.isFinite(value) || value < 0 || value > 1) throw invalid();
        return value;
    }

    private static void checkSum(double sum) {
        if (Math.abs(sum - 1.0) > PROPORTION_TOLERANCE) throw invalid();
    }

    private static long count(JsonNode node) {
        if (!node.canConvertToLong() || node.asLong() < 1) throw invalid();
        return node.asLong();
    }

    private static double positive(JsonNode node) {
        if (!node.isNumber() || !(node.asDouble() > 0) || !Double.isFinite(node.asDouble())) throw invalid();
        return node.asDouble();
    }

    private static ModelContractException invalid() { return new ModelContractException(INVALID); }
}
