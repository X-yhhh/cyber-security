package com.xyh.cybersecurity.inference;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.xyh.cybersecurity.ingest.contract.RecordMetadata;
import com.xyh.cybersecurity.model.runtime.ModelInputContract;
import com.xyh.cybersecurity.model.runtime.OnnxModelRuntime;

/**
 * 从 {@code ingest_record.normalized_payload} 读出模型输入（路线 B §10.1 第 2 项）。
 *
 * <p>按激活模型 manifest 的字段顺序逐列读取，只读取契约声明的字段；不插补、不编码、不派生。
 * 缺失、类型不符或非有限值直接给出细分原因，由调用方记为 {@code MODEL_INPUT_CONTRACT_MISMATCH}。
 * 只有契约声明 nullable 的数值列允许缺失（以 NaN 交给图内插补），v4 没有这类字段。</p>
 */
final class InferencePayload {
    private static final int MAX_CATEGORY_LENGTH = 128;

    private InferencePayload() { }

    /** @param metadata 记录元数据；三项全缺时为 {@code null}，由门禁按契约判定 */
    record Parsed(RecordMetadata metadata, JsonNode features) { }

    /** @param reason 仅失败时非空，例如 {@code feature_missing:dur} */
    record Extraction(OnnxModelRuntime.FlowInput input, String reason) {
        boolean ok() { return input != null; }

        static Extraction invalid(String reason) { return new Extraction(null, reason); }
    }

    /** 载荷不是 JSON 对象时返回 {@code null}。 */
    static Parsed parse(ObjectMapper json, String payload) {
        if (payload == null || payload.isBlank()) return null;
        JsonNode root;
        try {
            root = json.readTree(payload);
        } catch (JsonProcessingException exception) {
            return null;
        }
        if (root == null || !root.isObject()) return null;
        return new Parsed(metadata(root.path("metadata")), root.path("features"));
    }

    static Extraction extract(JsonNode features, ModelInputContract inputs) {
        if (features == null || !features.isObject()) return Extraction.invalid("features_missing");
        double[] numeric = new double[inputs.numericCount()];
        for (int column = 0; column < numeric.length; column++) {
            String name = inputs.numericFields().get(column);
            JsonNode value = features.get(name);
            if (value == null || value.isNull()) {
                if (!inputs.numericNullable(column)) return Extraction.invalid("feature_missing:" + name);
                numeric[column] = Double.NaN;
                continue;
            }
            if (!value.isNumber()) return Extraction.invalid("feature_type:" + name);
            double number = value.doubleValue();
            if (!Double.isFinite(number)) return Extraction.invalid("feature_non_finite:" + name);
            numeric[column] = number;
        }
        String[] categorical = new String[inputs.categoricalCount()];
        for (int column = 0; column < categorical.length; column++) {
            String name = inputs.categoricalFields().get(column);
            JsonNode value = features.get(name);
            if (value == null || !value.isTextual()) return Extraction.invalid("feature_missing:" + name);
            if (value.asText().length() > MAX_CATEGORY_LENGTH) return Extraction.invalid("feature_too_long:" + name);
            categorical[column] = value.asText();
        }
        return new Extraction(new OnnxModelRuntime.FlowInput(numeric, categorical), null);
    }

    private static RecordMetadata metadata(JsonNode node) {
        if (node == null || !node.isObject()) return null;
        String viewpoint = node.path("viewpoint").isTextual() ? node.path("viewpoint").asText() : null;
        String family = node.path("addressFamily").isTextual() ? node.path("addressFamily").asText() : null;
        Boolean handshake = node.path("handshakeSeen").isBoolean() ? node.path("handshakeSeen").booleanValue() : null;
        if (viewpoint == null && family == null && handshake == null) return null;
        return new RecordMetadata(viewpoint, family, handshake);
    }
}
