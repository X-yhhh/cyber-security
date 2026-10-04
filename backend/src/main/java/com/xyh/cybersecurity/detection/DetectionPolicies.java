package com.xyh.cybersecurity.detection;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * 一个批次使用的三类 active 检测策略快照（路线 B §11）：告警分级、事件关联时间窗、风险评分参数。
 *
 * <p>参数不合规或缺少 active 版本时抛 {@link DetectionUnavailableException}，不使用内置默认值兜底，
 * 否则告警上记录的策略版本与实际计算口径会不一致。</p>
 */
record DetectionPolicies(Severity severity, Correlation correlation, Risk risk) {
    static final Set<String> SEVERITIES = Set.of("low", "medium", "high", "critical");
    static final List<String> SEVERITY_ORDER = List.of("low", "medium", "high", "critical");

    /** @param bands 按 {@code minScore} 严格递减；最后一档须为 0，保证任何合法分数都有落点 */
    record Severity(String version, List<Band> bands, Signal signal) {
        Severity(String version, List<Band> bands) { this(version, bands, null); }
        String map(double score) {
            for (Band band : bands) if (score >= band.minScore()) return band.severity();
            return bands.getLast().severity();
        }

        /** 命中档位的下限，写入告警评分依据。 */
        double bandFloor(double score) {
            for (Band band : bands) if (score >= band.minScore()) return band.minScore();
            return bands.getLast().minScore();
        }
    }

    /** 分层只改变人工队列入口，模型原始判定及阈值不变。 */
    record Signal(boolean enabled, int countThreshold, double highScore) { }

    /** 登记与消费共用参数校验；新版本不得遗漏显式的分层开关。 */
    static void validate(String type, JsonNode config) {
        if (config == null || !config.isObject()) throw invalid();
        Set<String> allowed = switch (type) {
            case "severity_mapping" -> Set.of("model", "modelSignal");
            case "correlation" -> Set.of("windowSeconds", "dimensions");
            case "risk_score" -> Set.of("severityWeight", "criticalityWeight", "repeatStep", "repeatCap");
            default -> throw invalid();
        };
        config.fieldNames().forEachRemaining(k -> { if (!allowed.contains(k)) throw invalid(); });
        Loaded loaded = new Loaded("validation", config);
        switch (type) {
            case "severity_mapping" -> {
                if (!config.has("modelSignal")) throw invalid();
                severity(loaded);
            }
            case "correlation" -> correlation(loaded);
            case "risk_score" -> risk(loaded);
            default -> throw invalid();
        }
    }

    record Band(double minScore, String severity) { }

    record Correlation(String version, long windowSeconds) { }

    record Risk(String version, Map<String, Double> severityWeight, Map<String, Double> criticalityWeight,
                double repeatStep, double repeatCap) { }

    static DetectionPolicies load(DetectionMapper mapper, ObjectMapper json) {
        return new DetectionPolicies(severity(read(mapper, json, "severity_mapping")),
                correlation(read(mapper, json, "correlation")), risk(read(mapper, json, "risk_score")));
    }

    static int rank(String severity) { return SEVERITY_ORDER.indexOf(severity); }

    private record Loaded(String version, JsonNode config) { }

    private static Loaded read(DetectionMapper mapper, ObjectMapper json, String type) {
        DetectionMapper.PolicyRow row = mapper.findActivePolicy(type);
        if (row == null) throw new DetectionUnavailableException("DETECTION_POLICY_UNAVAILABLE");
        try {
            JsonNode config = json.readTree(row.configJson());
            if (config == null || !config.isObject()) throw new DetectionUnavailableException("DETECTION_POLICY_INVALID");
            return new Loaded(row.version(), config);
        } catch (JsonProcessingException exception) {
            throw new DetectionUnavailableException("DETECTION_POLICY_INVALID");
        }
    }

    private static Severity severity(Loaded loaded) {
        JsonNode bands = loaded.config().path("model");
        if (!bands.isArray() || bands.isEmpty()) throw invalid();
        List<Band> parsed = new ArrayList<>();
        double previous = Double.POSITIVE_INFINITY;
        for (JsonNode band : bands) {
            double min = unit(band.path("minScore"));
            String severity = band.path("severity").asText("");
            if (!SEVERITIES.contains(severity) || min >= previous) throw invalid();
            parsed.add(new Band(min, severity));
            previous = min;
        }
        if (parsed.getLast().minScore() != 0.0) throw invalid();
        Signal signal = null;
        if (loaded.config().has("modelSignal")) {
            JsonNode node = loaded.config().get("modelSignal");
            if (!node.isObject() || node.size() != 3 || !node.path("enabled").isBoolean()
                    || !node.path("countThreshold").isIntegralNumber() || !node.path("countThreshold").canConvertToInt()
                    || node.path("countThreshold").asInt() < 2 || node.path("countThreshold").asInt() > 10000) throw invalid();
            double high = unit(node.path("highScore"));
            if (high <= 0) throw invalid();
            signal = new Signal(node.path("enabled").asBoolean(), node.path("countThreshold").asInt(), high);
        }
        return new Severity(loaded.version(), List.copyOf(parsed), signal);
    }

    private static Correlation correlation(Loaded loaded) {
        JsonNode window = loaded.config().path("windowSeconds");
        JsonNode dimensions = loaded.config().path("dimensions");
        // 本期只支持资产维度（v4 不入库对端地址，路线 B §21）；声明其他维度说明策略与实现不一致。
        if (!window.isIntegralNumber() || !window.canConvertToLong() || window.asLong() < 60 || window.asLong() > 86_400
                || !dimensions.isArray() || dimensions.size() != 1 || !"asset".equals(dimensions.get(0).asText())) {
            throw invalid();
        }
        return new Correlation(loaded.version(), window.asLong());
    }

    private static Risk risk(Loaded loaded) {
        Map<String, Double> severityWeight = weights(loaded.config().path("severityWeight"));
        Map<String, Double> criticalityWeight = weights(loaded.config().path("criticalityWeight"));
        if (!severityWeight.keySet().equals(SEVERITIES) || !criticalityWeight.containsKey("medium")) throw invalid();
        return new Risk(loaded.version(), severityWeight, criticalityWeight,
                unit(loaded.config().path("repeatStep")), unit(loaded.config().path("repeatCap")));
    }

    private static Map<String, Double> weights(JsonNode node) {
        if (!node.isObject() || node.isEmpty()) throw invalid();
        Map<String, Double> weights = new TreeMap<>();
        node.fields().forEachRemaining(entry -> weights.put(entry.getKey(), unit(entry.getValue())));
        return Map.copyOf(weights);
    }

    private static double unit(JsonNode value) {
        if (!value.isNumber() || !Double.isFinite(value.asDouble()) || value.asDouble() < 0 || value.asDouble() > 1) {
            throw invalid();
        }
        return value.asDouble();
    }

    private static DetectionUnavailableException invalid() {
        return new DetectionUnavailableException("DETECTION_POLICY_INVALID");
    }
}
