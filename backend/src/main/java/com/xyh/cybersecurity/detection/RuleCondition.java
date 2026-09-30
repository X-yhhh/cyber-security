package com.xyh.cybersecurity.detection;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * 确定性检测规则的受限条件（数据库设计 §2.3：不允许任意脚本）。
 *
 * <p>形如 {@code {"all":[{"field":"features.ct_srv_src","op":"gte","value":50}]}}：只允许读取记录的
 * {@code features.*} 与 {@code metadata.*} 字段，比较运算限 eq/ne/gt/gte/lt/lte，全部条件同时满足才命中。
 * 字段缺失或类型不符视为不命中，不抛异常。</p>
 *
 * <p>可选 {@code window} 块把规则变为时间窗聚合规则（开发路线 §4.2）：{@code all} 只作为逐条过滤，
 * 同一资产在 {@code (t − seconds, t]} 内满足过滤的记录按 {@code aggregate} 聚合（{@code count} 计条数，
 * {@code sum} 对 {@code field} 求和），达到 {@code threshold} 时在当前记录上告警；告警后同一规则、同一资产
 * 在 {@code seconds} 内不再重复告警。窗口按记录事件时间计算，只用 v4 已有字段与元数据，不读对端地址。</p>
 */
final class RuleCondition {
    static final int MAX_CLAUSES = 16;
    static final int MIN_WINDOW_SECONDS = 10;
    static final int MAX_WINDOW_SECONDS = 3600;
    static final double MAX_THRESHOLD = 1e9;
    private static final Set<String> OPS = Set.of("eq", "ne", "gt", "gte", "lt", "lte");
    private static final Set<String> ORDERING = Set.of("gt", "gte", "lt", "lte");
    private static final Set<String> WINDOW_KEYS = Set.of("seconds", "aggregate", "field", "threshold", "groupBy");
    private static final Pattern FIELD = Pattern.compile("^(features|metadata)\\.[A-Za-z0-9_]{1,64}$");

    private record Clause(String section, String name, String field, String op, JsonNode value) { }

    /**
     * 时间窗聚合参数。
     *
     * @param seconds   窗口长度与告警抑制期（秒，10～3600）
     * @param aggregate {@code count} 或 {@code sum}
     * @param field     {@code sum} 的求和字段（仅 {@code features.*}）；{@code count} 时为 {@code null}
     * @param threshold 聚合值达到即告警（&gt; 0）
     */
    record Window(int seconds, String aggregate, String field, double threshold) {
        boolean sum() { return "sum".equals(aggregate); }

        /** 记录对聚合值的贡献；{@code sum} 字段缺失、非数值或为负时返回 {@code null}（该记录不计入）。 */
        Double contribution(JsonNode payload) {
            if (!sum()) return 1.0;
            int dot = field.indexOf('.');
            JsonNode value = payload.path(field.substring(0, dot)).get(field.substring(dot + 1));
            if (value == null || !value.isNumber() || !Double.isFinite(value.asDouble()) || value.asDouble() < 0) return null;
            return value.asDouble();
        }

        ObjectNode describe(ObjectMapper json) {
            ObjectNode node = json.createObjectNode().put("seconds", seconds).put("aggregate", aggregate)
                    .put("threshold", threshold).put("groupBy", "asset");
            if (field != null) node.put("field", field);
            return node;
        }
    }

    private final List<Clause> clauses;
    private final Window window;

    private RuleCondition(List<Clause> clauses, Window window) {
        this.clauses = clauses;
        this.window = window;
    }

    /** 时间窗参数；逐条规则为 {@code null}。 */
    Window window() { return window; }

    /** @throws IllegalArgumentException 条件结构不合规，消息为稳定原因，不回显条件内容 */
    static RuleCondition parse(JsonNode node) {
        if (node == null || !node.isObject() || !node.path("all").isArray()) {
            throw new IllegalArgumentException("condition_shape");
        }
        boolean windowed = node.has("window");
        if (node.size() != (windowed ? 2 : 1)) throw new IllegalArgumentException("condition_shape");
        JsonNode all = node.path("all");
        if (all.isEmpty() || all.size() > MAX_CLAUSES) throw new IllegalArgumentException("condition_clause_count");
        List<Clause> parsed = new ArrayList<>();
        for (JsonNode clause : all) {
            if (!clause.isObject() || clause.size() != 3) throw new IllegalArgumentException("clause_shape");
            String field = clause.path("field").asText("");
            String op = clause.path("op").asText("");
            JsonNode value = clause.path("value");
            if (!FIELD.matcher(field).matches()) throw new IllegalArgumentException("clause_field");
            if (!OPS.contains(op)) throw new IllegalArgumentException("clause_op");
            boolean scalar = value.isNumber() && Double.isFinite(value.asDouble())
                    || value.isTextual() && value.asText().length() <= 128 || value.isBoolean();
            if (!scalar || ORDERING.contains(op) && !value.isNumber()) throw new IllegalArgumentException("clause_value");
            int dot = field.indexOf('.');
            parsed.add(new Clause(field.substring(0, dot), field.substring(dot + 1), field, op, value.deepCopy()));
        }
        return new RuleCondition(List.copyOf(parsed), windowed ? window(node.get("window")) : null);
    }

    private static Window window(JsonNode node) {
        if (node == null || !node.isObject()) throw new IllegalArgumentException("window_shape");
        node.fieldNames().forEachRemaining(name -> {
            if (!WINDOW_KEYS.contains(name)) throw new IllegalArgumentException("window_shape");
        });
        JsonNode seconds = node.path("seconds");
        if (!seconds.isIntegralNumber() || seconds.asLong() < MIN_WINDOW_SECONDS || seconds.asLong() > MAX_WINDOW_SECONDS) {
            throw new IllegalArgumentException("window_seconds");
        }
        // 本期只按资产聚合：v4 不入库对端地址，也没有端口字段（路线 B §21）。
        if (node.has("groupBy") && !"asset".equals(node.path("groupBy").asText(""))) {
            throw new IllegalArgumentException("window_group_by");
        }
        String aggregate = node.path("aggregate").asText("");
        String field = null;
        if ("sum".equals(aggregate)) {
            field = node.path("field").asText("");
            if (!FIELD.matcher(field).matches() || !field.startsWith("features.")) {
                throw new IllegalArgumentException("window_field");
            }
        } else if (!"count".equals(aggregate) || node.has("field")) {
            throw new IllegalArgumentException("window_aggregate");
        }
        JsonNode threshold = node.path("threshold");
        if (!threshold.isNumber() || !Double.isFinite(threshold.asDouble()) || threshold.asDouble() <= 0
                || threshold.asDouble() > MAX_THRESHOLD) {
            throw new IllegalArgumentException("window_threshold");
        }
        return new Window(seconds.asInt(), aggregate, field, threshold.asDouble());
    }

    /** @return 命中时各条件字段的实际取值（写入评分依据）；未命中为 {@code null} */
    ObjectNode match(JsonNode payload, ObjectMapper json) {
        ObjectNode matched = json.createObjectNode();
        for (Clause clause : clauses) {
            JsonNode actual = payload.path(clause.section()).get(clause.name());
            if (actual == null || !holds(actual, clause)) return null;
            matched.set(clause.field(), actual.deepCopy());
        }
        return matched;
    }

    private static boolean holds(JsonNode actual, Clause clause) {
        JsonNode expected = clause.value();
        if (expected.isNumber()) {
            if (!actual.isNumber() || !Double.isFinite(actual.asDouble())) return false;
            int cmp = Double.compare(actual.asDouble(), expected.asDouble());
            return switch (clause.op()) {
                case "eq" -> cmp == 0;
                case "ne" -> cmp != 0;
                case "gt" -> cmp > 0;
                case "gte" -> cmp >= 0;
                case "lt" -> cmp < 0;
                default -> cmp <= 0;
            };
        }
        boolean sameType = expected.isTextual() ? actual.isTextual() : actual.isBoolean();
        boolean equal = sameType && actual.asText().equals(expected.asText());
        return "eq".equals(clause.op()) ? equal : sameType && !equal;
    }
}
