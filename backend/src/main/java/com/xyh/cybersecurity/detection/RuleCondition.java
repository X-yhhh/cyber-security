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
 */
final class RuleCondition {
    static final int MAX_CLAUSES = 16;
    private static final Set<String> OPS = Set.of("eq", "ne", "gt", "gte", "lt", "lte");
    private static final Set<String> ORDERING = Set.of("gt", "gte", "lt", "lte");
    private static final Pattern FIELD = Pattern.compile("^(features|metadata)\\.[A-Za-z0-9_]{1,64}$");

    private record Clause(String section, String name, String field, String op, JsonNode value) { }

    private final List<Clause> clauses;

    private RuleCondition(List<Clause> clauses) { this.clauses = clauses; }

    /** @throws IllegalArgumentException 条件结构不合规，消息为稳定原因，不回显条件内容 */
    static RuleCondition parse(JsonNode node) {
        if (node == null || !node.isObject() || node.size() != 1 || !node.path("all").isArray()) {
            throw new IllegalArgumentException("condition_shape");
        }
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
        return new RuleCondition(List.copyOf(parsed));
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
            if (!actual.isNumber()) return false;
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
