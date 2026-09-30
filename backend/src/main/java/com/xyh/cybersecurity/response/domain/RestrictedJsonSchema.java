package com.xyh.cybersecurity.response.domain;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * 受限 JSON Schema（Draft 2020-12 子集）校验器，只用于响应策略的 {@code match_json} 与动作参数。
 *
 * <p>只实现策略 Schema 实际用到的关键字：{@code type}、{@code required}、{@code properties}、
 * {@code additionalProperties}（仅 {@code false}）、{@code enum}、{@code minimum}/{@code maximum}、
 * {@code minLength}/{@code maxLength}、{@code pattern}、{@code items}、{@code minItems}/{@code maxItems}、
 * {@code uniqueItems}；注解关键字 {@code $schema}、{@code $id}、{@code title}、{@code description} 忽略。</p>
 *
 * <p>fail-closed：Schema 中出现任何未实现的关键字时加载失败（启动即报错），不会静默放过约束。
 * {@code pattern} 按整串匹配处理，Schema 作者须自行写 {@code ^...$}。这不是通用 JSON Schema 实现，
 * 不支持 {@code $ref}、组合关键字与格式断言。</p>
 */
public final class RestrictedJsonSchema {
    private static final Set<String> ANNOTATIONS = Set.of("$schema", "$id", "title", "description");
    private static final Set<String> KEYWORDS = Set.of("type", "required", "properties", "additionalProperties", "enum",
            "minimum", "maximum", "minLength", "maxLength", "pattern", "items", "minItems", "maxItems", "uniqueItems");
    private static final Set<String> TYPES = Set.of("object", "array", "string", "integer", "number", "boolean");

    private final JsonNode schema;
    private final Map<String, Pattern> patterns;

    private RestrictedJsonSchema(JsonNode schema, Map<String, Pattern> patterns) {
        this.schema = schema;
        this.patterns = patterns;
    }

    /** 从 classpath 加载并检查 Schema 只使用受支持的关键字。 */
    public static RestrictedJsonSchema load(ObjectMapper json, String classpathLocation) {
        try (InputStream in = RestrictedJsonSchema.class.getClassLoader().getResourceAsStream(classpathLocation)) {
            if (in == null) throw new IllegalStateException("响应策略 Schema 不存在: " + classpathLocation);
            return of(json.readTree(in));
        } catch (IOException exception) {
            throw new IllegalStateException("响应策略 Schema 无法读取: " + classpathLocation, exception);
        }
    }

    public static RestrictedJsonSchema of(JsonNode schema) {
        Map<String, Pattern> patterns = new java.util.HashMap<>();
        check(schema, "$", patterns);
        return new RestrictedJsonSchema(schema, Map.copyOf(patterns));
    }

    /** 返回全部违规（路径 + 原因），为空表示通过。违规信息不回显实例值，避免把输入原样写入错误。 */
    public List<String> validate(JsonNode instance) {
        List<String> errors = new ArrayList<>();
        validate(schema, instance, "$", errors);
        return errors;
    }

    private static void check(JsonNode node, String path, Map<String, Pattern> patterns) {
        if (!node.isObject()) throw new IllegalStateException("Schema 节点必须是对象: " + path);
        Iterator<String> names = node.fieldNames();
        while (names.hasNext()) {
            String name = names.next();
            if (!ANNOTATIONS.contains(name) && !KEYWORDS.contains(name)) {
                throw new IllegalStateException("Schema 使用了未实现的关键字 " + name + ": " + path);
            }
        }
        if (!node.has("type") || !TYPES.contains(node.path("type").asText())) {
            throw new IllegalStateException("Schema 必须声明受支持的 type: " + path);
        }
        if (node.has("additionalProperties") && !node.path("additionalProperties").isBoolean()) {
            throw new IllegalStateException("additionalProperties 只支持布尔值: " + path);
        }
        if (node.has("pattern")) patterns.put(path, Pattern.compile(node.path("pattern").asText()));
        node.path("properties").fields().forEachRemaining(e -> check(e.getValue(), path + "." + e.getKey(), patterns));
        if (node.has("items")) check(node.get("items"), path + "[]", patterns);
    }

    private void validate(JsonNode s, JsonNode value, String path, List<String> errors) {
        String type = s.path("type").asText();
        if (!typeMatches(type, value)) {
            errors.add(path + " 类型须为 " + type);
            return;
        }
        if (s.has("enum")) {
            boolean found = false;
            for (JsonNode option : s.get("enum")) found |= option.equals(value);
            if (!found) errors.add(path + " 取值不在允许集合内");
        }
        switch (type) {
            case "object" -> validateObject(s, value, path, errors);
            case "array" -> validateArray(s, value, path, errors);
            case "string" -> validateString(s, value.textValue(), path, errors);
            case "integer", "number" -> {
                if (s.has("minimum") && value.decimalValue().compareTo(s.get("minimum").decimalValue()) < 0) {
                    errors.add(path + " 小于下限 " + s.get("minimum").asText());
                }
                if (s.has("maximum") && value.decimalValue().compareTo(s.get("maximum").decimalValue()) > 0) {
                    errors.add(path + " 超过上限 " + s.get("maximum").asText());
                }
            }
            default -> { }
        }
    }

    private void validateObject(JsonNode s, JsonNode value, String path, List<String> errors) {
        for (JsonNode required : s.path("required")) {
            if (!value.has(required.asText())) errors.add(path + "." + required.asText() + " 缺失");
        }
        JsonNode properties = s.path("properties");
        boolean closed = s.has("additionalProperties") && !s.get("additionalProperties").asBoolean();
        value.fields().forEachRemaining(e -> {
            JsonNode child = properties.get(e.getKey());
            if (child != null) validate(child, e.getValue(), path + "." + e.getKey(), errors);
            else if (closed) errors.add(path + " 含未定义字段");
        });
    }

    private void validateArray(JsonNode s, JsonNode value, String path, List<String> errors) {
        if (s.has("minItems") && value.size() < s.get("minItems").asInt()) errors.add(path + " 元素过少");
        if (s.has("maxItems") && value.size() > s.get("maxItems").asInt()) errors.add(path + " 元素过多");
        if (s.path("uniqueItems").asBoolean(false)) {
            Set<JsonNode> seen = new HashSet<>();
            for (JsonNode element : value) if (!seen.add(element)) { errors.add(path + " 含重复元素"); break; }
        }
        if (s.has("items")) {
            int i = 0;
            for (JsonNode element : value) validate(s.get("items"), element, path + "[" + i++ + "]", errors);
        }
    }

    private void validateString(JsonNode s, String value, String path, List<String> errors) {
        int length = value.codePointCount(0, value.length());
        if (s.has("minLength") && length < s.get("minLength").asInt()) errors.add(path + " 过短");
        if (s.has("maxLength") && length > s.get("maxLength").asInt()) errors.add(path + " 过长");
        Pattern pattern = patterns.get(schemaPath(path));
        if (pattern != null && !pattern.matcher(value).matches()) errors.add(path + " 格式不符");
    }

    /** 实例路径中的数组下标 {@code [n]} 对应 Schema 路径中的 {@code []}。 */
    private static String schemaPath(String instancePath) {
        return instancePath.replaceAll("\\[\\d+]", "[]");
    }

    private static boolean typeMatches(String type, JsonNode value) {
        return switch (type) {
            case "object" -> value.isObject();
            case "array" -> value.isArray();
            case "string" -> value.isTextual();
            case "integer" -> value.isIntegralNumber();
            case "number" -> value.isNumber();
            case "boolean" -> value.isBoolean();
            default -> false;
        };
    }
}
