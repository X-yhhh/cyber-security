package com.xyh.cybersecurity.ingest.contract;

import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * 按已注册契约严格校验传感器上报的 raw fields；期望版本、字段集、单位约束与识别规则全部来自契约文件，
 * 不在代码中硬编码版本字面量或类别词表。
 *
 * <p>阻断（记录 rejected）：契约未登记、字段缺失/多余、非有限数、越界、非整数、类别格式非法、
 * {@code service} 不是契约规则可能产生的值、违反契约声明的边界约束、v4 记录缺少视角/地址族/握手元数据。</p>
 *
 * <p>非阻断遥测：类别不在激活模型词表内（{@code CATEGORY_OUT_OF_VOCABULARY}，ONNX 图按 −1 编码）、
 * 没有绑定该契约的激活模型（{@code VOCABULARY_UNAVAILABLE}）、视角或地址族不在模型评估范围
 * （{@code NOT_IN_MODEL_SCOPE}）。最终是否推理由推理入口门禁判定。</p>
 */
@Component
public final class FeatureContractValidator {
    /** 规格 §2.2：IANA 关键字小写；表外协议号记 {@code proto-<号>}。 */
    private static final String PROTO_PATTERN = "[a-z0-9][a-z0-9.+/-]{0,31}";

    private final FeatureContractRegistry registry;
    private final ActiveModelInputs activeModel;

    @Autowired
    public FeatureContractValidator(FeatureContractRegistry registry, ObjectProvider<ActiveModelInputs> activeModel) {
        this(registry, activeModel.getIfAvailable(() -> ActiveModelInputs.NONE));
    }

    public FeatureContractValidator(FeatureContractRegistry registry, ActiveModelInputs activeModel) {
        this.registry = registry;
        this.activeModel = activeModel;
    }

    /** 不带元数据的校验；对要求元数据的契约（v4）会产生 {@code RECORD_METADATA_INVALID}。 */
    public FeatureValidationResult validate(String version, JsonNode features) {
        return validate(version, features, null);
    }

    /**
     * 校验一条记录的特征与元数据。
     *
     * @param version  批次声明的契约版本
     * @param features 原始特征对象
     * @param metadata 视角、地址族、握手可见性；契约未声明视角时可为 {@code null}
     */
    public FeatureValidationResult validate(String version, JsonNode features, RecordMetadata metadata) {
        FeatureContract contract = registry.find(version);
        if (contract == null) {
            return FeatureValidationResult.rejected(issue("FEATURE_CONTRACT_MISMATCH", "featureContractVersion",
                    "registered contract", "unregistered"));
        }
        if (features == null || !features.isObject()) {
            return FeatureValidationResult.rejected(issue("REQUIRED_FIELD_MISSING", "features", "object", type(features)));
        }
        List<FeatureValidationResult.Issue> issues = new ArrayList<>();
        Set<String> allowed = new HashSet<>(contract.numericFieldNames());
        allowed.addAll(contract.categoricalFieldNames());
        features.fieldNames().forEachRemaining(field -> {
            if (!allowed.contains(field)) issues.add(issue("FEATURE_CONTRACT_MISMATCH", field, "declared contract field", "unknown"));
        });
        Set<String> validNumeric = new HashSet<>();
        for (FeatureContract.NumericField field : contract.numericFields()) {
            if (checkNumeric(field, features.get(field.name()), issues)) validNumeric.add(field.name());
        }
        Set<String> validCategorical = new HashSet<>();
        for (FeatureContract.CategoricalField field : contract.categoricalFields()) {
            if (checkCategorical(contract, field, features.get(field.name()), issues)) validCategorical.add(field.name());
        }
        checkConsistency(contract, features, validNumeric, validCategorical, issues);
        boolean metadataValid = checkMetadata(contract, metadata, issues);
        List<FeatureValidationResult.Issue> advisories = advisories(contract, features, validCategorical,
                metadataValid ? metadata : null);
        return new FeatureValidationResult(issues.isEmpty(), issues, advisories);
    }

    private static boolean checkNumeric(FeatureContract.NumericField field, JsonNode node,
                                        List<FeatureValidationResult.Issue> issues) {
        if (node == null) {
            issues.add(issue("REQUIRED_FIELD_MISSING", field.name(), "finite number", "missing"));
            return false;
        }
        if (node.isNull()) {
            if (!field.nullable()) issues.add(issue("REQUIRED_FIELD_MISSING", field.name(), "finite number", "null"));
            return false;
        }
        if (!node.isNumber() || !Double.isFinite(node.asDouble())) {
            issues.add(issue("FEATURE_VALUE_INVALID", field.name(), "finite number", type(node)));
            return false;
        }
        double value = node.asDouble();
        if (value < field.min() || (field.max() != null && value > field.max())) {
            issues.add(issue("FEATURE_VALUE_INVALID", field.name(), range(field), "out of range"));
            return false;
        }
        if (field.integer() && value != Math.rint(value)) {
            issues.add(issue("FEATURE_VALUE_INVALID", field.name(), "integer", "fractional"));
            return false;
        }
        return true;
    }

    private static boolean checkCategorical(FeatureContract contract, FeatureContract.CategoricalField field, JsonNode node,
                                            List<FeatureValidationResult.Issue> issues) {
        if (node == null || !node.isTextual() || node.textValue().isBlank() || node.textValue().length() > 64
                || !node.textValue().equals(node.textValue().toLowerCase(Locale.ROOT))) {
            issues.add(issue("FEATURE_VALUE_INVALID", field.name(), "lower-case non-empty string of at most 64 characters", type(node)));
            return false;
        }
        String value = node.textValue();
        if ("iana_protocol_keyword_lowercase".equals(field.rule()) && !value.matches(PROTO_PATTERN)) {
            issues.add(issue("FEATURE_VALUE_INVALID", field.name(), "IANA protocol keyword or proto-<number>", "malformed"));
            return false;
        }
        if ("service_rules".equals(field.rule()) && !contract.serviceRules().possibleValues().contains(value)) {
            // service 只能由契约端口表产生（规格 §2.3），其他取值说明来源识别口径与契约不一致。
            issues.add(issue("FEATURE_VALUE_INVALID", field.name(), "value produced by contract service rules", "not produced by rules"));
            return false;
        }
        return true;
    }

    /** 只在参与字段本身都合法时判定跨字段约束，避免同一缺陷重复计数。 */
    private static void checkConsistency(FeatureContract contract, JsonNode f, Set<String> numeric, Set<String> categorical,
                                         List<FeatureValidationResult.Issue> issues) {
        for (ConsistencyRule rule : contract.consistencyRules()) {
            switch (rule) {
                case HANDSHAKE_ZERO_WHEN_NOT_TCP -> {
                    if (!categorical.contains("proto") || !numeric.containsAll(List.of("synack", "ackdat", "tcprtt"))) continue;
                    if (!"tcp".equals(f.get("proto").textValue()) && (f.get("synack").asDouble() != 0
                            || f.get("ackdat").asDouble() != 0 || f.get("tcprtt").asDouble() != 0)) {
                        issues.add(issue("FEATURE_VALUE_INVALID", "synack", "0 for non-TCP flows", "non-zero"));
                    }
                }
                case REVERSE_DIRECTION_ZERO_WHEN_NO_PACKETS -> {
                    if (!numeric.containsAll(List.of("dpkts", "dbytes", "dmean", "dload"))) continue;
                    if (f.get("dpkts").asDouble() == 0 && (f.get("dbytes").asDouble() != 0
                            || f.get("dmean").asDouble() != 0 || f.get("dload").asDouble() != 0)) {
                        issues.add(issue("FEATURE_VALUE_INVALID", "dbytes", "0 when dpkts = 0", "non-zero"));
                    }
                }
                case LOAD_ZERO_WHEN_INSUFFICIENT_PACKETS_OR_DURATION -> {
                    if (!numeric.containsAll(List.of("dur", "spkts", "dpkts", "sload", "dload"))) continue;
                    boolean noDuration = f.get("dur").asDouble() == 0;
                    if ((noDuration || f.get("spkts").asDouble() <= 1) && f.get("sload").asDouble() != 0) {
                        issues.add(issue("FEATURE_VALUE_INVALID", "sload", "0 when dur = 0 or spkts <= 1", "non-zero"));
                    }
                    if ((noDuration || f.get("dpkts").asDouble() <= 1) && f.get("dload").asDouble() != 0) {
                        issues.add(issue("FEATURE_VALUE_INVALID", "dload", "0 when dur = 0 or dpkts <= 1", "non-zero"));
                    }
                }
            }
        }
    }

    private static boolean checkMetadata(FeatureContract contract, RecordMetadata metadata,
                                         List<FeatureValidationResult.Issue> issues) {
        if (!contract.requiresRecordMetadata()) return metadata == null || metadata.viewpoint() == null;
        int before = issues.size();
        if (metadata == null || metadata.viewpoint() == null || !contract.viewpoints().contains(metadata.viewpoint())) {
            issues.add(issue("RECORD_METADATA_INVALID", "viewpoint", String.join("|", contract.viewpoints()), metadata == null ? "missing" : "invalid"));
        }
        if (metadata == null || metadata.addressFamily() == null || !contract.addressFamilies().contains(metadata.addressFamily())) {
            issues.add(issue("RECORD_METADATA_INVALID", "addressFamily", String.join("|", contract.addressFamilies()), metadata == null ? "missing" : "invalid"));
        }
        if (metadata == null || metadata.handshakeSeen() == null) {
            issues.add(issue("RECORD_METADATA_INVALID", "handshakeSeen", "boolean", "missing"));
        }
        return issues.size() == before;
    }

    private List<FeatureValidationResult.Issue> advisories(FeatureContract contract, JsonNode features,
                                                           Set<String> validCategorical, RecordMetadata metadata) {
        List<FeatureValidationResult.Issue> out = new ArrayList<>();
        Optional<ActiveModelInputs.Scope> scope = activeModel.forContract(contract.version());
        if (scope.isEmpty()) {
            out.add(issue("VOCABULARY_UNAVAILABLE", "features", "active model bound to " + contract.version(), "none"));
            return out;
        }
        Map<String, Set<String>> vocabularies = scope.get().vocabularies();
        for (String field : contract.categoricalFieldNames()) {
            if (!validCategorical.contains(field)) continue;
            Set<String> vocabulary = vocabularies.get(field);
            // 只记录字段级漂移，不把传感器提供的类别字符串写入质量记录。
            if (vocabulary != null && !vocabulary.contains(features.get(field).textValue())) {
                out.add(issue("CATEGORY_OUT_OF_VOCABULARY", field, "model vocabulary", "out_of_vocabulary"));
            }
        }
        JsonNode proto = features == null ? null : features.get("proto");
        if (contract.requiresRecordMetadata() && metadata != null
                && !scope.get().covers(metadata, proto != null && proto.isTextual() ? proto.asText() : null)) {
            out.add(issue("NOT_IN_MODEL_SCOPE", "metadata", "model evaluation scope", "outside"));
        }
        return out;
    }

    private static String range(FeatureContract.NumericField field) {
        return field.max() == null ? ">= " + field.min() : field.min() + ".." + field.max();
    }

    private static FeatureValidationResult.Issue issue(String code, String field, String expected, String actual) {
        return new FeatureValidationResult.Issue(code, field, expected, actual);
    }

    private static String type(JsonNode node) {
        if (node == null || node.isNull()) return "null";
        if (node.isNumber()) return "number";
        if (node.isTextual()) return "string";
        if (node.isBoolean()) return "boolean";
        return node.getNodeType().name().toLowerCase(Locale.ROOT);
    }
}
