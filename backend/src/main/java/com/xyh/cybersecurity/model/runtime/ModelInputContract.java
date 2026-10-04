package com.xyh.cybersecurity.model.runtime;

import com.fasterxml.jackson.databind.JsonNode;
import com.xyh.cybersecurity.ingest.contract.FeatureContract;
import com.xyh.cybersecurity.model.validation.ModelContractException;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 从模型 manifest 与 preprocessing.json 解析出的模型输入契约（路线 B §9.1 第 4 项）。
 *
 * <p>取代原 {@code OnnxModelRuntime.NUMERIC_FEATURE_COUNT = 26} 常量：输入维度、字段顺序、单位与类别词表都来自
 * 交付包，并与三方交叉核对：</p>
 * <ol>
 *   <li>manifest {@code feature_contract.inputs} ↔ preprocessing.json {@code inputs.*.fields}（名称、下标、单位）；</li>
 *   <li>manifest ↔ 后端已注册的特征契约（版本、数值字段顺序与单位、类别字段、{@code spec_sha256}）；</li>
 *   <li>manifest ↔ ONNX 图输入形状（由 {@link OnnxModelRuntime#open} 执行）。</li>
 * </ol>
 *
 * <p>v3.1 交付包的 manifest 只有字段名，没有单位；此时只核对名称与顺序（v3.1 契约 {@code onlineEnabled=false}，
 * 仅用于离线回放）。v4 起单位必须逐项一致，否则 {@code MODEL_INPUT_CONTRACT_MISMATCH}。</p>
 *
 * @param numericFields             ONNX {@code flow_numeric} 列顺序
 * @param categoricalFields         ONNX {@code flow_categorical} 列顺序
 * @param nullableNumericFields     契约声明可空的数值字段（NaN 表示缺失，由图内插补）；v4 为空
 * @param vocabularies              类别字段 → 训练词表（仅作漂移遥测；编码在 ONNX 图内完成）
 * @param supportedViewpoints       manifest 声明的评估视角；v3.1 为空
 * @param supportedAddressFamilies  manifest 声明的评估地址族；v3.1 为空
 * @param supportedProtocols        manifest {@code supported_protocols}（{@code proto} 取值，如 {@code tcp}）；
 *                                  空表示不按协议限制（{@code 2026.10.1} 及以前的交付包）
 * @param requiresHandshakeSeen     manifest {@code requires_handshake_seen}；为 true 时只评估元数据
 *                                  {@code handshakeSeen=true} 的记录（开发路线 §3.7 A1）
 */
public record ModelInputContract(String contractVersion, String specSha256, List<String> numericFields,
                                 List<String> categoricalFields, Set<String> nullableNumericFields,
                                 Map<String, Set<String>> vocabularies,
                                 List<String> supportedViewpoints, List<String> supportedAddressFamilies,
                                 List<String> supportedProtocols, boolean requiresHandshakeSeen) {
    private static final java.util.regex.Pattern PROTOCOL = java.util.regex.Pattern.compile("^[a-z0-9][a-z0-9-]{0,31}$");

    public ModelInputContract {
        numericFields = List.copyOf(numericFields);
        categoricalFields = List.copyOf(categoricalFields);
        nullableNumericFields = Set.copyOf(nullableNumericFields);
        vocabularies = Map.copyOf(vocabularies);
        supportedViewpoints = List.copyOf(supportedViewpoints);
        supportedAddressFamilies = List.copyOf(supportedAddressFamilies);
        supportedProtocols = List.copyOf(supportedProtocols);
    }

    /** 不限制协议与握手的评估范围（{@code 2026.10.1} 及以前的交付包口径）。 */
    public ModelInputContract(String contractVersion, String specSha256, List<String> numericFields,
                              List<String> categoricalFields, Set<String> nullableNumericFields,
                              Map<String, Set<String>> vocabularies,
                              List<String> supportedViewpoints, List<String> supportedAddressFamilies) {
        this(contractVersion, specSha256, numericFields, categoricalFields, nullableNumericFields, vocabularies,
                supportedViewpoints, supportedAddressFamilies, List.of(), false);
    }

    public int numericCount() { return numericFields.size(); }

    public int categoricalCount() { return categoricalFields.size(); }

    /** 第 {@code column} 个数值列是否允许 NaN（仅契约声明 nullable 的字段）。 */
    public boolean numericNullable(int column) { return nullableNumericFields.contains(numericFields.get(column)); }

    /**
     * 解析并交叉核对。
     *
     * @param manifest      已核对哈希的 model_manifest.json
     * @param preprocessing 已核对哈希的 preprocessing.json
     * @param contract      后端注册表中与 manifest 版本同名的契约；{@code null} 表示未登记，直接拒绝
     * @throws ModelContractException 任一项不一致（稳定错误码，不回显交付包内容）
     */
    public static ModelInputContract from(JsonNode manifest, JsonNode preprocessing, FeatureContract contract) {
        String version = manifest.at("/feature_contract/version").asText("");
        if (contract == null || !contract.version().equals(version)) throw mismatch("MODEL_FEATURE_CONTRACT_UNREGISTERED");
        if (!version.equals(preprocessing.path("contract_version").asText())) {
            throw mismatch("MODEL_PREPROCESSING_CONTRACT_MISMATCH");
        }
        JsonNode inputs = manifest.at("/feature_contract/inputs");
        List<ManifestField> numeric = manifestFields(inputs.path("flow_numeric"));
        List<ManifestField> categorical = manifestFields(inputs.path("flow_categorical"));
        if (numeric.isEmpty() || categorical.isEmpty()) throw mismatch("MODEL_INPUT_CONTRACT_MISMATCH");

        JsonNode prepNumeric = preprocessing.at("/inputs/flow_numeric/fields");
        JsonNode prepCategorical = preprocessing.at("/inputs/flow_categorical/fields");
        requirePreprocessingOrder(numeric, prepNumeric, true);
        requirePreprocessingOrder(categorical, prepCategorical, false);
        if (preprocessing.at("/inputs/flow_numeric/shape/1").asInt(-1) != numeric.size()
                || preprocessing.at("/inputs/flow_categorical/shape/1").asInt(-1) != categorical.size()) {
            throw mismatch("MODEL_PREPROCESSING_CONTRACT_MISMATCH");
        }

        List<String> numericNames = numeric.stream().map(ManifestField::name).toList();
        List<String> categoricalNames = categorical.stream().map(ManifestField::name).toList();
        if (!numericNames.equals(contract.numericFieldNames()) || !categoricalNames.equals(contract.categoricalFieldNames())) {
            throw mismatch("MODEL_INPUT_CONTRACT_MISMATCH");
        }
        Set<String> nullable = new LinkedHashSet<>();
        for (int i = 0; i < numeric.size(); i++) {
            FeatureContract.NumericField declared = contract.numericFields().get(i);
            // preprocessing.json 声明了 nullable 时必须与契约一致；可空集合只取自契约，不由交付包扩大。
            JsonNode prepNullable = prepNumeric.get(i).path("nullable");
            if (prepNullable.isBoolean() && prepNullable.asBoolean() != declared.nullable()) {
                throw mismatch("MODEL_PREPROCESSING_CONTRACT_MISMATCH");
            }
            if (declared.nullable()) nullable.add(declared.name());
            String unit = numeric.get(i).unit();
            // 契约声明了单位时，manifest 必须给出同一单位；历史契约没有单位，只核对名称顺序。
            if (declared.unit() != null && (unit == null || !declared.unit().manifestLabel().equals(unit))) {
                throw mismatch("MODEL_INPUT_UNIT_MISMATCH");
            }
        }
        String specSha = manifest.at("/feature_contract/spec_sha256").asText(null);
        if (contract.specSha256() != null && !contract.specSha256().equals(specSha)) {
            throw mismatch("MODEL_SPEC_HASH_MISMATCH");
        }

        Map<String, Set<String>> vocabularies = new LinkedHashMap<>();
        for (JsonNode field : prepCategorical) {
            JsonNode vocabulary = field.path("vocabulary");
            if (!vocabulary.isArray() || vocabulary.isEmpty()) throw mismatch("MODEL_PREPROCESSING_CONTRACT_MISMATCH");
            Set<String> values = new LinkedHashSet<>();
            vocabulary.forEach(value -> values.add(value.asText()));
            vocabularies.put(field.path("name").asText(), Set.copyOf(values));
        }
        List<String> viewpoints = textList(manifest.at("/feature_contract/supported_viewpoints"));
        List<String> families = textList(manifest.at("/feature_contract/supported_address_families"));
        if (contract.requiresRecordMetadata() && (viewpoints.isEmpty() || families.isEmpty()
                || !contract.viewpoints().containsAll(viewpoints) || !contract.addressFamilies().containsAll(families))) {
            // v4 起模型必须声明评估范围，且只能是契约允许的取值；否则无法判定 not_in_model_scope。
            throw mismatch("MODEL_SCOPE_CONTRACT_MISMATCH");
        }
        // 协议与握手范围（可选，2026.10.2 起声明）：只收窄评估范围，不改变输入字段；
        // 握手只对 TCP 有定义，声明 requires_handshake_seen 时协议范围必须只含 tcp。
        List<String> protocols = textList(manifest.at("/feature_contract/supported_protocols"));
        if (protocols.stream().anyMatch(value -> !PROTOCOL.matcher(value).matches())
                || protocols.stream().distinct().count() != protocols.size()
                || vocabularies.containsKey("proto") && !vocabularies.get("proto").containsAll(protocols)) {
            throw mismatch("MODEL_SCOPE_CONTRACT_MISMATCH");
        }
        JsonNode handshakeNode = manifest.at("/feature_contract/requires_handshake_seen");
        if (!handshakeNode.isMissingNode() && !handshakeNode.isBoolean()) throw mismatch("MODEL_SCOPE_CONTRACT_MISMATCH");
        boolean requiresHandshake = handshakeNode.asBoolean(false);
        if (requiresHandshake && (!contract.requiresRecordMetadata() || !protocols.equals(List.of("tcp")))) {
            throw mismatch("MODEL_SCOPE_CONTRACT_MISMATCH");
        }
        if (!protocols.isEmpty() && !contract.requiresRecordMetadata()) throw mismatch("MODEL_SCOPE_CONTRACT_MISMATCH");
        return new ModelInputContract(version, specSha, numericNames, categoricalNames, nullable, vocabularies,
                viewpoints, families, protocols, requiresHandshake);
    }

    /** manifest 字段可为字符串（v3.1）或 {@code {name, unit}} 对象（v4 起）。 */
    private static List<ManifestField> manifestFields(JsonNode node) {
        if (!node.isArray()) return List.of();
        List<ManifestField> fields = new ArrayList<>();
        for (JsonNode item : node) {
            if (item.isTextual()) fields.add(new ManifestField(item.asText(), null));
            else if (item.isObject() && item.path("name").isTextual()) {
                fields.add(new ManifestField(item.path("name").asText(), item.path("unit").isTextual() ? item.path("unit").asText() : null));
            } else throw mismatch("MODEL_INPUT_CONTRACT_MISMATCH");
        }
        if (fields.stream().map(ManifestField::name).distinct().count() != fields.size()) throw mismatch("MODEL_INPUT_CONTRACT_MISMATCH");
        return List.copyOf(fields);
    }

    private static void requirePreprocessingOrder(List<ManifestField> manifest, JsonNode prep, boolean numeric) {
        if (!prep.isArray() || prep.size() != manifest.size()) throw mismatch("MODEL_PREPROCESSING_CONTRACT_MISMATCH");
        for (int i = 0; i < manifest.size(); i++) {
            JsonNode field = prep.get(i);
            if (!manifest.get(i).name().equals(field.path("name").asText()) || field.path("index").asInt(-1) != i) {
                throw mismatch("MODEL_PREPROCESSING_CONTRACT_MISMATCH");
            }
            String unit = manifest.get(i).unit();
            if (numeric && unit != null && !unit.equals(field.path("unit").asText())) {
                throw mismatch("MODEL_PREPROCESSING_CONTRACT_MISMATCH");
            }
        }
    }

    private static List<String> textList(JsonNode node) {
        if (node.isMissingNode()) return List.of();
        // 缺省允许兼容旧包；显式声明但类型错误不能退化为“不限制范围”。
        if (!node.isArray() || node.isEmpty()) throw mismatch("MODEL_SCOPE_CONTRACT_MISMATCH");
        List<String> out = new ArrayList<>();
        node.forEach(item -> { if (item.isTextual()) out.add(item.asText()); else throw mismatch("MODEL_SCOPE_CONTRACT_MISMATCH"); });
        return List.copyOf(out);
    }

    private static ModelContractException mismatch(String code) {
        return new ModelContractException(code);
    }

    private record ManifestField(String name, String unit) { }
}
