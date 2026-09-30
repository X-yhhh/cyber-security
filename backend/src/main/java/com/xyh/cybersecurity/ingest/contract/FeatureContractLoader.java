package com.xyh.cybersecurity.ingest.contract;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 解析并严格校验单份契约资源文件。任何结构、取值或一致性错误都抛出 {@link FeatureContractLoadException}，
 * 由注册表在启动时 fail-fast，不静默跳过、不补默认值。
 *
 * <p>支持两种格式：</p>
 * <ul>
 *   <li>历史格式（v3.1）：{@code numericFields} 为字段名字符串数组，无单位；只能 {@code onlineEnabled=false}，
 *       保留为 UNSW CSV 离线回放与历史对照，文件字节保持不变。</li>
 *   <li>结构化格式（v4 起）：字段带单位、来源、上下限；在线契约必须具备规格哈希、窗口、识别规则与 golden fixtures。</li>
 * </ul>
 *
 * <p>结构校验在此手写实现，覆盖路线 B §9.1 第 1 项要求的“字段唯一、顺序、单位枚举、specSha256 格式”，
 * 未引入额外的 JSON Schema 依赖；未知顶层键一律拒绝，防止拼写错误的约束被静默忽略。</p>
 */
public final class FeatureContractLoader {

    private static final String SHA256 = "[0-9a-f]{64}";
    private static final String FIELD_NAME = "[a-z][a-z0-9_]{0,63}";
    private static final List<String> WINDOW_ORDER = List.of("flowEndAt", "flowStartAt", "exportSeq");
    private static final Set<String> LEGACY_KEYS = Set.of("version", "manifest", "task", "numericFields",
            "categoricalFields", "nullableNumericFields", "onlineEnabled", "disabledReason");
    private static final Set<String> STRUCTURED_KEYS = Set.of("version", "task", "specDocument", "specSha256",
            "directionBasis", "viewpoints", "addressFamilies", "window", "flowClosure", "packetNormalization",
            "excludedFlows", "numericFields", "categoricalFields", "consistencyRules", "serviceRules",
            "removedFromV31", "goldenFixtures", "onlineEnabled", "onlineScope", "disabledReason");
    private static final Set<String> VIEWPOINTS = Set.of("responder", "initiator");
    private static final Set<String> ADDRESS_FAMILIES = Set.of("ipv4", "ipv6");

    private final ObjectMapper mapper;

    public FeatureContractLoader(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    /**
     * 解析一份契约。
     *
     * @param resourceName 资源文件名（如 {@code unsw-nb15-flow-v4.json}），必须等于 {@code version + ".json"}
     * @param bytes        文件原始字节；其 SHA-256 即契约文件哈希
     */
    public FeatureContract load(String resourceName, byte[] bytes) {
        JsonNode root;
        try {
            root = mapper.readTree(bytes);
        } catch (IOException exception) {
            throw fail(resourceName, "JSON 无法解析");
        }
        if (root == null || !root.isObject()) throw fail(resourceName, "顶层必须是 JSON 对象");
        String version = text(root, "version", resourceName);
        if (!version.matches("[a-z0-9][a-z0-9.-]{2,63}")) throw fail(resourceName, "version 格式无效");
        if (!(version + ".json").equals(resourceName)) throw fail(resourceName, "文件名必须等于 version + .json");
        JsonNode numeric = root.path("numericFields");
        if (!numeric.isArray() || numeric.isEmpty()) throw fail(resourceName, "numericFields 必须是非空数组");
        boolean legacy = numeric.get(0).isTextual();
        requireKnownKeys(root, legacy ? LEGACY_KEYS : STRUCTURED_KEYS, resourceName);
        FeatureContract contract = legacy ? legacy(root, version, resourceName, bytes)
                : structured(root, version, resourceName, bytes);
        validateCommon(contract, resourceName);
        return contract;
    }

    private FeatureContract legacy(JsonNode root, String version, String resource, byte[] bytes) {
        Set<String> nullable = new HashSet<>(stringList(root, "nullableNumericFields", resource, true));
        List<FeatureContract.NumericField> numeric = new ArrayList<>();
        for (JsonNode node : root.path("numericFields")) {
            if (!node.isTextual()) throw fail(resource, "历史格式 numericFields 只能是字符串");
            numeric.add(new FeatureContract.NumericField(node.asText(), null, FeatureContract.FieldSource.UNSPECIFIED,
                    nullable.contains(node.asText()), 0, null, false, false, null));
        }
        if (!nullable.stream().allMatch(name -> numeric.stream().anyMatch(field -> field.name().equals(name)))) {
            throw fail(resource, "nullableNumericFields 引用了未声明字段");
        }
        List<FeatureContract.CategoricalField> categorical = stringList(root, "categoricalFields", resource, false)
                .stream().map(name -> new FeatureContract.CategoricalField(name, "unspecified",
                        "active_model_preprocessing", null)).toList();
        boolean online = bool(root, "onlineEnabled", resource);
        if (online) throw fail(resource, "历史格式契约没有单位与规格哈希，不能 onlineEnabled=true");
        return new FeatureContract(version, text(root, "task", resource), null, null, null, numeric, categorical,
                List.of(), List.of(), null, null, List.of(), null, false, optionalText(root, "disabledReason"),
                resource, sha256(bytes));
    }

    private FeatureContract structured(JsonNode root, String version, String resource, byte[] bytes) {
        List<FeatureContract.NumericField> numeric = new ArrayList<>();
        for (JsonNode node : root.path("numericFields")) numeric.add(numericField(node, resource));
        List<FeatureContract.CategoricalField> categorical = new ArrayList<>();
        JsonNode categoricalNodes = root.path("categoricalFields");
        if (!categoricalNodes.isArray()) throw fail(resource, "categoricalFields 必须是数组");
        for (JsonNode node : categoricalNodes) {
            if (!node.isObject()) throw fail(resource, "categoricalFields 元素必须是对象");
            categorical.add(new FeatureContract.CategoricalField(text(node, "name", resource),
                    text(node, "rule", resource), text(node, "vocabularySource", resource),
                    optionalText(node, "specSection")));
        }
        String specSha = optionalText(root, "specSha256");
        if (specSha != null && !specSha.matches(SHA256)) throw fail(resource, "specSha256 必须是 64 位小写十六进制");
        String direction = optionalText(root, "directionBasis");
        if (direction != null && !"initiator_to_responder".equals(direction)) {
            throw fail(resource, "directionBasis 只能是 initiator_to_responder");
        }
        List<String> viewpoints = stringList(root, "viewpoints", resource, true);
        if (!VIEWPOINTS.containsAll(viewpoints) || new HashSet<>(viewpoints).size() != viewpoints.size()) {
            throw fail(resource, "viewpoints 取值无效或重复");
        }
        List<String> families = stringList(root, "addressFamilies", resource, true);
        if (!ADDRESS_FAMILIES.containsAll(families) || new HashSet<>(families).size() != families.size()) {
            throw fail(resource, "addressFamilies 取值无效或重复");
        }
        List<ConsistencyRule> rules = new ArrayList<>();
        for (String code : stringList(root, "consistencyRules", resource, true)) {
            rules.add(ConsistencyRule.fromCode(code).orElseThrow(() -> fail(resource, "未知 consistencyRules: " + code)));
        }
        requireOptionalType(root, "flowClosure", JsonNode::isObject, resource);
        requireOptionalType(root, "packetNormalization", JsonNode::isObject, resource);
        requireOptionalType(root, "excludedFlows", JsonNode::isArray, resource);
        requireOptionalType(root, "removedFromV31", JsonNode::isArray, resource);
        return new FeatureContract(version, text(root, "task", resource), optionalText(root, "specDocument"), specSha,
                direction, numeric, categorical, viewpoints, families, window(root.get("window"), resource),
                serviceRules(root.get("serviceRules"), resource), rules,
                fixtures(root.get("goldenFixtures"), resource), bool(root, "onlineEnabled", resource),
                optionalText(root, "disabledReason"), resource, sha256(bytes));
    }

    private FeatureContract.NumericField numericField(JsonNode node, String resource) {
        if (!node.isObject()) throw fail(resource, "结构化格式 numericFields 元素必须是对象");
        String name = text(node, "name", resource);
        String unitCode = text(node, "unit", resource);
        FeatureUnit unit = FeatureUnit.fromCode(unitCode).orElseThrow(() -> fail(resource, "未知单位: " + unitCode));
        FeatureContract.FieldSource source = switch (text(node, "source", resource)) {
            case "flow" -> FeatureContract.FieldSource.FLOW;
            case "window" -> FeatureContract.FieldSource.WINDOW;
            default -> throw fail(resource, name + " 的 source 只能是 flow 或 window");
        };
        JsonNode min = node.path("min");
        JsonNode max = node.path("max");
        if (!min.isNumber() || !Double.isFinite(min.asDouble()) || min.asDouble() < 0) {
            throw fail(resource, name + " 的 min 必须是非负有限数");
        }
        if (!max.isMissingNode() && (!max.isNumber() || !Double.isFinite(max.asDouble()) || max.asDouble() < min.asDouble())) {
            throw fail(resource, name + " 的 max 必须是不小于 min 的有限数");
        }
        return new FeatureContract.NumericField(name, unit, source, node.path("nullable").asBoolean(false),
                min.asDouble(), max.isMissingNode() ? null : max.asDouble(), bool(node, "integer", resource),
                bool(node, "unitVerified", resource), optionalText(node, "specSection"));
    }

    private FeatureContract.Window window(JsonNode node, String resource) {
        if (node == null || node.isNull()) return null;
        if (!node.isObject()) throw fail(resource, "window 必须是对象");
        if (!"last_n_completed_flows".equals(text(node, "kind", resource))) {
            throw fail(resource, "window.kind 只能是 last_n_completed_flows");
        }
        JsonNode size = node.path("size");
        if (!size.isIntegralNumber() || size.asInt() < 1 || size.asInt() > 10_000) {
            throw fail(resource, "window.size 必须是 1～10000 的整数");
        }
        List<String> order = stringList(node, "orderBy", resource, false);
        if (!WINDOW_ORDER.equals(order)) throw fail(resource, "window.orderBy 必须是 " + WINDOW_ORDER);
        JsonNode lateness = node.path("allowedLatenessSeconds");
        if (!lateness.isIntegralNumber() || lateness.asInt() < 0) {
            throw fail(resource, "window.allowedLatenessSeconds 必须是非负整数");
        }
        if (!bool(node, "includesCurrentFlow", resource)) throw fail(resource, "window 必须包含当前流（规格 §3）");
        return new FeatureContract.Window("last_n_completed_flows", size.asInt(), text(node, "scope", resource),
                true, order, lateness.asInt());
    }

    private FeatureContract.ServiceRules serviceRules(JsonNode node, String resource) {
        if (node == null || node.isNull()) return null;
        if (!node.isObject()) throw fail(resource, "serviceRules 必须是对象");
        if (!"responder_port".equals(text(node, "basis", resource))) {
            throw fail(resource, "serviceRules.basis 只能是 responder_port（规格 §2.3，不读载荷）");
        }
        Set<String> protocols = new LinkedHashSet<>(stringList(node, "protocols", resource, false));
        JsonNode portMap = node.path("portMap");
        if (!portMap.isObject() || portMap.isEmpty()) throw fail(resource, "serviceRules.portMap 必须是非空对象");
        Map<String, String> ports = new LinkedHashMap<>();
        portMap.fields().forEachRemaining(entry -> {
            String key = entry.getKey();
            if (!key.matches("[a-z0-9-]{1,16}/\\d{1,5}") || Integer.parseInt(key.substring(key.indexOf('/') + 1)) > 65_535
                    || !protocols.contains(key.substring(0, key.indexOf('/')))) {
                throw fail(resource, "serviceRules.portMap 键无效: " + key);
            }
            if (!entry.getValue().isTextual() || !entry.getValue().asText().matches("[a-z0-9-]{1,32}")) {
                throw fail(resource, "serviceRules.portMap 值无效: " + key);
            }
            ports.put(key, entry.getValue().asText());
        });
        return new FeatureContract.ServiceRules("responder_port", protocols, ports, text(node, "default", resource));
    }

    private FeatureContract.GoldenFixtures fixtures(JsonNode node, String resource) {
        if (node == null || node.isNull()) return null;
        if (!node.isObject()) throw fail(resource, "goldenFixtures 必须是对象");
        String sha = text(node, "checksumsSha256", resource);
        if (!sha.matches(SHA256)) throw fail(resource, "goldenFixtures.checksumsSha256 格式无效");
        String path = text(node, "path", resource);
        if (path.contains("..") || path.startsWith("/")) throw fail(resource, "goldenFixtures.path 必须是类路径相对路径");
        return new FeatureContract.GoldenFixtures(path, text(node, "sourceDelivery", resource), sha);
    }

    /** 对两种格式都成立的约束，以及在线契约的额外要求。 */
    private static void validateCommon(FeatureContract contract, String resource) {
        Set<String> names = new HashSet<>();
        for (FeatureContract.NumericField field : contract.numericFields()) {
            if (!field.name().matches(FIELD_NAME) || !names.add(field.name())) {
                throw fail(resource, "数值字段名无效或重复: " + field.name());
            }
        }
        for (FeatureContract.CategoricalField field : contract.categoricalFields()) {
            if (!field.name().matches(FIELD_NAME) || !names.add(field.name())) {
                throw fail(resource, "类别字段名无效或重复: " + field.name());
            }
        }
        if (contract.categoricalFields().isEmpty()) throw fail(resource, "categoricalFields 不能为空");
        boolean usesWindow = contract.numericFields().stream()
                .anyMatch(field -> field.source() == FeatureContract.FieldSource.WINDOW);
        if (usesWindow && contract.window() == null) throw fail(resource, "存在窗口字段但未声明 window");
        if (usesWindow) {
            for (FeatureContract.NumericField field : contract.numericFields()) {
                if (field.source() == FeatureContract.FieldSource.WINDOW
                        && (!field.integer() || field.max() == null || field.max() > contract.window().size())) {
                    throw fail(resource, field.name() + " 是窗口计数，必须为整数且上限不超过 window.size");
                }
            }
        }
        boolean serviceRule = contract.categoricalFields().stream().anyMatch(field -> "service_rules".equals(field.rule()));
        if (serviceRule && contract.serviceRules() == null) throw fail(resource, "service 引用 service_rules 但未声明 serviceRules");
        if (!contract.onlineEnabled()) return;
        if (contract.specSha256() == null) throw fail(resource, "在线契约必须声明 specSha256");
        if (contract.goldenFixtures() == null) throw fail(resource, "在线契约必须声明 goldenFixtures");
        if (contract.viewpoints().isEmpty() || contract.addressFamilies().isEmpty()) {
            throw fail(resource, "在线契约必须声明 viewpoints 与 addressFamilies");
        }
        for (FeatureContract.NumericField field : contract.numericFields()) {
            // 路线 B §3.1 约定 2：任一必需字段单位未核实时，契约可加载但不得在线。
            if (field.unit() == null || !field.unitVerified()) throw fail(resource, field.name() + " 单位未核实，不能在线");
            if (field.nullable()) throw fail(resource, field.name() + " 在线契约不允许可空数值字段（规格 §4）");
        }
    }

    private static void requireKnownKeys(JsonNode root, Set<String> allowed, String resource) {
        root.fieldNames().forEachRemaining(key -> {
            if (!allowed.contains(key)) throw fail(resource, "未知顶层键: " + key);
        });
    }

    private static void requireOptionalType(JsonNode root, String key, java.util.function.Predicate<JsonNode> type,
                                            String resource) {
        JsonNode node = root.get(key);
        if (node != null && !type.test(node)) throw fail(resource, key + " 类型无效");
    }

    private static String text(JsonNode node, String key, String resource) {
        JsonNode value = node.get(key);
        if (value == null || !value.isTextual() || value.asText().isBlank()) throw fail(resource, key + " 必须是非空字符串");
        return value.asText();
    }

    private static String optionalText(JsonNode node, String key) {
        JsonNode value = node.get(key);
        return value == null || value.isNull() ? null : value.asText();
    }

    private static boolean bool(JsonNode node, String key, String resource) {
        JsonNode value = node.get(key);
        if (value == null || !value.isBoolean()) throw fail(resource, key + " 必须是布尔值");
        return value.asBoolean();
    }

    private static List<String> stringList(JsonNode node, String key, String resource, boolean optional) {
        JsonNode value = node.get(key);
        if (value == null && optional) return List.of();
        if (value == null || !value.isArray()) throw fail(resource, key + " 必须是字符串数组");
        List<String> out = new ArrayList<>();
        for (JsonNode item : value) {
            if (!item.isTextual() || item.asText().isBlank()) throw fail(resource, key + " 只能包含非空字符串");
            out.add(item.asText());
        }
        return List.copyOf(out);
    }

    static String sha256(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException(exception);
        }
    }

    private static FeatureContractLoadException fail(String resource, String reason) {
        return new FeatureContractLoadException(resource, reason);
    }

    /** 契约加载失败；启动期抛出，阻止应用在契约不可信时提供服务。 */
    public static final class FeatureContractLoadException extends IllegalStateException {
        public FeatureContractLoadException(String resource, String reason) {
            super("特征契约 " + resource + " 加载失败：" + reason);
        }
    }
}
