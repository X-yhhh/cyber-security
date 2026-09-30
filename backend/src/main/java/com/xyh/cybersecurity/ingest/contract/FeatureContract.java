package com.xyh.cybersecurity.ingest.contract;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * 不可变的原始流特征契约快照，由 {@link FeatureContractLoader} 从 {@code classpath:feature-contract/*.json} 加载。
 *
 * <p>契约只描述“单条已完成流 + 所在窗口”的原始输入（字段、顺序、单位、识别规则、窗口与边界约束）；
 * 类别词表、插补、编码与派生特征属于模型，由激活模型的 preprocessing.json / ONNX 图负责，不在此重复。</p>
 *
 * <p>{@code fileSha256} 是契约资源文件的原始字节哈希，写入 V11 的 {@code feature_contract_sha256} 列，
 * 用于证明“映射/配置 ↔ 契约版本 ↔ 契约内容”一致。契约文件发布后不可原位修改。</p>
 *
 * @param version          契约版本，如 {@code unsw-nb15-flow-v4}
 * @param specSha256       特征规格文档 SHA-256；在线契约必填，并须与模型 manifest 的 {@code spec_sha256} 一致
 * @param numericFields    数值字段，顺序即 ONNX {@code flow_numeric} 列顺序
 * @param viewpoints       契约允许的视角；非空时记录必须携带 {@link RecordMetadata}
 * @param window           窗口定义；无窗口字段的历史契约为 {@code null}
 * @param serviceRules     {@code service} 识别规则；历史契约为 {@code null}
 * @param onlineEnabled    契约本身是否可用于在线特征构造（不等于传感器已获准上线）
 * @param fileSha256       契约资源文件字节的 SHA-256（小写十六进制）
 */
public record FeatureContract(String version, String task, String specDocument, String specSha256,
                              String directionBasis, List<NumericField> numericFields,
                              List<CategoricalField> categoricalFields, List<String> viewpoints,
                              List<String> addressFamilies, Window window, ServiceRules serviceRules,
                              List<ConsistencyRule> consistencyRules, GoldenFixtures goldenFixtures,
                              boolean onlineEnabled, String disabledReason, String resourceName, String fileSha256) {

    public FeatureContract {
        numericFields = List.copyOf(numericFields);
        categoricalFields = List.copyOf(categoricalFields);
        viewpoints = List.copyOf(viewpoints);
        addressFamilies = List.copyOf(addressFamilies);
        consistencyRules = List.copyOf(consistencyRules);
    }

    /** 数值字段名，按模型输入顺序。 */
    public List<String> numericFieldNames() {
        return numericFields.stream().map(NumericField::name).toList();
    }

    /** 类别字段名，按模型输入顺序。 */
    public List<String> categoricalFieldNames() {
        return categoricalFields.stream().map(CategoricalField::name).toList();
    }

    public Optional<NumericField> numericField(String name) {
        return numericFields.stream().filter(field -> field.name().equals(name)).findFirst();
    }

    /** 契约声明了视角时，记录必须携带视角、地址族和握手可见性元数据。 */
    public boolean requiresRecordMetadata() {
        return !viewpoints.isEmpty();
    }

    /** 数值字段来源：逐流测量值，或由窗口计数得到。历史契约未声明来源。 */
    public enum FieldSource { FLOW, WINDOW, UNSPECIFIED }

    /**
     * 数值字段定义。
     *
     * @param unit         单位；历史契约可为 {@code null}，此时 {@code unitVerified} 必为 false
     * @param min          闭区间下限
     * @param max          闭区间上限，{@code null} 表示无上限
     * @param integer      是否要求整数值（计数、字节、包数）
     * @param specSection  规格文档中的定义位置，便于审计追溯
     */
    public record NumericField(String name, FeatureUnit unit, FieldSource source, boolean nullable, double min,
                               Double max, boolean integer, boolean unitVerified, String specSection) { }

    /** 类别字段定义：契约只规定识别规则，词表来自激活模型（{@code vocabularySource}）。 */
    public record CategoricalField(String name, String rule, String vocabularySource, String specSection) { }

    /**
     * 窗口定义（规格 §3）。{@code orderBy} 固定为 {@code [flowEndAt, flowStartAt, exportSeq]}，
     * {@code allowedLatenessSeconds = 0} 表示任何排序键回退的记录都按迟到拒绝，由传感器先重排序再上报。
     */
    public record Window(String kind, int size, String scope, boolean includesCurrentFlow, List<String> orderBy,
                         int allowedLatenessSeconds) {
        public Window {
            orderBy = List.copyOf(orderBy);
        }
    }

    /**
     * {@code service} 识别规则（规格 §2.3）：只看协议与响应方端口，查固定映射表，未命中取默认值。
     *
     * @param portMap 键为 {@code 协议/端口}，如 {@code tcp/80}
     */
    public record ServiceRules(String basis, Set<String> protocols, Map<String, String> portMap, String defaultValue) {
        public ServiceRules {
            protocols = Set.copyOf(protocols);
            portMap = Map.copyOf(portMap);
        }

        /**
         * 按规格 §2.3 计算 {@code service}。非 TCP/UDP、端口缺失或未命中时返回默认值 {@code -}，不读载荷。
         */
        public String resolve(String proto, Integer responderPort) {
            if (proto == null || responderPort == null || !protocols.contains(proto)) return defaultValue;
            return portMap.getOrDefault(proto + "/" + responderPort, defaultValue);
        }

        /** 规则可能产生的全部取值（映射值 + 默认值），用于校验传感器上报的 {@code service}。 */
        public Set<String> possibleValues() {
            Set<String> values = new LinkedHashSet<>(portMap.values());
            values.add(defaultValue);
            return Set.copyOf(values);
        }
    }

    /** golden fixtures 的位置与 checksums.json 的 SHA-256。 */
    public record GoldenFixtures(String path, String sourceDelivery, String checksumsSha256) { }
}
