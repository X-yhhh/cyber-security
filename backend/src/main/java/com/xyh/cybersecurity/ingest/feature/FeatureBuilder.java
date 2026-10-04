package com.xyh.cybersecurity.ingest.feature;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.xyh.cybersecurity.ingest.contract.FeatureContract;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.BiPredicate;

/**
 * 契约驱动的 v4 特征构造参考实现（规格 {@code docs/特征规格-unsw-nb15-flow-v4.md}）。
 *
 * <p>输入是已完成的流（{@link FlowInput}，逐流测量值由流引擎或回放适配器提供）；输出按契约字段顺序的 raw features。
 * 用于 UNSW CSV 回放、golden fixtures 对拍与 G2 Go/Java 一致性对照，与 Go 传感器遵守同一份规格。</p>
 *
 * <p>本类负责：地址排除与视角（规格 §1.2）、{@code service} 识别（§2.3）、窗口计数 {@code ct_*}（§2.1 #12～#16、§3）、
 * 逐流边界取值（§4）。窗口按地址族分开维护，窗口长度取自契约 {@code window.size}。</p>
 *
 * <p>fail-closed：窗口未满（{@code window_not_ready}）、迟到、重复、排除流、逐流值非法都不输出特征，不造值、不补默认值。
 * 构造成功不代表可推理：视角/地址族是否在模型评估范围由推理入口依据 manifest 判定。本类不是线程安全的。</p>
 */
public final class FeatureBuilder {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final List<String> FLOW_FIELDS = List.of("dur", "sbytes", "dbytes", "sload", "dload", "tcprtt",
            "ackdat", "synack", "smean", "dmean", "spkts", "dpkts");

    /** 规格 §2.1 #12～#16 的窗口计数键；「源」= initiator，「目的」= responder，端口 = responder 端口。 */
    private static final Map<String, BiPredicate<FeatureWindow.Member, FeatureWindow.Member>> WINDOW_COUNTS = Map.of(
            "ct_srv_src", (m, c) -> m.service().equals(c.service()) && m.initiator().equals(c.initiator()),
            "ct_srv_dst", (m, c) -> m.service().equals(c.service()) && m.responder().equals(c.responder()),
            "ct_dst_ltm", (m, c) -> m.responder().equals(c.responder()),
            "ct_src_ltm", (m, c) -> m.initiator().equals(c.initiator()),
            "ct_src_dport_ltm", (m, c) -> m.initiator().equals(c.initiator())
                    && Objects.equals(m.responderPort(), c.responderPort()));

    private final FeatureContract contract;
    private final AddressPolicy addresses;
    private final Map<String, FeatureWindow> windows = new HashMap<>();

    /**
     * @param contract  必须声明窗口与 {@code service} 规则（v4 起）；历史契约 v3.1 使用 legacy 实现
     * @param addresses 本机地址与广播判定口径
     */
    public FeatureBuilder(FeatureContract contract, AddressPolicy addresses) {
        if (contract.window() == null || contract.serviceRules() == null) {
            throw new IllegalArgumentException("契约未声明窗口或 service 规则，不能用于 v4 特征构造");
        }
        for (FeatureContract.NumericField field : contract.numericFields()) {
            boolean known = field.source() == FeatureContract.FieldSource.WINDOW
                    ? WINDOW_COUNTS.containsKey(field.name()) : FLOW_FIELDS.contains(field.name());
            if (!known) throw new IllegalArgumentException("Feature Builder 未实现契约字段: " + field.name());
        }
        this.contract = contract;
        this.addresses = addresses;
    }

    /**
     * 接收一条已完成的流，按到达顺序更新窗口并构造特征。
     *
     * <p>顺序：地址分类 → 入窗（时间非法、迟到、重复拒绝且不入窗）→ 逐流值校验 → 窗口满时计数。
     * 窗口成员资格只取决于流元数据（地址、时间、端口），与逐流值是否合法无关：训练端 {@code recompute_ct}
     * 同样只按地址与排除规则建窗口（规格 §3「只用流元数据」），逐流值非法的记录照常占位，但自身不输出特征。</p>
     */
    public BuildResult accept(FlowInput flow) {
        AddressPolicy.Classification cls = addresses.classify(flow.initiatorAddress(), flow.responderAddress());
        if (cls.exclusion().isPresent()) return BuildResult.of(Status.EXCLUDED, cls.exclusion().get(), null, null, 0);
        if (flow.recordKey() == null || flow.flowStartAt() == null || flow.flowEndAt() == null
                || flow.flowEndAt().isBefore(flow.flowStartAt())) {
            return BuildResult.of(Status.REJECTED, "flow_time_invalid", cls, null, 0);
        }
        String proto = flow.proto() == null ? null : flow.proto().trim().toLowerCase(java.util.Locale.ROOT);
        String service = contract.serviceRules().resolve(proto, flow.responderPort());
        FeatureWindow window = windows.computeIfAbsent(cls.addressFamily(), family -> new FeatureWindow(contract.window().size()));
        FeatureWindow.Member member = new FeatureWindow.Member(flow.recordKey(), flow.flowStartAt(), flow.flowEndAt(),
                flow.exportSeq(), cls.initiator(), cls.responder(), flow.responderPort(), service);
        String rejected = window.add(member);
        if (rejected != null) return BuildResult.of(Status.REJECTED, rejected, cls, null, window.size());
        Optional<String> invalid = invalidFlowValue(flow, proto);
        if (invalid.isPresent()) return BuildResult.of(Status.REJECTED, invalid.get(), cls, null, window.size());
        if (!window.ready()) return BuildResult.of(Status.WINDOW_NOT_READY, "window_not_ready", cls, null, window.size());
        return BuildResult.of(Status.READY, null, cls, features(flow, proto, service, window, member), window.size());
    }

    /** 按契约字段顺序输出；逐流值应用规格 §4 边界规则，窗口字段为计数（含当前流自身）。 */
    private ObjectNode features(FlowInput flow, String proto, String service, FeatureWindow window, FeatureWindow.Member current) {
        Map<String, Double> perFlow = perFlowValues(flow);
        ObjectNode node = JSON.createObjectNode();
        for (FeatureContract.NumericField field : contract.numericFields()) {
            if (field.source() == FeatureContract.FieldSource.WINDOW) {
                node.put(field.name(), window.count(current, WINDOW_COUNTS.get(field.name())));
            } else {
                double value = perFlow.get(field.name());
                if (field.integer()) node.put(field.name(), (long) value); else node.put(field.name(), value);
            }
        }
        for (String field : contract.categoricalFieldNames()) node.put(field, "proto".equals(field) ? proto : service);
        return node;
    }

    /**
     * 逐流值（规格 §2.1 #0～#11）与边界（§4）。
     *
     * <ul>
     *   <li>{@code sload}/{@code dload}（#3/#4）：由流引擎按 {@code bytes × 8 × (pkts − 1) / pkts / dur} 计算；
     *       {@code dur = 0} 或该方向包数 ≤ 1 时强制为 0（§4，训练端 {@code apply_boundaries} 同口径）。</li>
     *   <li>{@code smean}/{@code dmean}（#8/#9）：原样使用流引擎给出的四舍五入整数；该方向包数为 0 时为 0。</li>
     *   <li>非 TCP 的握手字段（#5～#7）为 0；反向无包时反向字节、均值、load 为 0（§4）。</li>
     * </ul>
     */
    private static Map<String, Double> perFlowValues(FlowInput flow) {
        Map<String, Double> values = new HashMap<>();
        values.put("dur", flow.dur());
        values.put("sbytes", (double) flow.sbytes());
        values.put("dbytes", (double) flow.dbytes());
        values.put("spkts", (double) flow.spkts());
        values.put("dpkts", (double) flow.dpkts());
        values.put("sload", flow.dur() <= 0 || flow.spkts() <= 1 ? 0.0 : flow.sload());
        values.put("dload", flow.dur() <= 0 || flow.dpkts() <= 1 ? 0.0 : flow.dload());
        values.put("smean", flow.spkts() == 0 ? 0.0 : (double) flow.smean());
        values.put("dmean", flow.dpkts() == 0 ? 0.0 : (double) flow.dmean());
        values.put("synack", flow.synack());
        values.put("ackdat", flow.ackdat());
        values.put("tcprtt", flow.tcprtt());
        return values;
    }

    /** 逐流值的阻断校验；不修正、不补值。与 {@code FeatureContractValidator} 的边界规则保持同一口径。 */
    private static Optional<String> invalidFlowValue(FlowInput flow, String proto) {
        if (proto == null || proto.isEmpty()) return Optional.of("proto_missing");
        double[] seconds = {flow.dur(), flow.sload(), flow.dload(), flow.synack(), flow.ackdat(), flow.tcprtt()};
        for (double value : seconds) if (!Double.isFinite(value) || value < 0) return Optional.of("value_invalid");
        if (flow.spkts() < 1 || flow.dpkts() < 0 || flow.sbytes() < 0 || flow.dbytes() < 0 || flow.smean() < 0 || flow.dmean() < 0) {
            return Optional.of("value_invalid");
        }
        if (flow.dpkts() == 0 && (flow.dbytes() != 0 || flow.dmean() != 0)) return Optional.of("reverse_direction_inconsistent");
        if (!"tcp".equals(proto) && (flow.synack() != 0 || flow.ackdat() != 0 || flow.tcprtt() != 0)) {
            return Optional.of("handshake_on_non_tcp");
        }
        if (flow.responderPort() != null && (flow.responderPort() < 0 || flow.responderPort() > 65_535)) {
            return Optional.of("port_invalid");
        }
        return Optional.empty();
    }

    /** 构造结论。 */
    public enum Status { READY, WINDOW_NOT_READY, EXCLUDED, REJECTED }

    /**
     * 一条已完成的流（规格 §2.1 的逐流测量值 + 流标识）。地址与端口只在受控内存中用于窗口计数，不进入特征。
     *
     * @param exportSeq     导出序号，排序键的最终 tie-break（规格 §3）
     * @param responderPort 响应方端口；ICMP 等无端口协议为 0，来源缺失（如 UNSW 的 {@code -}）为 {@code null}
     * @param sload         流引擎按规格 #3 计算的值，边界由本类强制
     * @param smean         流引擎按规格 #8 四舍五入后的整数
     */
    public record FlowInput(String recordKey, Instant flowStartAt, Instant flowEndAt, long exportSeq,
                            String initiatorAddress, String responderAddress, Integer responderPort, String proto,
                            double dur, long sbytes, long dbytes, double sload, double dload, double tcprtt,
                            double ackdat, double synack, long smean, long dmean, long spkts, long dpkts) { }

    /**
     * @param reason        非 READY 时的原因代码（{@code window_not_ready}、{@code late_event}、{@code duplicate_record}、
     *                      排除原因或逐流值非法原因）
     * @param addressFamily 排除时为空
     * @param viewpoint     {@code responder} / {@code initiator}；排除时为空
     * @param features      仅 READY 时非空，字段顺序即契约顺序
     * @param windowSize    处理后该地址族窗口内的流数
     */
    public record BuildResult(Status status, String reason, String addressFamily, String viewpoint, ObjectNode features,
                              int windowSize) {
        static BuildResult of(Status status, String reason, AddressPolicy.Classification cls, ObjectNode features, int size) {
            return new BuildResult(status, reason, cls == null ? null : cls.addressFamily(),
                    cls == null ? null : cls.viewpoint(), features, size);
        }

        public boolean ready() { return status == Status.READY; }
    }

    /** 仅供测试检查窗口内容。 */
    List<FeatureWindow.Member> windowSnapshot(String addressFamily) {
        FeatureWindow window = windows.get(addressFamily);
        return window == null ? List.of() : window.snapshot();
    }
}
