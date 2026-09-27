package com.xyh.cybersecurity.ingest.feature;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.time.Duration;
import java.util.List;
import java.util.Objects;

/**
 * 从已完成的规范流元数据构造 v3.1 raw fields。派生速率、插补和类别编码仍由 ONNX 图完成。
 */
public final class FeatureBuilder {
    private static final ObjectMapper JSON = new ObjectMapper();

    public BuildResult build(FlowInput current, List<FlowInput> window, CtStateTtlCodebook codebook) {
        Objects.requireNonNull(current, "current");
        Objects.requireNonNull(window, "window");
        if (window.size() < FeatureWindow.WINDOW_SIZE) return BuildResult.notReady("window_warming");
        if (window.stream().noneMatch(flow -> current.recordKey().equals(flow.recordKey()))) {
            return BuildResult.rejected("window_current_flow_missing");
        }
        if (codebook == null) return BuildResult.rejected("ct_state_ttl_codebook_missing");
        try {
            ObjectNode out = JSON.createObjectNode();
            put(out, "dur", current.dur()); put(out, "sbytes", current.sbytes()); put(out, "dbytes", current.dbytes());
            put(out, "sttl", current.sttl()); put(out, "sload", current.sload()); put(out, "dload", current.dload());
            put(out, "sloss", current.sloss()); put(out, "dinpkt", current.dinpkt()); put(out, "sjit", current.sjit());
            put(out, "djit", current.djit()); put(out, "tcprtt", current.tcprtt()); put(out, "ackdat", current.ackdat());
            put(out, "smean", current.smean()); put(out, "dmean", current.dmean());
            put(out, "ct_srv_src", count(window, f -> eq(f.service(), current.service()) && eq(f.sourceAddress(), current.sourceAddress())));
            put(out, "ct_state_ttl", codebook.encode(current.state(), current.sttl()));
            put(out, "ct_dst_ltm", count(window, f -> eq(f.destinationAddress(), current.destinationAddress())));
            put(out, "ct_src_dport_ltm", count(window, f -> eq(f.sourceAddress(), current.sourceAddress()) && f.destinationPort() == current.destinationPort()));
            put(out, "ct_dst_sport_ltm", count(window, f -> eq(f.destinationAddress(), current.destinationAddress()) && f.sourcePort() == current.sourcePort()));
            put(out, "ct_dst_src_ltm", count(window, f -> eq(f.sourceAddress(), current.sourceAddress()) && eq(f.destinationAddress(), current.destinationAddress())));
            if (current.httpMethodCount() == null) out.putNull("ct_flw_http_mthd"); else put(out, "ct_flw_http_mthd", current.httpMethodCount());
            put(out, "ct_src_ltm", count(window, f -> eq(f.sourceAddress(), current.sourceAddress())));
            put(out, "ct_srv_dst", count(window, f -> eq(f.service(), current.service()) && eq(f.destinationAddress(), current.destinationAddress())));
            put(out, "spkts", current.spkts()); put(out, "dpkts", current.dpkts()); put(out, "synack", current.synack());
            out.put("proto", current.proto()); out.put("service", current.service());
            return BuildResult.ready(out);
        } catch (CtStateTtlCodebook.UnknownStateTtlException e) {
            return BuildResult.rejected("ct_state_ttl_codebook_value_missing");
        }
    }

    private static int count(List<FlowInput> window, java.util.function.Predicate<FlowInput> predicate) {
        return (int) window.stream().filter(predicate).count();
    }
    private static boolean eq(String a, String b) { return a != null && a.equals(b); }
    private static void put(ObjectNode out, String field, double value) { if (!Double.isFinite(value) || value < 0) throw new IllegalArgumentException("非法特征值: " + field); out.put(field, value); }
    private static void put(ObjectNode out, String field, long value) { if (value < 0) throw new IllegalArgumentException("非法特征值: " + field); out.put(field, value); }

    public record BuildResult(Status status, ObjectNode features, String reason) {
        static BuildResult ready(ObjectNode features) { return new BuildResult(Status.READY, features, null); }
        static BuildResult notReady(String reason) { return new BuildResult(Status.WARMING, null, reason); }
        static BuildResult rejected(String reason) { return new BuildResult(Status.REJECTED, null, reason); }
        public boolean ready() { return status == Status.READY; }
    }
    public enum Status { READY, WARMING, REJECTED }

    /** 来源适配器必须提供单位已核实的值；FeatureBuilder 不做单位猜测或补值。 */
    public record FlowInput(String recordKey, java.time.Instant flowEndAt, String sourceAddress, String destinationAddress,
                            int sourcePort, int destinationPort, String proto, String service, String state,
                            double dur, long sbytes, long dbytes, int sttl, double sload, double dload, long sloss,
                            double dinpkt, double sjit, double djit, double tcprtt, double ackdat, double smean,
                            double dmean, Long httpMethodCount, long spkts, long dpkts, double synack) {
        public FlowInput {
            if (recordKey == null || recordKey.isBlank() || flowEndAt == null || sourceAddress == null || destinationAddress == null
                    || proto == null || service == null || state == null || sourcePort < 0 || destinationPort < 0
                    || sourcePort > 65535 || destinationPort > 65535) throw new IllegalArgumentException("流元数据不完整");
            if (httpMethodCount != null && httpMethodCount < 0) throw new IllegalArgumentException("HTTP 计数不能为负数");
        }
    }
}
