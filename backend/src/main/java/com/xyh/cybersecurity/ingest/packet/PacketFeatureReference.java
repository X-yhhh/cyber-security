package com.xyh.cybersecurity.ingest.packet;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.xyh.cybersecurity.ingest.contract.FeatureContract;
import com.xyh.cybersecurity.ingest.feature.AddressPolicy;
import com.xyh.cybersecurity.ingest.feature.FeatureBuilder;

import java.io.IOException;
import java.io.InputStream;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

/**
 * G2 包级对拍的 Java 参考流水线：pcap → {@link PacketHeaders} → {@link PacketFlowAssembler} → 重排序 →
 * {@link FeatureBuilder}。时序约定与 Go 传感器 {@code internal/pipeline} 一致：
 *
 * <ul>
 *   <li>时间取报文时间；解析失败的帧只计数，不推进时间、不触发释放；</li>
 *   <li>每个成功解析的报文之后，释放 {@code flowEndAt ≤ now − 61 s} 的记录，按 (flowEndAt, flowStartAt, exportSeq) 入窗；</li>
 *   <li>文件结束时导出全部活动流（{@code shutdown}）并释放全部缓冲。</li>
 * </ul>
 *
 * <p>逐流值（{@code sload}、{@code smean} 等）在这里计算，浮点运算次序与 Go {@code feature.perFlow} 相同；
 * 边界规则、窗口与计数由现有 {@link FeatureBuilder} 负责。只用于离线对拍，不打开网卡、不上报。</p>
 */
public final class PacketFeatureReference {
    static final Duration REORDER_DELAY = Duration.ofSeconds(61);
    private static final int MAX_FLOWS = 1_000_000;
    private static final Comparator<PacketFlow.Completed> RELEASE_ORDER =
            Comparator.comparing((PacketFlow.Completed c) -> c.flow().last())
                    .thenComparing(c -> c.flow().start())
                    .thenComparingLong(PacketFlow.Completed::exportSeq);

    /** 一条释放后的记录；状态取值与 Go 相同：ready、window_not_ready、late_event、rejected。 */
    public record Output(String recordKey, long exportSeq, Instant flowStartAt, Instant flowEndAt, String status,
                         String reason, String closeReason, String addressFamily, String viewpoint,
                         boolean handshakeSeen, ObjectNode features) { }

    /** 与 Go {@code pipeline.Diagnostics} 对应的计数。 */
    public record Diagnostics(long frames, Map<String, Long> parseStatus, Map<String, Long> closeReasons,
                              PacketFlowAssembler.Diagnostics flow, Map<String, Long> excluded,
                              Map<String, Long> byStatus) { }

    public record Result(List<Output> records, Diagnostics diagnostics) { }

    private final PacketFlowAssembler assembler;
    private final FeatureBuilder builder;
    private final String keyBase;
    private final List<PacketFlow.Completed> pending = new ArrayList<>();
    private final List<Output> out = new ArrayList<>();
    private final Map<String, Long> parseStatus = new TreeMap<>();
    private final Map<String, Long> closeReasons = new TreeMap<>();
    private final Map<String, Long> excluded = new TreeMap<>();
    private final Map<String, Long> byStatus = new TreeMap<>();
    private long frames;
    private Instant now;

    private PacketFeatureReference(PacketFlowAssembler assembler, FeatureBuilder builder, String keyBase) {
        this.assembler = assembler;
        this.builder = builder;
        this.keyBase = keyBase;
    }

    /** 读取整个 pcap 并返回全部记录（含非 ready，排除的流只计数）与诊断计数。 */
    public static Result run(InputStream pcap, FeatureContract contract, AddressPolicy addresses, String keyBase, int mtu)
            throws IOException {
        PacketFeatureReference ref = new PacketFeatureReference(new PacketFlowAssembler(mtu, MAX_FLOWS),
                new FeatureBuilder(contract, addresses), keyBase);
        try (PcapReader reader = new PcapReader(pcap)) {
            for (PcapReader.Frame frame = reader.next(); frame != null; frame = reader.next()) ref.frame(frame);
        }
        if (ref.now != null) ref.push(ref.assembler.flush(ref.now));
        ref.release(true);
        return new Result(List.copyOf(ref.out), new Diagnostics(ref.frames, Map.copyOf(ref.parseStatus),
                Map.copyOf(ref.closeReasons), ref.assembler.diagnostics(), Map.copyOf(ref.excluded), Map.copyOf(ref.byStatus)));
    }

    private void frame(PcapReader.Frame frame) {
        frames++;
        PacketHeaders.Result parsed = PacketHeaders.parseEthernet(frame.data(), frame.wireLength(), frame.timestamp());
        parseStatus.merge(parsed.status().name().toLowerCase(Locale.ROOT), 1L, Long::sum);
        if (parsed.status() != PacketHeaders.Status.OK) return;
        if (now == null || frame.timestamp().isAfter(now)) now = frame.timestamp();
        push(assembler.accept(parsed.packet()));
        release(false);
    }

    private void push(List<PacketFlow.Completed> completed) {
        for (PacketFlow.Completed c : completed) closeReasons.merge(c.reason(), 1L, Long::sum);
        pending.addAll(completed);
    }

    private void release(boolean all) {
        if (pending.isEmpty()) return;
        pending.sort(RELEASE_ORDER);
        Instant cut = now == null ? Instant.MIN : now.minus(REORDER_DELAY);
        int n = 0;
        while (n < pending.size() && (all || !pending.get(n).flow().last().isAfter(cut))) n++;
        List<PacketFlow.Completed> ready = new ArrayList<>(pending.subList(0, n));
        pending.subList(0, n).clear();
        for (PacketFlow.Completed c : ready) build(c);
    }

    private void build(PacketFlow.Completed c) {
        PacketFlow.Flow f = c.flow();
        double dur = f.dur();
        double[] handshake = f.handshake();
        double synack = handshake[0];
        double ackdat = handshake[1];
        double sload = dur > 0 && f.spkts() > 1
                ? (double) f.sbytes() * 8 * (double) (f.spkts() - 1) / (double) f.spkts() / dur : 0;
        double dload = dur > 0 && f.dpkts() > 1
                ? (double) f.dbytes() * 8 * (double) (f.dpkts() - 1) / (double) f.dpkts() / dur : 0;
        String key = keyBase + ":" + c.exportSeq();
        FeatureBuilder.BuildResult r = builder.accept(new FeatureBuilder.FlowInput(key, f.start(), f.last(), c.exportSeq(),
                f.initiator().address().getHostAddress(), f.responder().address().getHostAddress(), f.responder().port(),
                IanaProtocols.name(f.key().protocol()), dur, f.sbytes(), f.dbytes(), sload, dload, synack + ackdat,
                ackdat, synack, roundDiv(f.sbytes(), f.spkts()), roundDiv(f.dbytes(), f.dpkts()), f.spkts(), f.dpkts()));
        if (r.status() == FeatureBuilder.Status.EXCLUDED) {
            excluded.merge(r.reason(), 1L, Long::sum);
            return;
        }
        String status = switch (r.status()) {
            case READY -> "ready";
            case WINDOW_NOT_READY -> "window_not_ready";
            default -> "late_event".equals(r.reason()) ? "late_event" : "rejected";
        };
        byStatus.merge(status, 1L, Long::sum);
        out.add(new Output(key, c.exportSeq(), f.start(), f.last(), status, r.ready() ? null : r.reason(), c.reason(),
                r.addressFamily(), r.viewpoint(), f.handshakeSeen(), r.features()));
    }

    /** round(a / b)，四舍五入；b = 0 时为 0。与 Go {@code feature.roundDiv} 相同的整数算法。 */
    static long roundDiv(long a, long b) {
        return b == 0 ? 0 : (2 * a + b) / (2 * b);
    }
}
