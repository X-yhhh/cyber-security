package com.xyh.cybersecurity.ingest.packet;

import com.xyh.cybersecurity.ingest.packet.PacketFlow.Completed;
import com.xyh.cybersecurity.ingest.packet.PacketFlow.Endpoint;
import com.xyh.cybersecurity.ingest.packet.PacketFlow.Flow;
import com.xyh.cybersecurity.ingest.packet.PacketFlow.Key;

import java.net.InetAddress;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * v4 包级组流器（特征规格 §1.1、§1.3、D11）：G2 包级对拍的 Java 参考实现，与 Go 传感器
 * {@code sensor/internal/flow} 的确定性约定逐条一致。
 *
 * <ul>
 *   <li>每个报文先检查自身流键：空闲超时或已满最长存活时间的旧流先导出，再处理报文；</li>
 *   <li>其余流的超时扫描只在报文时间跨过 1 秒时执行，扫描结果按 (末包时间, 首包时间, 流键) 排序；</li>
 *   <li>FIN/RST 导出后 5 秒墓碑期内，除纯 SYN 外的报文只计数不建流；满 60 秒切段后续段继承 initiator。</li>
 * </ul>
 *
 * <p>非线程安全；由单个读取循环串行调用。</p>
 */
public final class PacketFlowAssembler {
    static final Duration TCP_IDLE = Duration.ofSeconds(60);
    static final Duration OTHER_IDLE = Duration.ofSeconds(30);
    static final Duration MAX_LIFETIME = Duration.ofSeconds(60);
    static final Duration TOMBSTONE = Duration.ofSeconds(5);
    static final Duration FRAGMENT_WAIT = Duration.ofSeconds(30);
    private static final Duration SWEEP_INTERVAL = Duration.ofSeconds(1);

    private record FragKey(int addressFamily, InetAddress source, InetAddress destination, int protocol, long id) { }
    private record FragRef(Key key, Instant at) { }
    private record Continuation(Endpoint initiator, int segment, Instant at) { }
    private record Due(Flow flow, String reason) { }

    /** 流表诊断计数（§6，不进契约），字段含义与 Go {@code flow.Diagnostics} 相同。 */
    public record Diagnostics(long postClosePackets, long orphanFragments, long oversizePackets, long capacityDrops,
                              int maxActiveFlows) { }

    private final int mtu;
    private final int maxFlows;
    private final Map<Key, Flow> flows = new HashMap<>();
    private final Map<Key, Instant> tombs = new HashMap<>();
    private final Map<Key, Continuation> continuations = new HashMap<>();
    private final Map<FragKey, FragRef> fragments = new HashMap<>();
    private Instant lastSweep;
    private long seq;
    private long postClose, orphans, oversize, capacityDrops;
    private int maxActive;

    /** @param mtu D11 超大包判定；@param maxFlows 活动流上限，超出时新流丢弃并计数 */
    public PacketFlowAssembler(int mtu, int maxFlows) {
        this.mtu = mtu;
        this.maxFlows = maxFlows;
    }

    public int active() { return flows.size(); }

    public Diagnostics diagnostics() {
        return new Diagnostics(postClose, orphans, oversize, capacityDrops, maxActive);
    }

    private static Duration idle(int protocol) { return protocol == 6 ? TCP_IDLE : OTHER_IDLE; }

    /** {@code to − from ≥ d}，与 Go {@code to.Sub(from) >= d} 同义。 */
    private static boolean elapsed(Instant from, Instant to, Duration d) {
        return Duration.between(from, to).compareTo(d) >= 0;
    }

    private void complete(Flow flow, String reason, List<Completed> out) {
        out.add(new Completed(flow, reason, ++seq));
    }

    /** 处理一个解析成功的报文，返回因此导出的流（含整秒扫描结果）。 */
    public List<Completed> accept(PacketHeaders.Packet p) {
        List<Completed> out = new ArrayList<>();
        Instant ts = p.timestamp();
        if (lastSweep == null) lastSweep = ts;
        else if (elapsed(lastSweep, ts, SWEEP_INTERVAL)) out.addAll(sweep(ts));
        if (p.laterFragment()) {
            acceptFragment(p);
            return out;
        }
        Key key = Key.of(p);
        boolean pureSyn = p.protocol() == 6 && p.syn() && !p.ack();
        Instant tomb = tombs.get(key);
        if (tomb != null) {
            if (!elapsed(tomb, ts, TOMBSTONE) && !pureSyn) {
                postClose++;
                return out;
            }
            tombs.remove(key);
        }
        Flow flow = flows.get(key);
        if (flow != null) {
            if (elapsed(flow.last, ts, idle(key.protocol()))) {
                flows.remove(key);
                complete(flow, "idle_timeout", out);
                flow = null;
            } else if (elapsed(flow.start, ts, MAX_LIFETIME)) {
                flows.remove(key);
                continuations.put(key, new Continuation(flow.initiator, flow.segment + 1, ts));
                complete(flow, "max_lifetime", out);
                flow = null;
            }
        }
        if (flow == null) {
            if (flows.size() >= maxFlows) {
                capacityDrops++;
                return out;
            }
            Endpoint source = new Endpoint(p.source(), p.sourcePort());
            flow = new Flow(key, p.addressFamily(), source, new Endpoint(p.destination(), p.destinationPort()), ts, pureSyn);
            Continuation c = continuations.get(key);
            if (c != null && !elapsed(c.at(), ts, idle(key.protocol()))) {
                // §1.1：续段继承首段 initiator；续段首包若来自原 responder，则 responder 是本包发送方。
                flow.segment = c.segment();
                flow.initiator = c.initiator();
                if (!c.initiator().equals(source)) flow.responder = source;
                flow.handshakeSeen = false;
            }
            continuations.remove(key);
            flows.put(key, flow);
            maxActive = Math.max(maxActive, flows.size());
        }
        if (ts.isAfter(flow.last)) flow.last = ts;
        boolean fromInit = p.source().equals(flow.initiator.address()) && p.sourcePort() == flow.initiator.port();
        if (p.firstFragment()) {
            fragments.put(new FragKey(p.addressFamily(), p.source(), p.destination(), p.protocol(), p.fragmentId()),
                    new FragRef(key, ts));
        }
        if (p.protocol() == 6) flow.tcpState(p, fromInit);
        if (flow.count(p, fromInit, mtu)) oversize++;
        if (p.protocol() == 6 && (flow.rst || (flow.finInit && flow.finResp))) {
            flows.remove(key);
            tombs.put(key, ts);
            complete(flow, flow.rst ? "tcp_rst" : "tcp_fin", out);
        }
        return out;
    }

    private void acceptFragment(PacketHeaders.Packet p) {
        FragRef ref = fragments.get(new FragKey(p.addressFamily(), p.source(), p.destination(), p.protocol(), p.fragmentId()));
        Flow flow = ref == null ? null : flows.get(ref.key());
        if (flow == null || elapsed(ref.at(), p.timestamp(), FRAGMENT_WAIT)) {
            orphans++;
            return;
        }
        if (p.timestamp().isAfter(flow.last)) flow.last = p.timestamp();
        if (flow.count(p, p.source().equals(flow.initiator.address()), mtu)) oversize++;
    }

    /** 导出空闲超时与满最长存活时间的流，并清理过期的墓碑、续段与分片索引。 */
    public List<Completed> sweep(Instant now) {
        lastSweep = now;
        List<Due> due = new ArrayList<>();
        for (Iterator<Map.Entry<Key, Flow>> it = flows.entrySet().iterator(); it.hasNext(); ) {
            Map.Entry<Key, Flow> entry = it.next();
            Flow flow = entry.getValue();
            if (elapsed(flow.last, now, idle(entry.getKey().protocol()))) {
                due.add(new Due(flow, "idle_timeout"));
            } else if (elapsed(flow.start, now, MAX_LIFETIME)) {
                due.add(new Due(flow, "max_lifetime"));
                continuations.put(entry.getKey(), new Continuation(flow.initiator, flow.segment + 1, now));
            } else {
                continue;
            }
            it.remove();
        }
        due.sort((a, b) -> PacketFlow.COMPLETION_ORDER.compare(a.flow(), b.flow()));
        List<Completed> out = new ArrayList<>();
        for (Due d : due) complete(d.flow(), d.reason(), out);
        tombs.values().removeIf(at -> elapsed(at, now, TOMBSTONE));
        continuations.entrySet().removeIf(e -> elapsed(e.getValue().at(), now, idle(e.getKey().protocol())));
        fragments.values().removeIf(ref -> elapsed(ref.at(), now, FRAGMENT_WAIT));
        return out;
    }

    /** 停止时导出全部活动流：先按超时规则扫描，其余记 {@code shutdown}，顺序确定。 */
    public List<Completed> flush(Instant now) {
        List<Completed> out = sweep(now);
        List<Flow> rest = new ArrayList<>(flows.values());
        rest.sort(PacketFlow.COMPLETION_ORDER);
        for (Flow flow : rest) {
            flows.remove(flow.key);
            complete(flow, "shutdown", out);
        }
        return out;
    }
}
