package com.xyh.cybersecurity.ingest.flow;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * 有界的双向流聚合器。只在内存中保留构造特征所需的元数据，不保存完整报文。
 * 首个方向确定 initiator，后续反向报文永不翻转；达到容量时显式丢弃新流。
 */
public final class BidirectionalFlowEngine {
    private static final int MAX_PACKET_IDS_PER_FLOW = 8192;
    private final int maxFlows;
    private final Duration idleTimeout;
    private final Map<FlowKey, MutableFlow> flows = new HashMap<>();
    private long packetsSeen;
    private long flowStateCapacityDrops;
    private long duplicatePackets;

    public BidirectionalFlowEngine(int maxFlows, Duration idleTimeout) {
        if (maxFlows < 1 || idleTimeout == null || idleTimeout.isNegative() || idleTimeout.isZero()) {
            throw new IllegalArgumentException("流引擎容量和超时必须为正数");
        }
        this.maxFlows = maxFlows;
        this.idleTimeout = idleTimeout;
    }

    public synchronized List<CompletedFlow> accept(Packet packet) {
        Objects.requireNonNull(packet, "packet");
        if (packet.timestamp() == null || packet.bytes() < 0 || packet.protocol() == null
                || packet.source() == null || packet.destination() == null) {
            throw new IllegalArgumentException("packet 元数据不完整");
        }
        packetsSeen++;
        List<CompletedFlow> completed = expireBefore(packet.timestamp());
        FlowKey key = FlowKey.unordered(packet.observationScope(), packet.source(), packet.sourcePort(), packet.destination(), packet.destinationPort(), packet.protocol());
        MutableFlow flow = flows.get(key);
        if (flow == null) {
            if (flows.size() >= maxFlows) {
                flowStateCapacityDrops++;
                return completed;
            }
            flow = new MutableFlow(key, packet);
            flows.put(key, flow);
        } else if (packet.packetId() != null && !flow.packetIds.add(packet.packetId())) {
            duplicatePackets++;
            return completed;
        } else {
            flow.add(packet);
        }
        if (packet.fin() || packet.rst()) {
            flows.remove(key);
            completed.add(flow.complete(packet.fin() ? "tcp_fin" : "tcp_rst"));
        }
        return completed;
    }

    public synchronized List<CompletedFlow> flush(Instant now) {
        List<CompletedFlow> result = expireBefore(now == null ? Instant.now() : now.plusNanos(1));
        for (MutableFlow flow : new ArrayList<>(flows.values())) {
            flows.remove(flow.key);
            result.add(flow.complete("shutdown"));
        }
        return result;
    }

    public synchronized Metrics metrics() {
        return new Metrics(packetsSeen, flowStateCapacityDrops, duplicatePackets, flows.size());
    }

    private List<CompletedFlow> expireBefore(Instant timestamp) {
        List<CompletedFlow> result = new ArrayList<>();
        for (MutableFlow flow : new ArrayList<>(flows.values())) {
            if (!timestamp.isBefore(flow.lastSeen.plus(idleTimeout))) {
                flows.remove(flow.key);
                result.add(flow.complete("idle_timeout"));
            }
        }
        return result;
    }

    public record Packet(Instant timestamp, Endpoint source, Endpoint destination, String protocol, long bytes,
                         String packetId, boolean fin, boolean rst, String observationScope) {
        public Packet(Instant timestamp, Endpoint source, Endpoint destination, String protocol, long bytes,
                      String packetId, boolean fin, boolean rst) {
            this(timestamp, source, destination, protocol, bytes, packetId, fin, rst, "default");
        }
        public Packet {
            if (bytes < 0) throw new IllegalArgumentException("bytes 不能为负数");
            if (observationScope == null || observationScope.isBlank() || observationScope.length() > 160) {
                throw new IllegalArgumentException("observationScope 必须是 1 至 160 字符");
            }
        }
        public int sourcePort() { return source == null ? -1 : source.port(); }
        public int destinationPort() { return destination == null ? -1 : destination.port(); }
    }

    public record Endpoint(String address, int port) {
        public Endpoint {
            if (address == null || address.isBlank() || port < 0 || port > 65535) {
                throw new IllegalArgumentException("端点不合法");
            }
        }
    }

    public record CompletedFlow(FlowKey key, Instant flowStartAt, Instant flowEndAt,
                                Direction initiatorDirection, long sbytes, long dbytes,
                                long spkts, long dpkts, boolean bidirectional, String closeReason,
                                Set<String> qualityIssues) { }

    public record Metrics(long packetsSeen, long flowStateCapacityDrops, long duplicatePackets, int activeFlows) { }

    public record FlowKey(String observationScope, Endpoint left, Endpoint right, String protocol) {
        static FlowKey unordered(String observationScope, Endpoint source, int sourcePort, Endpoint destination, int destinationPort,
                                 String protocol) {
            Endpoint src = new Endpoint(source.address(), sourcePort);
            Endpoint dst = new Endpoint(destination.address(), destinationPort);
            return compare(src, dst) <= 0 ? new FlowKey(observationScope, src, dst, protocol.toLowerCase(java.util.Locale.ROOT))
                    : new FlowKey(observationScope, dst, src, protocol.toLowerCase(java.util.Locale.ROOT));
        }
        private static int compare(Endpoint a, Endpoint b) {
            int address = a.address().compareTo(b.address());
            return address != 0 ? address : Integer.compare(a.port(), b.port());
        }
    }

    public enum Direction { SOURCE_TO_DESTINATION, DESTINATION_TO_SOURCE }

    private static final class MutableFlow {
        private final FlowKey key;
        private final Instant flowStartAt;
        private final Direction initiatorDirection;
        private final LinkedHashSet<String> packetIds = new LinkedHashSet<>();
        private Instant lastSeen;
        private Instant flowEndAt;
        private long sbytes;
        private long dbytes;
        private long spkts;
        private long dpkts;
        private boolean bidirectional;
        private final Set<String> issues = new HashSet<>();

        MutableFlow(FlowKey key, Packet first) {
            this.key = key;
            this.flowStartAt = first.timestamp();
            this.flowEndAt = first.timestamp();
            this.lastSeen = first.timestamp();
            this.initiatorDirection = same(first.source(), first.sourcePort(), key.left())
                    ? Direction.SOURCE_TO_DESTINATION : Direction.DESTINATION_TO_SOURCE;
            if (first.packetId() != null) packetIds.add(first.packetId());
            add(first);
        }

        void add(Packet packet) {
            if (packet.timestamp().isBefore(flowStartAt)) issues.add("clock_skew");
            if (packet.timestamp().isBefore(lastSeen)) issues.add("out_of_order");
            lastSeen = lastSeen.isAfter(packet.timestamp()) ? lastSeen : packet.timestamp();
            flowEndAt = flowEndAt.isAfter(packet.timestamp()) ? flowEndAt : packet.timestamp();
            if (packet.packetId() != null) {
                packetIds.add(packet.packetId());
                if (packetIds.size() > MAX_PACKET_IDS_PER_FLOW) {
                    packetIds.remove(packetIds.iterator().next());
                    issues.add("dedup_window_exceeded");
                }
            }
            boolean sourceDirection = same(packet.source(), packet.sourcePort(), key.left());
            if (sourceDirection == (initiatorDirection == Direction.SOURCE_TO_DESTINATION)) {
                sbytes = Math.addExact(sbytes, packet.bytes());
                spkts++;
            } else {
                dbytes = Math.addExact(dbytes, packet.bytes());
                dpkts++;
                bidirectional = true;
            }
        }

        CompletedFlow complete(String reason) {
            if (!bidirectional) issues.add("unidirectional");
            return new CompletedFlow(key, flowStartAt, flowEndAt, initiatorDirection, sbytes, dbytes,
                    spkts, dpkts, bidirectional, reason, Set.copyOf(issues));
        }

        private static boolean same(Endpoint packetEndpoint, int port, Endpoint keyEndpoint) {
            return packetEndpoint.address().equals(keyEndpoint.address()) && port == keyEndpoint.port();
        }
    }
}
