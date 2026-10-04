package com.xyh.cybersecurity.ingest.packet;

import java.net.InetAddress;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Comparator;

/**
 * v4 包级组流的数据类型（特征规格 unsw-nb15-flow-v4 §1.1、§1.3、D11），与 Go 传感器
 * {@code sensor/internal/flow} 逐项同口径。只保存头部元数据与计数，不保存载荷。
 *
 * <p>已知差异：{@link InetAddress#getByAddress} 会把 16 字节的 IPv4 映射地址（::ffff:a.b.c.d）收成
 * {@code Inet4Address}，Go 的 {@code netip.AddrFrom16} 保留为 IPv6。G2 fixtures 不含此类地址。</p>
 */
public final class PacketFlow {
    private PacketFlow() { }

    /** （地址, 端口）；无端口协议端口为 0。排序与 Go {@code netip.Addr.Compare} 一致：地址长度 → 无符号字节 → 端口。 */
    public record Endpoint(InetAddress address, int port) implements Comparable<Endpoint> {
        @Override
        public int compareTo(Endpoint o) {
            byte[] a = address.getAddress();
            byte[] b = o.address.getAddress();
            if (a.length != b.length) return Integer.compare(a.length, b.length);
            int c = Arrays.compareUnsigned(a, b);
            return c != 0 ? c : Integer.compare(port, o.port);
        }
    }

    /** 规范化流键：低端点在前（§1.1）。 */
    public record Key(int protocol, Endpoint low, Endpoint high) implements Comparable<Key> {
        static Key of(PacketHeaders.Packet p) {
            Endpoint a = new Endpoint(p.source(), p.sourcePort());
            Endpoint b = new Endpoint(p.destination(), p.destinationPort());
            return b.compareTo(a) < 0 ? new Key(p.protocol(), b, a) : new Key(p.protocol(), a, b);
        }

        @Override
        public int compareTo(Key o) {
            if (protocol != o.protocol) return Integer.compare(protocol, o.protocol);
            int c = low.compareTo(o.low);
            return c != 0 ? c : high.compareTo(o.high);
        }
    }

    /** 已导出的流；{@code exportSeq} 是窗口排序键的最终 tie-break（§3）。 */
    public record Completed(Flow flow, String reason, long exportSeq) { }

    /** 扫描与停机导出的确定顺序：(末包时间, 首包时间, 流键)。 */
    static final Comparator<Flow> COMPLETION_ORDER = Comparator.comparing((Flow f) -> f.last)
            .thenComparing(f -> f.start).thenComparing(f -> f.key);

    /** 一条正在聚合或已完成的流。字段只由同包的组流器修改。 */
    public static final class Flow {
        final Key key;
        final int addressFamily;
        Endpoint initiator;
        Endpoint responder;
        final Instant start;
        Instant last;
        long spkts, dpkts, sbytes, dbytes;
        /** TCP 首包为纯 SYN（§1.1 元数据）；续段恒为 false。 */
        boolean handshakeSeen;
        int segment;
        Instant synAt, synAckAt, ackAt;
        int mssInit, mssResp;
        boolean finInit, finResp, rst;

        Flow(Key key, int addressFamily, Endpoint initiator, Endpoint responder, Instant start, boolean handshakeSeen) {
            this.key = key;
            this.addressFamily = addressFamily;
            this.initiator = initiator;
            this.responder = responder;
            this.start = start;
            this.last = start;
            this.handshakeSeen = handshakeSeen;
        }

        public Key key() { return key; }
        public Endpoint initiator() { return initiator; }
        public Endpoint responder() { return responder; }
        public Instant start() { return start; }
        public Instant last() { return last; }
        public long spkts() { return spkts; }
        public long dpkts() { return dpkts; }
        public long sbytes() { return sbytes; }
        public long dbytes() { return dbytes; }
        public boolean handshakeSeen() { return handshakeSeen; }

        /** 截断到微秒后转为秒（§2.1：dur 保留微秒），与 Go {@code Duration.Microseconds()} 同为向零截断。 */
        static double micro(Duration d) { return (double) (d.toNanos() / 1_000) / 1e6; }

        public double dur() { return micro(Duration.between(start, last)); }

        /** @return {synack, ackdat}；非 TCP 或三次握手未按序齐全时全为 0 */
        public double[] handshake() {
            if (key.protocol() != 6 || synAt == null || synAckAt == null || ackAt == null) return new double[] {0, 0};
            return new double[] {micro(Duration.between(synAt, synAckAt)), micro(Duration.between(synAckAt, ackAt))};
        }

        void tcpState(PacketHeaders.Packet p, boolean fromInit) {
            if (p.syn() && !p.ack() && fromInit) {
                if (synAt == null) synAt = p.timestamp();
                if (p.mss() != 0) mssInit = p.mss();
            } else if (p.syn() && p.ack() && !fromInit) {
                if (synAt != null && synAckAt == null) synAckAt = p.timestamp();
                if (p.mss() != 0) mssResp = p.mss();
            } else if (!p.syn() && p.ack() && fromInit) {
                if (synAckAt != null && ackAt == null) ackAt = p.timestamp();
            }
            if (p.fin()) {
                if (fromInit) finInit = true; else finResp = true;
            }
            if (p.rst()) rst = true;
        }

        /**
         * 按 §1.3 累加包数与字节；IP 总长超过 MTU 的 TCP 包按对端通告的 MSS 折算为线路分段（D11）。
         *
         * @return 是否发生了超大包折算
         */
        boolean count(PacketHeaders.Packet p, boolean fromInit, int mtu) {
            long segs = 1;
            long bytes = p.ipTotal();
            boolean oversize = false;
            if (p.protocol() == 6 && !p.laterFragment() && p.tcpHeader() >= 20 && p.ipTotal() > mtu) {
                int mss = fromInit ? mssResp : mssInit; // initiator 发出的分段受 responder 通告的 MSS 约束
                int hdr = p.ipHeader() + p.tcpHeader();
                if (mss == 0) mss = mtu - hdr;
                int payload = p.ipTotal() - hdr;
                if (mss > 0 && payload > 0) {
                    int n = (payload + mss - 1) / mss;
                    segs = n;
                    bytes = (long) payload + (long) n * hdr;
                    oversize = true;
                }
            }
            if (fromInit) {
                spkts += segs;
                sbytes += bytes;
            } else {
                dpkts += segs;
                dbytes += bytes;
            }
            return oversize;
        }
    }
}
