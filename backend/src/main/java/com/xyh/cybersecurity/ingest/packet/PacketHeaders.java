package com.xyh.cybersecurity.ingest.packet;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Instant;

/**
 * 以太网帧 IP/TCP/UDP 头部解析（特征规格 unsw-nb15-flow-v4 §1.3、D8）。G2 包级对拍的 Java 参考实现，
 * 与 Go 传感器 {@code sensor/internal/packet} 逐项同口径；只读头部字段，不保留载荷。
 */
public final class PacketHeaders {
    private PacketHeaders() { }

    public enum Status { OK, NON_IP, TRUNCATED, MALFORMED }

    /** 单个报文的头部元数据；ICMP 等无端口协议端口为 0。 */
    public record Packet(Instant timestamp, int addressFamily, InetAddress source, InetAddress destination,
                         int sourcePort, int destinationPort, int protocol, int ipTotal, int ipHeader, int tcpHeader,
                         boolean syn, boolean ack, boolean fin, boolean rst, int mss,
                         boolean firstFragment, boolean laterFragment, long fragmentId) { }

    public record Result(Status status, Packet packet) {
        static Result of(Status status) { return new Result(status, null); }
    }

    /** @param wireLength 线路帧长；IP 长度字段为 0 时用「线路长度 − 链路层头」推算 */
    public static Result parseEthernet(byte[] data, int wireLength, Instant timestamp) {
        if (data.length < 14) return Result.of(Status.TRUNCATED);
        int etype = u16(data, 12);
        int off = 14;
        while (etype == 0x8100 || etype == 0x88a8) {
            if (data.length < off + 4) return Result.of(Status.TRUNCATED);
            etype = u16(data, off + 2);
            off += 4;
        }
        return parseIp(data, off, etype, wireLength - off, timestamp);
    }

    private static Result parseIp(byte[] b, int o, int etype, int l3Wire, Instant ts) {
        int n = b.length - o;
        int af, ipHdr, ipTotal, proto;
        long fragId = 0;
        boolean first = false, later = false;
        InetAddress src, dst;
        if (etype == 0x0800) {
            if (n < 20) return Result.of(Status.TRUNCATED);
            int ihl = (b[o] & 0x0f) * 4;
            if ((b[o] & 0xff) >> 4 != 4 || ihl < 20) return Result.of(Status.MALFORMED);
            if (n < ihl) return Result.of(Status.TRUNCATED);
            af = 4;
            ipHdr = ihl;
            ipTotal = u16(b, o + 2);
            int ff = u16(b, o + 6);
            proto = b[o + 9] & 0xff;
            src = addr(b, o + 12, 4);
            dst = addr(b, o + 16, 4);
            fragId = u16(b, o + 4);
            if ((ff & 0x1fff) != 0) later = true; else if ((ff & 0x2000) != 0) first = true;
        } else if (etype == 0x86dd) {
            if (n < 40) return Result.of(Status.TRUNCATED);
            if ((b[o] & 0xff) >> 4 != 6) return Result.of(Status.MALFORMED);
            af = 6;
            int pl = u16(b, o + 4);
            ipTotal = pl == 0 ? 0 : 40 + pl;
            src = addr(b, o + 8, 16);
            dst = addr(b, o + 24, 16);
            int next = b[o + 6] & 0xff;
            int hdr = 40;
            ext:
            for (int i = 0; i < 8; i++) {
                switch (next) {
                    case 0, 43, 60 -> {
                        if (n < hdr + 2) return Result.of(Status.TRUNCATED);
                        int nh = b[o + hdr] & 0xff;
                        hdr += ((b[o + hdr + 1] & 0xff) + 1) * 8;
                        next = nh;
                    }
                    case 51 -> {
                        if (n < hdr + 2) return Result.of(Status.TRUNCATED);
                        int nh = b[o + hdr] & 0xff;
                        hdr += ((b[o + hdr + 1] & 0xff) + 2) * 4;
                        next = nh;
                    }
                    case 44 -> {
                        if (n < hdr + 8) return Result.of(Status.TRUNCATED);
                        fragId = u32(b, o + hdr + 4);
                        if ((u16(b, o + hdr + 2) >> 3) != 0) later = true;
                        else if ((b[o + hdr + 3] & 1) != 0) first = true;
                        int nh = b[o + hdr] & 0xff;
                        hdr += 8;
                        next = nh;
                    }
                    default -> { break ext; }
                }
            }
            ipHdr = hdr;
            proto = next;
        } else {
            return Result.of(Status.NON_IP);
        }
        if (ipTotal < ipHdr) ipTotal = l3Wire;
        int sport = 0, dport = 0, tcpHdr = 0, mss = 0;
        boolean syn = false, ack = false, fin = false, rst = false;
        if (!later) {
            if (n < ipHdr) return Result.of(Status.TRUNCATED);
            int t = o + ipHdr;
            int tn = b.length - t;
            if (proto == 6) {
                if (tn < 14) return Result.of(Status.TRUNCATED);
                sport = u16(b, t);
                dport = u16(b, t + 2);
                tcpHdr = ((b[t + 12] & 0xff) >> 4) * 4;
                if (tcpHdr < 20) return Result.of(Status.MALFORMED);
                int fl = b[t + 13] & 0xff;
                fin = (fl & 0x01) != 0; syn = (fl & 0x02) != 0; rst = (fl & 0x04) != 0; ack = (fl & 0x10) != 0;
                if (tn >= tcpHdr && syn) mss = findMss(b, t + 20, t + tcpHdr);
            } else if (proto == 17) {
                if (tn < 4) return Result.of(Status.TRUNCATED);
                sport = u16(b, t);
                dport = u16(b, t + 2);
            }
        }
        return new Result(Status.OK, new Packet(ts, af, src, dst, sport, dport, proto, ipTotal, ipHdr, tcpHdr,
                syn, ack, fin, rst, mss, first, later, fragId));
    }

    /** TCP 选项中的 MSS（kind=2, len=4）；只读头部选项。 */
    private static int findMss(byte[] b, int from, int to) {
        int i = from;
        while (i < to) {
            int kind = b[i] & 0xff;
            if (kind == 0) return 0;
            if (kind == 1) { i++; continue; }
            if (i + 1 >= to || (b[i + 1] & 0xff) < 2) return 0;
            int len = b[i + 1] & 0xff;
            if (kind == 2 && len == 4 && i + 4 <= to) return u16(b, i + 2);
            i += len;
        }
        return 0;
    }

    private static InetAddress addr(byte[] b, int off, int len) {
        byte[] raw = new byte[len];
        System.arraycopy(b, off, raw, 0, len);
        try {
            return InetAddress.getByAddress(raw);
        } catch (UnknownHostException exception) {
            throw new IllegalStateException("地址长度非法", exception);
        }
    }

    private static int u16(byte[] b, int off) { return ((b[off] & 0xff) << 8) | (b[off + 1] & 0xff); }

    private static long u32(byte[] b, int off) { return ((long) u16(b, off) << 16) | u16(b, off + 2); }
}
