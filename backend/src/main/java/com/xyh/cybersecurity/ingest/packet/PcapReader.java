package com.xyh.cybersecurity.ingest.packet;

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.time.Instant;

/**
 * 经典 pcap 文件读取（G2 包级对拍的 Java 参考实现）。只接受 LINKTYPE_ETHERNET；只读不写，
 * 不打开网卡。支持微秒（0xa1b2c3d4）与纳秒（0xa1b23c4d）时间戳魔数及两种字节序。
 */
public final class PcapReader implements AutoCloseable {
    /** 单条记录上限，防止损坏文件导致超大分配。 */
    private static final int MAX_RECORD = 262_144;

    public record Frame(Instant timestamp, byte[] data, int wireLength) { }

    private final DataInputStream in;
    private final ByteOrder order;
    private final boolean nanos;

    public PcapReader(InputStream stream) throws IOException {
        this.in = new DataInputStream(stream);
        byte[] header = in.readNBytes(24);
        if (header.length != 24) throw new IOException("不是可读的 pcap 文件");
        int magicLe = ByteBuffer.wrap(header, 0, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        int magicBe = ByteBuffer.wrap(header, 0, 4).order(ByteOrder.BIG_ENDIAN).getInt();
        if (magicLe == 0xa1b2c3d4 || magicLe == 0xa1b23c4d) {
            order = ByteOrder.LITTLE_ENDIAN;
            nanos = magicLe == 0xa1b23c4d;
        } else if (magicBe == 0xa1b2c3d4 || magicBe == 0xa1b23c4d) {
            order = ByteOrder.BIG_ENDIAN;
            nanos = magicBe == 0xa1b23c4d;
        } else {
            throw new IOException("不是经典 pcap 格式");
        }
        int linkType = ByteBuffer.wrap(header, 20, 4).order(order).getInt();
        if (linkType != 1) throw new IOException("链路类型 " + linkType + " 不是以太网");
    }

    /** @return 下一帧；文件结束返回 {@code null} */
    public Frame next() throws IOException {
        byte[] rec = in.readNBytes(16);
        if (rec.length == 0) return null;
        if (rec.length != 16) throw new EOFException("pcap 记录头被截断");
        ByteBuffer b = ByteBuffer.wrap(rec).order(order);
        long sec = Integer.toUnsignedLong(b.getInt());
        long frac = Integer.toUnsignedLong(b.getInt());
        int capLen = b.getInt();
        int wireLen = b.getInt();
        if (capLen < 0 || capLen > MAX_RECORD || wireLen < capLen) throw new IOException("pcap 记录长度非法");
        byte[] data = in.readNBytes(capLen);
        if (data.length != capLen) throw new EOFException("pcap 记录数据被截断");
        Instant ts = Instant.ofEpochSecond(sec, nanos ? frac : frac * 1_000);
        return new Frame(ts, data, wireLen);
    }

    @Override
    public void close() throws IOException { in.close(); }
}
