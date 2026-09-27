package com.xyh.cybersecurity.ingest.netflow;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 受控的 NetFlow v9/IPFIX 二进制解码器。只按已登记模板切分数据，不根据字段名称或长度猜测语义。
 */
public final class NetflowDecoder {
    private final NetflowTemplateRegistry templates;
    private final FieldNameResolver resolver;
    private final Map<SequenceKey, SequenceState> lastSequences = new HashMap<>();

    public NetflowDecoder(NetflowTemplateRegistry templates, FieldNameResolver resolver) {
        this.templates = templates;
        this.resolver = resolver == null ? (protocol, enterprise, id) -> null : resolver;
    }

    public synchronized DecodeResult decode(byte[] datagram, String protocol, String exporter, Instant receivedAt) {
        if (datagram == null || exporter == null || exporter.isBlank()) throw new IllegalArgumentException("报文或 exporter 不完整");
        if ("ipfix".equals(protocol)) return decodeIpfix(datagram, exporter, receivedAt == null ? Instant.now() : receivedAt);
        if ("netflow-v9".equals(protocol)) return decodeV9(datagram, exporter, receivedAt == null ? Instant.now() : receivedAt);
        throw new DecodeException("NETFLOW_VERSION_UNSUPPORTED");
    }

    private DecodeResult decodeIpfix(byte[] bytes, String exporter, Instant now) {
        if (bytes.length < 16) throw new DecodeException("IPFIX_HEADER_TRUNCATED");
        ByteBuffer b = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN);
        int version = unsignedShort(b.getShort()); int length = unsignedShort(b.getShort());
        if (version != 10 || length < 16 || length > bytes.length) throw new DecodeException("IPFIX_HEADER_INVALID");
        b.getInt(); long sequence = unsignedInt(b.getInt()); long domain = unsignedInt(b.getInt());
        return decodeSets(b, length, "ipfix", exporter, domain, sequence, 0, now);
    }

    private DecodeResult decodeV9(byte[] bytes, String exporter, Instant now) {
        if (bytes.length < 20) throw new DecodeException("NETFLOW_V9_HEADER_TRUNCATED");
        ByteBuffer b = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN);
        int version = unsignedShort(b.getShort()); int count = unsignedShort(b.getShort());
        b.getInt(); b.getInt(); long sequence = unsignedInt(b.getInt()); long sourceId = unsignedInt(b.getInt());
        if (version != 9 || count < 1) throw new DecodeException("NETFLOW_V9_HEADER_INVALID");
        return decodeSets(b, bytes.length, "netflow-v9", exporter, sourceId, sequence, count, now);
    }

    private DecodeResult decodeSets(ByteBuffer b, int packetLength, String protocol, String exporter,
                                    long domain, long sequence, long v9PacketCount, Instant now) {
        List<NetflowTemplateRegistry.Template> learned = new ArrayList<>();
        List<Map<String, Object>> records = new ArrayList<>();
        List<String> errors = new ArrayList<>();
        while (b.position() + 4 <= packetLength) {
            int setId = unsignedShort(b.getShort()); int setLength = unsignedShort(b.getShort());
            if (setLength < 4 || b.position() - 4 + setLength > packetLength) { errors.add("SET_LENGTH_INVALID"); break; }
            int end = b.position() - 4 + setLength;
            if (("ipfix".equals(protocol) && setId == 2) || ("netflow-v9".equals(protocol) && setId == 0)) {
                try {
                    for (var template : readTemplates(b, end, protocol, exporter, domain)) {
                        templates.register(template, now);
                        learned.add(template);
                    }
                } catch (DecodeException e) { errors.add(e.code); }
            } else if (setId >= 256) {
                try {
                    var key = new NetflowTemplateRegistry.TemplateKey(protocol, exporter, domain, setId);
                    var template = templates.require(key, now);
                    records.addAll(readData(b, end, template, protocol));
                } catch (NetflowTemplateRegistry.TemplateException | DecodeException e) { errors.add(e.getMessage()); }
            }
            b.position(end);
        }
        long increment = "ipfix".equals(protocol) ? records.size() : v9PacketCount;
        SequenceKey sequenceKey = new SequenceKey(protocol, exporter, domain);
        SequenceState previous = lastSequences.get(sequenceKey);
        boolean gap = !records.isEmpty() && previous != null && sequence != ((previous.start() + previous.increment()) & 0xffff_ffffL);
        if (!records.isEmpty()) lastSequences.put(sequenceKey, new SequenceState(sequence, increment));
        return new DecodeResult(protocol, exporter, domain, sequence, gap, List.copyOf(learned), List.copyOf(records), List.copyOf(errors));
    }

    private List<NetflowTemplateRegistry.Template> readTemplates(ByteBuffer b, int end, String protocol, String exporter, long domain) {
        List<NetflowTemplateRegistry.Template> result = new ArrayList<>();
        while (b.position() < end) {
            if (end - b.position() < 4) { b.position(end); break; }
            int id = unsignedShort(b.getShort()); int count = unsignedShort(b.getShort());
            if (id < 256 || count < 1) throw new DecodeException("TEMPLATE_EMPTY");
            List<NetflowTemplateRegistry.Field> fields = new ArrayList<>();
            for (int i = 0; i < count; i++) {
                if (b.position() + 4 > end) throw new DecodeException("TEMPLATE_FIELD_TRUNCATED");
                int rawId = unsignedShort(b.getShort()); int length = unsignedShort(b.getShort());
                long enterprise = 0;
                if ("ipfix".equals(protocol) && (rawId & 0x8000) != 0) {
                    rawId &= 0x7fff;
                    if (b.position() + 4 > end) throw new DecodeException("TEMPLATE_ENTERPRISE_TRUNCATED");
                    enterprise = unsignedInt(b.getInt());
                }
                String semantic = resolver.resolve(protocol, enterprise, rawId);
                if (semantic == null || semantic.isBlank()) semantic = "ie:" + enterprise + ":" + rawId;
                fields.add(new NetflowTemplateRegistry.Field(enterprise, rawId, length, "unknown", semantic));
            }
            result.add(new NetflowTemplateRegistry.Template(new NetflowTemplateRegistry.TemplateKey(protocol, exporter, domain, id), fields, Instant.EPOCH));
        }
        return result;
    }

    private List<Map<String, Object>> readData(ByteBuffer b, int end, NetflowTemplateRegistry.Template template, String protocol) {
        int width = template.fields().stream().mapToInt(NetflowTemplateRegistry.Field::length).sum();
        int remaining = end - b.position();
        if (width <= 0) throw new DecodeException("DATA_LENGTH_MISMATCH");
        int padding = remaining % width;
        if (padding != 0 && padding > 3) throw new DecodeException("DATA_LENGTH_MISMATCH");
        for (int i = 0; i < padding; i++) {
            if (b.get(b.position() + remaining - padding + i) != 0) throw new DecodeException("DATA_LENGTH_MISMATCH");
        }
        int dataEnd = end - padding;
        List<Map<String, Object>> result = new ArrayList<>();
        while (b.position() < dataEnd) {
            Map<String, Object> row = new HashMap<>();
            for (var field : template.fields()) {
                if (field.length() == 65535) throw new DecodeException("VARIABLE_LENGTH_UNSUPPORTED");
                row.put(field.semanticName(), readValue(b, field.length()));
            }
            result.add(Map.copyOf(row));
        }
        b.position(end);
        return result;
    }

    private static Object readValue(ByteBuffer b, int length) {
        if (length < 0 || length > b.remaining()) throw new DecodeException("DATA_FIELD_TRUNCATED");
        if (length == 1) return b.get() & 0xffL;
        if (length == 2) return unsignedShort(b.getShort());
        if (length == 4) return unsignedInt(b.getInt());
        if (length == 8) return b.getLong();
        byte[] value = new byte[length]; b.get(value); return value;
    }
    private static int unsignedShort(short value) { return Short.toUnsignedInt(value); }
    private static long unsignedInt(int value) { return Integer.toUnsignedLong(value); }

    public interface FieldNameResolver { String resolve(String protocol, long enterpriseId, long informationElementId); }
    private record SequenceKey(String protocol, String exporter, long domain) { }
    private record SequenceState(long start, long increment) { }
    public record DecodeResult(String protocol, String exporter, long observationDomain, long sequence, boolean sequenceGap,
                               List<NetflowTemplateRegistry.Template> learnedTemplates, List<Map<String, Object>> records,
                               List<String> errors) { }
    public static final class DecodeException extends RuntimeException {
        private final String code;
        public DecodeException(String code) { super(code); this.code = code; }
    }
}
