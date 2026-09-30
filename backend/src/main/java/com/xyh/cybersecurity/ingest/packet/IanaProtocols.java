package com.xyh.cybersecurity.ingest.packet;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.HashMap;
import java.util.Map;

/**
 * 特征规格 §2.2 的 proto 映射：IANA 协议号 → 关键字小写；表中没有的协议号记 {@code proto-<号>}。
 *
 * <p>读取 {@code classpath:feature-contract/tables/iana-protocol-numbers.json}，与 Go 传感器内嵌的是同一文件
 * （传感器单测逐字节比对）。表无效时类加载失败，不回退到其他口径。</p>
 */
public final class IanaProtocols {
    static final String LOCATION = "feature-contract/tables/iana-protocol-numbers.json";
    private static final Map<Integer, String> NAMES = load();

    private IanaProtocols() { }

    public static String name(int protocol) {
        String name = NAMES.get(protocol);
        return name != null ? name : "proto-" + protocol;
    }

    private static Map<Integer, String> load() {
        try (InputStream in = IanaProtocols.class.getClassLoader().getResourceAsStream(LOCATION)) {
            if (in == null) throw new IllegalStateException("IANA 协议表不存在: " + LOCATION);
            JsonNode root = new ObjectMapper().readTree(in);
            JsonNode entries = root.path("entries");
            if (!"iana-protocol-numbers".equals(root.path("name").asText()) || !entries.isObject() || entries.isEmpty()) {
                throw new IllegalStateException("IANA 协议表无效");
            }
            Map<Integer, String> out = new HashMap<>();
            entries.fields().forEachRemaining(entry -> {
                int number = Integer.parseInt(entry.getKey());
                if (number < 0 || number > 255 || !Integer.toString(number).equals(entry.getKey())) {
                    throw new IllegalStateException("IANA 协议表含非法协议号");
                }
                out.put(number, entry.getValue().asText());
            });
            return Map.copyOf(out);
        } catch (IOException exception) {
            throw new UncheckedIOException("IANA 协议表无法读取", exception);
        }
    }
}
