package com.xyh.cybersecurity.ingest.feature;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.xyh.cybersecurity.ingest.contract.FeatureContract;
import com.xyh.cybersecurity.ingest.contract.FeatureContractRegistry;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/**
 * 测试辅助：读取已入库的 v4 golden fixtures（来源交付包 unsw-binary-2026.10.0，地址已映射为 RFC 5737 文档地址，
 * 不含标签），并在读取前核对 checksums.json 与契约登记的哈希。
 */
public final class V4Fixtures {
    public static final String CONTRACT = "unsw-nb15-flow-v4";
    private static final ObjectMapper JSON = new ObjectMapper();

    private V4Fixtures() { }

    public static FeatureContract contract() {
        return FeatureContractRegistry.fromClasspath().require(CONTRACT);
    }

    /** 读取 fixtures 目录下的文件字节；缺失即失败，不跳过。 */
    public static byte[] bytes(String name) {
        String path = "/" + contract().goldenFixtures().path() + name;
        try (InputStream input = V4Fixtures.class.getResourceAsStream(path)) {
            if (input == null) throw new IllegalStateException("fixtures 文件缺失: " + name);
            return input.readAllBytes();
        } catch (IOException exception) {
            throw new IllegalStateException(exception);
        }
    }

    /** 核对 checksums.json 自身哈希等于契约登记值，且其中每个文件哈希都匹配。 */
    public static void verifyChecksums() {
        byte[] checksums = bytes("checksums.json");
        if (!sha256(checksums).equals(contract().goldenFixtures().checksumsSha256())) {
            throw new IllegalStateException("fixtures checksums.json 与契约登记哈希不一致");
        }
        try {
            JSON.readTree(checksums).fields().forEachRemaining(entry -> {
                if (!sha256(bytes(entry.getKey())).equals(entry.getValue().asText())) {
                    throw new IllegalStateException("fixtures 文件哈希不一致: " + entry.getKey());
                }
            });
        } catch (IOException exception) {
            throw new IllegalStateException(exception);
        }
    }

    public static JsonNode fixtureInfo() {
        try {
            return JSON.readTree(bytes("fixture.json"));
        } catch (IOException exception) {
            throw new IllegalStateException(exception);
        }
    }

    public static List<JsonNode> jsonl(String name) {
        List<JsonNode> rows = new ArrayList<>();
        for (String line : new String(bytes(name), StandardCharsets.UTF_8).split("\n")) {
            if (line.isBlank()) continue;
            try {
                rows.add(JSON.readTree(line));
            } catch (IOException exception) {
                throw new IllegalStateException(exception);
            }
        }
        return rows;
    }

    /** raw-flows.jsonl 的一行 → Feature Builder 输入；导出序号取 fixture 的 seq（已按 (ltime, stime, seq) 排序）。 */
    public static FeatureBuilder.FlowInput flow(JsonNode r) {
        return new FeatureBuilder.FlowInput("fixture-" + r.get("seq").asLong(),
                Instant.ofEpochSecond(r.get("stime").asLong()), Instant.ofEpochSecond(r.get("ltime").asLong()),
                r.get("seq").asLong(), r.get("srcip").asText(), r.get("dstip").asText(), r.get("dsport").asInt(),
                r.get("proto").asText(), r.get("dur").asDouble(), r.get("sbytes").asLong(), r.get("dbytes").asLong(),
                r.get("sload").asDouble(), r.get("dload").asDouble(), r.get("tcprtt").asDouble(),
                r.get("ackdat").asDouble(), r.get("synack").asDouble(), r.get("smean").asLong(),
                r.get("dmean").asLong(), r.get("spkts").asLong(), r.get("dpkts").asLong());
    }

    /** 以 fixture.json 的 sensor_host 为本机，按顺序构造全部流；返回 seq → 构造结论。 */
    public static Map<Long, FeatureBuilder.BuildResult> buildAll() {
        FeatureBuilder builder = new FeatureBuilder(contract(), AddressPolicy.unswReplay(fixtureInfo().get("sensor_host").asText()));
        Map<Long, FeatureBuilder.BuildResult> results = new java.util.LinkedHashMap<>();
        for (JsonNode row : jsonl("raw-flows.jsonl")) results.put(row.get("seq").asLong(), builder.accept(flow(row)));
        return results;
    }

    static String sha256(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (Exception exception) {
            throw new IllegalStateException(exception);
        }
    }
}
