package com.xyh.cybersecurity.ingest.packet;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.xyh.cybersecurity.ingest.feature.AddressPolicy;
import com.xyh.cybersecurity.ingest.feature.V4Fixtures;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * G2 包级对拍：同一合成 pcap 分别由 Go 传感器（fixtures 中的期望记录，由 sensor/cmd/g2fixtures 生成）与
 * Java 参考实现（{@link PacketFeatureReference}）独立计算，逐记录、逐字段、逐位比较。
 * fixtures 只含文档保留地址与零载荷，只验证实现一致性，不代表真实流量分布。
 */
class PacketLevelParityTest {
    private static final String DIR = "/feature-contract/fixtures/unsw-nb15-flow-v4-packet/";
    private static final ObjectMapper JSON = new ObjectMapper();

    private static byte[] bytes(String name) throws Exception {
        try (InputStream in = PacketLevelParityTest.class.getResourceAsStream(DIR + name)) {
            assertThat(in).as(name).isNotNull();
            return in.readAllBytes();
        }
    }

    @Test
    void fixturesMatchTheirChecksums() throws Exception {
        JsonNode sums = JSON.readTree(bytes("checksums.json"));
        assertThat(sums.size()).isEqualTo(4);
        for (Iterator<String> names = sums.fieldNames(); names.hasNext(); ) {
            String name = names.next();
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes(name));
            assertThat(java.util.HexFormat.of().formatHex(digest)).as(name).isEqualTo(sums.get(name).asText());
        }
    }

    @Test
    void javaReferenceMatchesGoSensorRecordByRecord() throws Exception {
        JsonNode fx = JSON.readTree(bytes("fixture.json"));
        assertThat(fx.path("contract").asText()).isEqualTo(V4Fixtures.CONTRACT);
        Set<String> locals = new HashSet<>();
        fx.path("localAddrs").forEach(a -> locals.add(a.asText()));
        List<String> subnets = new ArrayList<>();
        fx.path("subnets").forEach(s -> subnets.add(s.asText()));
        PacketFeatureReference.Result result = PacketFeatureReference.run(new ByteArrayInputStream(bytes("capture.pcap")),
                V4Fixtures.contract(), AddressPolicy.forSensor(locals, subnets), fx.path("keyBase").asText(),
                fx.path("mtu").asInt());

        List<JsonNode> expected = new ArrayList<>();
        for (String line : new String(bytes("expected-records.jsonl"), StandardCharsets.UTF_8).split("\n")) {
            if (!line.isBlank()) expected.add(JSON.readTree(line));
        }
        assertThat(result.records()).hasSize(expected.size());
        for (int i = 0; i < expected.size(); i++) compare(expected.get(i), result.records().get(i));

        JsonNode d = JSON.readTree(bytes("expected-diagnostics.json"));
        PacketFeatureReference.Diagnostics actual = result.diagnostics();
        assertThat(actual.frames()).isEqualTo(d.path("frames").asLong());
        assertThat(actual.parseStatus()).isEqualTo(counts(d.path("parse_status")));
        assertThat(actual.closeReasons()).isEqualTo(counts(d.path("close_reasons")));
        assertThat(actual.excluded()).isEqualTo(counts(d.path("feature").path("flows_excluded")));
        assertThat(actual.byStatus()).isEqualTo(counts(d.path("feature").path("records_by_status")));
        JsonNode flow = d.path("flow");
        assertThat(actual.flow()).isEqualTo(new PacketFlowAssembler.Diagnostics(flow.path("post_close_packets").asLong(),
                flow.path("orphan_fragments").asLong(), flow.path("oversize_tcp_packets").asLong(),
                flow.path("flow_capacity_drops").asLong(), flow.path("max_active_flows").asInt()));
        // fixtures 至少覆盖三种输出状态与三类排除，防止场景被意外删减后对拍变成空比较。
        assertThat(actual.byStatus()).containsKeys("ready", "window_not_ready", "rejected");
        assertThat(actual.excluded()).containsKeys("multicast_destination", "broadcast_destination", "no_local_endpoint");
    }

    private static void compare(JsonNode want, PacketFeatureReference.Output got) {
        String key = want.path("recordKey").asText();
        assertThat(got.recordKey()).as("recordKey").isEqualTo(key);
        assertThat(got.exportSeq()).as(key + " exportSeq").isEqualTo(want.path("exportSeq").asLong());
        assertThat(got.flowStartAt()).as(key + " flowStartAt").isEqualTo(Instant.parse(want.path("flowStartAt").asText()));
        assertThat(got.flowEndAt()).as(key + " flowEndAt").isEqualTo(Instant.parse(want.path("flowEndAt").asText()));
        assertThat(got.status()).as(key + " status").isEqualTo(want.path("status").asText());
        assertThat(got.reason()).as(key + " reason").isEqualTo(want.has("reason") ? want.get("reason").asText() : null);
        assertThat(got.closeReason()).as(key + " closeReason").isEqualTo(want.path("closeReason").asText());
        assertThat(got.addressFamily()).as(key + " addressFamily").isEqualTo(want.path("addressFamily").asText());
        assertThat(got.viewpoint()).as(key + " viewpoint").isEqualTo(want.path("viewpoint").asText());
        assertThat(got.handshakeSeen()).as(key + " handshakeSeen").isEqualTo(want.path("handshakeSeen").asBoolean());
        JsonNode wf = want.path("features");
        if (wf.isNull()) {
            assertThat(got.features()).as(key + " features").isNull();
            return;
        }
        assertThat(got.features()).as(key + " features").isNotNull();
        assertThat(names(got.features())).as(key + " 字段顺序").isEqualTo(names(wf));
        for (String name : names(wf)) {
            JsonNode w = wf.get(name);
            JsonNode g = got.features().get(name);
            if (w.isTextual()) {
                assertThat(g.isTextual() ? g.asText() : null).as(key + " " + name).isEqualTo(w.asText());
            } else {
                assertThat(g.isNumber()).as(key + " " + name + " 类型").isTrue();
                assertThat(g.asDouble()).as(key + " " + name).isEqualTo(w.asDouble());
            }
        }
    }

    private static List<String> names(JsonNode node) {
        List<String> out = new ArrayList<>();
        node.fieldNames().forEachRemaining(out::add);
        return out;
    }

    private static Map<String, Long> counts(JsonNode node) {
        Map<String, Long> out = new HashMap<>();
        node.fields().forEachRemaining(e -> out.put(e.getKey(), e.getValue().asLong()));
        return out;
    }
}
