package com.xyh.cybersecurity.ingest.replay;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.xyh.cybersecurity.ingest.feature.AddressPolicy;
import com.xyh.cybersecurity.ingest.feature.FeatureBuilder;
import com.xyh.cybersecurity.ingest.feature.V4Fixtures;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** 传感器回放命令：构造口径与在线 Feature Builder 一致、时间平移保间隔、切批上限、凭据传输限制。 */
class SensorReplayCliTest {
    private static final Instant ANCHOR = Instant.parse("2026-09-29T12:00:00Z");

    private static List<UnswRawFlowReplayAdapter.RawFlow> fixtureRows() {
        List<UnswRawFlowReplayAdapter.RawFlow> rows = new ArrayList<>();
        for (JsonNode row : V4Fixtures.jsonl("raw-flows.jsonl")) {
            rows.add(new UnswRawFlowReplayAdapter.RawFlow(V4Fixtures.flow(row), null, null));
        }
        return rows;
    }

    @Test
    void buildsReadyRecordsIdenticalToFeatureBuilderAndShiftsTimeUniformly() {
        List<UnswRawFlowReplayAdapter.RawFlow> rows = fixtureRows();
        SensorReplayCli.Built built = SensorReplayCli.build(rows, new FeatureBuilder(V4Fixtures.contract(),
                AddressPolicy.unswReplay(V4Fixtures.fixtureInfo().get("sensor_host").asText())), ANCHOR);

        // 与 fixture.json 登记的结论一致：99 条窗口预热不提交，其余 READY（含 1 条 initiator 视角）。
        assertThat(built.counts().get(FeatureBuilder.Status.WINDOW_NOT_READY)).isEqualTo(99);
        assertThat(built.records()).hasSize(rows.size() - 99);
        Map<Long, FeatureBuilder.BuildResult> expected = V4Fixtures.buildAll();
        for (ObjectNode record : built.records()) {
            long seq = rows.stream().filter(r -> r.flow().recordKey().equals(record.path("recordKey").asText()))
                    .findFirst().orElseThrow().flow().exportSeq();
            assertThat(record.path("features")).as("seq %d", seq).isEqualTo(expected.get(seq).features());
            assertThat(record.path("directionBasis").asText()).isEqualTo("initiator_to_responder");
            assertThat(record.has("srcip") || record.toString().contains("192.0.2.")).as("地址不出现在上报记录中").isFalse();
        }
        assertThat(built.records().stream().filter(r -> "initiator".equals(r.path("viewpoint").asText())).count()).isEqualTo(1);

        // 最晚一条流落在锚点前 120 秒；平移量对所有流相同，流内时长不变。
        Instant latest = built.records().stream().map(r -> Instant.parse(r.path("flowEndAt").asText()))
                .max(Instant::compareTo).orElseThrow();
        assertThat(latest).isEqualTo(ANCHOR.minusSeconds(120));
        UnswRawFlowReplayAdapter.RawFlow first = rows.stream()
                .filter(r -> r.flow().recordKey().equals(built.records().getFirst().path("recordKey").asText()))
                .findFirst().orElseThrow();
        ObjectNode firstRecord = built.records().getFirst();
        assertThat(Duration.between(Instant.parse(firstRecord.path("flowStartAt").asText()),
                Instant.parse(firstRecord.path("flowEndAt").asText())))
                .isEqualTo(Duration.between(first.flow().flowStartAt(), first.flow().flowEndAt()));
        assertThat(Instant.parse(firstRecord.path("flowEndAt").asText()))
                .isEqualTo(first.flow().flowEndAt().plusSeconds(built.shiftSeconds()));
    }

    @Test
    void chunksByCountAndPreservesOrder() {
        SensorReplayCli.Built built = SensorReplayCli.build(fixtureRows(), new FeatureBuilder(V4Fixtures.contract(),
                AddressPolicy.unswReplay(V4Fixtures.fixtureInfo().get("sensor_host").asText())), ANCHOR);
        List<List<ObjectNode>> batches = SensorReplayCli.chunk(built.records(), 120);
        assertThat(batches).hasSize(3);
        assertThat(batches.get(0)).hasSize(120);
        assertThat(batches.stream().mapToInt(List::size).sum()).isEqualTo(built.records().size());
        assertThat(batches.stream().flatMap(List::stream).toList()).isEqualTo(built.records());
    }

    @Test
    void credentialsOnlyTravelOverHttpsOrLoopback() {
        assertThat(SensorReplayCli.requireSafeBaseUrl("http://127.0.0.1:18080").getPort()).isEqualTo(18080);
        assertThat(SensorReplayCli.requireSafeBaseUrl("http://localhost:18080")).isNotNull();
        assertThat(SensorReplayCli.requireSafeBaseUrl("https://soc.example.test")).isNotNull();
        for (String unsafe : List.of("http://192.0.2.10:18080", "http://soc.example.test", "ftp://127.0.0.1", "https:///x")) {
            assertThatThrownBy(() -> SensorReplayCli.requireSafeBaseUrl(unsafe)).as(unsafe)
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    void rejectsInvalidOptions() {
        assertThatThrownBy(() -> SensorReplayCli.parse(new String[] {"--csv", "x.csv", "--batch-size", "501", "--dry-run"}))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SensorReplayCli.parse(new String[] {"--csv", "x.csv", "--key-prefix", "bad key", "--dry-run"}))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SensorReplayCli.parse(new String[] {"--csv", "x.csv", "--anchor",
                Instant.now().plusSeconds(3600).toString(), "--dry-run"})).isInstanceOf(IllegalArgumentException.class);
        assertThat(SensorReplayCli.parse(new String[] {"--csv", "x.csv", "--dry-run"}).sensorHost()).isEqualTo("149.171.126.3");
    }
}
