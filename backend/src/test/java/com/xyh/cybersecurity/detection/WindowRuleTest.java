package com.xyh.cybersecurity.detection;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.xyh.cybersecurity.ingest.IngestMapper;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** 时间窗聚合规则：条件解析、窗口判定与告警抑制、在线告警生成（开发路线 §4.2）。 */
class WindowRuleTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Instant T0 = Instant.parse("2026-09-30T11:14:00Z");
    private static final String SCAN = "{\"all\":[{\"field\":\"features.proto\",\"op\":\"eq\",\"value\":\"tcp\"},"
            + "{\"field\":\"metadata.viewpoint\",\"op\":\"eq\",\"value\":\"responder\"},"
            + "{\"field\":\"features.synack\",\"op\":\"eq\",\"value\":0}],"
            + "\"window\":{\"seconds\":60,\"aggregate\":\"count\",\"threshold\":3}}";

    private static RuleCondition.Window window(String json) throws Exception {
        return RuleCondition.parse(JSON.readTree(json)).window();
    }

    private static WindowAggregation.Point point(long id, int second, double value) {
        return new WindowAggregation.Point(id, T0.plusSeconds(second), value);
    }

    @Test
    void windowBlockParsesCountAndSum() throws Exception {
        RuleCondition.Window count = window(SCAN);
        assertThat(count.seconds()).isEqualTo(60);
        assertThat(count.sum()).isFalse();
        assertThat(count.field()).isNull();

        RuleCondition.Window sum = window("{\"all\":[{\"field\":\"features.proto\",\"op\":\"eq\",\"value\":\"udp\"}],"
                + "\"window\":{\"seconds\":30,\"aggregate\":\"sum\",\"field\":\"features.spkts\",\"threshold\":300,"
                + "\"groupBy\":\"asset\"}}");
        assertThat(sum.sum()).isTrue();
        assertThat(sum.contribution(JSON.readTree("{\"features\":{\"spkts\":1600}}"))).isEqualTo(1600.0);
        assertThat(sum.contribution(JSON.readTree("{\"features\":{\"spkts\":\"1600\"}}"))).isNull();
        assertThat(sum.contribution(JSON.readTree("{\"features\":{}}"))).isNull();
        // 逐条规则没有窗口，行为与 V13 一致。
        assertThat(RuleCondition.parse(JSON.readTree("{\"all\":[{\"field\":\"features.dur\",\"op\":\"gt\",\"value\":1}]}"))
                .window()).isNull();
    }

    @Test
    void windowBlockRejectsUnknownKeysGroupingAndBounds() {
        String clause = "{\"field\":\"features.proto\",\"op\":\"eq\",\"value\":\"tcp\"}";
        for (String window : new String[] {
                "{\"seconds\":60,\"aggregate\":\"count\",\"threshold\":3,\"script\":\"x\"}",
                "{\"seconds\":60,\"aggregate\":\"count\",\"threshold\":3,\"groupBy\":\"peer_ip\"}",
                "{\"seconds\":5,\"aggregate\":\"count\",\"threshold\":3}",
                "{\"seconds\":7200,\"aggregate\":\"count\",\"threshold\":3}",
                "{\"seconds\":60.5,\"aggregate\":\"count\",\"threshold\":3}",
                "{\"seconds\":60,\"aggregate\":\"distinct\",\"threshold\":3}",
                "{\"seconds\":60,\"aggregate\":\"count\",\"field\":\"features.spkts\",\"threshold\":3}",
                "{\"seconds\":60,\"aggregate\":\"sum\",\"field\":\"metadata.viewpoint\",\"threshold\":3}",
                "{\"seconds\":60,\"aggregate\":\"sum\",\"threshold\":3}",
                "{\"seconds\":60,\"aggregate\":\"count\",\"threshold\":0}",
                "{\"seconds\":60,\"aggregate\":\"count\",\"threshold\":\"3\"}",
                "[]"}) {
            String condition = "{\"all\":[" + clause + "],\"window\":" + window + "}";
            assertThatThrownBy(() -> RuleCondition.parse(JSON.readTree(condition))).as(window)
                    .isInstanceOf(IllegalArgumentException.class);
        }
        assertThatThrownBy(() -> RuleCondition.parse(JSON.readTree("{\"window\":{\"seconds\":60,\"aggregate\":\"count\","
                + "\"threshold\":3}}"))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> RuleCondition.parse(JSON.readTree("{\"all\":[" + clause + "],\"extra\":1}")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void firesWhenCountReachesThresholdThenSuppressesWithinWindow() throws Exception {
        RuleCondition.Window w = window(SCAN);
        List<WindowAggregation.Point> points = List.of(point(1, 0, 1), point(2, 10, 1), point(3, 20, 1),
                point(4, 30, 1), point(5, 79, 1), point(6, 81, 1), point(7, 82, 1));
        List<WindowAggregation.Firing> firings = WindowAggregation.evaluate(w, points, points, List.of());
        // 第 3 条（t=20）达到阈值；t=30、79 在抑制期内；t=81 时 (21,81] 内有 4、5、6 三条且已出抑制期。
        assertThat(firings).extracting(WindowAggregation.Firing::recordId).containsExactly(3L, 6L);
        assertThat(firings.getFirst().records()).isEqualTo(3);
        assertThat(firings.getFirst().firstEventAt()).isEqualTo(T0);
        assertThat(firings.get(1).firstEventAt()).isEqualTo(T0.plusSeconds(30));
    }

    @Test
    void windowLowerBoundIsExclusiveAndTiesOrderById() throws Exception {
        RuleCondition.Window w = window(SCAN);
        // (t−60, t]：t=60 时 t=0 的记录已出窗。
        List<WindowAggregation.Point> spread = List.of(point(1, 0, 1), point(2, 30, 1), point(3, 60, 1));
        assertThat(WindowAggregation.evaluate(w, spread, spread, List.of())).isEmpty();
        // 同一时刻的记录按 ID 排序，只有排在最后的那条看到全部三条。
        List<WindowAggregation.Point> tie = List.of(point(12, 5, 1), point(10, 5, 1), point(11, 5, 1));
        assertThat(WindowAggregation.evaluate(w, tie, tie, List.of()))
                .extracting(WindowAggregation.Firing::recordId).containsExactly(12L);
    }

    @Test
    void sumAggregatesPacketsOfFewFlows() throws Exception {
        RuleCondition.Window w = window("{\"all\":[{\"field\":\"features.proto\",\"op\":\"eq\",\"value\":\"udp\"}],"
                + "\"window\":{\"seconds\":30,\"aggregate\":\"sum\",\"field\":\"features.spkts\",\"threshold\":300}}");
        List<WindowAggregation.Point> burst = List.of(point(1, 0, 2), point(2, 24, 1600));
        List<WindowAggregation.Firing> firings = WindowAggregation.evaluate(w, burst, burst, List.of());
        assertThat(firings).singleElement().satisfies(f -> {
            assertThat(f.recordId()).isEqualTo(2L);
            assertThat(f.aggregate()).isEqualTo(1602.0);
            assertThat(f.records()).isEqualTo(2);
        });
        List<WindowAggregation.Point> benign = List.of(point(1, 0, 2), point(2, 10, 2), point(3, 20, 19));
        assertThat(WindowAggregation.evaluate(w, benign, benign, List.of())).isEmpty();
    }

    @Test
    void replayWithExistingFiringsProducesNoNewAlertsAndContextFromEarlierBatchesCounts() throws Exception {
        RuleCondition.Window w = window(SCAN);
        List<WindowAggregation.Point> all = List.of(point(1, 0, 1), point(2, 10, 1), point(3, 20, 1), point(4, 25, 1));
        // 重放：第 3 条已有告警，抑制期内的第 4 条不再告警，第 3 条本身由告警键去重。
        assertThat(WindowAggregation.evaluate(w, all, all, List.of(T0.plusSeconds(20)))).isEmpty();
        // 分批到达：前两条在上一批次已落库，本批只含第 3、4 条，仍在第 3 条上告警。
        List<WindowAggregation.Point> batch = all.subList(2, 4);
        assertThat(WindowAggregation.evaluate(w, all, batch, List.of()))
                .extracting(WindowAggregation.Firing::recordId).containsExactly(3L);
    }

    @Test
    void alertGeneratorCreatesOneWindowAlertPerBurstWithBasis() throws Exception {
        DetectionMapper mapper = mock(DetectionMapper.class);
        when(mapper.findActiveRules()).thenReturn(List.of(new DetectionMapper.RuleRow(41, "tcp-port-scan", "1",
                "{\"featureContractVersion\":\"unsw-nb15-flow-v4\"}", SCAN, "high")));
        when(mapper.findBatchContract(7)).thenReturn("unsw-nb15-flow-v4");
        when(mapper.findModelAlertCandidates(7)).thenReturn(List.of());
        when(mapper.lockAsset(3)).thenReturn(new DetectionMapper.AssetRow(3, "lab", "medium"));
        List<IngestMapper.AcceptedRecord> records = new ArrayList<>();
        List<DetectionMapper.WindowRecord> context = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            String payload = "{\"features\":{\"proto\":\"tcp\",\"synack\":0},\"metadata\":{\"viewpoint\":\"responder\"}}";
            records.add(new IngestMapper.AcceptedRecord(100 + i, 7, 3, "k" + i, T0.plusSeconds(i), 3, payload));
            context.add(new DetectionMapper.WindowRecord(100 + i, T0.plusSeconds(i), payload));
        }
        String benign = "{\"features\":{\"proto\":\"tcp\",\"synack\":0.01},\"metadata\":{\"viewpoint\":\"responder\"}}";
        records.add(new IngestMapper.AcceptedRecord(200, 7, 3, "b", T0.plusSeconds(2), 3, benign));
        context.add(new DetectionMapper.WindowRecord(200, T0.plusSeconds(2), benign));
        when(mapper.findAssetWindowRecords(eq(3L), any(), any(), eq("unsw-nb15-flow-v4"), anyInt())).thenReturn(context);
        when(mapper.findRuleFiringTimes(eq(41L), eq(3L), any(), any())).thenReturn(List.of());
        when(mapper.findExistingAlertKeys(any())).thenReturn(List.of());
        when(mapper.findAlertId(anyString())).thenReturn(900L);

        AlertGenerator generator = new AlertGenerator(mapper, JSON);
        List<AlertGenerator.NewAlert> alerts = generator.generate(7, records, policies(), T0.plusSeconds(60));
        assertThat(alerts).singleElement().satisfies(alert -> {
            assertThat(alert.recordId()).isEqualTo(102L);
            assertThat(alert.alertType()).isEqualTo("rule");
            assertThat(alert.severity()).isEqualTo("high");
            assertThat(alert.summary()).contains("tcp-port-scan@1").contains("count=3");
        });
        var captor = org.mockito.ArgumentCaptor.forClass(DetectionMapper.AlertInsert.class);
        org.mockito.Mockito.verify(mapper).insertAlert(captor.capture());
        DetectionMapper.AlertInsert insert = captor.getValue();
        assertThat(insert.alertKey()).isEqualTo("rule:41:102");
        var basis = JSON.readTree(insert.basisJson());
        assertThat(basis.at("/window/value").asDouble()).isEqualTo(3.0);
        assertThat(basis.at("/window/records").asInt()).isEqualTo(3);
        assertThat(basis.at("/window/groupBy").asText()).isEqualTo("asset");
        assertThat(basis.at("/matched/features.synack").asInt()).isZero();
    }

    @Test
    void scopedRuleSkipsBatchesOfOtherContracts() throws Exception {
        DetectionMapper mapper = mock(DetectionMapper.class);
        when(mapper.findActiveRules()).thenReturn(List.of(new DetectionMapper.RuleRow(41, "tcp-port-scan", "1",
                "{\"featureContractVersion\":\"unsw-nb15-flow-v4\"}", SCAN, "high")));
        when(mapper.findBatchContract(7)).thenReturn("unsw-nb15-flow-v3.1");
        String payload = "{\"features\":{\"proto\":\"tcp\",\"synack\":0},\"metadata\":{\"viewpoint\":\"responder\"}}";
        List<IngestMapper.AcceptedRecord> records = List.of(
                new IngestMapper.AcceptedRecord(1, 7, 3, "k", T0, 3, payload));
        assertThat(new AlertGenerator(mapper, JSON).generate(7, records, policies(), T0)).isEmpty();
        org.mockito.Mockito.verify(mapper, org.mockito.Mockito.never())
                .findAssetWindowRecords(anyLong(), any(), any(), isNull(), anyInt());
    }

    @Test
    void incompleteWindowFailsInsteadOfAcknowledgingSilently() throws Exception {
        DetectionMapper mapper = mock(DetectionMapper.class);
        when(mapper.findActiveRules()).thenReturn(List.of(new DetectionMapper.RuleRow(41, "burst", "1",
                "{}", SCAN, "high")));
        when(mapper.findBatchContract(7)).thenReturn("unsw-nb15-flow-v4");
        when(mapper.lockAsset(3)).thenReturn(new DetectionMapper.AssetRow(3, "lab", "medium"));
        String payload = "{\"features\":{\"proto\":\"tcp\",\"synack\":0},\"metadata\":{\"viewpoint\":\"responder\"}}";
        var row = new DetectionMapper.WindowRecord(1, T0, payload);
        when(mapper.findAssetWindowRecords(eq(3L), any(), any(), eq("unsw-nb15-flow-v4"),
                eq(AlertGenerator.WINDOW_CONTEXT_LIMIT + 1)))
                .thenReturn(java.util.Collections.nCopies(AlertGenerator.WINDOW_CONTEXT_LIMIT + 1, row));
        var records = List.of(new IngestMapper.AcceptedRecord(1, 7, 3, "r", T0, 3, payload));
        assertThatThrownBy(() -> new AlertGenerator(mapper, JSON).generate(7, records, policies(), T0))
                .isInstanceOf(DetectionUnavailableException.class).hasMessage("DETECTION_WINDOW_CAPACITY_EXCEEDED");
        org.mockito.Mockito.verify(mapper, org.mockito.Mockito.never()).insertAlert(any());
    }

    private static DetectionPolicies policies() {
        return new DetectionPolicies(new DetectionPolicies.Severity("severity-v1",
                List.of(new DetectionPolicies.Band(0.0, "medium"))),
                new DetectionPolicies.Correlation("correlation-v1", 900),
                new DetectionPolicies.Risk("risk-v1", java.util.Map.of("low", 0.25, "medium", 0.5, "high", 0.75,
                        "critical", 1.0), java.util.Map.of("medium", 0.75), 0.05, 0.2));
    }
}
