package com.xyh.cybersecurity.ingest.feature.legacy;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** v3.1 历史实现的回归测试：保留以证明 legacy 类行为未变，不代表 v3.1 可在线（路线 B §9.1 第 3 项）。 */
class V31FeatureBuilderTest {
    @Test
    void windowIsEventTimeSortedAndWarmingIsFailClosed() {
        var window = new V31FeatureWindow(Duration.ofSeconds(2));
        var flow = flow("a", Instant.parse("2026-09-28T00:00:00Z"));
        assertThat(window.add(flow).status()).isEqualTo("warming");
        assertThat(window.ready()).isFalse();
        assertThat(window.add(flow("late", Instant.parse("2026-09-27T23:59:57Z"))).accepted()).isFalse();
    }

    @Test
    void builderRequiresFrozenCodebookAndCountsCurrentWindow() {
        var current = flow("current", Instant.parse("2026-09-28T00:00:00Z"));
        var flows = new ArrayList<V31FeatureBuilder.FlowInput>();
        flows.add(current);
        for (int i = 1; i < 100; i++) flows.add(flow("f" + i, current.flowEndAt().plusMillis(i + 1)));
        var builder = new V31FeatureBuilder();
        assertThat(builder.build(current, flows, null).status()).isEqualTo(V31FeatureBuilder.Status.REJECTED);
        var codebook = CtStateTtlCodebook.from(java.util.Map.of(new CtStateTtlCodebook.StateTtl("established", 0, 64), 7));
        var result = builder.build(current, flows, codebook);
        assertThat(result.ready()).isTrue();
        assertThat(result.features().get("ct_state_ttl").asInt()).isEqualTo(7);
        assertThat(result.features().get("ct_src_ltm").asInt()).isEqualTo(100);
    }

    private static V31FeatureBuilder.FlowInput flow(String key, Instant at) {
        return new V31FeatureBuilder.FlowInput(key, at, "10.0.0.1", "10.0.0.2", 1234, 80,
                "tcp", "http", "established", 1, 100, 200, 32, 1, 2, 0,
                1, 1, 1, 0.1, 0.05, 100, 200, null, 1, 2, 0.05);
    }
}
