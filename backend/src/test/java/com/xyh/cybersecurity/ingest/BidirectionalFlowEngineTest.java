package com.xyh.cybersecurity.ingest;

import com.xyh.cybersecurity.ingest.flow.BidirectionalFlowEngine;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class BidirectionalFlowEngineTest {
    @Test
    void keepsInitiatorDirectionAndDeduplicatesPackets() {
        var engine = new BidirectionalFlowEngine(4, Duration.ofSeconds(30));
        var source = new BidirectionalFlowEngine.Endpoint("10.0.0.1", 1234);
        var destination = new BidirectionalFlowEngine.Endpoint("10.0.0.2", 80);
        Instant t = Instant.parse("2026-09-27T00:00:00Z");
        engine.accept(new BidirectionalFlowEngine.Packet(t, source, destination, "TCP", 100, "p1", false, false));
        engine.accept(new BidirectionalFlowEngine.Packet(t.plusMillis(1), source, destination, "TCP", 100, "p1", false, false));
        var completed = engine.accept(new BidirectionalFlowEngine.Packet(t.plusMillis(2), destination, source, "TCP", 40, "p2", true, false));
        assertThat(completed).hasSize(1);
        var flow = completed.getFirst();
        assertThat(flow.sbytes()).isEqualTo(100);
        assertThat(flow.dbytes()).isEqualTo(40);
        assertThat(flow.spkts()).isEqualTo(1);
        assertThat(flow.dpkts()).isEqualTo(1);
        assertThat(flow.bidirectional()).isTrue();
        assertThat(engine.metrics().duplicatePackets()).isEqualTo(1);
    }

    @Test
    void boundsFlowStateAndReportsDrop() {
        var engine = new BidirectionalFlowEngine(1, Duration.ofMinutes(1));
        var a = new BidirectionalFlowEngine.Endpoint("10.0.0.1", 1);
        var b = new BidirectionalFlowEngine.Endpoint("10.0.0.2", 2);
        var c = new BidirectionalFlowEngine.Endpoint("10.0.0.3", 3);
        var t = Instant.parse("2026-09-27T00:00:00Z");
        engine.accept(new BidirectionalFlowEngine.Packet(t, a, b, "udp", 1, null, false, false));
        engine.accept(new BidirectionalFlowEngine.Packet(t, a, c, "udp", 1, null, false, false));
        assertThat(engine.metrics().flowStateCapacityDrops()).isEqualTo(1);
    }

    @Test
    void keepsObservationPointsSeparateAndBoundsPacketDeduplicationState() {
        var engine = new BidirectionalFlowEngine(4, Duration.ofHours(1));
        var a = new BidirectionalFlowEngine.Endpoint("10.0.0.1", 1);
        var b = new BidirectionalFlowEngine.Endpoint("10.0.0.2", 2);
        var t = Instant.parse("2026-09-27T00:00:00Z");
        engine.accept(new BidirectionalFlowEngine.Packet(t, a, b, "tcp", 10, "p0", false, false, "sensor-a/eth0"));
        engine.accept(new BidirectionalFlowEngine.Packet(t, a, b, "tcp", 20, "p0", false, false, "sensor-b/eth0"));
        assertThat(engine.metrics().activeFlows()).isEqualTo(2);

        for (int i = 1; i <= 8193; i++) {
            engine.accept(new BidirectionalFlowEngine.Packet(t.plusMillis(i), a, b, "tcp", 1, "p" + i, false, false, "sensor-a/eth0"));
        }
        var completed = engine.accept(new BidirectionalFlowEngine.Packet(t.plusSeconds(1), b, a, "tcp", 1, "reverse", true, false, "sensor-a/eth0"));
        assertThat(completed).hasSize(1);
        assertThat(completed.getFirst().qualityIssues()).contains("dedup_window_exceeded");
        assertThat(completed.getFirst().spkts()).isEqualTo(8194);
    }
}
