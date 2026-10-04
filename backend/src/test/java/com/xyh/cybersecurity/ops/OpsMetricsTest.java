package com.xyh.cybersecurity.ops;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.mock;

class OpsMetricsTest {

    @Test
    void exposesSnapshotCountersWithoutSensitiveDetails() {
        OpsMetricsMapper mapper = mock(OpsMetricsMapper.class);
        when(mapper.countOutbox("pending")).thenReturn(2L);
        when(mapper.countOutbox("failed")).thenReturn(1L);
        when(mapper.countOutbox("dead_letter")).thenReturn(3L);
        when(mapper.oldestPendingAgeSeconds()).thenReturn(42D);
        when(mapper.averagePublishedDelaySeconds24h()).thenReturn(2.5D);
        when(mapper.countOnlineSensors()).thenReturn(3L);
        when(mapper.countSensorHeartbeatTimeouts()).thenReturn(1L);
        when(mapper.rejectionCounts24h()).thenReturn(new OpsMetricsMapper.RejectionCounts(7, 1, 2));
        when(mapper.countBlockedLogins()).thenReturn(0L);
        when(mapper.countLoginThrottleFailures()).thenReturn(4L);

        OpsMetrics metrics = new OpsMetrics(mapper, new SimpleMeterRegistry());
        assertThat(metrics.snapshot()).isEqualTo(new OpsMetrics.Snapshot(2, 1, 3, 42, 2.5, 3, 1, .2, 0, 4));
    }
}
