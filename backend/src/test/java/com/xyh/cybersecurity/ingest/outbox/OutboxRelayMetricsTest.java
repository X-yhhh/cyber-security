package com.xyh.cybersecurity.ingest.outbox;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.xyh.cybersecurity.ingest.IngestMapper;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class OutboxRelayMetricsTest {

    @Test
    void recordsPublisherDurationHistogramForEveryAttempt() {
        IngestMapper mapper = mock(IngestMapper.class);
        ObjectProvider<OutboxRelay.Publisher> providers = mock(ObjectProvider.class);
        OutboxRelay.Publisher publisher = (eventKey, topic, payload) -> { };
        when(providers.getIfAvailable()).thenReturn(publisher);
        when(mapper.listPendingOutbox(32)).thenReturn(List.of(
                new IngestMapper.OutboxRow(7, "event-7", "ingest.batch.received", "{\"count\":1}", 0)));
        SimpleMeterRegistry registry = new SimpleMeterRegistry();

        OutboxRelay relay = new OutboxRelay(mapper, new ObjectMapper(), providers, registry);

        assertThat(relay.publishPending()).isEqualTo(1);
        verify(mapper).markOutboxPublished(7);
        assertThat(registry.timer("cyber_security_outbox_publish_duration").count()).isEqualTo(1);
        assertThat(registry.timer("cyber_security_outbox_publish_duration").totalTime(java.util.concurrent.TimeUnit.NANOSECONDS))
                .isGreaterThanOrEqualTo(0);
    }
}
