package com.xyh.cybersecurity.ingest.outbox;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.xyh.cybersecurity.ingest.IngestMapper;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;

/**
 * 有界、至少一次 outbox relay。通过默认关闭的开关启用，broker consumer 必须按 eventKey 幂等。
 */
@Service
@ConditionalOnProperty(name = "cyber.ingest.outbox-relay.enabled", havingValue = "true")
public class OutboxRelay {
    private static final int MAX_ATTEMPTS = 12;
    private static final int PAGE_SIZE = 32;
    private final IngestMapper ingestMapper;
    private final ObjectMapper mapper;
    private final ObjectProvider<Publisher> publisher;
    private final MeterRegistry registry;
    private final Timer publishTimer;

    public OutboxRelay(IngestMapper ingestMapper, ObjectMapper mapper, ObjectProvider<Publisher> publisher,
                       MeterRegistry registry) {
        this.ingestMapper = ingestMapper; this.mapper = mapper; this.publisher = publisher; this.registry = registry;
        this.publishTimer = Timer.builder("cyber_security_outbox_publish_duration")
                .description("outbox 单条消息从 relay 调用 publisher 到返回的耗时")
                .publishPercentileHistogram()
                .register(registry);
    }

    /** 由独立调度 bean 经 Spring 代理调用，确保数据库行锁处于事务内。 */
    @Transactional
    public int publishPending() {
        List<IngestMapper.OutboxRow> events = ingestMapper.listPendingOutbox(PAGE_SIZE);
        for (IngestMapper.OutboxRow event : events) {
            Timer.Sample sample = Timer.start(registry);
            try {
                JsonNode payload = mapper.readTree(event.payload());
                Publisher target = publisher.getIfAvailable();
                if (target == null) throw new IllegalStateException("outbox publisher 未配置");
                target.publish(event.eventKey(), event.topic(), payload);
                ingestMapper.markOutboxPublished(event.id());
            } catch (Exception failure) {
                int attempts = event.attempts() + 1;
                String status = attempts >= MAX_ATTEMPTS ? "dead_letter" : "failed";
                long delaySeconds = Math.min(3600, 1L << Math.min(attempts, 11));
                ingestMapper.markOutboxFailed(event.id(), status, attempts, Instant.now().plusSeconds(delaySeconds));
            } finally {
                sample.stop(publishTimer);
            }
        }
        return events.size();
    }

    public interface Publisher { void publish(String eventKey, String topic, JsonNode payload) throws Exception; }
}
