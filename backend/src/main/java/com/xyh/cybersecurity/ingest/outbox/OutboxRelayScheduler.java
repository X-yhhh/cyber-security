package com.xyh.cybersecurity.ingest.outbox;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/** 单独调度 outbox relay，保证调用 publishPending 时经过事务代理。 */
@Component
@ConditionalOnProperty(name = "cyber.ingest.outbox-relay.enabled", havingValue = "true")
public class OutboxRelayScheduler {
    private final OutboxRelay relay;

    public OutboxRelayScheduler(OutboxRelay relay) {
        this.relay = relay;
    }

    @Scheduled(fixedDelayString = "${cyber.ingest.outbox-relay.poll-ms:1000}")
    public void poll() {
        relay.publishPending();
    }
}
