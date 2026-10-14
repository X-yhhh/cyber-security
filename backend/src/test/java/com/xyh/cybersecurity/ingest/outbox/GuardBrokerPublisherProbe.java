package com.xyh.cybersecurity.ingest.outbox;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.amqp.rabbit.core.RabbitTemplate;

/** 测试包内桥接生产 publisher 工厂；不复制确认逻辑、不扩大生产 API 的可见性。 */
public final class GuardBrokerPublisherProbe {
    private GuardBrokerPublisherProbe() { }
    public static OutboxRelay.Publisher publisher(RabbitTemplate template, ObjectMapper mapper, String exchange, long timeoutMs) {
        return new RabbitOutboxConfiguration().rabbitOutboxPublisher(template, mapper, exchange, timeoutMs);
    }
}
