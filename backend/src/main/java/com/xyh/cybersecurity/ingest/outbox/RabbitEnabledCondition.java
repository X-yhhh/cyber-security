package com.xyh.cybersecurity.ingest.outbox;

import org.springframework.boot.autoconfigure.condition.AnyNestedCondition;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.ConfigurationCondition.ConfigurationPhase;

/** Relay 与 consumer 共用 Rabbit 连接；任一显式启用时创建基础设施。 */
public final class RabbitEnabledCondition extends AnyNestedCondition {
    public RabbitEnabledCondition() {
        super(ConfigurationPhase.REGISTER_BEAN);
    }

    @ConditionalOnProperty(name = "cyber.ingest.outbox-relay.enabled", havingValue = "true")
    static class RelayEnabled { }

    @ConditionalOnProperty(name = "cyber.ingest.consumer.enabled", havingValue = "true")
    static class ConsumerEnabled { }
}
