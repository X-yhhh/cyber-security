package com.xyh.cybersecurity.ingest.outbox;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.amqp.rabbit.connection.CachingConnectionFactory;
import org.springframework.amqp.rabbit.connection.CorrelationData;
import org.springframework.amqp.rabbit.core.RabbitAdmin;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.amqp.core.TopicExchange;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.TimeUnit;

/** 仅在显式启用 outbox relay 时建立 RabbitMQ 连接和 durable topic exchange。 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "cyber.ingest.outbox-relay.enabled", havingValue = "true")
public class RabbitOutboxConfiguration {

    @Bean
    CachingConnectionFactory ingestRabbitConnectionFactory(
            @Value("${cyber.ingest.rabbitmq.host}") String host,
            @Value("${cyber.ingest.rabbitmq.port}") int port,
            @Value("${cyber.ingest.rabbitmq.virtual-host}") String virtualHost,
            @Value("${cyber.ingest.rabbitmq.username}") String username,
            @Value("${cyber.ingest.rabbitmq.password}") String password) {
        if (username.isBlank() || password.isBlank()) {
            throw new IllegalStateException("OUTBOX_RELAY_ENABLED requires RABBITMQ_USERNAME and RABBITMQ_PASSWORD");
        }
        CachingConnectionFactory factory = new CachingConnectionFactory(host, port);
        factory.setVirtualHost(virtualHost);
        factory.setUsername(username);
        factory.setPassword(password);
        factory.setPublisherConfirmType(CachingConnectionFactory.ConfirmType.CORRELATED);
        factory.setPublisherReturns(true);
        factory.setConnectionTimeout(3000);
        return factory;
    }

    @Bean
    RabbitTemplate ingestRabbitTemplate(CachingConnectionFactory ingestRabbitConnectionFactory) {
        RabbitTemplate template = new RabbitTemplate(ingestRabbitConnectionFactory);
        template.setMandatory(true);
        return template;
    }

    @Bean
    RabbitAdmin ingestRabbitAdmin(CachingConnectionFactory ingestRabbitConnectionFactory) {
        RabbitAdmin admin = new RabbitAdmin(ingestRabbitConnectionFactory);
        admin.setAutoStartup(true);
        admin.setIgnoreDeclarationExceptions(false);
        return admin;
    }

    @Bean
    TopicExchange ingestEventsExchange(@Value("${cyber.ingest.rabbitmq.exchange}") String exchange) {
        return new TopicExchange(exchange, true, false);
    }

    @Bean
    OutboxRelay.Publisher rabbitOutboxPublisher(RabbitTemplate ingestRabbitTemplate,
                                                ObjectMapper objectMapper,
                                                @Value("${cyber.ingest.rabbitmq.exchange}") String exchange,
                                                @Value("${cyber.ingest.rabbitmq.confirm-timeout-ms}") long confirmTimeoutMs) {
        return new RabbitOutboxPublisher(ingestRabbitTemplate, objectMapper, exchange, confirmTimeoutMs);
    }

    static final class RabbitOutboxPublisher implements OutboxRelay.Publisher {
        private static final String TOPIC_PATTERN = "[A-Za-z0-9_-]+(\\.[A-Za-z0-9_-]+)*";
        private final RabbitTemplate template;
        private final ObjectMapper objectMapper;
        private final String exchange;
        private final long confirmTimeoutMs;

        RabbitOutboxPublisher(RabbitTemplate template, ObjectMapper objectMapper, String exchange,
                              long confirmTimeoutMs) {
            this.template = template;
            this.objectMapper = objectMapper;
            this.exchange = exchange;
            this.confirmTimeoutMs = confirmTimeoutMs;
        }

        @Override
        public void publish(String eventKey, String topic, com.fasterxml.jackson.databind.JsonNode payload)
                throws Exception {
            if (eventKey == null || eventKey.isBlank() || eventKey.length() > 255
                    || topic == null || !topic.matches(TOPIC_PATTERN) || payload == null) {
                throw new IllegalArgumentException("outbox event envelope is invalid");
            }
            var envelope = objectMapper.createObjectNode();
            envelope.put("schemaVersion", 1);
            envelope.put("eventKey", eventKey);
            envelope.put("eventType", topic);
            envelope.set("payload", payload);

            var properties = new org.springframework.amqp.core.MessageProperties();
            properties.setContentType(org.springframework.amqp.core.MessageProperties.CONTENT_TYPE_JSON);
            properties.setDeliveryMode(org.springframework.amqp.core.MessageDeliveryMode.PERSISTENT);
            properties.setMessageId(eventKey);
            properties.setType(topic);
            var message = new org.springframework.amqp.core.Message(objectMapper.writeValueAsBytes(envelope), properties);
            CorrelationData correlation = new CorrelationData(eventKey);
            template.send(exchange, topic, message, correlation);

            var confirm = correlation.getFuture().get(confirmTimeoutMs, TimeUnit.MILLISECONDS);
            if (!confirm.isAck()) {
                throw new IllegalStateException("RabbitMQ did not confirm outbox event");
            }
            if (correlation.getReturned() != null) {
                throw new IllegalStateException("RabbitMQ returned unroutable outbox event");
            }
        }
    }
}
