package com.xyh.cybersecurity.ingest.outbox;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.amqp.core.BindingBuilder;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.core.Queue;
import org.springframework.amqp.core.TopicExchange;
import org.springframework.amqp.rabbit.connection.CachingConnectionFactory;
import org.springframework.amqp.rabbit.core.RabbitAdmin;
import org.springframework.amqp.rabbit.core.RabbitTemplate;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/** 通过独立临时 vhost 验证发布确认、路由和消息信封；不触碰应用或其他项目队列。 */
@EnabledIfEnvironmentVariable(named = "RABBITMQ_IT_ENABLED", matches = "true")
class RabbitOutboxPublisherIntegrationTest {
    private static final String ROUTING_KEY = "ingest.batch.received";
    private static CachingConnectionFactory connectionFactory;
    private static RabbitTemplate rabbitTemplate;
    private static RabbitAdmin rabbitAdmin;
    private static ObjectMapper objectMapper;
    private static String exchangeName;
    private static String queueName;

    @BeforeAll
    static void connectToIsolatedRabbitVhost() {
        connectionFactory = new CachingConnectionFactory(required("RABBITMQ_IT_HOST"),
                Integer.parseInt(required("RABBITMQ_IT_PORT")));
        connectionFactory.setVirtualHost(required("RABBITMQ_IT_VHOST"));
        connectionFactory.setUsername(required("RABBITMQ_IT_USERNAME"));
        connectionFactory.setPassword(required("RABBITMQ_IT_PASSWORD"));
        connectionFactory.setPublisherConfirmType(CachingConnectionFactory.ConfirmType.CORRELATED);
        connectionFactory.setPublisherReturns(true);
        rabbitTemplate = new RabbitTemplate(connectionFactory);
        rabbitTemplate.setMandatory(true);
        rabbitAdmin = new RabbitAdmin(connectionFactory);
        objectMapper = new ObjectMapper();
        exchangeName = "cyber-security.it." + UUID.randomUUID();
        queueName = "cyber-security.it." + UUID.randomUUID();

        TopicExchange exchange = new TopicExchange(exchangeName, true, false);
        Queue queue = new Queue(queueName, false, false, true);
        rabbitAdmin.declareExchange(exchange);
        rabbitAdmin.declareQueue(queue);
        rabbitAdmin.declareBinding(BindingBuilder.bind(queue).to(exchange).with(ROUTING_KEY));
    }

    @AfterAll
    static void closeConnection() {
        if (rabbitAdmin != null) {
            if (queueName != null) rabbitAdmin.deleteQueue(queueName);
            if (exchangeName != null) rabbitAdmin.deleteExchange(exchangeName);
        }
        if (connectionFactory != null) connectionFactory.destroy();
    }

    @Test
    void confirmsAndRoutesPersistentJsonEventWithStableKey() throws Exception {
        String eventKey = "ingest.batch:" + UUID.randomUUID();
        var payload = objectMapper.readTree("{\"batchId\":42,\"recordCount\":3}");
        var publisher = new RabbitOutboxConfiguration.RabbitOutboxPublisher(
                rabbitTemplate, objectMapper, exchangeName, 5000);

        publisher.publish(eventKey, ROUTING_KEY, payload);

        Message received = rabbitTemplate.receive(queueName, 5000);
        assertThat(received).isNotNull();
        assertThat(received.getMessageProperties().getMessageId()).isEqualTo(eventKey);
        assertThat(received.getMessageProperties().getType()).isEqualTo(ROUTING_KEY);
        assertThat(received.getMessageProperties().getContentType()).isEqualTo("application/json");
        assertThat(received.getMessageProperties().getReceivedDeliveryMode())
                .isEqualTo(org.springframework.amqp.core.MessageDeliveryMode.PERSISTENT);
        var envelope = objectMapper.readTree(new String(received.getBody(), StandardCharsets.UTF_8));
        assertThat(envelope.path("schemaVersion").asInt()).isEqualTo(1);
        assertThat(envelope.path("eventKey").asText()).isEqualTo(eventKey);
        assertThat(envelope.path("eventType").asText()).isEqualTo(ROUTING_KEY);
        assertThat(envelope.path("payload")).isEqualTo(payload);
    }

    private static String required(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) throw new IllegalStateException("Missing RabbitMQ integration setting: " + name);
        return value;
    }
}
