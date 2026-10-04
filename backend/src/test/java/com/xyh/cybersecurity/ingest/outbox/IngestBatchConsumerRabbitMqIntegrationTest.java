package com.xyh.cybersecurity.ingest.outbox;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.amqp.core.MessageDeliveryMode;
import org.springframework.amqp.core.MessageProperties;
import org.springframework.amqp.rabbit.connection.CachingConnectionFactory;
import org.springframework.amqp.rabbit.core.RabbitAdmin;
import org.springframework.amqp.rabbit.listener.RabbitListenerEndpointRegistry;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.sql.DriverManager;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/** 仅连接专用 DB_TEST schema 与 RabbitMQ 测试 vhost，验证消费者幂等和 TTL→DLQ。 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@Import(IngestBatchConsumerRabbitMqIntegrationTest.SubmitterConfiguration.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@EnabledIfEnvironmentVariable(named = "RABBITMQ_IT_ENABLED", matches = "true")
@EnabledIfEnvironmentVariable(named = "DB_TEST_BASE_URL", matches = ".+")
class IngestBatchConsumerRabbitMqIntegrationTest {
    private static final String SCHEMA = "cyber_security_ingest_consumer_it_20260928";
    private static final String EXCHANGE = "cyber-security.ingest.consumer.it." + UUID.randomUUID();
    private static final String DEAD_EXCHANGE = EXCHANGE + ".dlx";
    private static final String QUEUE = "cyber-security.ingest.consumer.it." + UUID.randomUUID();
    private static final String DLQ = QUEUE + ".dead";
    private static final String RETRY_PREFIX = QUEUE + ".retry.";
    private static final AtomicInteger submitCount = new AtomicInteger();
    private static final ConcurrentHashMap<String, AtomicInteger> failures = new ConcurrentHashMap<>();

    @BeforeAll
    static void prepareIsolatedSchema() throws Exception {
        String base = required("DB_TEST_BASE_URL");
        try (var connection = DriverManager.getConnection(base, required("DB_TEST_USERNAME"),
                required("DB_TEST_PASSWORD")); var statement = connection.createStatement()) {
            statement.execute("CREATE DATABASE IF NOT EXISTS " + SCHEMA
                    + " CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci");
        }
        Flyway.configure().dataSource(schemaUrl(base), required("DB_TEST_USERNAME"),
                required("DB_TEST_PASSWORD")).locations("classpath:db/migration").load().migrate();
    }

    @DynamicPropertySource
    static void applicationProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", () -> schemaUrl(required("DB_TEST_BASE_URL"))
                + "?connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true");
        registry.add("spring.datasource.username", () -> required("DB_TEST_USERNAME"));
        registry.add("spring.datasource.password", () -> required("DB_TEST_PASSWORD"));
        registry.add("spring.flyway.enabled", () -> false);
        registry.add("cyber.security.login-throttle.hmac-key", () -> "ingest-consumer-it-hmac-key-with-32-bytes-minimum");
        registry.add("cyber.ingest.outbox-relay.enabled", () -> false);
        registry.add("cyber.ingest.consumer.enabled", () -> true);
        // 本测试只验证 M2 投递语义，使用下方测试提交端口；关闭本机推理提交端口，避免出现两个候选 Bean。
        registry.add("cyber.inference.local.enabled", () -> false);
        registry.add("cyber.ingest.consumer.queue", () -> QUEUE);
        registry.add("cyber.ingest.consumer.dead-letter-queue", () -> DLQ);
        registry.add("cyber.ingest.consumer.retry-queue-prefix", () -> RETRY_PREFIX);
        registry.add("cyber.ingest.rabbitmq.exchange", () -> EXCHANGE);
        registry.add("cyber.ingest.rabbitmq.dead-letter-exchange", () -> DEAD_EXCHANGE);
        registry.add("cyber.ingest.rabbitmq.host", () -> required("RABBITMQ_IT_HOST"));
        registry.add("cyber.ingest.rabbitmq.port", () -> Integer.parseInt(required("RABBITMQ_IT_PORT")));
        registry.add("cyber.ingest.rabbitmq.virtual-host", () -> required("RABBITMQ_IT_VHOST"));
        registry.add("cyber.ingest.rabbitmq.username", () -> required("RABBITMQ_IT_USERNAME"));
        registry.add("cyber.ingest.rabbitmq.password", () -> required("RABBITMQ_IT_PASSWORD"));
        registry.add("cyber.ingest.rabbitmq.confirm-timeout-ms", () -> 5000);
    }

    @Autowired private RabbitTemplate rabbitTemplate;
    @Autowired private RabbitAdmin rabbitAdmin;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private RabbitListenerEndpointRegistry listenerRegistry;
    @Autowired private CachingConnectionFactory connectionFactory;

    @AfterAll
    void removeRabbitResourcesCreatedByThisTest() {
        for (int attempt = 1; attempt <= IngestBatchConsumer.MAX_RETRIES; attempt++) {
            rabbitAdmin.deleteQueue(RETRY_PREFIX + attempt);
        }
        rabbitAdmin.deleteQueue(QUEUE);
        rabbitAdmin.deleteQueue(DLQ);
        rabbitAdmin.deleteExchange(EXCHANGE);
        rabbitAdmin.deleteExchange(DEAD_EXCHANGE);
    }

    @Test
    void duplicateEventIsSubmittedOnceAndRetryLimitRoutesToDeadLetterQueue() throws Exception {
        submitCount.set(0);
        String duplicateKey = "consumer.it:" + UUID.randomUUID();
        send(duplicateKey);
        send(duplicateKey);

        await(() -> "consumed".equals(status(duplicateKey)), Duration.ofSeconds(10));
        assertThat(submitCount.get()).isEqualTo(1);
        assertThat(rabbitAdmin.getQueueInfo(QUEUE).getMessageCount()).isZero();

        String failedKey = "consumer.it.fail:" + UUID.randomUUID();
        failures.put(failedKey, new AtomicInteger());
        send(failedKey);
        await(() -> rabbitAdmin.getQueueInfo(DLQ).getMessageCount() == 1, Duration.ofSeconds(45));
        assertThat(status(failedKey)).isEqualTo("dead_lettered");
        assertThat(jdbc.queryForObject("SELECT attempts FROM consumed_message WHERE consumer=? AND message_key=?",
                Integer.class, IngestBatchProcessingService.CONSUMER_NAME, failedKey)).isEqualTo(6);
        assertThat(failures.get(failedKey).get()).isEqualTo(6);
    }

    @Test
    void unackedMessageFromStoppedConsumerIsRedeliveredAndProcessedOnce() throws Exception {
        var container = listenerRegistry.getListenerContainer(IngestBatchConsumer.LISTENER_ID);
        container.stop();
        String crashKey = "consumer.it.crash:" + UUID.randomUUID();
        try {
            submitCount.set(0);
            send(crashKey);
            await(() -> rabbitAdmin.getQueueInfo(QUEUE).getMessageCount() == 1, Duration.ofSeconds(10));

            // 用独立原生连接模拟消费进程取到消息后未提交、未 ack 即退出。
            try (var connection = connectionFactory.getRabbitConnectionFactory().newConnection()) {
                var channel = connection.createChannel();
                var response = channel.basicGet(QUEUE, false);
                assertThat(response).isNotNull();
                assertThat(response.getProps().getMessageId()).isEqualTo(crashKey);
                assertThat(rabbitAdmin.getQueueInfo(QUEUE).getMessageCount()).isZero();
            }
            assertThat(status(crashKey)).isNull();
            await(() -> rabbitAdmin.getQueueInfo(QUEUE).getMessageCount() == 1, Duration.ofSeconds(10));
        } finally {
            container.start();
        }

        await(() -> "consumed".equals(status(crashKey)), Duration.ofSeconds(10));
        assertThat(submitCount.get()).isEqualTo(1);
        await(() -> rabbitAdmin.getQueueInfo(QUEUE).getMessageCount() == 0, Duration.ofSeconds(10));
    }

    private void send(String eventKey) throws Exception {
        var envelope = objectMapper.createObjectNode();
        envelope.put("schemaVersion", 1);
        envelope.put("eventKey", eventKey);
        envelope.put("eventType", RabbitTopologyConfig.INGEST_ROUTE);
        var payload = envelope.putObject("payload");
        payload.put("batchId", 987654321L);
        payload.put("dataSourceId", 3L);
        payload.put("recordCount", 0);
        MessageProperties properties = new MessageProperties();
        properties.setContentType(MessageProperties.CONTENT_TYPE_JSON);
        properties.setDeliveryMode(MessageDeliveryMode.PERSISTENT);
        properties.setMessageId(eventKey);
        properties.setType(RabbitTopologyConfig.INGEST_ROUTE);
        rabbitTemplate.send(EXCHANGE, RabbitTopologyConfig.INGEST_ROUTE,
                new org.springframework.amqp.core.Message(objectMapper.writeValueAsBytes(envelope), properties));
    }

    private String status(String eventKey) {
        return jdbc.query("SELECT status FROM consumed_message WHERE consumer=? AND message_key=?",
                rs -> rs.next() ? rs.getString(1) : null, IngestBatchProcessingService.CONSUMER_NAME, eventKey);
    }

    private static void await(java.util.function.BooleanSupplier condition, Duration timeout) throws InterruptedException {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (System.nanoTime() < deadline) {
            if (condition.getAsBoolean()) return;
            Thread.sleep(100);
        }
        assertThat(condition.getAsBoolean()).as("condition completes within %s", timeout).isTrue();
    }

    private static String schemaUrl(String base) { return base.replaceFirst("/+$", "") + "/" + SCHEMA; }

    private static String required(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) throw new IllegalStateException("Missing integration setting: " + name);
        return value;
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class SubmitterConfiguration {
        @Bean
        InferenceTaskSubmitter testInferenceTaskSubmitter() {
            return (event, records) -> {
                if (failures.containsKey(event.eventKey())) {
                    failures.get(event.eventKey()).incrementAndGet();
                    throw new RetryableConsumerException("TEST_RETRY");
                }
                submitCount.incrementAndGet();
            };
        }
    }
}
