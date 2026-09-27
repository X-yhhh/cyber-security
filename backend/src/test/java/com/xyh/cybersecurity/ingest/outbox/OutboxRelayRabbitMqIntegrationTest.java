package com.xyh.cybersecurity.ingest.outbox;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.amqp.core.BindingBuilder;
import org.springframework.amqp.core.Queue;
import org.springframework.amqp.core.TopicExchange;
import org.springframework.amqp.rabbit.connection.CachingConnectionFactory;
import org.springframework.amqp.rabbit.core.RabbitAdmin;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.sql.DriverManager;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/** 仅在显式提供独立 MySQL 测试 schema 和 RabbitMQ 测试 vhost 时运行完整 outbox 投递验证。 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@EnabledIfEnvironmentVariable(named = "RABBITMQ_IT_ENABLED", matches = "true")
@EnabledIfEnvironmentVariable(named = "DB_TEST_BASE_URL", matches = ".+")
class OutboxRelayRabbitMqIntegrationTest {
    private static final String TEST_SCHEMA = "cyber_security_backend_outbox_it_20260928";
    private static final String ROUTING_KEY = "ingest.batch.received";
    private static CachingConnectionFactory testConnectionFactory;
    private static RabbitAdmin testRabbitAdmin;
    private static String exchange;
    private static String queue;

    @BeforeAll
    static void prepareIsolatedResources() throws Exception {
        String base = required("DB_TEST_BASE_URL");
        String username = required("DB_TEST_USERNAME");
        String password = required("DB_TEST_PASSWORD");
        try (var connection = DriverManager.getConnection(base, username, password);
             var statement = connection.createStatement()) {
            statement.execute("CREATE DATABASE IF NOT EXISTS " + TEST_SCHEMA
                    + " CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci");
        }
        Flyway.configure().dataSource(schemaUrl(base), username, password)
                .locations("classpath:db/migration").baselineOnMigrate(false).load().migrate();

        exchange = required("RABBITMQ_INGEST_EXCHANGE");
        queue = "cyber-security.outbox.it." + UUID.randomUUID();
        testConnectionFactory = new CachingConnectionFactory(required("RABBITMQ_IT_HOST"),
                Integer.parseInt(required("RABBITMQ_IT_PORT")));
        testConnectionFactory.setVirtualHost(required("RABBITMQ_IT_VHOST"));
        testConnectionFactory.setUsername(required("RABBITMQ_IT_USERNAME"));
        testConnectionFactory.setPassword(required("RABBITMQ_IT_PASSWORD"));
        testRabbitAdmin = new RabbitAdmin(testConnectionFactory);
        testRabbitAdmin.declareExchange(new TopicExchange(exchange, true, false));
        testRabbitAdmin.declareQueue(new Queue(queue, false, false, true));
        testRabbitAdmin.declareBinding(BindingBuilder.bind(new Queue(queue, false, false, true))
                .to(new TopicExchange(exchange, true, false)).with(ROUTING_KEY));
    }

    @DynamicPropertySource
    static void applicationProperties(DynamicPropertyRegistry registry) {
        String base = required("DB_TEST_BASE_URL");
        registry.add("spring.datasource.url", () -> schemaUrl(base)
                + "?connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true");
        registry.add("spring.datasource.username", () -> required("DB_TEST_USERNAME"));
        registry.add("spring.datasource.password", () -> required("DB_TEST_PASSWORD"));
        registry.add("spring.flyway.enabled", () -> false);
        registry.add("cyber.security.login-throttle.hmac-key", () -> "rabbit-outbox-integration-test-key");
        registry.add("cyber.ingest.outbox-relay.enabled", () -> true);
        registry.add("cyber.ingest.outbox-relay.poll-ms", () -> 60_000);
        registry.add("cyber.ingest.rabbitmq.exchange", () -> required("RABBITMQ_INGEST_EXCHANGE"));
        registry.add("cyber.ingest.rabbitmq.host", () -> required("RABBITMQ_IT_HOST"));
        registry.add("cyber.ingest.rabbitmq.port", () -> Integer.parseInt(required("RABBITMQ_IT_PORT")));
        registry.add("cyber.ingest.rabbitmq.virtual-host", () -> required("RABBITMQ_IT_VHOST"));
        registry.add("cyber.ingest.rabbitmq.username", () -> required("RABBITMQ_IT_USERNAME"));
        registry.add("cyber.ingest.rabbitmq.password", () -> required("RABBITMQ_IT_PASSWORD"));
    }

    @Autowired private JdbcTemplate jdbc;
    @Autowired private OutboxRelay relay;
    @Autowired private RabbitTemplate rabbitTemplate;
    @Autowired private ObjectMapper objectMapper;

    @AfterAll
    static void releaseQueueAndConnection() {
        if (testRabbitAdmin != null && queue != null) testRabbitAdmin.deleteQueue(queue);
        if (testConnectionFactory != null) testConnectionFactory.destroy();
    }

    @Test
    void relaysCommittedOutboxEventAndMarksItPublishedAfterBrokerConfirm() throws Exception {
        String eventKey = "outbox.it:" + UUID.randomUUID();
        jdbc.update("INSERT INTO outbox_event (event_key,aggregate_type,aggregate_id,topic,payload_json,status) "
                        + "VALUES (?, 'ingest_batch', '42', ?, ?, 'pending')",
                eventKey, ROUTING_KEY, "{\"batchId\":42,\"recordCount\":3}");

        assertThat(relay.publishPending()).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT status FROM outbox_event WHERE event_key=?", String.class, eventKey))
                .isEqualTo("published");
        assertThat(jdbc.queryForObject("SELECT published_at IS NOT NULL FROM outbox_event WHERE event_key=?",
                Boolean.class, eventKey)).isTrue();

        var received = rabbitTemplate.receive(queue, 5000);
        assertThat(received).isNotNull();
        var envelope = objectMapper.readTree(received.getBody());
        assertThat(envelope.path("eventKey").asText()).isEqualTo(eventKey);
        assertThat(envelope.path("eventType").asText()).isEqualTo(ROUTING_KEY);
        assertThat(envelope.path("payload").path("batchId").asLong()).isEqualTo(42);
    }

    private static String schemaUrl(String base) {
        return base.replaceFirst("/+$", "") + "/" + TEST_SCHEMA;
    }

    private static String required(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) throw new IllegalStateException("Missing integration setting: " + name);
        return value;
    }
}
