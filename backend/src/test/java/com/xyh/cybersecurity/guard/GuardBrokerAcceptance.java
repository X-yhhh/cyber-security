package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import com.rabbitmq.client.GetResponse;
import java.io.*;
import java.net.*;
import java.net.http.*;
import java.nio.ByteBuffer;
import java.nio.file.*;
import java.time.*;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.atomic.*;
import org.springframework.amqp.core.*;
import org.springframework.amqp.rabbit.connection.CachingConnectionFactory;
import org.springframework.amqp.rabbit.core.*;
import org.springframework.amqp.rabbit.support.DefaultMessagePropertiesConverter;
import com.xyh.cybersecurity.ingest.outbox.RabbitOutboxConfiguration;
import com.xyh.cybersecurity.ingest.outbox.GuardBrokerPublisherProbe;
import static com.xyh.cybersecurity.guard.GuardJson.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * BE-14c 的真实 broker 探针：生产 publisher、listener、MySQL 消费者与随机测试资产。
 * 仅本次 vhost 的固定前缀可建队列；重启请求只能交给 Python 管理的独立节点。
 * 确认超时通过回环代理丢弃 broker 的确认帧实现，不能把普通业务异常冒充确认超时。
 */
final class GuardBrokerAcceptance {
    private final GuardIntegrationTest fixture;
    private final Map<String, Boolean> checks = new LinkedHashMap<>();
    private final Map<String, Object> evidence = new LinkedHashMap<>();
    private final String host = required("P8_RABBIT_HOST");
    private final int port = Integer.parseInt(required("P8_RABBIT_PORT"));
    private final String prefix = required("P8_QUEUE_PREFIX");
    private final String exchange = prefix + ".events";

    GuardBrokerAcceptance(GuardIntegrationTest fixture) { this.fixture = fixture; }

    void run() throws Exception {
        assertThat(host).isEqualTo("127.0.0.1");
        assertThat(required("P8_RABBIT_VHOST")).startsWith("cyber-security-deploy-acceptance-");
        assertThat(prefix).startsWith("q.guard.p8.");
        var factory = connection(port);
        try {
            var template = template(factory);
            var admin = new RabbitAdmin(factory);
            admin.declareExchange(new TopicExchange(exchange, true, false));
            for (Declarable item : new GuardRabbitConfiguration().guardQueues(exchange, prefix).getDeclarables()) {
                if (item instanceof Exchange ex) admin.declareExchange(ex);
                else if (item instanceof org.springframework.amqp.core.Queue queue) admin.declareQueue(queue);
                else if (item instanceof Binding binding) admin.declareBinding(binding);
            }
            var publish = GuardBrokerPublisherProbe.publisher(template, JSON, exchange, 5000);
            String event = id();
            publish.publish(event, "guard.decision.recorded", object("probe", "publisher-confirm"));
            Message confirmed = template.receive(prefix, 5000);
            check("publisherConfirm", confirmed != null && event.equals(confirmed.getMessageProperties().getMessageId())
                    && confirmed.getMessageProperties().getReceivedDeliveryMode() == MessageDeliveryMode.PERSISTENT);

            try (var proxy = new ConfirmProxy(host, port)) {
                var delayed = connection(proxy.port());
                try {
                    var timed = GuardBrokerPublisherProbe.publisher(template(delayed), JSON, exchange, 250);
                    String timeoutEvent = id();
                    assertThatThrownBy(() -> timed.publish(timeoutEvent, "guard.decision.recorded", object("probe", "timeout")))
                            .isInstanceOf(java.util.concurrent.TimeoutException.class);
                    Message routed = template.receive(prefix, 5000);
                    check("confirmTimeout", proxy.dropped.get() > 0 && routed != null
                            && timeoutEvent.equals(routed.getMessageProperties().getMessageId()));
                    evidence.put("confirmTimeoutMs", 250);
                    evidence.put("suppressedConfirmFrames", proxy.dropped.get());
                } finally { delayed.destroy(); }
            }

            GuardIntegrationTest.Fixture f = fixture.setup("dos_slow", List.of(), false, 100, "alert_only", "authorized");
            var request = fixture.batch(f, List.of(fixture.observation(f, Instant.now().truncatedTo(ChronoUnit.MICROS), id(), 0)
                    .put("environment", "authorized")), 1);
            fixture.machine("/sensors/" + f.sensor() + "/observation-batches", request, f.sensorCredential());
            String consumeKey = id();
            publish.publish(consumeKey, "guard.observation.accepted", object("batchId", request.get("batchId")));
            var transientFailure = mock(GuardDetection.class);
            doThrow(new IllegalStateException("isolated transient failure")).when(transientFailure).consume(anyString(), anyString(), any());
            var failingListener = new GuardRabbitConfiguration.GuardListener(transientFailure, template, prefix);
            var listener = new GuardRabbitConfiguration.GuardListener(fixture.detection, template, prefix);
            try (var conn = factory.createConnection(); var channel = conn.createChannel(false)) {
                Message original = get(channel, prefix, 5000);
                failingListener.receive(original, channel);
                Message retry = get(channel, prefix, 8000);
                check("retryQueue", ((Number) retry.getMessageProperties().getHeaders().get("x-guard-attempt")).intValue() == 1
                        && retry.getMessageProperties().getHeaders().containsKey("x-death"));
                listener.receive(retry, channel);
                var beforeDuplicate = counts(f);
                check("consumerProcessed", beforeDuplicate.get("observations") == 1 && beforeDuplicate.get("decisions") > 0
                        && beforeDuplicate.get("inferences") == 1 && beforeDuplicate.get("actions") == 0 && beforeDuplicate.get("commands") == 0);
                publish.publish(consumeKey, "guard.observation.accepted", object("batchId", request.get("batchId")));
                listener.receive(get(channel, prefix, 5000), channel);
                check("consumerIdempotent", beforeDuplicate.equals(counts(f))
                        && fixture.jdbc.queryForObject("SELECT COUNT(*) FROM consumed_message WHERE consumer='guard-v5' AND message_key=? AND status='consumed'", Long.class, consumeKey) == 1L);
                evidence.put("consumerCounts", beforeDuplicate);

                var properties = new MessageProperties();
                properties.setDeliveryMode(MessageDeliveryMode.PERSISTENT);
                template.send(exchange, "guard.invalid", new Message("invalid-json".getBytes(java.nio.charset.StandardCharsets.UTF_8), properties));
                listener.receive(get(channel, prefix, 5000), channel);
                Message dead = get(channel, prefix + ".dead", 5000);
                check("deadLetter", dead.getMessageProperties().getHeaders().containsKey("x-death")
                        && new String(dead.getBody(), java.nio.charset.StandardCharsets.UTF_8).equals("invalid-json"));
                channel.basicAck(dead.getMessageProperties().getDeliveryTag(), false);

                properties = new MessageProperties();
                properties.setDeliveryMode(MessageDeliveryMode.PERSISTENT);
                properties.setHeader("x-guard-attempt", 5);
                template.send(exchange, "guard.decision.recorded", new Message(canonical(object("schemaVersion", 1, "eventKey", id(),
                        "eventType", "guard.decision.recorded", "payload", object("probe", "retry-exhausted"))).getBytes(java.nio.charset.StandardCharsets.UTF_8), properties));
                failingListener.receive(get(channel, prefix, 5000), channel);
                Message exhausted = get(channel, prefix + ".dead", 5000);
                check("retryExhaustion", exhausted.getMessageProperties().getHeaders().containsKey("x-death")
                        && ((Number) exhausted.getMessageProperties().getHeaders().get("x-guard-attempt")).intValue() == 5);
                channel.basicAck(exhausted.getMessageProperties().getDeliveryTag(), false);
            }

            String restartEvent = id();
            publish.publish(restartEvent, "guard.decision.recorded", object("probe", "durable-recovery"));
            // 留下未确认消息：连接关闭重入队后，仍必须在完整 broker 进程重启后恢复。
            try (var conn = factory.createConnection(); var channel = conn.createChannel(false)) {
                assertThat(get(channel, prefix, 5000).getMessageProperties().getMessageId()).isEqualTo(restartEvent);
            }
            factory.destroy();
            JsonNode restart = restart();
            if ("isolated_node".equals(restart.path("kind").asText()))
                check("brokerProcessRestarted", restart.path("passed").asBoolean()
                        && restart.path("pidBefore").asLong() > 0 && restart.path("pidAfter").asLong() > 0
                        && restart.path("pidBefore").asLong() != restart.path("pidAfter").asLong());
            else check("sharedBrokerLeftRunning", restart.path("kind").asText().equals("shared_node_unchanged")
                    && restart.path("passed").asBoolean());
            evidence.put("restart", restart);
            factory = connection(port);
            template = template(factory);
            try (var conn = factory.createConnection(); var channel = conn.createChannel(false)) {
                Message recovered = get(channel, prefix, 10000);
                check("durableRecovery", restartEvent.equals(recovered.getMessageProperties().getMessageId())
                        && Boolean.TRUE.equals(recovered.getMessageProperties().getRedelivered()));
                channel.basicAck(recovered.getMessageProperties().getDeliveryTag(), false);
            }
            admin = new RabbitAdmin(factory);
            for (String queue : queues()) admin.purgeQueue(queue);
            final var recoveredFactory = factory;
            check("queuesEmpty", queues().stream().allMatch(q -> {
                var props = adminFor(recoveredFactory).getQueueProperties(q);
                return props != null && ((Number) props.get(RabbitAdmin.QUEUE_MESSAGE_COUNT)).intValue() == 0;
            }));
            evidence.put("checks", checks);
            evidence.put("passed", checks.values().stream().allMatch(Boolean::booleanValue));
            evidence.put("schema", GuardIntegrationTest.SCHEMA);
            evidence.put("vhost", required("P8_RABBIT_VHOST"));
            evidence.put("queuePrefix", prefix);
            evidence.put("javaVersion", Runtime.version().toString());
            evidence.put("productionClassesSha256", Map.of("publisher", classHash(publish.getClass()),
                    "listener", classHash(GuardRabbitConfiguration.GuardListener.class), "consumer", classHash(GuardDetection.class)));
            Files.writeString(Path.of(required("P8_BROKER_REPORT_FILE")), JSON.writerWithDefaultPrettyPrinter().writeValueAsString(evidence) + "\n");
        } finally { factory.destroy(); }
    }

    private Map<String, Long> counts(GuardIntegrationTest.Fixture f) {
        long asset = number(fixture.store.external("asset", f.asset(), false), "id");
        var result = new LinkedHashMap<String, Long>();
        for (var pair : Map.of("observations", "guard_observation", "decisions", "guard_decision",
                "inferences", "guard_inference", "actions", "guard_action").entrySet())
            result.put(pair.getKey(), fixture.jdbc.queryForObject("SELECT COUNT(*) FROM " + pair.getValue() + " WHERE asset_id=?", Long.class, asset));
        result.put("commands", fixture.jdbc.queryForObject("SELECT COUNT(*) FROM guard_command c JOIN guard_action a ON a.id=c.action_id WHERE a.asset_id=?", Long.class, asset));
        return result;
    }
    private List<String> queues() {
        var queues = new ArrayList<>(List.of(prefix, prefix + ".dead"));
        for (int i = 1; i <= 5; i++) queues.add(prefix + ".retry." + i);
        return queues;
    }
    private void check(String name, boolean value) {
        checks.put(name, value);assertThat(value).as(name).isTrue();
    }
    private CachingConnectionFactory connection(int targetPort) {
        var factory = new CachingConnectionFactory(host, targetPort);
        factory.setVirtualHost(required("P8_RABBIT_VHOST"));
        factory.setUsername(required("P8_RABBIT_USERNAME"));
        factory.setPassword(required("P8_RABBIT_PASSWORD"));
        factory.setPublisherConfirmType(CachingConnectionFactory.ConfirmType.CORRELATED);
        factory.setPublisherReturns(true);factory.setConnectionTimeout(3000);
        return factory;
    }
    private static RabbitTemplate template(CachingConnectionFactory factory) {
        var template = new RabbitTemplate(factory);template.setMandatory(true);return template;
    }
    private static RabbitAdmin adminFor(CachingConnectionFactory factory) { return new RabbitAdmin(factory); }
    private static Message get(com.rabbitmq.client.Channel channel, String queue, long timeout) throws Exception {
        long until = System.nanoTime() + timeout * 1_000_000;
        while (System.nanoTime() < until) {
            GetResponse response = channel.basicGet(queue, false);
            if (response != null) {
                var properties = new DefaultMessagePropertiesConverter().toMessageProperties(response.getProps(), response.getEnvelope(), "UTF-8");
                return new Message(response.getBody(), properties);
            }
            Thread.sleep(25);
        }
        throw new IllegalStateException("acceptance queue timeout: " + queue);
    }
    private static JsonNode restart() throws Exception {
        URI uri = URI.create(required("P8_RESTART_URL"));
        assertThat(uri.getHost()).isEqualTo("127.0.0.1");
        String token = Files.readString(Path.of(required("P8_RESTART_TOKEN_FILE"))).strip();
        var request = HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(90)).header("Authorization", "Bearer " + token)
                .POST(HttpRequest.BodyPublishers.noBody()).build();
        var response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(200);return parse(response.body());
    }
    private static String classHash(Class<?> type) throws IOException {
        try (InputStream stream = type.getResourceAsStream("/" + type.getName().replace('.', '/') + ".class")) {
            return sha(Objects.requireNonNull(stream).readAllBytes());
        }
    }
    private static String required(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) throw new IllegalStateException("missing acceptance setting: " + name);
        return value;
    }

    /** AMQP 0-9-1 帧透传，仅丢弃 Basic.Ack/Nack；代理不读取/记录鉴权或业务内容。 */
    private static final class ConfirmProxy implements AutoCloseable {
        private final ServerSocket server;
        private final Set<Socket> sockets = java.util.concurrent.ConcurrentHashMap.newKeySet();
        final AtomicInteger dropped = new AtomicInteger();
        ConfirmProxy(String host, int port) throws IOException {
            server = new ServerSocket(0, 8, InetAddress.getByName("127.0.0.1"));
            Thread.ofVirtual().start(() -> {
                try {
                    while (!server.isClosed()) {
                        Socket client = server.accept(), broker = new Socket(host, port);
                        sockets.add(client);sockets.add(broker);
                        Thread.ofVirtual().start(() -> copy(client, broker));
                        Thread.ofVirtual().start(() -> frames(broker, client));
                    }
                } catch (IOException ignored) { /* 关闭代理结束本次故障注入。 */ }
            });
        }
        int port() { return server.getLocalPort(); }
        private static void copy(Socket source, Socket destination) {
            try { source.getInputStream().transferTo(destination.getOutputStream()); }
            catch (IOException ignored) { /* 连接关闭不改变验收结论。 */ }
        }
        private void frames(Socket source, Socket destination) {
            try {
                var input = new DataInputStream(source.getInputStream());
                var output = new DataOutputStream(destination.getOutputStream());
                while (true) {
                    int type = input.readUnsignedByte(), channel = input.readUnsignedShort(), size = input.readInt();
                    if (size < 0 || size > 16 * 1024 * 1024) throw new IOException("invalid AMQP frame");
                    byte[] body = input.readNBytes(size);int end = input.readUnsignedByte();
                    if (body.length != size || end != 0xce) throw new IOException("invalid AMQP frame");
                    if (type == 1 && channel > 0 && size >= 4) {
                        var bytes = ByteBuffer.wrap(body);
                        int klass = Short.toUnsignedInt(bytes.getShort()), method = Short.toUnsignedInt(bytes.getShort());
                        if (klass == 60 && (method == 80 || method == 120)) { dropped.incrementAndGet();continue; }
                    }
                    output.writeByte(type);output.writeShort(channel);output.writeInt(size);output.write(body);output.writeByte(end);output.flush();
                }
            } catch (IOException ignored) { /* 故障注入范围仅本次代理连接。 */ }
        }
        @Override public void close() throws IOException {
            server.close();for (Socket socket : sockets) socket.close();
        }
    }
}
