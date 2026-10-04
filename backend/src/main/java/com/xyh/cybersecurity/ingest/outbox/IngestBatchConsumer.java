package com.xyh.cybersecurity.ingest.outbox;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.rabbitmq.client.Channel;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.MessageDigest;
import java.util.HexFormat;

/**
 * 接收已发布的 ingest 批次事件，按 eventKey 幂等提交 M3 推理任务。
 * 使用手动 ack：数据库事务成功后 ack；可重试故障进入 TTL 延迟队列，契约/业务故障直接进入死信。
 * <p>
 * 投递语义为至少一次：进程在事务提交前或 ack 前退出时，broker 会重新投递未确认消息；
 * 重复投递由 {@code consumed_message} 唯一键和行锁去重，因此每个 eventKey 最多成功交接一次。
 */
@Component
@ConditionalOnProperty(name = "cyber.ingest.consumer.enabled", havingValue = "true")
public class IngestBatchConsumer {
    public static final String LISTENER_ID = "ingestBatchConsumer";
    public static final int MAX_RETRIES = 5;
    public static final int MAX_DELIVERIES = MAX_RETRIES + 1;
    private static final String EVENT_TYPE = RabbitTopologyConfig.INGEST_ROUTE;
    private static final String SAFE_KEY_PATTERN = "[A-Za-z0-9._:-]{1,255}";

    private final ObjectMapper objectMapper;
    private final IngestBatchProcessingService processingService;
    private final RabbitTopologyConfig.IngestRetryPublisher retryPublisher;

    public IngestBatchConsumer(ObjectMapper objectMapper, IngestBatchProcessingService processingService,
                               RabbitTopologyConfig.IngestRetryPublisher retryPublisher) {
        this.objectMapper = objectMapper;
        this.processingService = processingService;
        this.retryPublisher = retryPublisher;
    }

    @RabbitListener(id = LISTENER_ID, queues ="${cyber.ingest.consumer.queue:q.ingest.batch.received}",
            containerFactory = "ingestRabbitListenerContainerFactory")
    public void consume(Message message, Channel channel) throws IOException {
        long deliveryTag = message.getMessageProperties().getDeliveryTag();
        String messageKey = messageKey(message);
        try {
            IngestBatchEvent event = parse(message);
            messageKey = event.eventKey();
            processingService.process(event);
        } catch (NonRetryableConsumerException failure) {
            deadLetter(message, channel, deliveryTag, messageKey, code(failure), failure.getMessage());
            return;
        } catch (RetryableConsumerException failure) {
            retry(message, channel, deliveryTag, messageKey, code(failure), failure.getMessage());
            return;
        } catch (Exception failure) {
            retry(message, channel, deliveryTag, messageKey, "CONSUMER_UNAVAILABLE", "消费者暂时不可用");
            return;
        }
        // ack 失败交给容器处理，不能把已提交的成功消费改写成 retrying 台账。
        channel.basicAck(deliveryTag, false);
    }

    private void retry(Message message, Channel channel, long deliveryTag, String messageKey,
                       String errorCode, String errorMessage) throws IOException {
        int currentAttempt = currentAttempt(message);
        boolean deadLetter = currentAttempt >= MAX_RETRIES;
        IngestBatchProcessingService.FailureResult failure;
        try {
            failure = processingService.recordFailure(messageKey, errorCode, safeMessage(errorMessage), deadLetter);
        } catch (RuntimeException ledgerFailure) {
            // 幂等台账不可写时不能确认或丢弃消息，交回主队列等待基础设施恢复。
            channel.basicNack(deliveryTag, false, true);
            return;
        }
        if (failure.alreadyConsumed()) {
            channel.basicAck(deliveryTag, false);
            return;
        }
        if (failure.attempts() >= MAX_DELIVERIES) {
            channel.basicNack(deliveryTag, false, false);
            return;
        }
        try {
            retryPublisher.publish(message, failure.attempts());
            channel.basicAck(deliveryTag, false);
        } catch (Exception publishFailure) {
            // 未确认延迟消息时重新入主队列，避免原事件在 broker 内丢失。
            channel.basicNack(deliveryTag, false, true);
        }
    }

    private void deadLetter(Message message, Channel channel, long deliveryTag, String messageKey,
                            String errorCode, String errorMessage) throws IOException {
        IngestBatchProcessingService.FailureResult failure;
        try {
            failure = processingService.recordFailure(messageKey, errorCode, safeMessage(errorMessage), true);
        } catch (RuntimeException ledgerFailure) {
            channel.basicNack(deliveryTag, false, true);
            return;
        }
        if (failure.alreadyConsumed()) {
            channel.basicAck(deliveryTag, false);
            return;
        }
        channel.basicNack(deliveryTag, false, false);
    }

    private IngestBatchEvent parse(Message message) {
        try {
            JsonNode root = objectMapper.readTree(message.getBody());
            if (root == null || !root.isObject() || !root.path("schemaVersion").isIntegralNumber()
                    || !root.path("schemaVersion").canConvertToInt()
                    || root.path("schemaVersion").asInt(-1) != 1
                    || !root.path("eventType").isTextual()
                    || !root.path("eventType").asText().equals(EVENT_TYPE)) {
                throw new NonRetryableConsumerException("INGEST_EVENT_SCHEMA_INVALID");
            }
            if (!root.path("eventKey").isTextual()) {
                throw new NonRetryableConsumerException("INGEST_EVENT_KEY_INVALID");
            }
            String eventKey = root.path("eventKey").asText("");
            String messageId = message.getMessageProperties().getMessageId();
            if (eventKey.isBlank() || eventKey.length() > 255 || !eventKey.matches(SAFE_KEY_PATTERN)
                    || (messageId != null && !messageId.equals(eventKey))) {
                throw new NonRetryableConsumerException("INGEST_EVENT_KEY_INVALID");
            }
            JsonNode payload = root.path("payload");
            if (!payload.isObject() || !payload.path("batchId").isIntegralNumber()
                    || !payload.path("dataSourceId").isIntegralNumber()
                    || !payload.path("recordCount").isIntegralNumber()
                    || !payload.path("batchId").canConvertToLong()
                    || !payload.path("dataSourceId").canConvertToLong()
                    || !payload.path("recordCount").canConvertToInt()) {
                throw new NonRetryableConsumerException("INGEST_EVENT_PAYLOAD_INVALID");
            }
            long batchId = payload.path("batchId").asLong(-1);
            long dataSourceId = payload.path("dataSourceId").asLong(-1);
            int recordCount = payload.path("recordCount").asInt(-1);
            if (batchId < 1 || dataSourceId < 1 || recordCount < 0 || recordCount > 500) {
                throw new NonRetryableConsumerException("INGEST_EVENT_PAYLOAD_INVALID");
            }
            return new IngestBatchEvent(eventKey, EVENT_TYPE, batchId, dataSourceId, recordCount);
        } catch (NonRetryableConsumerException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new NonRetryableConsumerException("INGEST_EVENT_JSON_INVALID", exception);
        }
    }

    private int currentAttempt(Message message) {
        Object value = message.getMessageProperties().getHeaders().get("x-ingest-retry-attempt");
        if (value instanceof Number number) return Math.max(0, number.intValue());
        if (value instanceof String text) {
            try { return Math.max(0, Integer.parseInt(text)); } catch (NumberFormatException ignored) { return 0; }
        }
        return 0;
    }

    private String messageKey(Message message) {
        String messageId = message.getMessageProperties().getMessageId();
        if (messageId != null && messageId.matches(SAFE_KEY_PATTERN)) return messageId;
        byte[] digest;
        try { digest = MessageDigest.getInstance("SHA-256").digest(message.getBody()); }
        catch (Exception exception) { digest = message.getBody(); }
        return "body:" + HexFormat.of().formatHex(digest);
    }

    private String code(RuntimeException failure) {
        String message = failure.getMessage();
        return message == null || message.isBlank() ? "CONSUMER_FAILED" : message.substring(0, Math.min(96, message.length()));
    }

    private String safeMessage(String message) {
        if (message == null || message.isBlank()) return "consumer failure";
        return message.substring(0, Math.min(500, message.length())).replaceAll("[\\r\\n\\t]", " ");
    }
}
