package com.xyh.cybersecurity.ingest.outbox;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.core.MessageProperties;
import org.springframework.amqp.core.MessageDeliveryMode;
import com.rabbitmq.client.Channel;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class IngestBatchConsumerTest {
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void acknowledgesAfterTransactionalProcessing() throws Exception {
        IngestBatchProcessingService processing = mock(IngestBatchProcessingService.class);
        when(processing.process(any())).thenReturn(IngestBatchProcessingService.ProcessResult.PROCESSED);
        RabbitTopologyConfig.IngestRetryPublisher retry = mock(RabbitTopologyConfig.IngestRetryPublisher.class);
        Channel channel = mock(Channel.class);
        IngestBatchConsumer consumer = new IngestBatchConsumer(objectMapper, processing, retry);

        Message message = message("event-1", "{\"batchId\":7,\"dataSourceId\":3,\"recordCount\":2}");
        consumer.consume(message, channel);

        verify(channel).basicAck(11L, false);
        verify(processing).process(new IngestBatchEvent("event-1", RabbitTopologyConfig.INGEST_ROUTE, 7, 3, 2));
    }

    @Test
    void routesRetryableFailureToDelayedQueueBeforeAckingOriginal() throws Exception {
        IngestBatchProcessingService processing = mock(IngestBatchProcessingService.class);
        doThrow(new RetryableConsumerException("INFERENCE_TASK_SUBMISSION_FAILED"))
                .when(processing).process(any());
        when(processing.recordFailure(eq("event-2"), eq("INFERENCE_TASK_SUBMISSION_FAILED"), any(), eq(false)))
                .thenReturn(new IngestBatchProcessingService.FailureResult(1, "retrying"));
        RabbitTopologyConfig.IngestRetryPublisher retry = mock(RabbitTopologyConfig.IngestRetryPublisher.class);
        Channel channel = mock(Channel.class);
        IngestBatchConsumer consumer = new IngestBatchConsumer(objectMapper, processing, retry);

        consumer.consume(message("event-2", "{\"batchId\":8,\"dataSourceId\":3,\"recordCount\":0}"), channel);

        verify(retry).publish(any(Message.class), eq(1));
        verify(channel).basicAck(11L, false);
    }

    @Test
    void requeuesOriginalIfRetryPublishIsNotConfirmed() throws Exception {
        IngestBatchProcessingService processing = mock(IngestBatchProcessingService.class);
        doThrow(new RetryableConsumerException("TEMPORARY_FAILURE")).when(processing).process(any());
        when(processing.recordFailure(eq("event-3"), eq("TEMPORARY_FAILURE"), any(), eq(false)))
                .thenReturn(new IngestBatchProcessingService.FailureResult(1, "retrying"));
        RabbitTopologyConfig.IngestRetryPublisher retry = mock(RabbitTopologyConfig.IngestRetryPublisher.class);
        doThrow(new IllegalStateException("confirm timeout")).when(retry).publish(any(Message.class), eq(1));
        Channel channel = mock(Channel.class);
        IngestBatchConsumer consumer = new IngestBatchConsumer(objectMapper, processing, retry);

        consumer.consume(message("event-3", "{\"batchId\":8,\"dataSourceId\":3,\"recordCount\":0}"), channel);

        verify(channel).basicNack(11L, false, true);
    }

    @Test
    void rejectsMalformedEnvelopeToDeadLetter() throws Exception {
        IngestBatchProcessingService processing = mock(IngestBatchProcessingService.class);
        when(processing.recordFailure(eq("bad-event"), eq("INGEST_EVENT_PAYLOAD_INVALID"), any(), eq(true)))
                .thenReturn(new IngestBatchProcessingService.FailureResult(1, "dead_lettered"));
        RabbitTopologyConfig.IngestRetryPublisher retry = mock(RabbitTopologyConfig.IngestRetryPublisher.class);
        Channel channel = mock(Channel.class);
        IngestBatchConsumer consumer = new IngestBatchConsumer(objectMapper, processing, retry);

        consumer.consume(message("bad-event", "{\"schemaVersion\":2}"), channel);

        verify(channel).basicNack(11L, false, false);
        verify(processing).recordFailure(eq("bad-event"), eq("INGEST_EVENT_PAYLOAD_INVALID"), any(), eq(true));
    }

    @Test
    void acknowledgesWithoutRetryWhenConcurrentDeliveryAlreadyConsumed() throws Exception {
        IngestBatchProcessingService processing = mock(IngestBatchProcessingService.class);
        doThrow(new RetryableConsumerException("TEMPORARY_FAILURE")).when(processing).process(any());
        when(processing.recordFailure(eq("event-4"), eq("TEMPORARY_FAILURE"), any(), eq(false)))
                .thenReturn(new IngestBatchProcessingService.FailureResult(0, "consumed"));
        RabbitTopologyConfig.IngestRetryPublisher retry = mock(RabbitTopologyConfig.IngestRetryPublisher.class);
        Channel channel = mock(Channel.class);
        IngestBatchConsumer consumer = new IngestBatchConsumer(objectMapper, processing, retry);

        consumer.consume(message("event-4", "{\"batchId\":8,\"dataSourceId\":3,\"recordCount\":0}"), channel);

        verify(channel).basicAck(11L, false);
        verify(retry, never()).publish(any(Message.class), anyInt());
        verify(channel, never()).basicNack(anyLong(), anyBoolean(), anyBoolean());
    }

    private Message message(String eventKey, String payload) {
        MessageProperties properties = new MessageProperties();
        properties.setDeliveryTag(11L);
        properties.setMessageId(eventKey);
        properties.setDeliveryMode(MessageDeliveryMode.PERSISTENT);
        properties.setType(RabbitTopologyConfig.INGEST_ROUTE);
        var root = objectMapper.createObjectNode();
        root.put("schemaVersion", 1);
        root.put("eventKey", eventKey);
        root.put("eventType", RabbitTopologyConfig.INGEST_ROUTE);
        try { root.set("payload", objectMapper.readTree(payload)); }
        catch (Exception exception) { throw new AssertionError(exception); }
        try { return new Message(objectMapper.writeValueAsBytes(root), properties); }
        catch (Exception exception) { throw new AssertionError(exception); }
    }
}
