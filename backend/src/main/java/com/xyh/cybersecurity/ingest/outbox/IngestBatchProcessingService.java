package com.xyh.cybersecurity.ingest.outbox;

import com.xyh.cybersecurity.ingest.IngestMapper;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * 在数据库事务中完成消费幂等、批次读取和 M3 任务提交。
 * RabbitMQ ack 必须在该事务成功提交后才由监听器执行；失败时不产生成功消费标记。
 */
@Service
public class IngestBatchProcessingService {
    public static final String CONSUMER_NAME = "ingest.batch.received";

    private final IngestMapper mapper;
    private final ObjectProvider<InferenceTaskSubmitter> submitterProvider;

    public IngestBatchProcessingService(IngestMapper mapper, ObjectProvider<InferenceTaskSubmitter> submitterProvider) {
        this.mapper = mapper;
        this.submitterProvider = submitterProvider;
    }

    @Transactional
    public ProcessResult process(IngestBatchEvent event) {
        IngestMapper.ConsumedMessageRow existing = mapper.findConsumedMessageForUpdate(CONSUMER_NAME, event.eventKey());
        if (existing != null && ("consumed".equals(existing.status()) || "dead_lettered".equals(existing.status()))) {
            return ProcessResult.DUPLICATE;
        }
        if (existing == null) {
            mapper.insertConsumedMessage(CONSUMER_NAME, event.eventKey());
        } else {
            mapper.markConsumedProcessing(CONSUMER_NAME, event.eventKey());
        }

        List<IngestMapper.AcceptedRecord> records = mapper.findAcceptedRecords(event.batchId());
        if (records.size() != event.recordCount()) {
            throw new NonRetryableConsumerException("INGEST_RECORD_COUNT_MISMATCH");
        }
        if (records.stream().anyMatch(record -> record.dataSourceId() != event.dataSourceId())) {
            throw new NonRetryableConsumerException("INGEST_SOURCE_MISMATCH");
        }
        InferenceTaskSubmitter submitter = submitterProvider.getIfAvailable();
        if (submitter == null) {
            throw new RetryableConsumerException("INFERENCE_TASK_SUBMITTER_UNAVAILABLE");
        }
        try {
            submitter.submit(event, records);
        } catch (NonRetryableConsumerException | RetryableConsumerException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw new RetryableConsumerException("INFERENCE_TASK_SUBMISSION_FAILED", exception);
        }
        mapper.markConsumed(CONSUMER_NAME, event.eventKey());
        return ProcessResult.PROCESSED;
    }

    /** 失败记录必须独立提交，随后才能安全地 ack 原消息或转入延迟/死信队列。 */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public FailureResult recordFailure(String messageKey, String errorCode, String errorMessage,
                                       boolean deadLetter) {
        IngestMapper.ConsumedMessageRow existing = mapper.findConsumedMessageForUpdate(CONSUMER_NAME, messageKey);
        // 并发重复投递时败方可能因死锁回滚；胜方已提交则保持 consumed，不能改回 retrying 触发二次提交。
        if (existing != null && "consumed".equals(existing.status())) {
            return new FailureResult(existing.attempts(), "consumed");
        }
        int attempts = existing == null ? 1 : existing.attempts() + 1;
        String status = deadLetter || attempts >= IngestBatchConsumer.MAX_DELIVERIES
                ? "dead_lettered" : "retrying";
        if (existing == null) {
            mapper.insertConsumedFailureRow(CONSUMER_NAME, messageKey, status, errorCode, errorMessage);
            return new FailureResult(attempts, status);
        }
        mapper.recordConsumedFailure(CONSUMER_NAME, messageKey, status, errorCode, errorMessage);
        return new FailureResult(attempts, status);
    }

    public record FailureResult(int attempts, String status) {
        /** 同一消息已由其他投递成功提交；监听器应直接 ack，不再重试或死信。 */
        public boolean alreadyConsumed() { return "consumed".equals(status); }
    }
    public enum ProcessResult { PROCESSED, DUPLICATE }
}
