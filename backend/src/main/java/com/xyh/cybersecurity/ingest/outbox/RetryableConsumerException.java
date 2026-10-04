package com.xyh.cybersecurity.ingest.outbox;

/** 可通过延迟队列重试的消费者失败。错误摘要不应包含凭据、原始载荷或连接详情。 */
public class RetryableConsumerException extends RuntimeException {
    public RetryableConsumerException(String message) { super(message); }
    public RetryableConsumerException(String message, Throwable cause) { super(message, cause); }
}
