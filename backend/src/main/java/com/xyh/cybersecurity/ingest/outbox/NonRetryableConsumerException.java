package com.xyh.cybersecurity.ingest.outbox;

/** 消息契约或业务输入不可恢复时使用的消费者失败。 */
public class NonRetryableConsumerException extends RuntimeException {
    public NonRetryableConsumerException(String message) { super(message); }
    public NonRetryableConsumerException(String message, Throwable cause) { super(message, cause); }
}
