package com.xyh.cybersecurity.ingest.outbox;

/**
 * 接入事务写入 outbox 行后发布的进程内信号，只用于在事务提交后尽快唤醒 relay。
 *
 * <p>信号不携带、也不代替 outbox 行：它可能因进程退出或 relay 未启用而丢失，此时由定时轮询兜底，
 * 至少一次语义仍以 MySQL 中的 outbox 行为准。</p>
 *
 * @param batchId 写入 outbox 的批次，仅用于诊断
 */
public record OutboxAppended(long batchId) { }
