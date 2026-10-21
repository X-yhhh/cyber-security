package com.xyh.cybersecurity.ingest;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.time.Instant;
import java.util.List;

/**
 * outbox 中继的持久化边界。guard 事务内写入的 {@code outbox_event} 由中继逐页锁定、发布并回写状态；
 * 业务服务不直接拼接 JDBC SQL。
 */
@Mapper
public interface IngestMapper {
    /** 锁定一页可发布事件（pending 或已到重试时间的 failed），并发中继以 SKIP LOCKED 互不阻塞。 */
    List<OutboxRow> listPendingOutbox(@Param("limit") int limit);

    int markOutboxPublished(@Param("id") long id);

    /** 记录一次发布失败；超过重试上限时由调用方传入 {@code dead_letter} 终态。 */
    int markOutboxFailed(@Param("id") long id, @Param("status") String status,
                         @Param("attempts") int attempts, @Param("nextAttemptAt") Instant nextAttemptAt);

    record OutboxRow(long id, String eventKey, String topic, String payload, int attempts) { }
}
