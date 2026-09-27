package com.xyh.cybersecurity.ingest.outbox;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;

/**
 * 有界、至少一次 outbox relay。通过默认关闭的开关启用，broker consumer 必须按 eventKey 幂等。
 */
@Service
@ConditionalOnProperty(name = "cyber.ingest.outbox-relay.enabled", havingValue = "true")
public class OutboxRelay {
    private static final int MAX_ATTEMPTS = 12;
    private static final int PAGE_SIZE = 32;
    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;
    private final ObjectProvider<Publisher> publisher;

    public OutboxRelay(JdbcTemplate jdbc, ObjectMapper mapper, ObjectProvider<Publisher> publisher) {
        this.jdbc = jdbc; this.mapper = mapper; this.publisher = publisher;
    }

    /** 由独立调度 bean 经 Spring 代理调用，确保数据库行锁处于事务内。 */
    @Transactional
    public int publishPending() {
        List<Event> events = jdbc.query("SELECT id,event_key,topic,payload_json,attempts FROM outbox_event "
                        + "WHERE status IN ('pending','failed') AND (next_attempt_at IS NULL OR next_attempt_at<=UTC_TIMESTAMP(3)) "
                        + "ORDER BY id LIMIT " + PAGE_SIZE + " FOR UPDATE SKIP LOCKED",
                (rs, n) -> new Event(rs.getLong("id"), rs.getString("event_key"), rs.getString("topic"),
                        rs.getString("payload_json"), rs.getInt("attempts")));
        for (Event event : events) {
            try {
                JsonNode payload = mapper.readTree(event.payload());
                Publisher target = publisher.getIfAvailable();
                if (target == null) throw new IllegalStateException("outbox publisher 未配置");
                target.publish(event.eventKey(), event.topic(), payload);
                jdbc.update("UPDATE outbox_event SET status='published',published_at=UTC_TIMESTAMP(3),next_attempt_at=NULL WHERE id=?",
                        event.id());
            } catch (Exception failure) {
                int attempts = event.attempts() + 1;
                String status = attempts >= MAX_ATTEMPTS ? "dead_letter" : "failed";
                long delaySeconds = Math.min(3600, 1L << Math.min(attempts, 11));
                jdbc.update("UPDATE outbox_event SET status=?,attempts=?,next_attempt_at=? WHERE id=?",
                        status, attempts, Timestamp.from(Instant.now().plusSeconds(delaySeconds)), event.id());
            }
        }
        return events.size();
    }

    public interface Publisher { void publish(String eventKey, String topic, JsonNode payload) throws Exception; }
    private record Event(long id, String eventKey, String topic, String payload, int attempts) { }
}
