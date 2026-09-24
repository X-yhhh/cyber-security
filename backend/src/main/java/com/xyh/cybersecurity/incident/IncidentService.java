package com.xyh.cybersecurity.incident;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.xyh.cybersecurity.common.api.ApiRequestException;
import com.xyh.cybersecurity.identity.IdentityPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.PreparedStatement;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/** 提供范围内告警/事件视图，并以 compare-and-set 状态迁移追加研判证据。 */
@Service
public class IncidentService {

    private static final Map<String, Set<String>> TRANSITIONS = Map.of(
            "open", Set.of("investigating"),
            "investigating", Set.of("contained", "resolved", "false_positive", "closed"),
            "contained", Set.of("investigating", "resolved", "closed"),
            "resolved", Set.of("closed"),
            "false_positive", Set.of("closed"),
            "closed", Set.of());

    private final IncidentMapper mapper;
    private final JdbcTemplate jdbc;
    private final ObjectMapper objectMapper;

    public IncidentService(IncidentMapper mapper, JdbcTemplate jdbc, ObjectMapper objectMapper) {
        this.mapper = mapper;
        this.jdbc = jdbc;
        this.objectMapper = objectMapper;
    }

    public Page<IncidentMapper.AlertView> alerts(long userId, int page, int size) {
        int offset = checkedOffset(page, size);
        return new Page<>(mapper.countVisibleAlerts(userId), page, size,
                mapper.listVisibleAlerts(userId, offset, size));
    }

    public IncidentMapper.AlertView alert(long userId, long alertId) {
        IncidentMapper.AlertView alert = mapper.findVisibleAlert(userId, alertId);
        if (alert == null) throw ApiRequestException.notFound();
        return alert;
    }

    public Page<IncidentMapper.EventView> events(long userId, int page, int size) {
        int offset = checkedOffset(page, size);
        return new Page<>(mapper.countVisibleEvents(userId), page, size,
                mapper.listVisibleEvents(userId, offset, size));
    }

    public EventDetail event(long userId, long eventId) {
        IncidentMapper.EventView event = mapper.findVisibleEvent(userId, eventId);
        if (event == null) throw ApiRequestException.notFound();
        return new EventDetail(event, mapper.listEventAlertsVisible(userId, eventId),
                mapper.listEventAssetsVisible(userId, eventId), mapper.listEventTimelineVisible(userId, eventId));
    }

    @Transactional
    public EventDetail transition(long userId, long eventId, String newStatus, String reason,
                                  HttpServletRequest request) {
        String note = validatedText(reason);
        IncidentMapper.EventView event = visibleEvent(userId, eventId);
        Set<String> allowed = TRANSITIONS.get(event.status());
        if (allowed == null || !allowed.contains(newStatus)) {
            throw ApiRequestException.conflict("事件状态迁移不允许");
        }
        if (mapper.transitionVisibleEvent(userId, eventId, event.status(), newStatus) != 1) {
            throw ApiRequestException.conflict("事件状态已被其他请求更新");
        }
        String details = json(Map.of("from", event.status(), "to", newStatus));
        if (mapper.appendTimelineForInvestigator(userId, eventId, "status_transition",
                Long.toString(userId), note, details) != 1) {
            throw ApiRequestException.conflict("事件授权或状态已变化");
        }
        audit(userId, eventId, "event.status.transition", request);
        return event(userId, eventId);
    }

    @Transactional
    public EventDetail addNote(long userId, long eventId, String note, HttpServletRequest request) {
        String summary = validatedText(note);
        visibleEvent(userId, eventId);
        if (mapper.appendTimelineForInvestigator(userId, eventId, "analyst_note",
                Long.toString(userId), summary, json(Map.of("kind", "analyst_note"))) != 1) {
            throw ApiRequestException.notFound();
        }
        audit(userId, eventId, "event.note.created", request);
        return event(userId, eventId);
    }

    private IncidentMapper.EventView visibleEvent(long userId, long eventId) {
        IncidentMapper.EventView event = mapper.findVisibleEvent(userId, eventId);
        if (event == null) throw ApiRequestException.notFound();
        return event;
    }

    private void audit(long userId, long eventId, String action, HttpServletRequest request) {
        Object requestId = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        GeneratedKeyHolder key = new GeneratedKeyHolder();
        jdbc.update(connection -> {
            PreparedStatement statement = connection.prepareStatement(
                    "INSERT INTO audit_log (occurred_at,actor_type,actor_id,action,resource_type,resource_id,request_id,outcome,reason) "
                            + "VALUES (?,'human',?,?, 'security_event', ?, ?, 'success', 'scoped analyst workflow')",
                    Statement.RETURN_GENERATED_KEYS);
            statement.setTimestamp(1, Timestamp.from(Instant.now()));
            statement.setString(2, Long.toString(userId));
            statement.setString(3, action);
            statement.setString(4, Long.toString(eventId));
            statement.setString(5, requestId instanceof String value ? value : null);
            return statement;
        }, key);
        long auditId = key.getKey().longValue();
        jdbc.update("INSERT IGNORE INTO audit_resource_scope (audit_id,scope_type,scope_id) "
                        + "SELECT ?, 'asset', CAST(asset_id AS CHAR) FROM event_asset_link WHERE event_id=?",
                auditId, eventId);
        jdbc.update("INSERT IGNORE INTO audit_resource_scope (audit_id,scope_type,scope_id) "
                        + "SELECT ?, 'asset', CAST(ir.asset_id AS CHAR) FROM event_alert_link eal "
                        + "JOIN detection_alert da ON da.id=eal.alert_id "
                        + "JOIN ingest_record ir ON ir.id=da.ingest_record_id "
                        + "WHERE eal.event_id=? AND ir.asset_id IS NOT NULL",
                auditId, eventId);
        jdbc.update("INSERT IGNORE INTO audit_resource_scope (audit_id,scope_type,scope_id) "
                        + "SELECT ?, 'data_source', CAST(ib.data_source_id AS CHAR) FROM event_alert_link eal "
                        + "JOIN detection_alert da ON da.id=eal.alert_id "
                        + "JOIN ingest_record ir ON ir.id=da.ingest_record_id "
                        + "JOIN ingest_batch ib ON ib.id=ir.batch_id WHERE eal.event_id=?",
                auditId, eventId);
    }

    private String validatedText(String value) {
        if (value == null) throw ApiRequestException.badRequest("研判说明不能为空");
        String result = value.trim();
        if (result.isEmpty() || result.length() > 1000 || result.chars().anyMatch(Character::isISOControl)) {
            throw ApiRequestException.badRequest("研判说明长度或字符无效");
        }
        return result;
    }

    private String json(Map<String, String> value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception exception) {
            throw new IllegalStateException("Unable to serialize event timeline details", exception);
        }
    }

    private static int checkedOffset(int page, int size) {
        if (page < 0 || size < 1 || size > 100 || (long) page * size > Integer.MAX_VALUE) {
            throw ApiRequestException.badRequest("分页参数超出允许范围");
        }
        return page * size;
    }

    public record Page<T>(long totalElements, int page, int size, List<T> items) { }
    public record EventDetail(IncidentMapper.EventView event, List<IncidentMapper.AlertView> alerts,
                              List<IncidentMapper.EventAssetView> assets,
                              List<IncidentMapper.TimelineView> timeline) { }
}
