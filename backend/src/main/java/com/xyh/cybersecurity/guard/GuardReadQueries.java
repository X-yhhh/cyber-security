package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.MultiValueMap;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Set;

import static com.xyh.cybersecurity.guard.GuardJson.*;
import static com.xyh.cybersecurity.guard.GuardReadMapper.*;

/** 仅组装已持久化事实；不依赖审批、健康验证、预算恢复或任何写入服务。 */
@Service
@Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ)
public class GuardReadQueries {
    private final GuardReadMapper mapper;
    private final GuardAccess access;
    private final GuardReadCursor cursors;

    public GuardReadQueries(GuardReadMapper mapper, GuardAccess access, GuardReadCursor cursors) {
        this.mapper = mapper;
        this.access = access;
        this.cursors = cursors;
    }

    public JsonNode list(Kind kind, MultiValueMap<String, String> parameters) {
        long actor = actor(kind);
        GuardReadRequest request = GuardReadRequest.parse(kind, parameters);
        for (var entry : request.filters().entrySet()) {
            if (Set.of("assetId", "sensorId", "executorId", "captureScopeId").contains(entry.getKey())
                    && !mapper.referenceVisible(actor, kind.permission, entry.getKey(), entry.getValue().toString())) {
                throw error(404, "RESOURCE_NOT_FOUND");
            }
        }
        String binding = request.binding(kind, actor);
        Query base = new Query(kind, actor, request.filters(), request.limit() + 1, null, null, null, null, null);
        LocalDateTime asOf;
        Long ceiling;
        GuardReadCursor.Position position = null;
        if (request.cursor() == null) {
            asOf = mapper.now();
            ceiling = mapper.ceiling(base);
            if (ceiling == null) ceiling = 0L;
        } else {
            position = cursors.decode(request.cursor(), binding);
            asOf = position.asOf();
            ceiling = position.ceiling();
            Query anchor = new Query(kind, actor, request.filters(), 1, ceiling, position.id(), null, null, null);
            var anchors = mapper.list(anchor);
            if (anchors.isEmpty()) throw error(404, "RESOURCE_NOT_FOUND");
            if (!sortTime(anchors.getFirst()).equals(position.time())) throw error(400, "INVALID_CURSOR");
        }
        var rows = mapper.list(new Query(kind, actor, request.filters(), request.limit() + 1, ceiling, null,
                position == null ? null : position.time(), position == null ? null : position.id(), null));
        var items = rows.stream().limit(request.limit()).map(row -> GuardReadViews.view(kind, row, asOf)).toList();
        String next = null;
        if (rows.size() > request.limit()) {
            var last = rows.get(request.limit() - 1);
            next = cursors.encode(new GuardReadCursor.Position(ceiling, number(last, "internal_id"), sortTime(last), asOf), binding);
        }
        return object("asOf", asOf.toInstant(ZoneOffset.UTC).toString(), "items", items, "nextCursor", next);
    }

    public JsonNode get(Kind kind, String id) {
        long actor = actor(kind);
        var rows = mapper.list(new Query(kind, actor, Map.of(), 1, null, null, null, null, uuid(id)));
        if (rows.isEmpty()) throw error(404, "RESOURCE_NOT_FOUND");
        return GuardReadViews.view(kind, rows.getFirst(), mapper.now());
    }

    private long actor(Kind kind) {
        long actor = access.human();
        if (!mapper.hasPermission(actor, kind.permission)) throw error(403, "SCOPE_DENIED");
        return actor;
    }

    private static LocalDateTime sortTime(Map<String, Object> row) {
        return LocalDateTime.ofInstant(instant(row.get("sort_time")), ZoneOffset.UTC);
    }
}
