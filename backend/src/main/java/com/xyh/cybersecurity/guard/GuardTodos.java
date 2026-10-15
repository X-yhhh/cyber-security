package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.MultiValueMap;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import static com.xyh.cybersecurity.guard.GuardJson.*;
import static com.xyh.cybersecurity.guard.GuardTodoMapper.TodoKind;

/** BE-22 待办中心：同一只读快照计算完整计数，先按处理分组再按创建时间倒序选取最近 100 条。 */
@Service
public class GuardTodos {
    private static final int MAX_ITEMS = 100;
    private static final List<String> GROUPS = List.of("approve", "triage", "other");
    private final GuardAccess access;
    private final GuardTodoMapper mapper;

    public GuardTodos(GuardAccess access, GuardTodoMapper mapper) {
        this.access = access;
        this.mapper = mapper;
    }

    /** 无查询参数；仅人工会话可调用。没有任何可处理类别时 groups 为空，不补权限外的计数。 */
    @Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ)
    public JsonNode todos(MultiValueMap<String, String> params) {
        if (params != null && !params.isEmpty()) throw error(400, "INVALID_QUERY");
        long actor = access.human();
        LocalDateTime now = mapper.now();
        ArrayNode groups = JSON.createArrayNode();
        int remaining = MAX_ITEMS;
        long total = 0;
        for (String group : GROUPS) {
            List<JsonNode> candidates = new ArrayList<>();
            long count = 0;
            boolean visible = false;
            for (TodoKind kind : TodoKind.values()) {
                if (!kind.group.equals(group) || !mapper.allowed(actor, kind.permission, kind.global)) continue;
                visible = true;
                long kindCount = mapper.todoCount(actor, kind, now);
                count += kindCount;
                // 每类最多取剩余配额，再在分组内归并；计数不受 LIMIT 影响。
                if (kindCount == 0 || remaining == 0) continue;
                for (var row : mapper.todoItems(actor, kind, now, remaining)) {
                    String id = str(row, "public_id"), assetId = str(row, "asset_public_id"), detail = str(row, "detail");
                    String title = kind == TodoKind.EVENT ? kind.title + "：" + detail
                            : kind == TodoKind.BUNDLE_APPROVAL && "approved".equals(detail) ? "待激活发布组合" : kind.title;
                    candidates.add(object("kind", kind.key, "id", id, "title", title, "assetId", assetId,
                            "createdAt", instant(row.get("created_at")).toString(), "route", route(kind, id, assetId, detail)));
                }
            }
            if (!visible) continue;
            candidates.sort(Comparator.<JsonNode, java.time.Instant>comparing(n -> java.time.Instant.parse(n.path("createdAt").asText()))
                    .reversed().thenComparing(n -> n.path("kind").asText()).thenComparing(n -> n.path("id").asText(), Comparator.reverseOrder()));
            ArrayNode items = JSON.createArrayNode();
            for (var item : candidates) {
                if (remaining == 0) break;
                items.add(item);
                remaining--;
            }
            groups.add(object("kind", group, "count", count, "items", items));
            total += count;
        }
        return object("groups", groups, "truncated", total > MAX_ITEMS);
    }

    /** 跳转只携带公开 UUID；目标页仍需独立鉴权，待办链接不授予处理权限。 */
    private static String route(TodoKind kind, String id, String assetId, String detail) {
        return switch (kind) {
            case AUTHORIZATION, EXPIRING_AUTHORIZATION -> "/console/assets/list?assetId=" + assetId + "&tab=authorizations&id=" + id;
            case SENSOR_CONFIG -> "/console/assets/agents?tab=configs&sensorId=" + detail + "&id=" + id;
            case ACTION -> "/console/response/actions?id=" + id;
            case LAB -> "/console/release/bundles?tab=validation&id=" + id;
            case POLICY -> "/console/release/bundles?tab=policies&id=" + id;
            case BUNDLE_APPROVAL, BUNDLE_SEALING -> "/console/release/bundles?tab=bundles&id=" + id;
            case FEEDBACK -> "/console/detect/feedback?id=" + id;
            case EVENT -> "/console/detect/events/" + id;
            case MODEL -> "/console/release/models?tab=models&id=" + id;
            case DEVICE -> "/console/assets/agents?tab=" + ("executor".equals(detail) ? "executors" : "sensors") + "&id=" + id;
        };
    }
}
