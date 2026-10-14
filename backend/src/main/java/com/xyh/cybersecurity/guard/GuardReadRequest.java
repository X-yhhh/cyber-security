package com.xyh.cybersecurity.guard;

import org.springframework.util.MultiValueMap;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import static com.xyh.cybersecurity.guard.GuardJson.error;
import static com.xyh.cybersecurity.guard.GuardJson.uuid;
import static com.xyh.cybersecurity.guard.GuardReadMapper.Kind;

/** 新查询严格解析参数，避免拼写错误被静默忽略而扩大数据范围。 */
record GuardReadRequest(Map<String, Object> filters, int limit, String cursor) {
    private static final Set<String> REFERENCES = Set.of("assetId", "sensorId", "executorId", "captureScopeId");

    static GuardReadRequest parse(Kind kind, MultiValueMap<String, String> input) {
        Set<String> allowed = switch (kind) {
            case AUTHORIZATIONS -> Set.of("assetId", "status", "q", "from", "until", "sort");
            case CONFIGS -> Set.of("assetId", "sensorId", "status", "q", "from", "until", "sort");
            case SENSORS -> Set.of("assetId", "sensorId", "status", "from", "until");
            case AUDIT -> Set.of("assetId", "action", "requestId", "from", "until");
            case HEALTH -> Set.of("assetId", "sensorId", "captureScopeId", "verificationStatus", "from", "until");
            case EXECUTORS -> Set.of("assetId", "executorId", "status", "from", "until");
            case MACHINE_CLIENTS -> Set.of("assetId", "sensorId", "executorId", "clientType", "status", "q", "from", "until", "sort");
            case ASSIGNABLE_USERS, OPS -> Set.of("assetId");
        };
        Map<String, Object> filters = new TreeMap<>();
        int limit = 50;
        String cursor = null;
        for (var entry : input.entrySet()) {
            String key = entry.getKey();
            if (entry.getValue().size() != 1 || entry.getValue().getFirst() == null
                    || entry.getValue().getFirst().isBlank()) throw error(400, "INVALID_QUERY");
            String value = entry.getValue().getFirst();
            if (key.equals("limit")) {
                if (!value.matches("[0-9]{1,3}")) throw error(400, "INVALID_PAGE_SIZE");
                limit = Integer.parseInt(value);
                if (limit < 1 || limit > 200) throw error(400, "INVALID_PAGE_SIZE");
            } else if (key.equals("cursor")) {
                if (value.length() > 2048) throw error(400, "INVALID_CURSOR");
                cursor = value;
            } else if (!allowed.contains(key)) {
                throw error(400, "INVALID_QUERY");
            } else if (REFERENCES.contains(key)) {
                filters.put(key, uuid(value));
            } else if (key.equals("from") || key.equals("until")) {
                filters.put(key, time(value));
            } else if (key.equals("q")) {
                filters.put(key, GuardCollectionFilter.parse(value, null, null, null).values().get("prefix"));
            } else if (key.equals("sort")) {
                filters.put(key, GuardCollectionFilter.parse(null, null, null, value).sort());
            } else {
                if (!value.matches("[A-Za-z0-9_.:/-]{1,128}")) throw error(400, "INVALID_QUERY");
                if (key.equals("status") && !statuses(kind).contains(value)) throw error(400, "INVALID_QUERY");
                if (key.equals("clientType") && !Set.of("sensor", "executor").contains(value)) throw error(400, "INVALID_QUERY");
                if (key.equals("verificationStatus") && !Set.of("healthy", "replay_healthy", "REPLAY_KERNEL_DROPS_INVALID", "HEALTH_DELAY_EXCEEDED", "CLOCK_UNTRUSTED",
                        "CAPTURE_GAP", "COUNTER_UNKNOWN", "CAPTURE_DROPS", "HEALTH_CHAIN_INCOMPLETE", "HEALTH_IDENTITY_CHANGED")
                        .contains(value)) throw error(400, "INVALID_QUERY");
                filters.put(key, value);
            }
        }
        if (kind == Kind.ASSIGNABLE_USERS && !filters.containsKey("assetId")) throw error(400, "INVALID_QUERY");
        if (Set.of(Kind.AUTHORIZATIONS, Kind.CONFIGS, Kind.MACHINE_CLIENTS).contains(kind))
            filters.putIfAbsent("sort", "createdAt");
        if (filters.containsKey("from") && filters.containsKey("until")
                && !((LocalDateTime) filters.get("from")).isBefore((LocalDateTime) filters.get("until"))) {
            throw error(400, "INVALID_TIME_RANGE");
        }
        return new GuardReadRequest(Map.copyOf(filters), limit, cursor);
    }

    private static LocalDateTime time(String text) {
        try {
            if (!text.matches("[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,6})?Z")) {
                throw new IllegalArgumentException();
            }
            return LocalDateTime.ofInstant(Instant.parse(text), ZoneOffset.UTC);
        } catch (RuntimeException e) {
            throw error(400, "INVALID_TIME_RANGE");
        }
    }

    private static Set<String> statuses(Kind kind) {
        return switch (kind) {
            case AUTHORIZATIONS -> Set.of("pending", "active", "expired", "revoked");
            case CONFIGS -> Set.of("draft", "pending", "approved", "active", "retired", "rejected");
            case SENSORS -> Set.of("pending", "active", "offline", "revoked");
            case EXECUTORS -> Set.of("pending", "active", "suspended", "revoked");
            case MACHINE_CLIENTS -> Set.of("active", "disabled", "revoked");
            default -> Set.of();
        };
    }

    /** 长度前缀消除拼接歧义；标准化过滤绑定主体与集合，limit 不参与绑定。 */
    String binding(Kind kind, long actor) {
        StringBuilder result = new StringBuilder(kind.name()).append(':').append(actor);
        new TreeMap<>(filters).forEach((key, value) -> result.append('|').append(key.length()).append(':')
                .append(key).append(':').append(value.toString().length()).append(':').append(value));
        return result.toString();
    }
}
