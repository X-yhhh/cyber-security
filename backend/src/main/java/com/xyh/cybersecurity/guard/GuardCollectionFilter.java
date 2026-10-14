package com.xyh.cybersecurity.guard;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Set;
import static com.xyh.cybersecurity.guard.GuardJson.*;

/** 控制台集合的公共筛选契约：前缀、UTC 时间区间和排序均规范化后绑定认证加密游标。 */
public record GuardCollectionFilter(String q, LocalDateTime from, LocalDateTime until, String sort) {
    public static GuardCollectionFilter parse(String q, String from, String until, String sort) {
        if (q != null && (q.isBlank() || q.length() > 128 || q.chars().anyMatch(Character::isISOControl)))
            throw error(400, "INVALID_QUERY");
        String order = sort == null ? "createdAt" : sort;
        if (!Set.of("createdAt", "updatedAt").contains(order)) throw error(400, "INVALID_QUERY");
        LocalDateTime start = utc(from), end = utc(until);
        if (start != null && end != null && !start.isBefore(end)) throw error(400, "INVALID_QUERY");
        return new GuardCollectionFilter(q, start, end, order);
    }

    public Map<String, Object> values() {
        return map("prefix", q == null ? null : q.replace("!", "!!").replace("%", "!%").replace("_", "!_") + "%",
                "from", from, "until", until, "sort", sort);
    }

    public String binding(long actor, String collection, String assetId, String status, String active) {
        return canonical(object("actor", actor, "collection", collection, "assetId", assetId, "status", status,
                "q", q, "from", from == null ? null : from.toString(), "until", until == null ? null : until.toString(),
                "sort", sort, "active", active));
    }

    private static LocalDateTime utc(String value) {
        if (value == null) return null;
        try {
            if (!value.matches("[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,6})?Z"))
                throw new IllegalArgumentException();
            return LocalDateTime.ofInstant(Instant.parse(value), ZoneOffset.UTC);
        } catch (RuntimeException invalid) {
            throw error(400, "INVALID_QUERY");
        }
    }
}
