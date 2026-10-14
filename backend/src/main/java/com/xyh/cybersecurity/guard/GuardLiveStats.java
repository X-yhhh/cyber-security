package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.MultiValueMap;

import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.xyh.cybersecurity.guard.GuardJson.JSON;
import static com.xyh.cybersecurity.guard.GuardJson.error;
import static com.xyh.cybersecurity.guard.GuardJson.instant;
import static com.xyh.cybersecurity.guard.GuardJson.object;

/**
 * B5.2 实时态势统计 {@code GET /api/v2/stats/live}（权限设计第 10.5 节，前端契约 frontend/src/api/v2/stats.ts）。
 *
 * <p>输入：{@code range}（15m、1h、24h、7d，缺省 15m）与可选 {@code step}（10—3600 秒，须整除范围且点数不超过 500；
 * 缺省按范围取 10、60、900、3600）。其他、重复或空参数一律 400 {@code INVALID_QUERY}。
 *
 * <p>输出：时间桶 {@code [from+i·step, from+(i+1)·step)}，末桶覆盖当前时刻。各序列按权限裁剪，无权限的字段不返回：
 * {@code inbound}、{@code alerts}、{@code today.inbound/alerts/openEvents} 需 detection.read；
 * {@code blocked}、{@code today.blocked} 需 action.read；{@code devices} 需 ops.read。全部按调用者在该权限下的资产范围统计。
 *
 * <p>桶值语义：该时段内没有任何已接收的采集健康窗口覆盖（同一权限范围内的资产）时为 {@code null}——传感器未接入或缺口，
 * 不补 0；有覆盖但没有事件时为 0。{@code asOf} 为可见范围内最后一次接收健康窗口的时间，从未接入为 null。
 *
 * <p>只做聚合查询，不返回明细、不写审计、不使用缓存；“今日”按服务器所在时区的自然日计算。
 */
@Service
@Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ)
public class GuardLiveStats {
    static final Map<String, Long> SPANS = Map.of("15m", 900L, "1h", 3_600L, "24h", 86_400L, "7d", 604_800L);
    static final Map<String, Integer> DEFAULT_STEPS = Map.of("15m", 10, "1h", 60, "24h", 900, "7d", 3_600);
    static final int MAX_POINTS = 500;
    static final int FRESH_HEARTBEAT_SECONDS = 10;
    /** 四类攻击家族固定返回，保证前端按类别稳定分色；其他家族按出现情况追加。 */
    private static final List<String> FAMILIES = List.of("port_scan", "brute_force", "dos_flood", "dos_slow");
    private static final Set<String> PARAMS = Set.of("range", "step");

    private final GuardReadMapper mapper;
    private final GuardAccess access;
    private final ZoneId zone;

    @Autowired
    public GuardLiveStats(GuardReadMapper mapper, GuardAccess access) {
        this(mapper, access, ZoneId.systemDefault());
    }

    GuardLiveStats(GuardReadMapper mapper, GuardAccess access, ZoneId zone) {
        this.mapper = mapper;
        this.access = access;
        this.zone = zone;
    }

    /** 已校验的范围与步长。 */
    record Window(String range, int step, int points) { }

    static Window window(MultiValueMap<String, String> params) {
        if (params != null) {
            for (var e : params.entrySet()) {
                if (!PARAMS.contains(e.getKey()) || e.getValue() == null || e.getValue().size() != 1
                        || e.getValue().getFirst() == null || e.getValue().getFirst().isBlank()) {
                    throw error(400, "INVALID_QUERY");
                }
            }
        }
        String range = params == null || !params.containsKey("range") ? "15m" : params.getFirst("range");
        if (!SPANS.containsKey(range)) throw error(400, "INVALID_QUERY");
        int step = DEFAULT_STEPS.get(range);
        if (params != null && params.containsKey("step")) {
            String raw = params.getFirst("step");
            if (!raw.matches("[0-9]{1,4}")) throw error(400, "INVALID_QUERY");
            step = Integer.parseInt(raw);
        }
        long span = SPANS.get(range);
        if (step < 10 || step > 3_600 || span % step != 0 || span / step > MAX_POINTS) throw error(400, "INVALID_QUERY");
        return new Window(range, step, (int) (span / step));
    }

    public JsonNode live(MultiValueMap<String, String> params) {
        Window w = window(params);
        long actor = access.human();
        boolean detection = mapper.hasPermission(actor, "detection.read");
        boolean action = mapper.hasPermission(actor, "action.read");
        boolean ops = mapper.hasPermission(actor, "ops.read");
        if (!detection && !action && !ops) throw error(403, "SCOPE_DENIED");

        LocalDateTime now = mapper.now();
        long nowSec = now.toEpochSecond(ZoneOffset.UTC);
        long toSec = Math.floorDiv(nowSec, w.step()) * w.step() + w.step();
        long fromSec = toSec - (long) w.points() * w.step();
        LocalDateTime from = LocalDateTime.ofEpochSecond(fromSec, 0, ZoneOffset.UTC);
        LocalDateTime to = LocalDateTime.ofEpochSecond(toSec, 0, ZoneOffset.UTC);

        ObjectNode out = object();
        out.put("range", w.range());
        out.put("step", w.step());
        out.put("from", Instant.ofEpochSecond(fromSec).toString());
        out.put("to", Instant.ofEpochSecond(toSec).toString());
        out.put("points", w.points());
        Object asOf = mapper.liveAsOf(actor);
        if (asOf == null) out.putNull("asOf");
        else out.put("asOf", instant(asOf).toString());

        // 以数据库时间为准换算服务器时区的当日零点，再转回 UTC 与存储列比较。
        LocalDateTime dayStart = LocalDate.ofInstant(now.toInstant(ZoneOffset.UTC), zone)
                .atStartOfDay(zone).withZoneSameInstant(ZoneOffset.UTC).toLocalDateTime();
        ObjectNode today = object();

        if (detection) {
            boolean[] covered = coverage(mapper.liveCoverage(actor, "detection.read", from, to, w.step()), w.points());
            out.set("inbound", series(mapper.liveInbound(actor, from, to, w.step()), covered));
            Map<String, long[]> byFamily = new LinkedHashMap<>();
            for (String f : FAMILIES) byFamily.put(f, new long[w.points()]);
            for (var row : mapper.liveAlerts(actor, from, to, w.step())) {
                int b = bucket(row, w.points());
                if (b < 0) continue;
                byFamily.computeIfAbsent(family(row.get("family")), k -> new long[w.points()])[b] += count(row);
            }
            ObjectNode alerts = object();
            byFamily.forEach((k, v) -> alerts.set(k, masked(v, covered)));
            out.set("alerts", alerts);
            today.put("inbound", mapper.liveTodayInbound(actor, dayStart));
            today.put("alerts", mapper.liveTodayAlerts(actor, dayStart));
            today.put("openEvents", mapper.summaryOpenEvents(actor));
        }
        if (action) {
            boolean[] covered = coverage(mapper.liveCoverage(actor, "action.read", from, to, w.step()), w.points());
            out.set("blocked", series(mapper.liveBlocked(actor, from, to, w.step()), covered));
            today.put("blocked", mapper.liveTodayBlocked(actor, dayStart));
        }
        if (!today.isEmpty()) out.set("today", today);
        if (ops) {
            LocalDateTime fresh = now.minusSeconds(FRESH_HEARTBEAT_SECONDS);
            Map<String, Object> s = mapper.liveSensors(actor, fresh);
            Map<String, Object> e = mapper.liveExecutors(actor, fresh);
            out.set("devices", object("sensorsOnline", num(s, "online"), "sensorsTotal", num(s, "total"),
                    "executorsOnline", num(e, "online"), "executorsTotal", num(e, "total")));
        }
        return out;
    }

    /** 健康窗口起止所在桶（窗口不超过 5 秒、步长至少 10 秒，因此最多跨两桶）标记为有覆盖。 */
    static boolean[] coverage(List<Map<String, Object>> rows, int points) {
        boolean[] covered = new boolean[points];
        for (var row : rows) {
            long s = Math.max(0, ((Number) row.get("s")).longValue());
            long e = Math.min(points - 1L, ((Number) row.get("e")).longValue());
            for (long i = s; i <= e; i++) covered[(int) i] = true;
        }
        return covered;
    }

    static ArrayNode series(List<Map<String, Object>> rows, boolean[] covered) {
        long[] counts = new long[covered.length];
        for (var row : rows) {
            int b = bucket(row, covered.length);
            if (b >= 0) counts[b] += count(row);
        }
        return masked(counts, covered);
    }

    /** 无覆盖的桶输出 null；无覆盖但有事件（如健康窗口延迟到达）时仍输出实际计数，不吞掉已发生的事实。 */
    static ArrayNode masked(long[] counts, boolean[] covered) {
        ArrayNode arr = JSON.createArrayNode();
        for (int i = 0; i < counts.length; i++) {
            if (covered[i] || counts[i] > 0) arr.add(counts[i]);
            else arr.addNull();
        }
        return arr;
    }

    private static int bucket(Map<String, Object> row, int points) {
        Object b = row.get("b");
        if (!(b instanceof Number n)) return -1;
        long i = n.longValue();
        return i < 0 || i >= points ? -1 : (int) i;
    }

    private static long count(Map<String, Object> row) {
        return row.get("n") instanceof Number n ? n.longValue() : 0L;
    }

    private static long num(Map<String, Object> row, String key) {
        return row != null && row.get(key) instanceof Number n ? n.longValue() : 0L;
    }

    private static String family(Object raw) {
        String f = raw == null ? null : raw.toString();
        return f == null || f.isBlank() || "null".equals(f) ? "unknown" : f;
    }
}
