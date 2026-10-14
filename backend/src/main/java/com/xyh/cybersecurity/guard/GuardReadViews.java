package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static com.xyh.cybersecurity.guard.GuardJson.*;
import static com.xyh.cybersecurity.guard.GuardReadMapper.Kind;

/** 逐字段及逐类型建立查询视图；未知嵌套结构不得以允许字段名穿透到响应。 */
final class GuardReadViews {
    private GuardReadViews() { }

    static ObjectNode view(Kind kind, Map<String, Object> row, LocalDateTime asOf) {
        ObjectNode result = object();
        if (kind == Kind.AUDIT) {
            result.put("id", reference("audit", row.get("internal_id")));
            columns(result, row, "occurred_at actor_type action resource_type request_id outcome");
            Object resource = row.get("resource_id");
            String value = resource == null ? null : resource.toString();
            result.put("resourceId", value == null ? null : isUuid(value) ? value
                    : reference("resource:" + row.get("resource_type"), resource));
            return result;
        }
        if (kind == Kind.ASSIGNABLE_USERS) {
            result.set("id", node(row.get("user_key")));
            result.set("assetId", node(row.get("asset_public_id")));
            columns(result, row, "user_key username display_name status");
            return result;
        }
        result.set("id", node(row.get("public_id")));
        if (kind != Kind.OPS) result.set("assetId", node(row.get("asset_public_id")));
        switch (kind) {
            case AUTHORIZATIONS -> {
                columns(result, row, "status revision created_at valid_from valid_until");
                Instant now = asOf.toInstant(ZoneOffset.UTC);
                result.put("validity", now.isBefore(instant(row.get("valid_from"))) ? "not_yet_valid"
                        : !now.isBefore(instant(row.get("valid_until"))) ? "expired" : "valid");
                JsonNode source = payload(row, "scope_json");
                ObjectNode scope = object();
                scope.set("interfaces", strings(source.path("interfaces")));
                scope.set("observationAllowed", scalar(source.path("observationAllowed"), 'b'));
                var scopes = JSON.createArrayNode();
                JsonNode executions = source.path("executionScopes");
                if (executions.isArray()) {
                    for (var execution : executions) {
                        if (!execution.isObject()) continue;
                        var item = object();
                        jsonFields(item, execution, "scope direction transport addressFamily capabilityId", 's');
                        jsonFields(item, execution, "servicePort", 'n');
                        scopes.add(item);
                    }
                }
                scope.set("executionScopes", executions.isArray() ? scopes : node(null));
                result.set("scope", scope);
            }
            case CONFIGS -> {
                result.set("sensorId", node(row.get("sensor_public_id")));
                columns(result, row, "status revision created_at config_version feature_contract_version activated_at content_sha256");
                JsonNode source = payload(row, "guard_definition_json");
                result.set("definition", source.isObject() ? definition(source) : node(null));
            }
            case MACHINE_CLIENTS -> {
                result.set("sensorId", node(row.get("sensor_public_id")));
                result.set("executorId", node(row.get("executor_public_id")));
                columns(result, row, "client_type status created_at last_used_at expires_at");
            }
            case HEALTH -> {
                result.set("sensorId", node(row.get("sensor_public_id")));
                result.set("captureScopeId", node(row.get("capture_scope_public_id")));
                result.set("sequence", node(row.get("sequence_no")));
                columns(result, row, "observer_session_id interval_start interval_end received_at verification_status");
                Object status = row.get("verification_status");
                result.set("serverVerifiedHealthy", status == null ? node(null) : node("healthy".equals(status)));
                result.set("failureReason", "healthy".equals(status) || "replay_healthy".equals(status) ? node(null) : node(status));
                result.put("freshness", freshness(row.get("interval_end"), asOf));
                result.put("healthState", windowState(status, row.get("interval_end"), row.get("received_at"), asOf));
                result.put("healthBasis", "replay_healthy".equals(status) ? "server_verified_file_replay_window" : "server_verified_window");
                JsonNode source = payload(row, "payload_json");
                jsonFields(result, source, "healthVersion captureSource configSha256 buildSha256", 's');
                jsonFields(result, source, "captureGap", 'b');
                jsonFields(result, source, "clockSkewMs", 'n');
                for (String counters : new String[]{"counterStart", "counterEnd"}) {
                    var values = object();
                    jsonFields(values, source.path(counters), "packetsSeen kernelDrops capacityDrops", 'n');
                    result.set(counters, values);
                }
            }
            case SENSORS, EXECUTORS -> {
                columns(result, row, "status revision received_at boot_id");
                result.put("projection", "latest");
                result.put("freshness", freshness(row.get("received_at"), asOf));
                result.put("healthState", heartbeatState(row.get("status"), row.get("received_at"), asOf));
                result.put("healthBasis", "heartbeat_and_status");
                result.putNull("serverVerifiedHealthy");
                if (kind == Kind.SENSORS) {
                    columns(result, row, "agent_version");
                    result.putNull("reportedConfigSha256");
                    result.putNull("lastSequence");
                    result.putNull("clockSkewMs");
                    if (row.get("config_public_id") == null) result.putNull("currentConfig");
                    else {
                        var config = object("id", row.get("config_public_id"));
                        columns(config, row, "config_version content_sha256");
                        jsonFields(config, payload(row, "guard_definition_json"), "buildSha256", 's');
                        result.set("currentConfig", config);
                    }
                } else {
                    columns(result, row, "adapter_version capability_hash");
                    var reported = object();
                    JsonNode source = payload(row, "health_json");
                    jsonFields(reported, source, "pendingRecovery", 'b');
                    jsonFields(reported, source, "activeRuleCount clockSkewMs", 'n');
                    result.set("reported", reported);
                }
            }
            case OPS -> columns(result, row, "status sensor_count executor_count last_sensor_heartbeat_at"
                    + " last_executor_heartbeat_at health_window_count last_health_received_at"
                    + " budget_target_count budget_reset_count last_budget_reset_at");
            default -> throw new IllegalArgumentException("Unsupported view");
        }
        return result;
    }

    private static ObjectNode definition(JsonNode source) {
        var result = object();
        jsonFields(result, source, "contractVersion profileSha256 captureHealthVersion captureScopeId addressFamily buildSha256", 's');
        result.set("interfaceIds", strings(source.path("interfaceIds")));
        var limits = object();
        jsonFields(limits, source.path("limits"), "maxBatchSize", 'n');
        result.set("limits", limits);
        return result;
    }

    private static JsonNode payload(Map<String, Object> row, String field) {
        Object value = row.get(field);
        return value == null ? node(null) : parse(value.toString());
    }

    private static void jsonFields(ObjectNode target, JsonNode source, String names, char type) {
        for (String name : names.split(" ")) target.set(name, scalar(source.path(name), type));
    }

    private static JsonNode scalar(JsonNode value, char type) {
        boolean valid = switch (type) {
            case 's' -> value.isTextual();
            case 'n' -> value.isNumber();
            case 'b' -> value.isBoolean();
            default -> false;
        };
        return valid ? value.deepCopy() : node(null);
    }

    private static JsonNode strings(JsonNode value) {
        if (!value.isArray()) return node(null);
        var array = JSON.createArrayNode();
        value.forEach(item -> { if (item.isTextual()) array.add(item.textValue()); });
        return array;
    }

    private static void columns(ObjectNode target, Map<String, Object> row, String columns) {
        for (String column : columns.split(" ")) {
            Object value = row.get(column);
            if (value instanceof LocalDateTime time) value = time.toInstant(ZoneOffset.UTC).toString();
            else if (value instanceof java.util.Date date) value = date.toInstant().toString();
            target.set(camel(column), node(value));
        }
    }

    private static String camel(String name) {
        String[] words = name.split("_");
        var result = new StringBuilder(words[0]);
        for (int i = 1; i < words.length; i++) result.append(Character.toUpperCase(words[i].charAt(0))).append(words[i].substring(1));
        return result.toString();
    }

    static String freshness(Object received, LocalDateTime asOf) {
        if (received == null) return "no_record";
        Duration age = Duration.between(instant(received), asOf.toInstant(ZoneOffset.UTC));
        return age.isNegative() ? "unknown" : age.compareTo(Duration.ofSeconds(10)) > 0 ? "stale" : "fresh";
    }

    /** 计数未知或时钟不可信只说明无法证明健康，展示为 unknown，不归入 healthy。 */
    private static final Set<String> UNKNOWN_HEALTH_REASONS = Set.of("COUNTER_UNKNOWN", "CLOCK_UNTRUSTED");
    /** 机器已被停用、离线、暂停或吊销时，无论心跳是否新鲜都不是健康。 */
    private static final Set<String> UNHEALTHY_MACHINE_STATUSES = Set.of("offline", "revoked", "suspended");

    /**
     * 健康窗口展示 unknown、stale、unhealthy、healthy 与独立的 replay_healthy。
     * 只映射写入时已持久化的服务端判定（verification_status），并按与 GuardHealth.current 相同的
     * intervalEnd 10 秒新鲜度区分 healthy/stale；不重新运行健康验证，也不参与预算恢复。
     * 状态缺失、计数未知、时钟不可信或 intervalEnd 晚于 asOf 均为 unknown；HEALTH_DELAY_EXCEEDED
     * 若 intervalEnd 晚于服务端接收时间（未来窗口）为 unknown，否则是迟到窗口，为 stale；
     * 其余非 healthy 判定（含未来新增的判定码）一律 unhealthy，避免未知被显示为正常。
     */
    static String windowState(Object verificationStatus, Object intervalEnd, Object receivedAt, LocalDateTime asOf) {
        if (verificationStatus == null) return "unknown";
        String status = verificationStatus.toString();
        if (UNKNOWN_HEALTH_REASONS.contains(status)) return "unknown";
        if (status.equals("HEALTH_DELAY_EXCEEDED")) {
            if (intervalEnd == null || receivedAt == null) return "unknown";
            return instant(intervalEnd).isAfter(instant(receivedAt)) ? "unknown" : "stale";
        }
        if (!status.equals("healthy") && !status.equals("replay_healthy")) return "unhealthy";
        return switch (freshness(intervalEnd, asOf)) {
            case "fresh" -> status;
            case "stale" -> "stale";
            default -> "unknown";
        };
    }

    /**
     * 心跳的四态展示，只表示机器存活与服务端已有状态投影，不代表采集健康（采集健康以健康窗口为准）。
     * 停用类状态为 unhealthy；从未收到或时间晚于 asOf 为 unknown；超过 10 秒为 stale；
     * 新鲜且服务端状态为 active 才是 healthy，新鲜但 pending 等未确认状态仍为 unknown。
     */
    static String heartbeatState(Object machineStatus, Object received, LocalDateTime asOf) {
        String status = machineStatus == null ? null : machineStatus.toString();
        if (status != null && UNHEALTHY_MACHINE_STATUSES.contains(status)) return "unhealthy";
        String receivedState = freshness(received, asOf);
        if (receivedState.equals("stale")) return "stale";
        if (!receivedState.equals("fresh")) return "unknown";
        return "active".equals(status) ? "healthy" : "unknown";
    }

    private static boolean isUuid(String value) {
        return value.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
    }

    private static String reference(String type, Object id) {
        return UUID.nameUUIDFromBytes(("host-guard-query/1:" + type + ":" + id).getBytes(StandardCharsets.UTF_8)).toString();
    }
}
