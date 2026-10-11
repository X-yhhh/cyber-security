package com.xyh.cybersecurity.guard;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.SelectProvider;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

/** B5 独立只读 SQL；标识符只取内部枚举，所有请求值绑定参数，范围过滤先于分页。 */
@Mapper
public interface GuardReadMapper {
    enum Kind {
        AUTHORIZATIONS("resource.read"), CONFIGS("resource.read"), AUDIT("audit.read"),
        HEALTH("ops.read"), SENSORS("ops.read"), EXECUTORS("ops.read"), OPS("ops.read");
        final String permission;
        Kind(String permission) { this.permission = permission; }
    }

    /** ceiling 固定新追加行边界；anchorId 用相同范围/筛选重新验证，不能借游标跨资产。 */
    record Query(Kind kind, long actor, Map<String, Object> filters, int limit,
                 Long ceiling, Long anchorId, LocalDateTime beforeTime, Long beforeId, String publicId) {
        public String permission() { return kind.permission; }
    }

    String PERMISSION_ROWS = """
            SELECT 1 FROM sys_user_role ur
            JOIN sys_user u ON u.id=ur.user_id AND u.status='active'
            JOIN sys_role role_row ON role_row.id=ur.role_id AND role_row.status='active'
            JOIN sys_role_permission rp ON rp.role_id=role_row.id
            JOIN sys_permission p ON p.id=rp.permission_id AND p.status='active'
            WHERE ur.user_id=#{actor} AND p.permission_key=#{permission}
            """;

    @Select("SELECT EXISTS(" + PERMISSION_ROWS + ")")
    boolean hasPermission(@Param("actor") long actor, @Param("permission") String permission);

    @Select("SELECT UTC_TIMESTAMP(6)")
    LocalDateTime now();

    @SelectProvider(type = Sql.class, method = "list")
    List<Map<String, Object>> list(@Param("q") Query query);

    @SelectProvider(type = Sql.class, method = "ceiling")
    Long ceiling(@Param("q") Query query);

    @SelectProvider(type = Sql.class, method = "reference")
    boolean referenceVisible(@Param("actor") long actor, @Param("permission") String permission,
                             @Param("type") String type, @Param("publicId") String publicId);

    final class Sql {
        private Sql() { }

        private static String permissions() {
            // 子查询角色别名使用 role_row，避免遮蔽外层资源 r。
            return PERMISSION_ROWS.replace("#{actor}", "#{q.actor}").replace("#{permission}", "#{q.permission}");
        }

        private static String assetScope(String asset) {
            return "EXISTS(" + permissions() + " AND ((ur.scope_type='global' AND ur.scope_id='*')"
                    + " OR (ur.scope_type='asset' AND ur.scope_id=CAST(" + asset + " AS CHAR))))";
        }

        private static String auditScope() {
            // 与 AuditMapper.visibleAuditPredicate 一致：仅全局 platform_admin 可绕过逐项精确范围。
            return "(EXISTS(" + permissions() + " AND role_row.role_key='platform_admin'"
                    + " AND ur.scope_type='global' AND ur.scope_id='*') OR ("
                    + "EXISTS(SELECT 1 FROM audit_resource_scope s WHERE s.audit_id=r.id) AND NOT EXISTS("
                    + "SELECT 1 FROM audit_resource_scope s WHERE s.audit_id=r.id AND NOT EXISTS("
                    + permissions() + " AND ur.scope_type=s.scope_type AND ur.scope_id=s.scope_id))))";
        }

        private static String source(Kind kind) {
            return switch (kind) {
                case AUTHORIZATIONS -> "asset_authorization r JOIN asset a ON a.id=r.asset_id";
                case CONFIGS -> "sensor_config r JOIN sensor_agent s ON s.id=r.sensor_id JOIN asset a ON a.id=s.asset_id";
                case AUDIT -> "audit_log r";
                case HEALTH -> "guard_capture_health_window r JOIN asset a ON a.id=r.asset_id"
                        + " JOIN sensor_agent s ON s.id=r.sensor_id AND s.asset_id=r.asset_id"
                        + " JOIN guard_capture_scope cs ON cs.id=r.capture_scope_id AND cs.asset_id=r.asset_id AND cs.sensor_id=r.sensor_id";
                case SENSORS -> "sensor_agent r JOIN asset a ON a.id=r.asset_id LEFT JOIN sensor_config c"
                        + " ON c.id=(SELECT c2.id FROM sensor_config c2 WHERE c2.sensor_id=r.id AND c2.status='active' ORDER BY c2.id DESC LIMIT 1)";
                case EXECUTORS -> "guard_executor r JOIN asset a ON a.id=r.asset_id";
                case OPS -> "asset r";
            };
        }

        private static String sort(Kind kind) {
            return switch (kind) {
                case AUDIT -> "r.occurred_at";
                case HEALTH -> "r.received_at";
                default -> "r.created_at";
            };
        }

        private static String filterTime(Kind kind) {
            return switch (kind) {
                case SENSORS -> "r.last_heartbeat_at";
                case EXECUTORS -> "r.last_heartbeat";
                default -> sort(kind);
            };
        }

        private static String columns(Kind kind) {
            String common = "r.id internal_id," + sort(kind) + " sort_time,";
            return common + switch (kind) {
                case AUTHORIZATIONS -> "r.public_id,a.public_id asset_public_id,r.status,r.revision,r.created_at,"
                        + "r.valid_from,r.valid_until,r.scope_json";
                case CONFIGS -> "r.public_id,a.public_id asset_public_id,s.public_id sensor_public_id,"
                        + "r.status,r.revision,r.created_at,r.config_version,r.feature_contract_version,r.activated_at,r.content_sha256,r.guard_definition_json";
                case AUDIT -> "r.occurred_at,r.actor_type,r.action,r.resource_type,r.resource_id,r.request_id,r.outcome";
                case HEALTH -> "r.public_id,a.public_id asset_public_id,s.public_id sensor_public_id,cs.public_id capture_scope_public_id,"
                        + "r.observer_session_id,r.sequence_no,r.interval_start,r.interval_end,r.received_at,r.verification_status,r.payload_json";
                case SENSORS -> "r.public_id,a.public_id asset_public_id,r.status,r.revision,r.last_heartbeat_at received_at,"
                        + "r.guard_boot_id boot_id,r.agent_version,c.public_id config_public_id,c.config_version,c.content_sha256,c.guard_definition_json";
                case EXECUTORS -> "r.public_id,a.public_id asset_public_id,r.status,r.revision,r.last_heartbeat received_at,"
                        + "r.boot_id,r.adapter_version,r.capability_hash,r.health_json";
                case OPS -> "r.public_id,r.status,"
                        + "(SELECT COUNT(*) FROM sensor_agent s WHERE s.asset_id=r.id) sensor_count,"
                        + "(SELECT COUNT(*) FROM guard_executor e WHERE e.asset_id=r.id) executor_count,"
                        + "(SELECT MAX(s.last_heartbeat_at) FROM sensor_agent s WHERE s.asset_id=r.id) last_sensor_heartbeat_at,"
                        + "(SELECT MAX(e.last_heartbeat) FROM guard_executor e WHERE e.asset_id=r.id) last_executor_heartbeat_at,"
                        + "(SELECT COUNT(*) FROM guard_capture_health_window h WHERE h.asset_id=r.id) health_window_count,"
                        + "(SELECT MAX(h.received_at) FROM guard_capture_health_window h WHERE h.asset_id=r.id) last_health_received_at,"
                        + "(SELECT COUNT(*) FROM guard_budget_target t WHERE t.asset_id=r.id) budget_target_count,"
                        + "(SELECT COUNT(*) FROM guard_budget_event b JOIN guard_budget_target t ON t.id=b.budget_target_id"
                        + " WHERE t.asset_id=r.id AND b.event_kind='reset') budget_reset_count,"
                        + "(SELECT MAX(b.created_at) FROM guard_budget_event b JOIN guard_budget_target t ON t.id=b.budget_target_id"
                        + " WHERE t.asset_id=r.id AND b.event_kind='reset') last_budget_reset_at";
            };
        }

        private static String where(Query q) {
            StringBuilder sql = new StringBuilder(q.kind == Kind.AUDIT ? auditScope()
                    : assetScope(q.kind == Kind.OPS ? "r.id" : "a.id"));
            for (String key : q.filters.keySet()) {
                String column = switch (key) {
                    case "assetId" -> q.kind == Kind.OPS ? "r.public_id" : "a.public_id";
                    case "sensorId" -> q.kind == Kind.SENSORS ? "r.public_id" : "s.public_id";
                    case "executorId" -> "r.public_id";
                    case "captureScopeId" -> "cs.public_id";
                    case "status" -> "r.status";
                    case "verificationStatus" -> "r.verification_status";
                    case "action" -> "r.action";
                    case "requestId" -> "r.request_id";
                    case "from", "until" -> filterTime(q.kind);
                    default -> throw new IllegalArgumentException("Unknown query filter");
                };
                if (key.equals("assetId") && q.kind == Kind.AUDIT) {
                    sql.append(" AND EXISTS(SELECT 1 FROM audit_resource_scope af JOIN asset a ON CAST(a.id AS CHAR)=af.scope_id"
                            + " WHERE af.audit_id=r.id AND af.scope_type='asset' AND a.public_id=#{q.filters.assetId})");
                } else {
                    sql.append(" AND ").append(column).append(key.equals("from") ? ">=" : key.equals("until") ? "<" : "=")
                            .append("#{q.filters.").append(key).append("}");
                }
            }
            if (q.publicId != null) sql.append(" AND r.public_id=#{q.publicId}");
            if (q.ceiling != null) sql.append(" AND r.id<=#{q.ceiling}");
            if (q.anchorId != null) sql.append(" AND r.id=#{q.anchorId}");
            if (q.beforeId != null) sql.append(" AND (").append(sort(q.kind)).append("<#{q.beforeTime} OR (")
                    .append(sort(q.kind)).append("=#{q.beforeTime} AND r.id<#{q.beforeId}))");
            return sql.toString();
        }

        public static String list(Map<String, Object> parameters) {
            Query q = (Query) parameters.get("q");
            return "SELECT " + columns(q.kind) + " FROM " + source(q.kind) + " WHERE " + where(q)
                    + " ORDER BY " + sort(q.kind) + " DESC,r.id DESC LIMIT #{q.limit}";
        }

        public static String ceiling(Map<String, Object> parameters) {
            Query q = (Query) parameters.get("q");
            return "SELECT MAX(r.id) FROM " + source(q.kind) + " WHERE " + where(q);
        }

        public static String reference(Map<String, Object> parameters) {
            String from = switch ((String) parameters.get("type")) {
                case "assetId" -> "asset x";
                case "sensorId" -> "sensor_agent ref JOIN asset x ON x.id=ref.asset_id";
                case "executorId" -> "guard_executor ref JOIN asset x ON x.id=ref.asset_id";
                case "captureScopeId" -> "guard_capture_scope ref JOIN asset x ON x.id=ref.asset_id";
                default -> throw new IllegalArgumentException("Unknown resource reference");
            };
            String alias = parameters.get("type").equals("assetId") ? "x" : "ref";
            String scope = assetScope("x.id").replace("#{q.actor}", "#{actor}")
                    .replace("#{q.permission}", "#{permission}");
            return "SELECT EXISTS(SELECT 1 FROM " + from + " WHERE " + alias + ".public_id=#{publicId} AND " + scope + ")";
        }
    }
}
