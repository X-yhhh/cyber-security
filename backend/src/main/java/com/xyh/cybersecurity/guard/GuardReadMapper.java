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
        AUTHORIZATIONS("resource.read"), CONFIGS("resource.read"), MACHINE_CLIENTS("resource.read"),
        ASSIGNABLE_USERS("event.manage"), AUDIT("audit.read"),
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

    @SelectProvider(type = Sql.class, method = "summaryOpenEvents")
    long summaryOpenEvents(@Param("actor") long actor);

    @SelectProvider(type = Sql.class, method = "summaryPendingAuthorizations")
    long summaryPendingAuthorizations(@Param("actor") long actor);

    @SelectProvider(type = Sql.class, method = "summaryPendingSensorConfigs")
    long summaryPendingSensorConfigs(@Param("actor") long actor);

    @SelectProvider(type = Sql.class, method = "summaryPendingActions")
    long summaryPendingActions(@Param("actor") long actor);

    @SelectProvider(type = Sql.class, method = "summaryPendingLabRuns")
    long summaryPendingLabRuns(@Param("actor") long actor);

    @Select("SELECT COUNT(*) FROM guard_decision_policy WHERE status='draft' AND created_by<>#{actor}")
    long summaryPendingPolicies(@Param("actor") long actor);

    @Select("SELECT COUNT(*) FROM guard_release_bundle WHERE status='evaluated' AND requested_by<>#{actor}")
    long summaryPendingBundles(@Param("actor") long actor);

    @SelectProvider(type = Sql.class, method = "summaryPendingFeedbackReviews")
    long summaryPendingFeedbackReviews(@Param("actor") long actor);

    @Select("SELECT COUNT(*) FROM guard_release_bundle WHERE status=#{status}")
    long summaryBundlesByStatus(@Param("status") String status);

    @Select("SELECT COUNT(*) FROM guard_model WHERE validation_status='pending'")
    long summaryModelsPendingValidation();

    @SelectProvider(type = Sql.class, method = "summarySensorsUnhealthy")
    long summarySensorsUnhealthy(@Param("actor") long actor, @Param("floor") LocalDateTime floor);

    @SelectProvider(type = Sql.class, method = "summaryExecutorsUnhealthy")
    long summaryExecutorsUnhealthy(@Param("actor") long actor, @Param("floor") LocalDateTime floor);

    @SelectProvider(type = Sql.class, method = "summaryLastHealthAt")
    Object summaryLastHealthAt(@Param("actor") long actor);

    @SelectProvider(type = Sql.class, method = "summaryRecentAuditCount24h")
    long summaryRecentAuditCount24h(@Param("actor") long actor, @Param("since") LocalDateTime since);

    /* ---------- B5.2 实时态势：只做按桶聚合，桶号 b = TIMESTAMPDIFF(SECOND, from, t) DIV step ---------- */

    @SelectProvider(type = Sql.class, method = "liveCoverage")
    List<Map<String, Object>> liveCoverage(@Param("actor") long actor, @Param("permission") String permission,
                                           @Param("from") LocalDateTime from, @Param("until") LocalDateTime until, @Param("step") int step);

    @SelectProvider(type = Sql.class, method = "liveInbound")
    List<Map<String, Object>> liveInbound(@Param("actor") long actor, @Param("from") LocalDateTime from,
                                          @Param("until") LocalDateTime until, @Param("step") int step);

    @SelectProvider(type = Sql.class, method = "liveAlerts")
    List<Map<String, Object>> liveAlerts(@Param("actor") long actor, @Param("from") LocalDateTime from,
                                         @Param("until") LocalDateTime until, @Param("step") int step);

    @SelectProvider(type = Sql.class, method = "liveBlocked")
    List<Map<String, Object>> liveBlocked(@Param("actor") long actor, @Param("from") LocalDateTime from,
                                          @Param("until") LocalDateTime until, @Param("step") int step);

    @SelectProvider(type = Sql.class, method = "liveTodayInbound")
    long liveTodayInbound(@Param("actor") long actor, @Param("since") LocalDateTime since);

    @SelectProvider(type = Sql.class, method = "liveTodayAlerts")
    long liveTodayAlerts(@Param("actor") long actor, @Param("since") LocalDateTime since);

    @SelectProvider(type = Sql.class, method = "liveTodayBlocked")
    long liveTodayBlocked(@Param("actor") long actor, @Param("since") LocalDateTime since);

    @SelectProvider(type = Sql.class, method = "liveAsOf")
    Object liveAsOf(@Param("actor") long actor);

    @SelectProvider(type = Sql.class, method = "liveSensors")
    Map<String, Object> liveSensors(@Param("actor") long actor, @Param("fresh") LocalDateTime fresh);

    @SelectProvider(type = Sql.class, method = "liveExecutors")
    Map<String, Object> liveExecutors(@Param("actor") long actor, @Param("fresh") LocalDateTime fresh);

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

        private static String machineClientScope() {
            String rows = PERMISSION_ROWS.replace("#{actor}", "#{q.actor}")
                    .replace("p.permission_key=#{permission}", "p.permission_key IN ('iam.manage','sensor.manage')");
            return "r.client_type IN ('sensor','executor') AND EXISTS(" + rows
                    + " AND ((ur.scope_type='global' AND ur.scope_id='*')"
                    + " OR (ur.scope_type='asset' AND ur.scope_id=CAST(a.id AS CHAR))))";
        }

        private static String assignableScope() {
            return assetScope("a.id")
                    + " AND r.status='active' AND EXISTS("
                    + "SELECT 1 FROM sys_user_role target_ur"
                    + " JOIN sys_role target_role ON target_role.id=target_ur.role_id AND target_role.status='active'"
                    + " JOIN sys_role_permission target_rp ON target_rp.role_id=target_role.id"
                    + " JOIN sys_permission target_p ON target_p.id=target_rp.permission_id AND target_p.status='active'"
                    + " WHERE target_ur.user_id=r.id AND target_p.permission_key='event.manage'"
                    + " AND ((target_ur.scope_type='global' AND target_ur.scope_id='*')"
                    + " OR (target_ur.scope_type='asset' AND target_ur.scope_id=CAST(a.id AS CHAR))))";
        }

        private static String auditScope() {
            // v2 全局 audit.read 覆盖每个已登记范围；局部授权仍须覆盖全部关联范围。
            // 历史无范围记录仅保留 platform_admin 例外，旧 AuditMapper 的范围规则不变。
            return "(EXISTS(" + permissions() + " AND role_row.role_key='platform_admin'"
                    + " AND ur.scope_type='global' AND ur.scope_id='*') OR ("
                    + "EXISTS(SELECT 1 FROM audit_resource_scope s WHERE s.audit_id=r.id) AND NOT EXISTS("
                    + "SELECT 1 FROM audit_resource_scope s WHERE s.audit_id=r.id AND NOT EXISTS("
                    + permissions() + " AND ((ur.scope_type='global' AND ur.scope_id='*')"
                    + " OR (ur.scope_type=s.scope_type AND ur.scope_id=s.scope_id))))))";
        }

        /** 表名仅由内部集合枚举选择，不能来自请求参数。 */
        private static String table(Kind kind) {
            return switch (kind) {
                case AUTHORIZATIONS -> "asset_authorization";
                case CONFIGS -> "sensor_config";
                case MACHINE_CLIENTS -> "api_client";
                case ASSIGNABLE_USERS -> "sys_user";
                case AUDIT -> "audit_log";
                case HEALTH -> "guard_capture_health_window";
                case SENSORS -> "sensor_agent";
                case EXECUTORS -> "guard_executor";
                case OPS -> "asset";
            };
        }

        /** 键页仍保留归属与筛选关联；传感器配置只在读取投影时关联，避免大 JSON 进入排序。 */
        private static String joins(Kind kind,boolean projection) {
            return switch (kind) {
                case AUTHORIZATIONS,EXECUTORS -> " JOIN asset a ON a.id=r.asset_id";
                case CONFIGS -> " JOIN sensor_agent s ON s.id=r.sensor_id JOIN asset a ON a.id=s.asset_id";
                case MACHINE_CLIENTS -> " LEFT JOIN sensor_agent s ON s.id=r.sensor_id"
                        + " LEFT JOIN guard_executor ex ON ex.api_client_id=r.id"
                        + " JOIN asset a ON a.id=COALESCE(s.asset_id,ex.asset_id)";
                case ASSIGNABLE_USERS -> " JOIN asset a ON a.public_id=#{q.filters.assetId}";
                case AUDIT,OPS -> "";
                case HEALTH -> " JOIN asset a ON a.id=r.asset_id"
                        + " JOIN sensor_agent s ON s.id=r.sensor_id AND s.asset_id=r.asset_id"
                        + " JOIN guard_capture_scope cs ON cs.id=r.capture_scope_id AND cs.asset_id=r.asset_id AND cs.sensor_id=r.sensor_id";
                case SENSORS -> " JOIN asset a ON a.id=r.asset_id"+(projection?" LEFT JOIN sensor_config c"
                        + " ON c.id=(SELECT c2.id FROM sensor_config c2 WHERE c2.sensor_id=r.id AND c2.status='active' ORDER BY c2.id DESC LIMIT 1)":"");
            };
        }

        private static String source(Kind kind) {
            return table(kind)+" r"+joins(kind,true);
        }

        private static String sort(Kind kind) {
            return switch (kind) {
                case AUDIT -> "r.occurred_at";
                case HEALTH -> "r.received_at";
                default -> "r.created_at";
            };
        }

        private static String sort(Query q) {
            return "updatedAt".equals(q.filters.get("sort")) ? "r.updated_at" : sort(q.kind);
        }

        private static String filterTime(Kind kind) {
            return switch (kind) {
                case SENSORS -> "r.last_heartbeat_at";
                case EXECUTORS -> "r.last_heartbeat";
                default -> sort(kind);
            };
        }

        private static String columns(Query q) {
            Kind kind=q.kind;
            String common = "r.id internal_id," + sort(q) + " sort_time,";
            return common + switch (kind) {
                case AUTHORIZATIONS -> "r.public_id,a.public_id asset_public_id,r.status,r.revision,r.created_at,"
                        + "r.requested_by,r.valid_from,r.valid_until,r.scope_json";
                case CONFIGS -> "r.public_id,a.public_id asset_public_id,s.public_id sensor_public_id,"
                        + "r.status,r.revision,r.created_at,r.requested_by,r.config_version,r.feature_contract_version,r.activated_at,r.content_sha256,r.guard_definition_json";
                case MACHINE_CLIENTS -> "r.public_id,a.public_id asset_public_id,s.public_id sensor_public_id,"
                        + "ex.public_id executor_public_id,r.client_key,r.client_type,r.status,"
                        + "r.created_at,COALESCE(s.last_heartbeat_at,ex.last_heartbeat) last_used_at,r.expires_at";
                case ASSIGNABLE_USERS -> "r.user_key,r.username,r.display_name,r.status,a.public_id asset_public_id";
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
            StringBuilder sql = new StringBuilder(switch (q.kind) {
                case AUDIT -> auditScope();
                case MACHINE_CLIENTS -> machineClientScope();
                case ASSIGNABLE_USERS -> assignableScope();
                case OPS -> assetScope("r.id");
                default -> assetScope("a.id");
            });
            for (String key : q.filters.keySet()) {
                if (q.kind == Kind.ASSIGNABLE_USERS && key.equals("assetId")) continue;
                if (key.equals("sort")) continue;
                if (key.equals("q")) {
                    // 每种集合明确登记可搜索列；请求值只绑定参数，LIKE 的通配符已由解析层转义。
                    var columns=switch(q.kind){
                        case AUTHORIZATIONS -> java.util.List.of("a.asset_key","a.display_name","r.authorization_ref");
                        case CONFIGS -> java.util.List.of("a.asset_key","a.display_name","s.display_name","r.config_version");
                        case MACHINE_CLIENTS -> java.util.List.of("a.asset_key","a.display_name","s.display_name","ex.display_name","r.client_key");
                        default -> throw new IllegalArgumentException("Unsupported search");
                    };
                    sql.append(" AND (").append(String.join(" OR ",columns.stream()
                            .map(c->c+" LIKE #{q.filters.q} ESCAPE '!'").toList())).append(')');
                    continue;
                }
                String column = switch (key) {
                    case "assetId" -> q.kind == Kind.OPS ? "r.public_id" : "a.public_id";
                    case "sensorId" -> q.kind == Kind.SENSORS ? "r.public_id" : "s.public_id";
                    case "executorId" -> q.kind == Kind.MACHINE_CLIENTS ? "ex.public_id" : "r.public_id";
                    case "captureScopeId" -> "cs.public_id";
                    case "clientType" -> "r.client_type";
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
            if (q.beforeId != null) sql.append(" AND (").append(sort(q)).append("<#{q.beforeTime} OR (")
                    .append(sort(q)).append("=#{q.beforeTime} AND r.id<#{q.beforeId}))");
            return sql.toString();
        }

        public static String list(Map<String, Object> parameters) {
            Query q = (Query) parameters.get("q");
            // LIMIT 让键页物化；STRAIGHT_JOIN 固定先遍历有界键页，再取完整行。
            // 权限、范围、筛选、读取上界及游标锚点全部留在内层，不允许取页后再过滤。
            if(switch(q.kind){case AUTHORIZATIONS,CONFIGS,HEALTH,SENSORS -> true;default -> false;}) {
                return "SELECT "+columns(q)+" FROM (SELECT r.id,"+sort(q)+" sort_time FROM "
                        +table(q.kind)+" r"+joins(q.kind,false)+" WHERE "+where(q)
                        +" ORDER BY "+sort(q)+" DESC,r.id DESC LIMIT #{q.limit}) k STRAIGHT_JOIN "
                        +table(q.kind)+" r ON r.id=k.id"+joins(q.kind,true)
                        +" ORDER BY k.sort_time DESC,k.id DESC";
            }
            return "SELECT " + columns(q) + " FROM " + source(q.kind) + " WHERE " + where(q)
                    + " ORDER BY " + sort(q) + " DESC,r.id DESC LIMIT #{q.limit}";
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
            String scope;
            if ("machineClient".equals(parameters.get("permission"))) {
                String rows = PERMISSION_ROWS.replace("p.permission_key=#{permission}", "p.permission_key IN ('iam.manage','sensor.manage')");
                scope = "EXISTS(" + rows + " AND ((ur.scope_type='global' AND ur.scope_id='*')"
                        + " OR (ur.scope_type='asset' AND ur.scope_id=CAST(x.id AS CHAR))))";
            } else {
                scope = assetScope("x.id").replace("#{q.actor}", "#{actor}")
                        .replace("#{q.permission}", "#{permission}");
            }
            return "SELECT EXISTS(SELECT 1 FROM " + from + " WHERE " + alias + ".public_id=#{publicId} AND " + scope + ")";
        }

        private static String actorAssetScope(String asset, String permissionExpr) {
            String rows = PERMISSION_ROWS.replace("p.permission_key=#{permission}", permissionExpr);
            return "EXISTS(" + rows + " AND ((ur.scope_type='global' AND ur.scope_id='*')"
                    + " OR (ur.scope_type='asset' AND ur.scope_id=CAST(" + asset + " AS CHAR))))";
        }

        public static String summaryOpenEvents() {
            return "SELECT COUNT(*) FROM security_event r JOIN asset a ON a.id=r.guard_asset_id"
                    + " WHERE r.status NOT IN ('resolved','false_positive','closed') AND "
                    + actorAssetScope("a.id", "p.permission_key IN ('event.manage','detection.read')");
        }

        public static String summaryPendingAuthorizations() {
            return "SELECT COUNT(*) FROM asset_authorization r JOIN asset a ON a.id=r.asset_id"
                    + " WHERE r.status='pending' AND r.requested_by<>#{actor} AND "
                    + actorAssetScope("a.id", "p.permission_key='authorization.approve'");
        }

        public static String summaryPendingSensorConfigs() {
            return "SELECT COUNT(*) FROM sensor_config r JOIN sensor_agent s ON s.id=r.sensor_id JOIN asset a ON a.id=s.asset_id"
                    + " WHERE r.status IN ('draft','pending') AND (r.requested_by IS NULL OR r.requested_by<>#{actor}) AND "
                    + actorAssetScope("a.id", "p.permission_key='authorization.approve'");
        }

        public static String summaryPendingActions() {
            return "SELECT COUNT(*) FROM guard_action r JOIN asset a ON a.id=r.asset_id"
                    + " WHERE r.mode='manual' AND r.observed_state='pending' AND r.approved_by IS NULL"
                    + " AND (r.created_by IS NULL OR r.created_by<>#{actor}) AND "
                    + actorAssetScope("a.id", "p.permission_key='authorization.approve'");
        }

        public static String summaryPendingLabRuns() {
            return "SELECT COUNT(*) FROM guard_validation_session r JOIN asset a ON a.id=r.asset_id"
                    + " WHERE r.status='pending' AND r.requested_by<>#{actor} AND "
                    + actorAssetScope("a.id", "p.permission_key='authorization.approve'");
        }

        public static String summaryPendingFeedbackReviews() {
            return "SELECT COUNT(*) FROM guard_feedback r JOIN asset a ON a.id=r.asset_id"
                    + " WHERE r.status='pending' AND r.created_by<>#{actor} AND "
                    + actorAssetScope("a.id", "p.permission_key='feedback.review'");
        }

        public static String summarySensorsUnhealthy() {
            return "SELECT COUNT(*) FROM sensor_agent r JOIN asset a ON a.id=r.asset_id"
                    + " WHERE r.status<>'revoked' AND (r.status<>'active' OR r.last_heartbeat_at IS NULL OR r.last_heartbeat_at<#{floor}) AND "
                    + actorAssetScope("a.id", "p.permission_key='ops.read'");
        }

        public static String summaryExecutorsUnhealthy() {
            return "SELECT COUNT(*) FROM guard_executor r JOIN asset a ON a.id=r.asset_id"
                    + " WHERE r.status<>'revoked' AND (r.status<>'active' OR r.last_heartbeat IS NULL OR r.last_heartbeat<#{floor}) AND "
                    + actorAssetScope("a.id", "p.permission_key='ops.read'");
        }

        public static String summaryLastHealthAt() {
            return "SELECT MAX(r.received_at) FROM guard_capture_health_window r JOIN asset a ON a.id=r.asset_id"
                    + " WHERE " + actorAssetScope("a.id", "p.permission_key='ops.read'");
        }

        private static String bucketOf(String column) {
            return "TIMESTAMPDIFF(SECOND,#{from}," + column + ") DIV #{step}";
        }

        /** 每条已接收健康窗口起止所在的桶；权限名由服务层传入（detection.read 或 action.read）。 */
        public static String liveCoverage() {
            return "SELECT DISTINCT " + bucketOf("GREATEST(r.interval_start,#{from})") + " AS s, "
                    + bucketOf("LEAST(DATE_SUB(r.interval_end,INTERVAL 1 MICROSECOND),DATE_SUB(#{until},INTERVAL 1 MICROSECOND))") + " AS e"
                    + " FROM guard_capture_health_window r WHERE r.interval_end>#{from} AND r.interval_start<#{until} AND "
                    + actorAssetScope("r.asset_id", "p.permission_key=#{permission}");
        }

        public static String liveInbound() {
            return "SELECT " + bucketOf("r.as_of") + " AS b, COUNT(*) AS n FROM guard_observation r"
                    + " WHERE r.as_of>=#{from} AND r.as_of<#{until} AND " + actorAssetScope("r.asset_id", "p.permission_key='detection.read'")
                    + " GROUP BY b";
        }

        public static String liveAlerts() {
            return "SELECT JSON_UNQUOTE(JSON_EXTRACT(r.evidence_json,'$.family')) AS family, " + bucketOf("r.decided_at") + " AS b, COUNT(*) AS n"
                    + " FROM guard_decision r WHERE r.decision IN ('alert','block_candidate') AND r.decided_at>=#{from} AND r.decided_at<#{until} AND "
                    + actorAssetScope("r.asset_id", "p.permission_key='detection.read'") + " GROUP BY family, b";
        }

        /** 每条命令首次通过实态核对的 applied 回执时间，即“拦截生效”时刻；撤销回执不计。 */
        private static String firstApplied() {
            return "(SELECT r.command_id, MIN(r.observed_at) AS t FROM guard_action_receipt r"
                    + " WHERE r.status='applied' AND r.projected=TRUE AND r.revocation_id IS NULL AND "
                    + actorAssetScope("r.asset_id", "p.permission_key='action.read'") + " GROUP BY r.command_id) x";
        }

        public static String liveBlocked() {
            return "SELECT " + bucketOf("x.t") + " AS b, COUNT(*) AS n FROM " + firstApplied()
                    + " WHERE x.t>=#{from} AND x.t<#{until} GROUP BY b";
        }

        public static String liveTodayInbound() {
            return "SELECT COUNT(*) FROM guard_observation r WHERE r.as_of>=#{since} AND "
                    + actorAssetScope("r.asset_id", "p.permission_key='detection.read'");
        }

        public static String liveTodayAlerts() {
            return "SELECT COUNT(*) FROM guard_decision r WHERE r.decision IN ('alert','block_candidate') AND r.decided_at>=#{since} AND "
                    + actorAssetScope("r.asset_id", "p.permission_key='detection.read'");
        }

        public static String liveTodayBlocked() {
            return "SELECT COUNT(*) FROM " + firstApplied() + " WHERE x.t>=#{since}";
        }

        public static String liveAsOf() {
            return "SELECT MAX(r.received_at) FROM guard_capture_health_window r WHERE "
                    + actorAssetScope("r.asset_id", "p.permission_key IN ('detection.read','action.read','ops.read')");
        }

        public static String liveSensors() {
            return "SELECT COUNT(*) AS total, COALESCE(SUM(r.status='active' AND r.last_heartbeat_at>=#{fresh}),0) AS online"
                    + " FROM sensor_agent r WHERE r.status<>'revoked' AND " + actorAssetScope("r.asset_id", "p.permission_key='ops.read'");
        }

        public static String liveExecutors() {
            return "SELECT COUNT(*) AS total, COALESCE(SUM(r.status='active' AND r.last_heartbeat>=#{fresh}),0) AS online"
                    + " FROM guard_executor r WHERE r.status<>'revoked' AND " + actorAssetScope("r.asset_id", "p.permission_key='ops.read'");
        }

        public static String summaryRecentAuditCount24h() {
            String auditVisibility = auditScope().replace("#{q.actor}", "#{actor}").replace("#{q.permission}", "'audit.read'");
            return "SELECT COUNT(*) FROM audit_log r WHERE r.occurred_at>=#{since} AND " + auditVisibility;
        }
    }
}
