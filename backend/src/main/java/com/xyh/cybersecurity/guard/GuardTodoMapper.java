package com.xyh.cybersecurity.guard;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.SelectProvider;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

/** BE-22 查询投影：权限与资产范围在同一个 EXISTS 内校验，所有外部参数均绑定；不更新业务状态。 */
@Mapper
public interface GuardTodoMapper {
    /** 十二类待办及其处理分组；全局对象必须持有全局权限，不能借资产角色查看。 */
    enum TodoKind {
        AUTHORIZATION("authorization", "approve", "authorization.approve", false, "待批资产授权"),
        SENSOR_CONFIG("sensor_config", "approve", "authorization.approve", false, "待批采集配置"),
        ACTION("action", "approve", "authorization.approve", false, "待批处置申请"),
        LAB("lab", "approve", "authorization.approve", false, "待批 lab 资格"),
        POLICY("policy", "approve", "policy.approve", true, "待审决策策略"),
        BUNDLE_APPROVAL("bundle_approval", "approve", "bundle.approve", true, "待批或待激活发布组合"),
        FEEDBACK("feedback", "triage", "feedback.review", false, "待复核标注"),
        EVENT("event", "triage", "event.manage", false, "待研判事件"),
        MODEL("model", "other", "model.validate", true, "待校验模型"),
        BUNDLE_SEALING("bundle_sealing", "other", "bundle.request", true, "待封存发布组合"),
        EXPIRING_AUTHORIZATION("expiring_authorization", "other", "authorization.request", false, "授权即将到期"),
        DEVICE("device", "other", "ops.read", false, "设备异常");

        final String key, group, permission, title;
        final boolean global;
        TodoKind(String key, String group, String permission, boolean global, String title) {
            this.key = key; this.group = group; this.permission = permission; this.global = global; this.title = title;
        }
    }

    @Select("SELECT UTC_TIMESTAMP(6)")
    LocalDateTime now();

    @SelectProvider(type = Sql.class, method = "permission")
    boolean allowed(@Param("actor") long actor, @Param("permission") String permission, @Param("global") boolean global);

    @SelectProvider(type = Sql.class, method = "todoCount")
    long todoCount(@Param("actor") long actor, @Param("kind") TodoKind kind, @Param("now") LocalDateTime now);

    @SelectProvider(type = Sql.class, method = "todoItems")
    List<Map<String, Object>> todoItems(@Param("actor") long actor, @Param("kind") TodoKind kind,
                                      @Param("now") LocalDateTime now, @Param("limit") int limit);

    final class Sql {
        private Sql() { }

        public static String permission(Map<String, Object> p) {
            String scope = Boolean.TRUE.equals(p.get("global"))
                    ? "ur.scope_type='global' AND ur.scope_id='*'"
                    : "((ur.scope_type='global' AND ur.scope_id='*') OR (ur.scope_type='asset'"
                    + " AND EXISTS(SELECT 1 FROM asset a WHERE ur.scope_id=CAST(a.id AS CHAR))))";
            return "SELECT EXISTS(" + GuardReadMapper.PERMISSION_ROWS + " AND " + scope + ")";
        }

        private static String visible(String permission, String asset) {
            String rows = GuardReadMapper.PERMISSION_ROWS.replace("#{permission}", "'" + permission + "'");
            return "EXISTS(" + rows + " AND ((ur.scope_type='global' AND ur.scope_id='*')"
                    + (asset == null ? "" : " OR (ur.scope_type='asset' AND ur.scope_id=CAST(" + asset + " AS CHAR))") + "))";
        }

        /** 与现有心跳视图相同：10 秒新鲜度，未知不冒充异常或在线；停用/吊销为 unhealthy。 */
        private static String health(String status, String heartbeat) {
            return "CASE WHEN " + status + " IN ('offline','revoked','suspended','disabled','retired') THEN 'unhealthy'"
                    + " WHEN " + heartbeat + " IS NULL OR " + heartbeat + ">#{now} THEN 'unknown'"
                    + " WHEN " + heartbeat + "<DATE_SUB(#{now},INTERVAL 10 SECOND) THEN 'stale'"
                    + " WHEN " + status + "='active' THEN 'healthy' ELSE 'unknown' END";
        }

        private static String deviceRows() {
            return "SELECT r.public_id,a.public_id asset_public_id,r.created_at,'sensor' device_type,"
                    + "r.last_heartbeat_at heartbeat_at," + health("r.status", "r.last_heartbeat_at") + " health_state"
                    + " FROM sensor_agent r JOIN asset a ON a.id=r.asset_id WHERE " + visible("ops.read", "r.asset_id")
                    + " UNION ALL SELECT r.public_id,a.public_id asset_public_id,r.created_at,'executor' device_type,"
                    + "r.last_heartbeat heartbeat_at," + health("r.status", "r.last_heartbeat") + " health_state"
                    + " FROM guard_executor r JOIN asset a ON a.id=r.asset_id WHERE " + visible("ops.read", "r.asset_id");
        }

        private static String todoRows(TodoKind kind) {
            if (kind == TodoKind.DEVICE) return "SELECT d.public_id,d.asset_public_id,d.created_at,"
                    + "d.device_type detail FROM (" + deviceRows() + ") d WHERE d.health_state IN ('stale','unhealthy')";
            String source = switch (kind) {
                case AUTHORIZATION, EXPIRING_AUTHORIZATION -> "asset_authorization r JOIN asset a ON a.id=r.asset_id";
                case SENSOR_CONFIG -> "sensor_config r JOIN sensor_agent s ON s.id=r.sensor_id JOIN asset a ON a.id=s.asset_id";
                case ACTION -> "guard_action r JOIN asset a ON a.id=r.asset_id";
                case LAB -> "guard_validation_session r JOIN guard_lab_run lr ON lr.session_id=r.id JOIN asset a ON a.id=r.asset_id";
                case POLICY -> "guard_decision_policy r";
                case BUNDLE_APPROVAL, BUNDLE_SEALING -> "guard_release_bundle r";
                case FEEDBACK -> "guard_feedback r JOIN asset a ON a.id=r.asset_id";
                case EVENT -> "security_event r JOIN asset a ON a.id=r.guard_asset_id";
                case MODEL -> "guard_model r";
                default -> throw new IllegalArgumentException("待办类型不支持");
            };
            String condition = switch (kind) {
                case AUTHORIZATION -> "r.status='pending' AND r.requested_by<>#{actor}";
                case SENSOR_CONFIG -> "r.status IN ('draft','pending') AND r.requested_by<>#{actor}";
                case ACTION -> "r.mode='manual' AND r.desired_state='active' AND r.observed_state='pending'"
                        + " AND r.approved_by IS NULL AND r.created_by<>#{actor} AND r.block_until>#{now}";
                case LAB -> "r.status='pending' AND r.requested_by<>#{actor} AND r.valid_until>#{now}";
                case POLICY -> "r.status='draft' AND r.created_by<>#{actor}";
                case BUNDLE_APPROVAL -> "((r.status='evaluated' AND r.requested_by<>#{actor}) OR r.status='approved')";
                case FEEDBACK -> "r.status='pending' AND r.created_by<>#{actor}";
                case EVENT -> "r.status IN ('open','investigating') AND (r.assignee_id IS NULL OR r.assignee_id=#{actor})";
                case MODEL -> "r.validation_status='pending'";
                case BUNDLE_SEALING -> "r.status='candidate' AND r.requested_by=#{actor}";
                case EXPIRING_AUTHORIZATION -> "r.status='active' AND r.valid_from<=#{now} AND r.valid_until>#{now}"
                        + " AND r.valid_until<=DATE_ADD(#{now},INTERVAL 7 DAY)";
                default -> throw new IllegalArgumentException("待办类型不支持");
            };
            String detail = switch (kind) {
                case SENSOR_CONFIG -> "s.public_id";
                case EVENT -> "r.title";
                case BUNDLE_APPROVAL -> "r.status";
                default -> "NULL";
            };
            return "SELECT r.public_id," + (kind.global ? "NULL" : "a.public_id") + " asset_public_id,"
                    + "r.created_at," + detail + " detail FROM " + source + " WHERE " + condition
                    + " AND " + visible(kind.permission, kind.global ? null : "a.id");
        }

        public static String todoCount(Map<String, Object> p) {
            return "SELECT COUNT(*) FROM (" + todoRows((TodoKind) p.get("kind")) + ") todos";
        }

        public static String todoItems(Map<String, Object> p) {
            return todoRows((TodoKind) p.get("kind")) + " ORDER BY created_at DESC,public_id DESC LIMIT #{limit}";
        }

    }
}
