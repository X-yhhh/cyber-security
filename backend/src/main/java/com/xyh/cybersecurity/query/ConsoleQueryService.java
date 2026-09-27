package com.xyh.cybersecurity.query;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.xyh.cybersecurity.common.api.ApiRequestException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.List;

/**
 * 控制台只读查询服务。
 * 每个查询都在 SQL 内按“功能权限 + 资源范围”复核：platform_admin 仅在 global:* 绑定时全局可见，
 * 其他角色必须持有对应 asset / data_source / model_registry 范围绑定。结果只包含引用与状态，
 * 不返回凭据、授权证明原文或原始载荷；查询失败按统一错误处理脱敏返回。
 */
@Service
public class ConsoleQueryService {

    private static final int LIMIT = 200;
    private final JdbcTemplate jdbc;
    private final ObjectMapper objectMapper;

    public ConsoleQueryService(JdbcTemplate jdbc, ObjectMapper objectMapper) {
        this.jdbc = jdbc;
        this.objectMapper = objectMapper;
    }

    /** 生成范围谓词；permission 与 scopeType 仅来自本类常量，参数只绑定 userId。 */
    private static String scoped(String permission, String scopeType, String expression, boolean globalAdmin) {
        return "EXISTS (SELECT 1 FROM sys_user su JOIN sys_user_role ur ON ur.user_id=su.id "
                + "JOIN sys_role r ON r.id=ur.role_id AND r.status='active' "
                + "JOIN sys_role_permission rp ON rp.role_id=r.id "
                + "JOIN sys_permission p ON p.id=rp.permission_id AND p.status='active' "
                + "WHERE su.id=? AND su.status='active' AND p.permission_key='" + permission + "' AND ("
                + "(ur.scope_type='" + scopeType + "' AND ur.scope_id=CAST(" + expression + " AS CHAR))"
                + (globalAdmin ? " OR (r.role_key='platform_admin' AND ur.scope_type='global' AND ur.scope_id='*')" : "")
                + "))";
    }

    public List<SensorView> sensors(long userId) {
        return jdbc.query("SELECT sa.id,sa.agent_key,sa.asset_id,a.asset_key,sa.platform,sa.agent_version,sa.status,"
                        + "sa.last_heartbeat_at,h.window_end,h.flows_seen,h.flows_emitted,h.flows_dropped,h.queue_depth_max,"
                        + "(SELECT sc.config_version FROM sensor_config sc WHERE sc.sensor_id=sa.id AND sc.status='active' "
                        + " ORDER BY sc.activated_at DESC LIMIT 1) config_version,"
                        + "(SELECT sc.flow_window_seconds FROM sensor_config sc WHERE sc.sensor_id=sa.id AND sc.status='active' "
                        + " ORDER BY sc.activated_at DESC LIMIT 1) flow_window_seconds "
                        + "FROM sensor_agent sa JOIN asset a ON a.id=sa.asset_id "
                        + "LEFT JOIN sensor_health_window h ON h.id=(SELECT h2.id FROM sensor_health_window h2 "
                        + " WHERE h2.sensor_id=sa.id ORDER BY h2.window_end DESC LIMIT 1) "
                        + "WHERE " + scoped("sensor.read", "asset", "sa.asset_id", true)
                        + " ORDER BY sa.id LIMIT " + LIMIT,
                (rs, n) -> new SensorView(rs.getLong("id"), rs.getString("agent_key"), rs.getLong("asset_id"),
                        rs.getString("asset_key"), rs.getString("platform"), rs.getString("agent_version"),
                        rs.getString("status"), time(rs, "last_heartbeat_at"), rs.getString("config_version"),
                        (Integer) rs.getObject("flow_window_seconds", Integer.class), time(rs, "window_end"),
                        rs.getObject("flows_seen", Long.class), rs.getObject("flows_emitted", Long.class),
                        rs.getObject("flows_dropped", Long.class), rs.getObject("queue_depth_max", Long.class)),
                userId);
    }

    public List<AuthorizationView> authorizations(long userId, long assetId) {
        return jdbc.query("SELECT aa.id,aa.asset_id,aa.authorization_ref,aa.status,aa.valid_from,aa.valid_until,"
                        + "rq.username requested_by,ap.username approved_by,aa.created_at "
                        + "FROM asset_authorization aa LEFT JOIN sys_user rq ON rq.id=aa.requested_by "
                        + "LEFT JOIN sys_user ap ON ap.id=aa.approved_by WHERE aa.asset_id=? AND "
                        + scoped("asset.authorization.read", "asset", "aa.asset_id", true)
                        + " ORDER BY aa.valid_until DESC,aa.id DESC LIMIT " + LIMIT,
                (rs, n) -> new AuthorizationView(rs.getLong("id"), rs.getLong("asset_id"),
                        rs.getString("authorization_ref"), effectiveStatus(rs), time(rs, "valid_from"),
                        time(rs, "valid_until"), rs.getString("requested_by"), rs.getString("approved_by"),
                        time(rs, "created_at")),
                assetId, userId);
    }

    /** active 但已过 valid_until 的授权按 expired 呈现，避免把过期授权显示为有效。 */
    private static String effectiveStatus(ResultSet rs) throws SQLException {
        String status = rs.getString("status");
        Timestamp until = rs.getTimestamp("valid_until");
        if ("active".equals(status) && until != null && until.toLocalDateTime().isBefore(LocalDateTime.now(java.time.ZoneOffset.UTC))) {
            return "expired";
        }
        return status;
    }

    public List<IngestSummary> ingestSummary(long userId) {
        return jdbc.query("SELECT ds.id,COUNT(ib.id) batches,COALESCE(SUM(ib.accepted_count),0) accepted,"
                        + "COALESCE(SUM(ib.rejected_count),0) rejected,MAX(ib.created_at) last_batch_at,"
                        + "(SELECT sm.mapping_version FROM source_mapping sm WHERE sm.data_source_id=ds.id "
                        + " ORDER BY sm.id DESC LIMIT 1) mapping_version,"
                        + "(SELECT sm.status FROM source_mapping sm WHERE sm.data_source_id=ds.id "
                        + " ORDER BY sm.id DESC LIMIT 1) mapping_status "
                        + "FROM data_source ds LEFT JOIN ingest_batch ib ON ib.data_source_id=ds.id WHERE "
                        + scoped("ingest.batch.read", "data_source", "ds.id", true)
                        + " GROUP BY ds.id ORDER BY ds.id LIMIT " + LIMIT,
                (rs, n) -> new IngestSummary(rs.getLong("id"), rs.getLong("batches"), rs.getLong("accepted"),
                        rs.getLong("rejected"), time(rs, "last_batch_at"), rs.getString("mapping_version"),
                        rs.getString("mapping_status")),
                userId);
    }

    public List<PolicyView> policies() {
        return jdbc.query("SELECT id,policy_key,version,environment,action_type,CAST(action_params_json AS CHAR) params,"
                        + "auto_execute,approval_required,max_duration_seconds,status,approved_by IS NOT NULL approved "
                        + "FROM response_policy ORDER BY policy_key,id DESC LIMIT " + LIMIT,
                (rs, n) -> new PolicyView(rs.getLong("id"), rs.getString("policy_key"), rs.getString("version"),
                        rs.getString("environment"), rs.getString("action_type"), json(rs.getString("params")),
                        rs.getBoolean("auto_execute"), rs.getBoolean("approval_required"),
                        rs.getInt("max_duration_seconds"), rs.getString("status"), rs.getBoolean("approved")));
    }

    /**
     * 审批/申请台账。mine=true 时只列本人申请；否则列 permission 资产范围内全部状态的审批。
     * 执行状态取该审批最新的 action_execution；执行器未开放时为 null。
     */
    public List<LedgerView> ledger(long userId, String permission, boolean mine) {
        String sql = "SELECT at.id,at.event_id,e.event_key,req.asset_id,a.asset_key,"
                + "CAST(at.action_request_json AS CHAR) snapshot,at.status,rq.username requester,rv.username reviewer,"
                + "at.decision_reason,at.expires_at,at.created_at,at.reviewed_at,"
                + "(SELECT x.status FROM action_execution x WHERE x.approval_task_id=at.id ORDER BY x.id DESC LIMIT 1) exec_status "
                + "FROM approval_task at "
                + "JOIN JSON_TABLE(at.action_request_json, '$' COLUMNS(asset_id BIGINT PATH '$.assetId')) req "
                + "JOIN asset a ON a.id=req.asset_id JOIN security_event e ON e.id=at.event_id "
                + "JOIN sys_user rq ON rq.id=at.requested_by LEFT JOIN sys_user rv ON rv.id=at.reviewed_by WHERE "
                + (mine ? "at.requested_by=? AND " : "")
                + scoped(permission, "asset", "req.asset_id", true)
                + " ORDER BY at.created_at DESC,at.id DESC LIMIT " + LIMIT;
        Object[] args = mine ? new Object[]{userId, userId} : new Object[]{userId};
        return jdbc.query(sql, (rs, n) -> new LedgerView(rs.getLong("id"), rs.getLong("event_id"),
                rs.getString("event_key"), rs.getLong("asset_id"), rs.getString("asset_key"), json(rs.getString("snapshot")),
                rs.getString("status"), rs.getString("requester"), rs.getString("reviewer"),
                rs.getString("decision_reason"), time(rs, "expires_at"), time(rs, "created_at"),
                time(rs, "reviewed_at"), rs.getString("exec_status")), args);
    }

    public List<ReleaseView> releases(long userId, long modelId) {
        return jdbc.query("SELECT mr.id,mr.release_status,mr.review_status,rq.username requester,ap.username approver,"
                        + "mr.request_reason,mr.decision_reason,mr.reviewed_at,mr.created_at "
                        + "FROM model_release_record mr JOIN model_version mv ON mv.id=mr.model_version_id "
                        + "LEFT JOIN sys_user rq ON rq.id=mr.requested_by LEFT JOIN sys_user ap ON ap.id=mr.approved_by "
                        + "WHERE mv.id=? AND " + scoped("model.validation.read", "model_registry", "mv.model_key", false)
                        + " ORDER BY mr.id DESC LIMIT " + LIMIT,
                (rs, n) -> new ReleaseView(rs.getLong("id"), rs.getString("release_status"),
                        rs.getString("review_status"), rs.getString("requester"), rs.getString("approver"),
                        rs.getString("request_reason"), rs.getString("decision_reason"), time(rs, "reviewed_at"),
                        time(rs, "created_at")),
                modelId, userId);
    }

    public List<DeploymentView> deployments(long userId) {
        return jdbc.query("SELECT md.id,md.environment,md.mode,md.model_version_id,mv.model_key,mv.version,md.runtime_type,"
                        + "md.status,md.activated_at FROM model_deployment md JOIN model_version mv ON mv.id=md.model_version_id "
                        + "WHERE " + scoped("model.validation.read", "model_registry", "mv.model_key", false)
                        + " ORDER BY md.id DESC LIMIT " + LIMIT,
                (rs, n) -> new DeploymentView(rs.getLong("id"), rs.getString("environment"), rs.getString("mode"),
                        rs.getLong("model_version_id"), rs.getString("model_key"), rs.getString("version"),
                        rs.getString("runtime_type"), rs.getString("status"), time(rs, "activated_at")),
                userId);
    }

    public List<DriftView> drift(long userId) {
        return jdbc.query("SELECT dw.id,dw.data_source_id,mv.model_key,mv.version,dw.window_start,dw.window_end,"
                        + "CAST(dw.feature_stats_json AS CHAR) features,CAST(dw.score_stats_json AS CHAR) scores,"
                        + "dw.quality_reject_rate,dw.drift_status FROM drift_metric_window dw "
                        + "JOIN model_version mv ON mv.id=dw.model_version_id WHERE "
                        + scoped("model.validation.read", "model_registry", "mv.model_key", false)
                        + " ORDER BY dw.window_end DESC LIMIT " + LIMIT,
                (rs, n) -> new DriftView(rs.getLong("id"), rs.getLong("data_source_id"), rs.getString("model_key"),
                        rs.getString("version"), time(rs, "window_start"), time(rs, "window_end"),
                        json(rs.getString("features")), json(rs.getString("scores")),
                        rs.getBigDecimal("quality_reject_rate"), rs.getString("drift_status")),
                userId);
    }

    /** 反馈样本与训练任务属于模型治理台账，仅按 model.validation.read 功能权限开放，不含原始载荷。 */
    public List<FeedbackView> feedback(long userId) {
        return jdbc.query("SELECT fs.id,fs.alert_id,da.alert_key,fs.label,fs.label_source,rv.username reviewer,"
                        + "fs.reviewed_at,fs.dataset_version,fs.training_eligible FROM feedback_sample fs "
                        + "LEFT JOIN detection_alert da ON da.id=fs.alert_id LEFT JOIN sys_user rv ON rv.id=fs.reviewed_by "
                        + "ORDER BY fs.id DESC LIMIT " + LIMIT,
                (rs, n) -> new FeedbackView(rs.getLong("id"), rs.getObject("alert_id", Long.class),
                        rs.getString("alert_key"), rs.getString("label"), rs.getString("label_source"),
                        rs.getString("reviewer"), time(rs, "reviewed_at"), rs.getString("dataset_version"),
                        rs.getBoolean("training_eligible")));
    }

    public List<TrainingJobView> trainingJobs(long userId) {
        return jdbc.query("SELECT tj.id,tj.job_key,tj.dataset_version,tj.sample_manifest_ref,tj.train_host_ref,tj.status,"
                        + "rq.username requester,tj.started_at,tj.finished_at,tj.result_manifest_ref,tj.failure_reason "
                        + "FROM model_training_job tj LEFT JOIN sys_user rq ON rq.id=tj.requested_by "
                        + "ORDER BY tj.id DESC LIMIT " + LIMIT,
                (rs, n) -> new TrainingJobView(rs.getLong("id"), rs.getString("job_key"),
                        rs.getString("dataset_version"), rs.getString("sample_manifest_ref"),
                        rs.getString("train_host_ref"), rs.getString("status"), rs.getString("requester"),
                        time(rs, "started_at"), time(rs, "finished_at"), rs.getString("result_manifest_ref"),
                        rs.getString("failure_reason")));
    }

    public List<ReplayScenarioView> replayScenarios() {
        return jdbc.query("SELECT rs.id,rs.scenario_key,rs.name,rs.dataset_ref,rs.environment,rs.safety_profile,rs.status,"
                        + "lr.run_key,lr.status run_status,lr.speed,lr.progress,lr.started_at,lr.finished_at,"
                        + "CAST(lr.summary_json AS CHAR) summary FROM replay_scenario rs "
                        + "LEFT JOIN replay_run lr ON lr.id=(SELECT r2.id FROM replay_run r2 WHERE r2.scenario_id=rs.id "
                        + " ORDER BY r2.id DESC LIMIT 1) ORDER BY rs.id LIMIT " + LIMIT,
                (rs, n) -> new ReplayScenarioView(rs.getLong("id"), rs.getString("scenario_key"), rs.getString("name"),
                        rs.getString("dataset_ref"), rs.getString("environment"), rs.getString("safety_profile"),
                        rs.getString("status"), rs.getString("run_key"), rs.getString("run_status"),
                        rs.getBigDecimal("speed"), rs.getBigDecimal("progress"), time(rs, "started_at"),
                        time(rs, "finished_at"), json(rs.getString("summary"))));
    }

    /**
     * 态势汇总：近 24 小时按小时的可见告警数、质量门禁统计与活动模型。
     * 告警可见性沿用告警列表的“资产 + 数据源”双范围；没有 alert.read 的用户得到空序列。
     */
    public OverviewView overview(long userId, boolean canReadAlerts) {
        List<HourCount> hourly = !canReadAlerts ? List.of() : jdbc.query(
                "SELECT DATE_FORMAT(da.detected_at,'%Y-%m-%dT%H:00:00') h,COUNT(*) c FROM detection_alert da "
                        + "JOIN ingest_record ir ON ir.id=da.ingest_record_id JOIN ingest_batch ib ON ib.id=ir.batch_id "
                        + "WHERE da.detected_at>=UTC_TIMESTAMP(3)-INTERVAL 24 HOUR AND ir.asset_id IS NOT NULL AND "
                        + scoped("asset.read", "asset", "ir.asset_id", true) + " AND "
                        + scoped("source.read", "data_source", "ib.data_source_id", true)
                        + " GROUP BY h ORDER BY h",
                (rs, n) -> new HourCount(rs.getString("h"), rs.getLong("c")), userId, userId);
        QualityView quality = jdbc.queryForObject("SELECT "
                        + "COALESCE(SUM(quality_status='accepted'),0) a,COALESCE(SUM(quality_status='manual_review'),0) m,"
                        + "COALESCE(SUM(quality_status='rejected'),0) r FROM ingest_record ir "
                        + "WHERE ir.created_at>=UTC_TIMESTAMP(3)-INTERVAL 24 HOUR AND ir.asset_id IS NOT NULL AND "
                        + scoped("asset.read", "asset", "ir.asset_id", true),
                (rs, n) -> new QualityView(rs.getLong("a"), rs.getLong("m"), rs.getLong("r")), userId);
        return new OverviewView(hourly, quality);
    }

    public List<RoleBindingView> roleBindings(long userId) {
        Integer exists = jdbc.queryForObject("SELECT COUNT(*) FROM sys_user WHERE id=?", Integer.class, userId);
        if (exists == null || exists == 0) throw ApiRequestException.notFound();
        return jdbc.query("SELECT r.role_key,r.name,ur.scope_type,ur.scope_id FROM sys_user_role ur "
                        + "JOIN sys_role r ON r.id=ur.role_id WHERE ur.user_id=? ORDER BY r.role_key,ur.scope_type,ur.scope_id",
                (rs, n) -> new RoleBindingView(rs.getString("role_key"), rs.getString("name"),
                        rs.getString("scope_type"), rs.getString("scope_id")),
                userId);
    }

    private static LocalDateTime time(ResultSet rs, String column) throws SQLException {
        Timestamp value = rs.getTimestamp(column);
        return value == null ? null : value.toLocalDateTime();
    }

    private JsonNode json(String value) {
        if (value == null) return null;
        try {
            return objectMapper.readTree(value);
        } catch (Exception exception) {
            throw new IllegalStateException("Stored JSON is invalid", exception);
        }
    }

    public record SensorView(long id, String agentKey, long assetId, String assetKey, String platform,
                             String agentVersion, String status, LocalDateTime lastHeartbeatAt, String configVersion,
                             Integer flowWindowSeconds, LocalDateTime healthWindowEnd, Long flowsSeen,
                             Long flowsEmitted, Long flowsDropped, Long queueDepthMax) { }
    public record AuthorizationView(long id, long assetId, String authorizationRef, String status,
                                    LocalDateTime validFrom, LocalDateTime validUntil, String requestedBy,
                                    String approvedBy, LocalDateTime createdAt) { }
    public record IngestSummary(long dataSourceId, long batches, long accepted, long rejected,
                                LocalDateTime lastBatchAt, String mappingVersion, String mappingStatus) { }
    public record PolicyView(long id, String policyKey, String version, String environment, String actionType,
                             JsonNode actionParams, boolean autoExecute, boolean approvalRequired,
                             int maxDurationSeconds, String status, boolean approved) { }
    public record LedgerView(long id, long eventId, String eventKey, long assetId, String assetKey,
                             JsonNode actionRequest, String status, String requester, String reviewer,
                             String decisionReason, LocalDateTime expiresAt, LocalDateTime createdAt,
                             LocalDateTime reviewedAt, String executionStatus) { }
    public record ReleaseView(long id, String releaseStatus, String reviewStatus, String requester, String approver,
                              String requestReason, String decisionReason, LocalDateTime reviewedAt,
                              LocalDateTime createdAt) { }
    public record DeploymentView(long id, String environment, String mode, long modelVersionId, String modelKey,
                                 String version, String runtimeType, String status, LocalDateTime activatedAt) { }
    public record DriftView(long id, long dataSourceId, String modelKey, String version, LocalDateTime windowStart,
                            LocalDateTime windowEnd, JsonNode featureStats, JsonNode scoreStats,
                            BigDecimal qualityRejectRate, String driftStatus) { }
    public record FeedbackView(long id, Long alertId, String alertKey, String label, String labelSource,
                               String reviewer, LocalDateTime reviewedAt, String datasetVersion,
                               boolean trainingEligible) { }
    public record TrainingJobView(long id, String jobKey, String datasetVersion, String sampleManifestRef,
                                  String trainHostRef, String status, String requester, LocalDateTime startedAt,
                                  LocalDateTime finishedAt, String resultManifestRef, String failureReason) { }
    public record ReplayScenarioView(long id, String scenarioKey, String name, String datasetRef, String environment,
                                     String safetyProfile, String status, String lastRunKey, String lastRunStatus,
                                     BigDecimal lastRunSpeed, BigDecimal lastRunProgress, LocalDateTime lastRunStartedAt,
                                     LocalDateTime lastRunFinishedAt, JsonNode lastRunSummary) { }
    public record HourCount(String hour, long count) { }
    public record QualityView(long accepted, long manualReview, long rejected) { }
    public record OverviewView(List<HourCount> hourlyAlerts, QualityView quality24h) { }
    public record RoleBindingView(String roleKey, String roleName, String scopeType, String scopeId) { }
}
