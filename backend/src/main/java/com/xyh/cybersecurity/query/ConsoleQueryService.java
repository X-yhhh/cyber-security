package com.xyh.cybersecurity.query;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.xyh.cybersecurity.common.api.ApiRequestException;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
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

    private final ConsoleQueryMapper mapper;
    private final ObjectMapper objectMapper;

    public ConsoleQueryService(ConsoleQueryMapper mapper, ObjectMapper objectMapper) {
        this.mapper = mapper;
        this.objectMapper = objectMapper;
    }

    public List<SensorView> sensors(long userId) {
        return mapper.sensors(userId).stream().map(row -> new SensorView(row.id(), row.agentKey(), row.assetId(),
                row.assetKey(), row.platform(), row.agentVersion(), row.status(), row.lastHeartbeatAt(),
                row.configVersion(), row.flowWindowSeconds(), row.healthWindowEnd(), row.flowsSeen(),
                row.flowsEmitted(), row.flowsDropped(), row.queueDepthMax())).toList();
    }

    public List<AuthorizationView> authorizations(long userId, long assetId) {
        return mapper.authorizations(userId, assetId).stream()
                .map(row -> new AuthorizationView(row.id(), row.assetId(), row.authorizationRef(),
                        effectiveStatus(row.status(), row.validUntil()), row.validFrom(), row.validUntil(),
                        row.requestedBy(), row.approvedBy(), row.createdAt(), row.revokedBy(), row.revokedAt(),
                        row.revokeReason()))
                .toList();
    }

    /** active 但已过 valid_until 的授权按 expired 呈现，避免把过期授权显示为有效。 */
    private static String effectiveStatus(String status, LocalDateTime until) {
        if ("active".equals(status) && until != null && until.isBefore(LocalDateTime.now(java.time.ZoneOffset.UTC))) {
            return "expired";
        }
        return status;
    }

    public List<IngestSummary> ingestSummary(long userId) {
        return mapper.ingestSummary(userId).stream()
                .map(row -> new IngestSummary(row.dataSourceId(), row.batches(), row.accepted(), row.rejected(),
                        row.lastBatchAt(), row.mappingVersion(), row.mappingStatus())).toList();
    }

    /**
     * 审批/申请台账。mine=true 时只列本人申请；否则列 permission 资产范围内全部状态的审批。
     * 执行状态取该审批最新的 action_execution；执行器未开放时为 null。
     */
    public List<LedgerView> ledger(long userId, String permission, boolean mine) {
        return mapper.ledger(userId, permission, mine).stream()
                .map(row -> new LedgerView(row.id(), row.eventId(), row.eventKey(), row.assetId(), row.assetKey(),
                        json(row.snapshot()), row.status(), row.requester(), row.reviewer(), row.decisionReason(),
                        row.expiresAt(), row.createdAt(), row.reviewedAt(), row.executionStatus(),
                        row.withdrawReason(), row.withdrawnAt())).toList();
    }

    public List<ReleaseView> releases(long userId, long modelId) {
        return mapper.releases(userId, modelId).stream()
                .map(row -> new ReleaseView(row.id(), row.releaseStatus(), row.reviewStatus(), row.requester(),
                        row.approver(), row.requestReason(), row.decisionReason(), row.reviewedAt(), row.createdAt())).toList();
    }

    public List<DeploymentView> deployments(long userId) {
        return mapper.deployments(userId).stream()
                .map(row -> new DeploymentView(row.id(), row.environment(), row.mode(), row.modelVersionId(),
                        row.modelKey(), row.version(), row.runtimeType(), row.status(), row.activatedAt())).toList();
    }

    public List<DriftView> drift(long userId) {
        return mapper.drift(userId).stream()
                .map(row -> new DriftView(row.id(), row.dataSourceId(), row.modelKey(), row.version(), row.windowStart(),
                        row.windowEnd(), json(row.features()), json(row.scores()), row.qualityRejectRate(), row.driftStatus())).toList();
    }

    /** 反馈样本与训练任务属于模型治理台账，仅按 model.validation.read 功能权限开放，不含原始载荷。 */
    public List<FeedbackView> feedback(long userId) {
        return mapper.feedback(userId).stream()
                .map(row -> new FeedbackView(row.id(), row.alertId(), row.alertKey(), row.label(), row.labelSource(),
                        row.reviewer(), row.reviewedAt(), row.datasetVersion(), row.trainingEligible())).toList();
    }

    public List<TrainingJobView> trainingJobs(long userId) {
        return mapper.trainingJobs(userId).stream()
                .map(row -> new TrainingJobView(row.id(), row.jobKey(), row.datasetVersion(), row.sampleManifestRef(),
                        row.trainHostRef(), row.status(), row.requester(), row.startedAt(), row.finishedAt(),
                        row.resultManifestRef(), row.failureReason())).toList();
    }

    public List<ReplayScenarioView> replayScenarios() {
        return mapper.replayScenarios().stream()
                .map(row -> new ReplayScenarioView(row.id(), row.scenarioKey(), row.name(), row.datasetRef(),
                        row.environment(), row.safetyProfile(), row.status(), row.lastRunKey(), row.lastRunStatus(),
                        row.lastRunSpeed(), row.lastRunProgress(), row.lastRunStartedAt(), row.lastRunFinishedAt(),
                        json(row.lastRunSummary()))).toList();
    }

    /**
     * 态势汇总：近 24 小时按小时的可见告警数、质量门禁统计与活动模型。
     * 告警可见性沿用告警列表的“资产 + 数据源”双范围；没有 alert.read 的用户得到空序列。
     */
    public OverviewView overview(long userId, boolean canReadAlerts) {
        List<HourCount> hourly = !canReadAlerts ? List.of() : mapper.hourlyAlerts(userId).stream()
                .map(row -> new HourCount(row.hour(), row.count())).toList();
        ConsoleQueryMapper.QualityRow qualityRow = mapper.quality24h(userId);
        QualityView quality = qualityRow == null ? new QualityView(0, 0, 0)
                : new QualityView(qualityRow.accepted(), qualityRow.manualReview(), qualityRow.rejected());
        return new OverviewView(hourly, quality);
    }

    public List<RoleBindingView> roleBindings(long userId) {
        if (mapper.countUsers(userId) == 0) throw ApiRequestException.notFound();
        return mapper.roleBindings(userId).stream()
                .map(row -> new RoleBindingView(row.roleKey(), row.roleName(), row.scopeType(), row.scopeId())).toList();
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
                                    String approvedBy, LocalDateTime createdAt, String revokedBy,
                                    LocalDateTime revokedAt, String revokeReason) { }
    public record IngestSummary(long dataSourceId, long batches, long accepted, long rejected,
                                LocalDateTime lastBatchAt, String mappingVersion, String mappingStatus) { }
    public record LedgerView(long id, long eventId, String eventKey, long assetId, String assetKey,
                             JsonNode actionRequest, String status, String requester, String reviewer,
                             String decisionReason, LocalDateTime expiresAt, LocalDateTime createdAt,
                             LocalDateTime reviewedAt, String executionStatus, String withdrawReason,
                             LocalDateTime withdrawnAt) { }
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
