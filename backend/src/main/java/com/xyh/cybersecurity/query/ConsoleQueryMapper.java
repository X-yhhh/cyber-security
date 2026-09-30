package com.xyh.cybersecurity.query;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;

/**
 * 控制台只读查询的 MyBatis 边界。范围条件和分页均在 SQL 内执行，
 * 这里不暴露表名、列名或可拼接的排序参数。
 */
@Mapper
public interface ConsoleQueryMapper {

    List<SensorRow> sensors(@Param("userId") long userId);

    List<AuthorizationRow> authorizations(@Param("userId") long userId, @Param("assetId") long assetId);

    List<IngestSummaryRow> ingestSummary(@Param("userId") long userId);


    List<LedgerRow> ledger(@Param("userId") long userId, @Param("permission") String permission,
                          @Param("mine") boolean mine);

    List<ReleaseRow> releases(@Param("userId") long userId, @Param("modelId") long modelId);

    List<DeploymentRow> deployments(@Param("userId") long userId);

    List<DriftRow> drift(@Param("userId") long userId);

    List<FeedbackRow> feedback(@Param("userId") long userId);

    List<TrainingJobRow> trainingJobs(@Param("userId") long userId);

    List<ReplayScenarioRow> replayScenarios();

    List<HourCountRow> hourlyAlerts(@Param("userId") long userId);

    QualityRow quality24h(@Param("userId") long userId);

    int countUsers(@Param("userId") long userId);

    List<RoleBindingRow> roleBindings(@Param("userId") long userId);

    record SensorRow(long id, String agentKey, long assetId, String assetKey, String platform,
                     String agentVersion, String status, LocalDateTime lastHeartbeatAt,
                     String configVersion, Integer flowWindowSeconds, LocalDateTime healthWindowEnd,
                     Long flowsSeen, Long flowsEmitted, Long flowsDropped, Long queueDepthMax) { }

    record AuthorizationRow(long id, long assetId, String authorizationRef, String status,
                            LocalDateTime validFrom, LocalDateTime validUntil, String requestedBy,
                            String approvedBy, LocalDateTime createdAt) { }

    record IngestSummaryRow(long dataSourceId, long batches, long accepted, long rejected,
                            LocalDateTime lastBatchAt, String mappingVersion, String mappingStatus) { }

    record LedgerRow(long id, long eventId, String eventKey, long assetId, String assetKey,
                     String snapshot, String status, String requester, String reviewer,
                     String decisionReason, LocalDateTime expiresAt, LocalDateTime createdAt,
                     LocalDateTime reviewedAt, String executionStatus) { }

    record ReleaseRow(long id, String releaseStatus, String reviewStatus, String requester,
                      String approver, String requestReason, String decisionReason,
                      LocalDateTime reviewedAt, LocalDateTime createdAt) { }

    record DeploymentRow(long id, String environment, String mode, long modelVersionId,
                         String modelKey, String version, String runtimeType, String status,
                         LocalDateTime activatedAt) { }

    record DriftRow(long id, long dataSourceId, String modelKey, String version,
                    LocalDateTime windowStart, LocalDateTime windowEnd, String features,
                    String scores, BigDecimal qualityRejectRate, String driftStatus) { }

    record FeedbackRow(long id, Long alertId, String alertKey, String label, String labelSource,
                       String reviewer, LocalDateTime reviewedAt, String datasetVersion,
                       boolean trainingEligible) { }

    record TrainingJobRow(long id, String jobKey, String datasetVersion, String sampleManifestRef,
                          String trainHostRef, String status, String requester, LocalDateTime startedAt,
                          LocalDateTime finishedAt, String resultManifestRef, String failureReason) { }

    record ReplayScenarioRow(long id, String scenarioKey, String name, String datasetRef,
                             String environment, String safetyProfile, String status,
                             String lastRunKey, String lastRunStatus, BigDecimal lastRunSpeed,
                             BigDecimal lastRunProgress, LocalDateTime lastRunStartedAt,
                             LocalDateTime lastRunFinishedAt, String lastRunSummary) { }

    record HourCountRow(String hour, long count) { }

    record QualityRow(long accepted, long manualReview, long rejected) { }

    record RoleBindingRow(String roleKey, String roleName, String scopeType, String scopeId) { }
}
