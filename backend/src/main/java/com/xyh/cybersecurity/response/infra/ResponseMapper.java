package com.xyh.cybersecurity.response.infra;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;

/**
 * 响应台账的 MyBatis 映射。所有资源范围、状态和有效期条件必须在 SQL 内复核，
 * 写入方法只暴露受控字段，不接受任意 SQL、URL 或命令。
 */
@Mapper
public interface ResponseMapper {
    int withdraw(@Param("id") long id, @Param("actor") long actor, @Param("reason") String reason);


    ApprovalRow findByIdempotency(@Param("userId") long userId, @Param("key") String key);

    ApprovalRow findApproval(@Param("id") long id);

    long countPendingApprovals(@Param("userId") long userId);

    List<ApprovalRow> listPendingApprovals(@Param("userId") long userId,
                                           @Param("offset") int offset,
                                           @Param("limit") int limit);

    PolicyRow findPolicy(@Param("policyId") long policyId);

    PolicyRow findPolicyForUpdate(@Param("policyId") long policyId);

    AssetRow findAsset(@Param("assetId") long assetId);

    AssetRow findAssetForUpdate(@Param("assetId") long assetId);

    AuthorizationRow findCurrentAuthorization(@Param("assetId") long assetId,
                                              @Param("actionType") String actionType);

    boolean eventContainsAsset(@Param("eventId") long eventId, @Param("assetId") long assetId);

    boolean eventContainsAssetForUpdate(@Param("eventId") long eventId, @Param("assetId") long assetId);

    String eventStatus(@Param("eventId") long eventId);

    String eventStatusForUpdate(@Param("eventId") long eventId);

    boolean hasAssetPermission(@Param("userId") long userId, @Param("permission") String permission,
                               @Param("assetId") long assetId);

    List<Long> lockScopedRoleIds(@Param("userId") long userId, @Param("assetId") long assetId);

    int insertApproval(ApprovalInsert approval);

    int updateApproval(@Param("id") long id, @Param("status") String status,
                       @Param("reviewedBy") long reviewedBy, @Param("reason") String reason,
                       @Param("actorId") long actorId, @Param("assetId") long assetId,
                       @Param("actionType") String actionType, @Param("policyId") long policyId,
                       @Param("eventId") long eventId);

    /** 返回影响行数；自增编号由 MyBatis 回填到 {@link AuditInsert#getId()}。 */
    int insertAudit(AuditInsert audit);

    int insertAuditResourceScope(@Param("auditId") long auditId, @Param("assetId") long assetId);

    int insertTimeline(@Param("eventId") long eventId, @Param("actorId") long actorId,
                       @Param("entryType") String entryType, @Param("taskId") long taskId,
                       @Param("summary") String summary);

    record ApprovalRow(long id, long eventId, long assetId, String actionRequestJson, String status,
                       long requestedBy, Long reviewedBy, LocalDateTime expiresAt,
                       LocalDateTime createdAt, String requestDigest) { }

    record PolicyRow(long id, String policyKey, String version, String environment,
                     String matchJson, String actionType, String actionParamsJson,
                     BigDecimal riskLimit, Boolean autoExecute, Boolean approvalRequired,
                     int maxDurationSeconds, String status, Long approvedBy) { }

    record AssetRow(long id, String environment) { }

    record AuthorizationRow(String scopeJson, LocalDateTime validFrom, LocalDateTime validUntil) { }

    /** 新建审批任务的参数对象；id 由数据库自增回填。 */
    final class ApprovalInsert {
        private long id;
        private final String taskKey;
        private final long eventId;
        private final long policyId;
        private final String snapshot;
        private final long requestedBy;
        private final String idempotencyKey;
        private final String requestDigest;
        private final LocalDateTime expiresAt;

        public ApprovalInsert(String taskKey, long eventId, long policyId, String snapshot,
                              long requestedBy, String idempotencyKey, String requestDigest,
                              LocalDateTime expiresAt) {
            this.taskKey = taskKey;
            this.eventId = eventId;
            this.policyId = policyId;
            this.snapshot = snapshot;
            this.requestedBy = requestedBy;
            this.idempotencyKey = idempotencyKey;
            this.requestDigest = requestDigest;
            this.expiresAt = expiresAt;
        }

        public long getId() { return id; }
        public void setId(long id) { this.id = id; }
        public String getTaskKey() { return taskKey; }
        public long getEventId() { return eventId; }
        public long getPolicyId() { return policyId; }
        public String getSnapshot() { return snapshot; }
        public long getRequestedBy() { return requestedBy; }
        public String getIdempotencyKey() { return idempotencyKey; }
        public String getRequestDigest() { return requestDigest; }
        public LocalDateTime getExpiresAt() { return expiresAt; }
    }

    /** 追加式审计写入参数；原因必须是已脱敏摘要。 */
    final class AuditInsert {
        private long id;
        private final LocalDateTime occurredAt;
        private final String actorId;
        private final String action;
        private final long approvalId;
        private final String requestId;
        private final String reason;

        public AuditInsert(LocalDateTime occurredAt, String actorId, String action, long approvalId,
                           String requestId, String reason) {
            this.occurredAt = occurredAt;
            this.actorId = actorId;
            this.action = action;
            this.approvalId = approvalId;
            this.requestId = requestId;
            this.reason = reason;
        }

        public long getId() { return id; }
        public void setId(long id) { this.id = id; }
        public LocalDateTime getOccurredAt() { return occurredAt; }
        public String getActorId() { return actorId; }
        public String getAction() { return action; }
        public long getApprovalId() { return approvalId; }
        public String getRequestId() { return requestId; }
        public String getReason() { return reason; }
    }
}
