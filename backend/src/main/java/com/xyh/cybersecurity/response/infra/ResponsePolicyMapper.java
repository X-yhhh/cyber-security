package com.xyh.cybersecurity.response.infra;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;

/**
 * 响应策略版本台账（M6）。版本内容只在插入时写入，之后只更新状态与审批/退役字段；
 * 每个状态更新语句在 SQL 中复核起点状态与参与者，返回 0 行表示并发冲突或条件不再成立。
 */
@Mapper
public interface ResponsePolicyMapper {

    List<PolicyRow> list(@Param("status") String status, @Param("policyKey") String policyKey,
                         @Param("limit") int limit);

    PolicyRow find(@Param("id") long id);

    PolicyRow findForUpdate(@Param("id") long id);

    /** 锁定同一策略键的全部版本行，串行化新版本号分配与 active 切换。 */
    List<PolicyRow> lockKey(@Param("policyKey") String policyKey);

    int insert(PolicyInsert insert);

    int submit(@Param("id") long id, @Param("actorId") long actorId);

    int approve(@Param("id") long id, @Param("actorId") long actorId, @Param("reason") String reason);

    int reject(@Param("id") long id, @Param("actorId") long actorId, @Param("reason") String reason);

    /** 起草人撤回 draft/pending 版本。 */
    int withdraw(@Param("id") long id, @Param("actorId") long actorId);

    /** 退役 active 版本（审批人主动退役，或批准新版本时取代）。 */
    int retireActive(@Param("id") long id, @Param("actorId") long actorId);

    int insertAudit(PolicyAudit audit);

    record PolicyRow(long id, String policyKey, String version, String environment, String matchJson,
                     String actionType, String actionParamsJson, BigDecimal riskLimit, boolean autoExecute,
                     boolean approvalRequired, int maxDurationSeconds, String status, Long createdBy,
                     Long basedOnPolicyId, String changeReason, String contentSha256, LocalDateTime submittedAt,
                     Long approvedBy, Long reviewedBy, LocalDateTime reviewedAt, String decisionReason,
                     LocalDateTime retiredAt, Long retiredBy, LocalDateTime createdAt) { }

    /** 插入参数；自增编号回填到 {@link #getId()}。状态固定为 draft，不接受调用方指定。 */
    final class PolicyInsert {
        private long id;
        private final String policyKey;
        private final String version;
        private final String environment;
        private final String matchJson;
        private final String actionType;
        private final String actionParamsJson;
        private final BigDecimal riskLimit;
        private final boolean autoExecute;
        private final boolean approvalRequired;
        private final int maxDurationSeconds;
        private final long createdBy;
        private final Long basedOnPolicyId;
        private final String changeReason;
        private final String contentSha256;

        public PolicyInsert(String policyKey, String version, String environment, String matchJson, String actionType,
                            String actionParamsJson, BigDecimal riskLimit, boolean autoExecute, boolean approvalRequired,
                            int maxDurationSeconds, long createdBy, Long basedOnPolicyId, String changeReason,
                            String contentSha256) {
            this.policyKey = policyKey;
            this.version = version;
            this.environment = environment;
            this.matchJson = matchJson;
            this.actionType = actionType;
            this.actionParamsJson = actionParamsJson;
            this.riskLimit = riskLimit;
            this.autoExecute = autoExecute;
            this.approvalRequired = approvalRequired;
            this.maxDurationSeconds = maxDurationSeconds;
            this.createdBy = createdBy;
            this.basedOnPolicyId = basedOnPolicyId;
            this.changeReason = changeReason;
            this.contentSha256 = contentSha256;
        }

        public long getId() { return id; }
        public void setId(long id) { this.id = id; }
        public String getPolicyKey() { return policyKey; }
        public String getVersion() { return version; }
        public String getEnvironment() { return environment; }
        public String getMatchJson() { return matchJson; }
        public String getActionType() { return actionType; }
        public String getActionParamsJson() { return actionParamsJson; }
        public BigDecimal getRiskLimit() { return riskLimit; }
        public boolean isAutoExecute() { return autoExecute; }
        public boolean isApprovalRequired() { return approvalRequired; }
        public int getMaxDurationSeconds() { return maxDurationSeconds; }
        public long getCreatedBy() { return createdBy; }
        public Long getBasedOnPolicyId() { return basedOnPolicyId; }
        public String getChangeReason() { return changeReason; }
        public String getContentSha256() { return contentSha256; }
    }

    /** 策略审计：{@code afterHash} 为迁移后的内容哈希，便于复核审批对象未被替换。 */
    final class PolicyAudit {
        private long id;
        private final LocalDateTime occurredAt;
        private final long actorId;
        private final String action;
        private final long policyId;
        private final String requestId;
        private final String reason;
        private final String afterHash;

        public PolicyAudit(LocalDateTime occurredAt, long actorId, String action, long policyId, String requestId,
                           String reason, String afterHash) {
            this.occurredAt = occurredAt;
            this.actorId = actorId;
            this.action = action;
            this.policyId = policyId;
            this.requestId = requestId;
            this.reason = reason;
            this.afterHash = afterHash;
        }

        public long getId() { return id; }
        public void setId(long id) { this.id = id; }
        public LocalDateTime getOccurredAt() { return occurredAt; }
        public long getActorId() { return actorId; }
        public String getAction() { return action; }
        public long getPolicyId() { return policyId; }
        public String getRequestId() { return requestId; }
        public String getReason() { return reason; }
        public String getAfterHash() { return afterHash; }
    }
}
