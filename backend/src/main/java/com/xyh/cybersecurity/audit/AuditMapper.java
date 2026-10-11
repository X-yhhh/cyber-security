package com.xyh.cybersecurity.audit;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Options;

import java.time.LocalDateTime;
import java.util.List;

/** 只读审计查询会隐藏无范围记录并要求所有关联范围均可见。 */
@Mapper
public interface AuditMapper {

    /**
     * 追加一条已脱敏审计事实。返回值是影响行数；数据库生成的编号会回填到
     * {@link AuditInsert#getId()}，调用方必须使用该编号在同一事务内写入范围行。
     */
    int insertAudit(AuditInsert audit);
    /** 同一事务内批量追加审计，逐行回填主键后绑定资源范围，不合并独立审计事件。 */
    @Insert("""
        <script>INSERT INTO audit_log (occurred_at,actor_type,actor_id,action,resource_type,resource_id,request_id,outcome,reason) VALUES
        <foreach collection="rows" item="r" separator=",">(#{r.occurredAt},#{r.actorType},#{r.actorId},#{r.action},#{r.resourceType},#{r.resourceId},#{r.requestId},#{r.outcome},#{r.reason})</foreach></script>
        """)
    @Options(useGeneratedKeys=true,keyProperty="rows.id")
    int insertAudits(@Param("rows") List<AuditInsert> rows);

    /** 批量绑定已生成的审计主键与资产，严格新增，避免丢失范围导致审计不可见。 */
    @Insert("""
        <script>INSERT INTO audit_resource_scope (audit_id,scope_type,scope_id) VALUES
        <foreach collection="rows" item="r" separator=",">(#{r.auditId},'asset',#{r.assetId})</foreach></script>
        """)
    int insertAssetScopes(@Param("rows") List<java.util.Map<String,Object>> rows);

    int insertResourceScope(@Param("auditId") long auditId, @Param("scopeType") String scopeType,
                            @Param("scopeId") String scopeId);

    int insertEventAssetScopes(@Param("auditId") long auditId, @Param("eventId") long eventId);

    int insertEventAlertAssetScopes(@Param("auditId") long auditId, @Param("eventId") long eventId);

    int insertEventAlertSourceScopes(@Param("auditId") long auditId, @Param("eventId") long eventId);

    long countVisible(@Param("userId") long userId);

    List<AuditView> listVisible(@Param("userId") long userId,
                                @Param("offset") int offset,
                                @Param("limit") int limit);

    record AuditView(long id, LocalDateTime occurredAt, String actorType, String action,
                     String resourceType, String resourceId, String requestId, String outcome) { }

    /** 审计写入参数；reason 只允许稳定的脱敏摘要，不放入请求载荷或凭据。 */
    final class AuditInsert {
        private long id;
        private final LocalDateTime occurredAt;
        private final String actorType;
        private final String actorId;
        private final String action;
        private final String resourceType;
        private final String resourceId;
        private final String requestId;
        private final String outcome;
        private final String reason;

        public AuditInsert(LocalDateTime occurredAt, String actorType, String actorId, String action,
                           String resourceType, String resourceId, String requestId,
                           String outcome, String reason) {
            this.occurredAt = occurredAt;
            this.actorType = actorType;
            this.actorId = actorId;
            this.action = action;
            this.resourceType = resourceType;
            this.resourceId = resourceId;
            this.requestId = requestId;
            this.outcome = outcome;
            this.reason = reason;
        }

        public long getId() { return id; }
        public void setId(long id) { this.id = id; }
        public LocalDateTime getOccurredAt() { return occurredAt; }
        public String getActorType() { return actorType; }
        public String getActorId() { return actorId; }
        public String getAction() { return action; }
        public String getResourceType() { return resourceType; }
        public String getResourceId() { return resourceId; }
        public String getRequestId() { return requestId; }
        public String getOutcome() { return outcome; }
        public String getReason() { return reason; }
    }
}
