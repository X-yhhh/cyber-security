package com.xyh.cybersecurity.detection;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Collection;
import java.util.List;

/** M4 告警生成与事件关联的持久化边界；所有写入都在 M2 消费事务内执行。 */
@Mapper
public interface DetectionMapper {

    /** 指定类型的 active 策略；不存在时为 {@code null}。 */
    PolicyRow findActivePolicy(@Param("type") String type);

    /** 批次内推理成功且模型判为 Attack 的记录（以数据库为准，不依赖推理函数返回值）。 */
    List<ModelCandidate> findModelAlertCandidates(@Param("batchId") long batchId);

    List<String> findExistingAlertKeys(@Param("keys") Collection<String> keys);

    int insertAlert(AlertInsert input);

    Long findAlertId(@Param("alertKey") String alertKey);

    /** 已批准且 active 的规则。 */
    List<RuleRow> findActiveRules();

    String findBatchContract(@Param("batchId") long batchId);

    /**
     * 时间窗规则的上下文：资产在 {@code [from, to]} 内已通过门禁的记录，按 {@code (事件时间, ID)} 排序。
     *
     * @param contract 规则范围声明的契约版本；为 {@code null} 时不按契约过滤
     */
    List<WindowRecord> findAssetWindowRecords(@Param("assetId") long assetId, @Param("from") Instant from,
                                              @Param("to") Instant to, @Param("contract") String contract,
                                              @Param("limit") int limit);

    /** 同一规则在该资产 {@code [from, to]} 内已有告警对应记录的事件时间（用于告警抑制）。 */
    List<Instant> findRuleFiringTimes(@Param("ruleId") long ruleId, @Param("assetId") long assetId,
                                      @Param("from") Instant from, @Param("to") Instant to);

    /** 锁定资产行，使同一资产的事件关联串行执行。 */
    AssetRow lockAsset(@Param("assetId") long assetId);

    /** 关联窗口内未结束的同键事件（加行锁）；没有时为 {@code null}。 */
    Long findOpenCorrelatedEvent(@Param("correlationKey") String correlationKey,
                                 @Param("from") Instant from, @Param("to") Instant to);

    int insertEvent(EventInsert input);

    Long findEventId(@Param("eventKey") String eventKey);

    int updateEventWindow(@Param("eventId") long eventId, @Param("seenAt") Instant seenAt);

    int insertAlertLink(@Param("eventId") long eventId, @Param("alertId") long alertId);

    int upsertAssetLink(@Param("eventId") long eventId, @Param("assetId") long assetId);

    int insertTimeline(@Param("eventId") long eventId, @Param("occurredAt") Instant occurredAt,
                       @Param("summary") String summary, @Param("evidenceRef") String evidenceRef,
                       @Param("detailsJson") String detailsJson);

    List<String> listEventAlertSeverities(@Param("eventId") long eventId);

    int updateEventRisk(@Param("eventId") long eventId, @Param("severity") String severity,
                        @Param("riskScore") BigDecimal riskScore, @Param("riskVersion") String riskVersion,
                        @Param("basisJson") String basisJson);

    // ---- 规则登记与批准（申请人与批准人分离） ----

    List<RuleView> listRules();

    RuleView findRuleForUpdate(@Param("id") long id);

    int insertRule(@Param("ruleKey") String ruleKey, @Param("version") String version,
                   @Param("scopeJson") String scopeJson, @Param("conditionJson") String conditionJson,
                   @Param("severity") String severity, @Param("requestedBy") long requestedBy);

    Long findRuleId(@Param("ruleKey") String ruleKey, @Param("version") String version);

    int activateRule(@Param("id") long id, @Param("approvedBy") long approvedBy);

    /** 同一规则键的其他 active 版本转 retired，保证每个规则键至多一个生效版本。 */
    int retireOtherActiveVersions(@Param("ruleKey") String ruleKey, @Param("exceptId") long exceptId);

    int rejectRule(@Param("id") long id);

    record RuleView(long id, String ruleKey, String version, String scopeJson, String conditionJson,
                    String severity, String status, Long requestedBy, Long approvedBy, Instant createdAt,
                    Instant updatedAt) { }

    record PolicyRow(String version, String configJson) { }

    record ModelCandidate(long inferenceRequestId, long recordId, Long assetId, Instant eventTime,
                          long modelVersionId, String modelKey, String modelVersion, String artifactSha256,
                          String contractVersion, String contractSha256, double attackProbability,
                          double decisionThreshold, String thresholdPolicyVersion) { }

    record RuleRow(long id, String ruleKey, String version, String scopeJson, String conditionJson,
                   String severity) { }

    record AlertInsert(String alertKey, long ingestRecordId, Long inferenceRequestId, Long modelVersionId,
                       String contractVersion, String contractSha256, Long detectionRuleId, String alertType,
                       String severity, String severityPolicyVersion, BigDecimal score, String thresholdVersion,
                       String basisJson, Instant detectedAt) { }

    record AssetRow(long id, String assetKey, String criticality) { }

    record WindowRecord(long id, Instant eventTime, String normalizedPayload) { }

    record EventInsert(String eventKey, String title, String severity, Instant firstSeenAt, Instant lastSeenAt,
                       String correlationKey, String correlationPolicyVersion) { }
}
