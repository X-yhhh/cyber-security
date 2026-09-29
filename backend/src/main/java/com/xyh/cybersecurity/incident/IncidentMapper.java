package com.xyh.cybersecurity.incident;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;

/** 告警与事件读写映射；所有列表、详情和状态写入都在 SQL 内复核功能权限及资源范围。 */
@Mapper
public interface IncidentMapper {

    long countVisibleAlerts(@Param("userId") long userId);

    List<AlertView> listVisibleAlerts(@Param("userId") long userId,
                                      @Param("offset") int offset,
                                      @Param("limit") int limit);

    AlertView findVisibleAlert(@Param("userId") long userId, @Param("alertId") long alertId);

    long countVisibleEvents(@Param("userId") long userId);

    List<EventView> listVisibleEvents(@Param("userId") long userId,
                                      @Param("offset") int offset,
                                      @Param("limit") int limit);

    EventView findVisibleEvent(@Param("userId") long userId, @Param("eventId") long eventId);

    List<AlertView> listEventAlertsVisible(@Param("userId") long userId, @Param("eventId") long eventId);

    List<EventAssetView> listEventAssetsVisible(@Param("userId") long userId, @Param("eventId") long eventId);

    List<TimelineView> listEventTimelineVisible(@Param("userId") long userId, @Param("eventId") long eventId);

    int transitionVisibleEvent(@Param("userId") long userId, @Param("eventId") long eventId,
                               @Param("expectedStatus") String expectedStatus,
                               @Param("newStatus") String newStatus);

    int appendTimelineForInvestigator(@Param("userId") long userId, @Param("eventId") long eventId,
                                      @Param("entryType") String entryType,
                                      @Param("actorId") String actorId,
                                      @Param("summary") String summary,
                                      @Param("detailsJson") String detailsJson);

    /**
     * 告警视图。V13 起追加来源追溯：模型告警带模型版本、契约版本与哈希、分级策略版本；规则告警带规则键与版本；
     * {@code basisJson} 为生成时的评分依据快照（分数、阈值或命中条件），不含记录原文。
     */
    record AlertView(long id, String alertKey, String alertType, String severity, String status,
                     BigDecimal score, LocalDateTime detectedAt, long dataSourceId, Long assetId,
                     Long modelVersionId, String modelKey, String modelVersion, String contractVersion,
                     String contractSha256, Long detectionRuleId, String ruleKey, String ruleVersion,
                     String severityPolicyVersion, String thresholdVersion, String basisJson) { }

    record EventView(long id, String eventKey, String title, String category, String severity,
                     String status, BigDecimal riskScore, LocalDateTime firstSeenAt, LocalDateTime lastSeenAt,
                     Long assigneeId, long alertCount, long assetCount, String riskRuleVersion,
                     String riskBasisJson, String correlationKey, String correlationPolicyVersion) { }

    record EventAssetView(long assetId, String assetKey, String relationType, long evidenceCount) { }

    record TimelineView(long id, LocalDateTime occurredAt, String entryType, String actorType,
                        String actorId, String summary, String evidenceRef, String detailsJson) { }
}
