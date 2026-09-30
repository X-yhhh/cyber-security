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

    /** 事件关联告警总数；事件不可见（含任一关联资源越权）时为 0。 */
    long countEventAlertsVisible(@Param("userId") long userId, @Param("eventId") long eventId);

    /** 事件关联告警一页，按检测时间倒序；可见性与 {@link #findVisibleEvent} 同一 SQL 谓词。 */
    List<AlertView> listEventAlertsVisible(@Param("userId") long userId, @Param("eventId") long eventId,
                                           @Param("offset") int offset, @Param("limit") int limit);

    List<EventAssetView> listEventAssetsVisible(@Param("userId") long userId, @Param("eventId") long eventId);

    /** 事件时间线总条数；事件不可见时为 0。 */
    long countEventTimelineVisible(@Param("userId") long userId, @Param("eventId") long eventId);

    /** 事件时间线一页，按发生时间倒序（最新证据与研判在第一页）。 */
    List<TimelineView> listEventTimelineVisible(@Param("userId") long userId, @Param("eventId") long eventId,
                                                @Param("offset") int offset, @Param("limit") int limit);

    int transitionVisibleEvent(@Param("userId") long userId, @Param("eventId") long eventId,
                               @Param("expectedStatus") String expectedStatus,
                               @Param("newStatus") String newStatus);

    int appendTimelineForInvestigator(@Param("userId") long userId, @Param("eventId") long eventId,
                                      @Param("entryType") String entryType,
                                      @Param("actorId") String actorId,
                                      @Param("summary") String summary,
                                      @Param("detailsJson") String detailsJson);

    // ---- 告警级人工标注（V16，M8 反馈 / 阶段 7 人工抽检）。可见范围与功能权限在 SQL 内复核，不可见一律返回空。

    /** 锁定调用者可见、且其持有 {@code permission} 的告警行；不可见或无权限返回 null。 */
    AlertTarget lockVisibleAlert(@Param("userId") long userId, @Param("alertId") long alertId,
                                 @Param("permission") String permission);

    /** 告警当前的有效标注（pending / training_approved）。 */
    FeedbackView findActiveFeedback(@Param("alertId") long alertId);

    int insertFeedback(FeedbackInsert insert);

    /** 状态 compare-and-set：仅当告警仍为 {@code expected} 时改为 {@code status}。 */
    int transitionAlert(@Param("alertId") long alertId, @Param("expected") String expected,
                        @Param("status") String status);

    /** 锁定调用者可见（持有 feedback.review）的标注行；不可见返回 null。 */
    FeedbackView lockVisibleFeedback(@Param("userId") long userId, @Param("feedbackId") long feedbackId);

    int decideReview(@Param("feedbackId") long feedbackId, @Param("reviewerId") long reviewerId,
                     @Param("status") String status, @Param("trainingEligible") boolean trainingEligible,
                     @Param("reason") String reason);

    /** 告警的全部标注（含被驳回的历史），按时间倒序。 */
    List<FeedbackView> listForAlert(@Param("userId") long userId, @Param("alertId") long alertId);

    long countPendingReviews(@Param("userId") long userId);

    /** 从给定告警中筛出调用者可见的（影子报告抽检明细按同一可见性谓词过滤）。 */
    List<Long> filterVisibleAlertIds(@Param("userId") long userId, @Param("alertIds") List<Long> alertIds);

    /** 待复核标注（不含调用者本人标注的，职责分离），按标注时间正序。 */
    List<FeedbackView> listPendingReviews(@Param("userId") long userId, @Param("offset") int offset,
                                          @Param("limit") int limit);

    record AlertTarget(long id, String alertKey, String alertType, String status, long ingestRecordId,
                       Long inferenceRequestId, long dataSourceId, long assetId) { }

    /**
     * @param label        {@code false_positive} 或 {@code true_positive}
     * @param reviewStatus {@code pending} / {@code training_approved} / {@code rejected}
     */
    record FeedbackView(long id, long alertId, String alertKey, String alertType, String label, String note,
                        long reviewedBy, String reviewerName, LocalDateTime reviewedAt, String reviewStatus,
                        Long secondReviewedBy, String secondReviewerName, LocalDateTime secondReviewedAt,
                        String secondReviewReason, boolean trainingEligible, long dataSourceId, long assetId) { }

    final class FeedbackInsert {
        private long id;
        private final long sourceRecordId;
        private final long alertId;
        private final String label;
        private final String evidenceRef;
        private final String note;
        private final long reviewedBy;

        public FeedbackInsert(long sourceRecordId, long alertId, String label, String evidenceRef, String note,
                              long reviewedBy) {
            this.sourceRecordId = sourceRecordId;
            this.alertId = alertId;
            this.label = label;
            this.evidenceRef = evidenceRef;
            this.note = note;
            this.reviewedBy = reviewedBy;
        }

        public long getId() { return id; }
        public void setId(long id) { this.id = id; }
        public long getSourceRecordId() { return sourceRecordId; }
        public long getAlertId() { return alertId; }
        public String getLabel() { return label; }
        public String getEvidenceRef() { return evidenceRef; }
        public String getNote() { return note; }
        public long getReviewedBy() { return reviewedBy; }
    }

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
