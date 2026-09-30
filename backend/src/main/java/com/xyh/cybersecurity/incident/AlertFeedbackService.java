package com.xyh.cybersecurity.incident;

import com.xyh.cybersecurity.audit.AuditMapper;
import com.xyh.cybersecurity.common.api.ApiRequestException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Set;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/**
 * 告警级人工标注与第二人复核（M8 反馈；阶段 7 G3“人工抽检误报率”的数据来源，路线 B §13.2、§13.3）。
 *
 * <p>契约：</p>
 * <ul>
 *   <li>标注：研判员对范围内告警标注 {@code false_positive} / {@code true_positive}，写入 {@code feedback_sample}
 *       （{@code label_source=analyst}、{@code training_eligible=false}、{@code review_status=pending}），并同事务迁移告警状态：
 *       误报 {@code new|acknowledged → false_positive}，真报 {@code new → acknowledged}（已确认则不变）。一条告警至多一条有效标注，
 *       已结案（resolved / closed / false_positive）的告警不接受新标注。</li>
 *   <li>复核：第二人（≠标注人）决定该标注是否可用于离线训练。批准只置 {@code training_eligible=true}，不改告警；
 *       驳回使标注失效，误报标注对应的告警退回 {@code acknowledged}，可重新标注。</li>
 *   <li>标注只进入离线候选流程：不改阈值、不换模型、不触发处置（§13.3）。</li>
 * </ul>
 *
 * <p>失败边界：不可见（越权、不存在）一律 404；状态不允许或并发冲突 409；说明文本不合规 400。每次成功写入追加审计，
 * 审计范围为告警所属数据源与资产。</p>
 */
@Service
public class AlertFeedbackService {
    static final String FALSE_POSITIVE = "false_positive";
    static final String TRUE_POSITIVE = "true_positive";
    private static final Set<String> LABELS = Set.of(FALSE_POSITIVE, TRUE_POSITIVE);
    private static final Set<String> LABELABLE = Set.of("new", "acknowledged");

    private final IncidentMapper mapper;
    private final AuditMapper auditMapper;

    public AlertFeedbackService(IncidentMapper mapper, AuditMapper auditMapper) {
        this.mapper = mapper;
        this.auditMapper = auditMapper;
    }

    /**
     * 标注告警。
     *
     * @param label {@code false_positive} 或 {@code true_positive}
     * @param note  研判依据（1～1000 字符，不得含控制字符；不要写入地址等原始网络数据）
     */
    @Transactional
    public IncidentMapper.FeedbackView label(long userId, long alertId, String label, String note,
                                             HttpServletRequest request) {
        if (label == null || !LABELS.contains(label)) throw ApiRequestException.badRequest("标注取值无效");
        String text = validatedText(note);
        IncidentMapper.AlertTarget alert = mapper.lockVisibleAlert(userId, alertId, "alert.feedback.label");
        if (alert == null) throw ApiRequestException.notFound();
        if (!LABELABLE.contains(alert.status())) {
            throw new ApiRequestException(HttpStatus.CONFLICT, "ALERT_NOT_LABELABLE", "告警已结案，不能再标注");
        }
        if (mapper.findActiveFeedback(alertId) != null) {
            throw new ApiRequestException(HttpStatus.CONFLICT, "ALERT_ALREADY_LABELED", "该告警已有有效标注");
        }
        String evidence = "alert:" + alert.alertKey()
                + (alert.inferenceRequestId() == null ? "" : ";inference_request:" + alert.inferenceRequestId());
        IncidentMapper.FeedbackInsert insert = new IncidentMapper.FeedbackInsert(alert.ingestRecordId(), alertId, label,
                evidence, text, userId);
        try {
            mapper.insertFeedback(insert);
        } catch (DuplicateKeyException concurrent) {
            throw new ApiRequestException(HttpStatus.CONFLICT, "ALERT_ALREADY_LABELED", "该告警已有有效标注");
        }
        String target = FALSE_POSITIVE.equals(label) ? FALSE_POSITIVE : "acknowledged";
        if (!target.equals(alert.status()) && mapper.transitionAlert(alertId, alert.status(), target) != 1) {
            throw ApiRequestException.conflict("告警状态已被其他请求更新");
        }
        audit(userId, "alert.feedback.labeled", "detection_alert", alertId, alert.dataSourceId(), alert.assetId(),
                label, request);
        return mapper.findActiveFeedback(alertId);
    }

    /**
     * 第二人复核。
     *
     * @param decision {@code approve}（可用于训练）或 {@code reject}（标注失效）
     */
    @Transactional
    public IncidentMapper.FeedbackView review(long userId, long feedbackId, String decision, String reason,
                                              HttpServletRequest request) {
        boolean approve = "approve".equals(decision);
        if (!approve && !"reject".equals(decision)) throw ApiRequestException.badRequest("复核决定无效");
        String text = validatedText(reason);
        IncidentMapper.FeedbackView feedback = mapper.lockVisibleFeedback(userId, feedbackId);
        if (feedback == null) throw ApiRequestException.notFound();
        if (!"pending".equals(feedback.reviewStatus())) {
            throw new ApiRequestException(HttpStatus.CONFLICT, "FEEDBACK_ALREADY_REVIEWED", "该标注已复核");
        }
        if (feedback.reviewedBy() == userId) {
            throw new ApiRequestException(HttpStatus.FORBIDDEN, "REVIEW_SEPARATION_REQUIRED", "不能复核本人的标注");
        }
        // 驳回前先锁告警，保证“标注失效 + 告警回退”与并发标注互斥。
        IncidentMapper.AlertTarget alert = approve ? null
                : mapper.lockVisibleAlert(userId, feedback.alertId(), "feedback.review");
        if (!approve && alert == null) throw ApiRequestException.notFound();
        String status = approve ? "training_approved" : "rejected";
        if (mapper.decideReview(feedbackId, userId, status, approve, text) != 1) {
            throw ApiRequestException.conflict("标注状态已被其他请求更新");
        }
        if (!approve && FALSE_POSITIVE.equals(feedback.label()) && FALSE_POSITIVE.equals(alert.status())
                && mapper.transitionAlert(feedback.alertId(), FALSE_POSITIVE, "acknowledged") != 1) {
            throw ApiRequestException.conflict("告警状态已被其他请求更新");
        }
        audit(userId, approve ? "alert.feedback.approved" : "alert.feedback.rejected", "feedback_sample", feedbackId,
                feedback.dataSourceId(), feedback.assetId(), status, request);
        return mapper.listForAlert(userId, feedback.alertId()).stream()
                .filter(row -> row.id() == feedbackId).findFirst().orElseThrow(ApiRequestException::notFound);
    }

    /** 告警的标注历史（含被驳回的）；告警不可见时 404。 */
    public List<IncidentMapper.FeedbackView> history(long userId, long alertId) {
        if (mapper.findVisibleAlert(userId, alertId) == null) throw ApiRequestException.notFound();
        return mapper.listForAlert(userId, alertId);
    }

    /** 待本人复核的标注（不含本人标注的）。 */
    public IncidentService.Page<IncidentMapper.FeedbackView> pendingReviews(long userId, int page, int size) {
        if (page < 0 || size < 1 || size > 100 || (long) page * size > Integer.MAX_VALUE) {
            throw ApiRequestException.badRequest("分页参数超出允许范围");
        }
        return new IncidentService.Page<>(mapper.countPendingReviews(userId), page, size,
                mapper.listPendingReviews(userId, page * size, size));
    }

    private void audit(long userId, String action, String resourceType, long resourceId, long sourceId, long assetId,
                       String outcomeDetail, HttpServletRequest request) {
        Object requestId = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        AuditMapper.AuditInsert audit = new AuditMapper.AuditInsert(LocalDateTime.now(ZoneOffset.UTC), "human",
                Long.toString(userId), action, resourceType, Long.toString(resourceId),
                requestId instanceof String value ? value : null, "success", outcomeDetail);
        auditMapper.insertAudit(audit);
        auditMapper.insertResourceScope(audit.getId(), "data_source", Long.toString(sourceId));
        auditMapper.insertResourceScope(audit.getId(), "asset", Long.toString(assetId));
    }

    private static String validatedText(String value) {
        if (value == null) throw ApiRequestException.badRequest("说明不能为空");
        String result = value.trim();
        if (result.isEmpty() || result.length() > 1000 || result.chars().anyMatch(Character::isISOControl)) {
            throw ApiRequestException.badRequest("说明长度或字符无效");
        }
        return result;
    }
}
