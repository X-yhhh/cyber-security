package com.xyh.cybersecurity.incident;

import com.xyh.cybersecurity.common.api.ApiEnvelope;
import com.xyh.cybersecurity.identity.IdentityPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/** 暴露 SQL 范围过滤后的告警与事件视图及人工研判命令。 */
@RestController
@RequestMapping("/api/v1")
public class IncidentController {

    private final IncidentService service;
    private final AlertFeedbackService feedback;

    public IncidentController(IncidentService service, AlertFeedbackService feedback) {
        this.service = service;
        this.feedback = feedback;
    }

    @GetMapping("/alerts")
    @PreAuthorize("hasAuthority('alert.read')")
    public ApiEnvelope<IncidentService.Page<IncidentMapper.AlertView>> alerts(
            @RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "alert") String layer,
            @AuthenticationPrincipal IdentityPrincipal principal, HttpServletRequest request) {
        return ApiEnvelope.success(service.alerts(principal.id(), page, size, layer), requestId(request));
    }

    @GetMapping("/alerts/{id}")
    @PreAuthorize("hasAuthority('alert.read')")
    public ApiEnvelope<IncidentMapper.AlertView> alert(@PathVariable long id,
                                                        @AuthenticationPrincipal IdentityPrincipal principal,
                                                        HttpServletRequest request) {
        return ApiEnvelope.success(service.alert(principal.id(), id), requestId(request));
    }

    @GetMapping("/events")
    @PreAuthorize("hasAuthority('event.read')")
    public ApiEnvelope<IncidentService.Page<IncidentMapper.EventView>> events(
            @RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "20") int size,
            @AuthenticationPrincipal IdentityPrincipal principal, HttpServletRequest request) {
        return ApiEnvelope.success(service.events(principal.id(), page, size), requestId(request));
    }

    @GetMapping("/events/{id}")
    @PreAuthorize("hasAuthority('event.read')")
    public ApiEnvelope<IncidentService.EventDetail> event(@PathVariable long id,
                                                           @AuthenticationPrincipal IdentityPrincipal principal,
                                                           HttpServletRequest request) {
        return ApiEnvelope.success(service.event(principal.id(), id), requestId(request));
    }

    /** 事件关联告警分页（按检测时间倒序）；size 1-100，事件不可见 404。 */
    @GetMapping("/events/{id}/alerts")
    @PreAuthorize("hasAuthority('event.read')")
    public ApiEnvelope<IncidentService.Page<IncidentMapper.AlertView>> eventAlerts(
            @PathVariable long id, @RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "20") int size,
            @AuthenticationPrincipal IdentityPrincipal principal, HttpServletRequest request) {
        return ApiEnvelope.success(service.eventAlerts(principal.id(), id, page, size), requestId(request));
    }

    /** 事件时间线分页（按发生时间倒序）；size 1-100，事件不可见 404。 */
    @GetMapping("/events/{id}/timeline")
    @PreAuthorize("hasAuthority('event.read')")
    public ApiEnvelope<IncidentService.Page<IncidentMapper.TimelineView>> eventTimeline(
            @PathVariable long id, @RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "20") int size,
            @AuthenticationPrincipal IdentityPrincipal principal, HttpServletRequest request) {
        return ApiEnvelope.success(service.eventTimeline(principal.id(), id, page, size), requestId(request));
    }

    @PostMapping("/events/{id}/transitions")
    @PreAuthorize("hasAuthority('event.read') and hasAuthority('event.investigate')")
    public ApiEnvelope<IncidentService.EventDetail> transition(@PathVariable long id,
                                                                @Valid @RequestBody TransitionBody body,
                                                                @AuthenticationPrincipal IdentityPrincipal principal,
                                                                HttpServletRequest request) {
        return ApiEnvelope.success(service.transition(principal.id(), id, body.status(), body.reason(), request),
                requestId(request));
    }

    /** null 取消指派；目标用户必须 active 且能研判该事件的全部证据。 */
    @org.springframework.web.bind.annotation.PutMapping("/events/{id}/assignee")
    @PreAuthorize("hasAuthority('event.read') and hasAuthority('event.investigate')")
    public ApiEnvelope<IncidentService.EventDetail> assign(@PathVariable long id, @Valid @RequestBody AssigneeBody body,
            @AuthenticationPrincipal IdentityPrincipal principal, HttpServletRequest request) {
        return ApiEnvelope.success(service.assign(principal.id(), id, body.assigneeId(), body.reason(), request), requestId(request));
    }
    public record AssigneeBody(Long assigneeId, @NotBlank @Size(max=1000) String reason) { }

    @PostMapping("/events/{id}/notes")
    @PreAuthorize("hasAuthority('event.read') and hasAuthority('event.investigate')")
    public ApiEnvelope<IncidentService.EventDetail> addNote(@PathVariable long id,
                                                             @Valid @RequestBody NoteBody body,
                                                             @AuthenticationPrincipal IdentityPrincipal principal,
                                                             HttpServletRequest request) {
        return ApiEnvelope.success(service.addNote(principal.id(), id, body.note(), request), requestId(request));
    }

    /** 告警的人工标注历史（含被复核驳回的）；告警不可见 404。 */
    @GetMapping("/alerts/{id}/feedback")
    @PreAuthorize("hasAuthority('alert.read')")
    public ApiEnvelope<List<IncidentMapper.FeedbackView>> alertFeedback(@PathVariable long id,
                                                                       @AuthenticationPrincipal IdentityPrincipal principal,
                                                                       HttpServletRequest request) {
        return ApiEnvelope.success(feedback.history(principal.id(), id), requestId(request));
    }

    /** 标注告警为真报/误报（阶段 7 人工抽检）；一条告警至多一条有效标注。 */
    @PostMapping("/alerts/{id}/feedback")
    @PreAuthorize("hasAuthority('alert.read') and hasAuthority('alert.feedback.label')")
    public ApiEnvelope<IncidentMapper.FeedbackView> labelAlert(@PathVariable long id, @Valid @RequestBody LabelBody body,
                                                                @AuthenticationPrincipal IdentityPrincipal principal,
                                                                HttpServletRequest request) {
        return ApiEnvelope.success(feedback.label(principal.id(), id, body.label(), body.note(), request),
                requestId(request));
    }

    /** 待本人复核的标注（不含本人标注的）。 */
    @GetMapping("/feedback-reviews")
    @PreAuthorize("hasAuthority('alert.read') and hasAuthority('feedback.review')")
    public ApiEnvelope<IncidentService.Page<IncidentMapper.FeedbackView>> pendingReviews(
            @RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "20") int size,
            @AuthenticationPrincipal IdentityPrincipal principal, HttpServletRequest request) {
        return ApiEnvelope.success(feedback.pendingReviews(principal.id(), page, size), requestId(request));
    }

    /** 第二人复核：approve 使标注可用于离线训练，reject 使标注失效；复核人不能是标注人。 */
    @PostMapping("/feedback-samples/{id}/review")
    @PreAuthorize("hasAuthority('alert.read') and hasAuthority('feedback.review')")
    public ApiEnvelope<IncidentMapper.FeedbackView> reviewFeedback(@PathVariable long id, @Valid @RequestBody ReviewBody body,
                                                                    @AuthenticationPrincipal IdentityPrincipal principal,
                                                                    HttpServletRequest request) {
        return ApiEnvelope.success(feedback.review(principal.id(), id, body.decision(), body.reason(), request),
                requestId(request));
    }

    private String requestId(HttpServletRequest request) {
        Object value = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        return value instanceof String id ? id : "unknown";
    }

    public record TransitionBody(@NotBlank @Size(max = 32) String status,
                                 @NotBlank @Size(max = 1000) String reason) { }
    public record NoteBody(@NotBlank @Size(max = 1000) String note) { }
    public record LabelBody(@NotBlank @Size(max = 32) String label, @NotBlank @Size(max = 1000) String note) { }
    public record ReviewBody(@NotBlank @Size(max = 16) String decision, @NotBlank @Size(max = 1000) String reason) { }
}
