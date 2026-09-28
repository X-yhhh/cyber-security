package com.xyh.cybersecurity.response;

import com.fasterxml.jackson.databind.JsonNode;
import com.xyh.cybersecurity.common.api.ApiEnvelope;
import com.xyh.cybersecurity.identity.IdentityPrincipal;
import com.xyh.cybersecurity.response.application.ActionRequestService;
import com.xyh.cybersecurity.response.application.ApprovalDecisionService;
import com.xyh.cybersecurity.response.application.ResponseQueryService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/** 提供响应申请和审批台账；执行端点明确不可用且不接触适配器。 */
@RestController
@RequestMapping("/api/v1")
public class ResponseController {

    private final ActionRequestService actionRequests;
    private final ApprovalDecisionService decisions;
    private final ResponseQueryService queries;

    public ResponseController(ActionRequestService actionRequests, ApprovalDecisionService decisions,
                              ResponseQueryService queries) {
        this.actionRequests = actionRequests;
        this.decisions = decisions;
        this.queries = queries;
    }

    @PostMapping("/events/{eventId}/actions")
    @PreAuthorize("hasAuthority('action.request')")
    public ResponseEntity<ApiEnvelope<ResponseService.ApprovalView>> requestAction(
            @PathVariable long eventId, @RequestHeader("Idempotency-Key") String idempotencyKey,
            @Valid @RequestBody ActionBody body, @AuthenticationPrincipal IdentityPrincipal actor,
            HttpServletRequest request) {
        ResponseService.RequestResult result = actionRequests.request(eventId,
                new ResponseService.ActionRequest(body.assetId(), body.policyId(), body.actionType(),
                        body.parameters(), body.reason()), idempotencyKey, actor, request);
        return ResponseEntity.status(result.created() ? HttpStatus.CREATED : HttpStatus.OK)
                .body(ApiEnvelope.success(result.approval(), requestId(request)));
    }

    @GetMapping("/approvals")
    @PreAuthorize("hasAuthority('approval.read')")
    public ApiEnvelope<ResponseService.Page> approvals(@RequestParam(defaultValue = "0") int page,
                                                        @RequestParam(defaultValue = "20") int size,
                                                        @AuthenticationPrincipal IdentityPrincipal actor,
                                                        HttpServletRequest request) {
        return ApiEnvelope.success(queries.listApprovals(actor.id(), page, size), requestId(request));
    }

    @GetMapping("/approvals/{id}")
    @PreAuthorize("hasAuthority('approval.read')")
    public ApiEnvelope<ResponseService.ApprovalView> approval(@PathVariable long id,
                                                              @AuthenticationPrincipal IdentityPrincipal actor,
                                                              HttpServletRequest request) {
        return ApiEnvelope.success(queries.getApproval(actor.id(), id), requestId(request));
    }

    @GetMapping("/actions/{id}")
    @PreAuthorize("hasAuthority('action.request')")
    public ApiEnvelope<ResponseService.ApprovalView> action(@PathVariable long id,
                                                             @AuthenticationPrincipal IdentityPrincipal actor,
                                                             HttpServletRequest request) {
        return ApiEnvelope.success(queries.getAction(actor.id(), id), requestId(request));
    }

    @PostMapping("/approvals/{id}/decision")
    @PreAuthorize("hasAuthority('approval.decide')")
    public ApiEnvelope<ResponseService.ApprovalView> decide(@PathVariable long id,
                                                             @Valid @RequestBody DecisionBody body,
                                                             @AuthenticationPrincipal IdentityPrincipal actor,
                                                             HttpServletRequest request) {
        return ApiEnvelope.success(decisions.decide(id, body.decision(), body.reason(), actor, request),
                requestId(request));
    }

    @PostMapping("/actions/{id}/execute")
    @PreAuthorize("hasAuthority('action.request')")
    public ApiEnvelope<Void> execute(@PathVariable long id, @AuthenticationPrincipal IdentityPrincipal actor,
                                     HttpServletRequest request) {
        throw actionRequests.rejectExecution(id, actor, request);
    }

    private static String requestId(HttpServletRequest request) {
        Object value = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        return value instanceof String id ? id : "unknown";
    }

    public record ActionBody(long assetId, long policyId, @NotBlank @Size(max = 48) String actionType,
                            @NotNull JsonNode parameters, @NotBlank @Size(max = 1000) String reason) { }
    public record DecisionBody(@NotBlank String decision, @NotBlank @Size(max = 1000) String reason) { }
}
