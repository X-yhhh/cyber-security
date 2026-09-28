package com.xyh.cybersecurity.query;

import com.xyh.cybersecurity.common.api.ApiEnvelope;
import com.xyh.cybersecurity.identity.IdentityPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/** 模型策略、发布、部署、漂移及离线训练台账的只读查询控制器。 */
@RestController
@RequestMapping("/api/v1")
public class ModelQueryController {
    private final ConsoleQueryService service;
    public ModelQueryController(ConsoleQueryService service) { this.service = service; }

    @GetMapping("/response-policies")
    @PreAuthorize("hasAuthority('response.policy.read')")
    public ApiEnvelope<List<ConsoleQueryService.PolicyView>> policies(HttpServletRequest request) {
        return ApiEnvelope.success(service.policies(), requestId(request));
    }

    @GetMapping("/models/{id}/release-requests")
    @PreAuthorize("hasAuthority('model.validation.read')")
    public ApiEnvelope<List<ConsoleQueryService.ReleaseView>> releases(
            @PathVariable long id, @AuthenticationPrincipal IdentityPrincipal actor, HttpServletRequest request) {
        return ApiEnvelope.success(service.releases(actor.id(), id), requestId(request));
    }

    @GetMapping("/model-deployments")
    @PreAuthorize("hasAuthority('model.validation.read')")
    public ApiEnvelope<List<ConsoleQueryService.DeploymentView>> deployments(
            @AuthenticationPrincipal IdentityPrincipal actor, HttpServletRequest request) {
        return ApiEnvelope.success(service.deployments(actor.id()), requestId(request));
    }

    @GetMapping("/model-drift-windows")
    @PreAuthorize("hasAuthority('model.validation.read')")
    public ApiEnvelope<List<ConsoleQueryService.DriftView>> drift(@AuthenticationPrincipal IdentityPrincipal actor,
                                                                  HttpServletRequest request) {
        return ApiEnvelope.success(service.drift(actor.id()), requestId(request));
    }

    @GetMapping("/feedback-samples")
    @PreAuthorize("hasAuthority('model.validation.read')")
    public ApiEnvelope<List<ConsoleQueryService.FeedbackView>> feedback(@AuthenticationPrincipal IdentityPrincipal actor,
                                                                        HttpServletRequest request) {
        return ApiEnvelope.success(service.feedback(actor.id()), requestId(request));
    }

    @GetMapping("/training-jobs")
    @PreAuthorize("hasAuthority('model.validation.read')")
    public ApiEnvelope<List<ConsoleQueryService.TrainingJobView>> trainingJobs(
            @AuthenticationPrincipal IdentityPrincipal actor, HttpServletRequest request) {
        return ApiEnvelope.success(service.trainingJobs(actor.id()), requestId(request));
    }

    private static String requestId(HttpServletRequest request) {
        Object value = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        return value instanceof String id ? id : "unknown";
    }
}
