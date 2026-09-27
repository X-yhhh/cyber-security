package com.xyh.cybersecurity.model;

import com.fasterxml.jackson.databind.JsonNode;
import com.xyh.cybersecurity.common.api.ApiEnvelope;
import com.xyh.cybersecurity.identity.IdentityPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/** 登记不可变模型元数据，并执行候选校验、独立发布审批和显式本机激活。 */
@RestController
@RequestMapping("/api/v1")
public class ModelController {

    private final ModelService service;

    public ModelController(ModelService service) { this.service = service; }

    @GetMapping("/models")
    @PreAuthorize("hasAuthority('model.validation.read')")
    public ApiEnvelope<ModelService.Page> list(@RequestParam(defaultValue = "0") int page,
                                               @RequestParam(defaultValue = "20") int size,
                                               @AuthenticationPrincipal IdentityPrincipal actor,
                                               HttpServletRequest request) {
        return ApiEnvelope.success(service.list(actor.id(), page, size), requestId(request));
    }

    @GetMapping("/models/{id}")
    @PreAuthorize("hasAuthority('model.validation.read')")
    public ApiEnvelope<ModelService.ModelView> get(@PathVariable long id,
                                                    @AuthenticationPrincipal IdentityPrincipal actor,
                                                    HttpServletRequest request) {
        return ApiEnvelope.success(service.get(actor.id(), id), requestId(request));
    }

    @PostMapping("/models")
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAuthority('model.candidate.manage')")
    public ApiEnvelope<ModelService.ModelView> register(@Valid @RequestBody CandidateBody body,
                                                         @AuthenticationPrincipal IdentityPrincipal actor,
                                                         HttpServletRequest request) {
        return ApiEnvelope.success(service.register(new ModelService.CandidateRequest(body.modelKey(), body.version(),
                body.taskType(), body.manifestVersion(), body.manifest(), body.artifactRef(), body.artifactSha256(),
                body.featureContractVersion()), actor, request), requestId(request));
    }

    @PostMapping("/models/{id}/release-requests")
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAuthority('model.release.request')")
    public ApiEnvelope<ModelService.ReleaseView> requestRelease(@PathVariable long id,
                                                                 @Valid @RequestBody ReasonBody body,
                                                                 @AuthenticationPrincipal IdentityPrincipal actor,
                                                                 HttpServletRequest request) {
        return ApiEnvelope.success(service.requestRelease(id, body.reason(), actor, request), requestId(request));
    }

    @PostMapping("/model-release-requests/{requestId}/decision")
    @PreAuthorize("hasAuthority('model.release.approve')")
    public ApiEnvelope<ModelService.ReleaseView> decideRelease(@PathVariable long requestId,
                                                                @Valid @RequestBody DecisionBody body,
                                                                @AuthenticationPrincipal IdentityPrincipal actor,
                                                                HttpServletRequest request) {
        return ApiEnvelope.success(service.decideRelease(requestId, body.decision(), body.reason(), actor, request),
                requestId(request));
    }

    @PostMapping("/models/{id}/validate")
    @PreAuthorize("hasAuthority('model.candidate.validate')")
    public ApiEnvelope<OnnxModelManager.ValidationResult> validate(@PathVariable long id,
                                                                    @AuthenticationPrincipal IdentityPrincipal actor,
                                                                    HttpServletRequest request) {
        return ApiEnvelope.success(service.validate(id, actor, request), requestId(request));
    }

    @org.springframework.web.bind.annotation.PutMapping("/model-deployments/active")
    @PreAuthorize("hasAuthority('model.deployment.activate')")
    public ApiEnvelope<ModelService.DeploymentView> activate(@Valid @RequestBody ActivationBody body,
                                                               @AuthenticationPrincipal IdentityPrincipal actor,
                                                               HttpServletRequest request) {
        return ApiEnvelope.success(service.activate(body.modelVersionId(), body.reason(), actor, request),
                requestId(request));
    }

    private static String requestId(HttpServletRequest request) {
        Object value = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        return value instanceof String id ? id : "unknown";
    }

    public record CandidateBody(@NotBlank @Size(max = 128) String modelKey,
                                @NotBlank @Size(max = 64) String version,
                                @NotBlank @Size(max = 48) String taskType,
                                @NotBlank @Size(max = 64) String manifestVersion,
                                @NotNull JsonNode manifest,
                                @NotBlank @Size(max = 512) String artifactRef,
                                @NotBlank @Size(max = 64) String artifactSha256,
                                @NotBlank @Size(max = 64) String featureContractVersion) { }
    public record ReasonBody(@NotBlank @Size(max = 1000) String reason) { }
    public record DecisionBody(@NotBlank String decision, @NotBlank @Size(max = 1000) String reason) { }
    public record ActivationBody(@jakarta.validation.constraints.Positive long modelVersionId,
                                 @NotBlank @Size(max = 1000) String reason) { }
}
