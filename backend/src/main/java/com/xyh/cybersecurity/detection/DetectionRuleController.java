package com.xyh.cybersecurity.detection;

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
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/** 确定性检测规则：查看、登记（待批准）与他人批准/拒绝。规则只产生告警，不触发处置。 */
@RestController
@RequestMapping("/api/v1/detection-rules")
public class DetectionRuleController {
    private final DetectionRuleService service;

    public DetectionRuleController(DetectionRuleService service) { this.service = service; }

    @GetMapping
    @PreAuthorize("hasAuthority('detection.rule.read')")
    public ApiEnvelope<List<DetectionMapper.RuleView>> list(HttpServletRequest request) {
        return ApiEnvelope.success(service.list(), requestId(request));
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAuthority('detection.rule.manage')")
    public ApiEnvelope<DetectionMapper.RuleView> create(@Valid @RequestBody CreateBody body,
                                                        @AuthenticationPrincipal IdentityPrincipal actor,
                                                        HttpServletRequest request) {
        return ApiEnvelope.success(service.create(new DetectionRuleService.CreateRule(body.ruleKey(), body.version(),
                body.severity(), body.condition(), body.scope(), body.reason()), actor, request), requestId(request));
    }

    @PostMapping("/{id}/decision")
    @PreAuthorize("hasAuthority('detection.rule.approve')")
    public ApiEnvelope<DetectionMapper.RuleView> decide(@PathVariable long id, @Valid @RequestBody DecisionBody body,
                                                        @AuthenticationPrincipal IdentityPrincipal actor,
                                                        HttpServletRequest request) {
        return ApiEnvelope.success(service.decide(id, body.decision(), body.reason(), actor, request),
                requestId(request));
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('detection.rule.read')")
    public ApiEnvelope<DetectionMapper.RuleView> get(@PathVariable long id, HttpServletRequest request) {
        return ApiEnvelope.success(service.get(id), requestId(request));
    }

    @PostMapping("/{id}/versions")
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAuthority('detection.rule.manage')")
    public ApiEnvelope<DetectionMapper.RuleView> version(@PathVariable long id, @Valid @RequestBody VersionBody body,
            @AuthenticationPrincipal IdentityPrincipal actor, HttpServletRequest request) {
        return ApiEnvelope.success(service.createVersion(id, new DetectionRuleService.CreateRule(null, body.version(),
                body.severity(), body.condition(), body.scope(), body.reason()), actor, request), requestId(request));
    }

    @PostMapping("/{id}/retire")
    @PreAuthorize("hasAuthority('detection.rule.approve')")
    public ApiEnvelope<DetectionMapper.RuleView> retire(@PathVariable long id, @Valid @RequestBody ReasonBody body,
            @AuthenticationPrincipal IdentityPrincipal actor, HttpServletRequest request) {
        return ApiEnvelope.success(service.retire(id, body.reason(), actor, request), requestId(request));
    }

    public record VersionBody(@NotBlank @Size(max=32) String version, String severity, JsonNode condition,
                              JsonNode scope, @NotBlank @Size(max=1000) String reason) { }
    public record ReasonBody(@NotBlank @Size(max=1000) String reason) { }

    private static String requestId(HttpServletRequest request) {
        Object value = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        return value instanceof String id ? id : "unknown";
    }

    public record CreateBody(@NotBlank @Size(max = 64) String ruleKey, @NotBlank @Size(max = 32) String version,
                             @NotBlank String severity, @NotNull JsonNode condition, JsonNode scope,
                             @NotBlank @Size(max = 1000) String reason) { }

    public record DecisionBody(@NotBlank String decision, @NotBlank @Size(max = 1000) String reason) { }
}
