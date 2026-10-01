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
import org.springframework.web.bind.annotation.*;
import java.util.List;
import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/** 检测策略 API；仅适配协议，审批、不可变内容和状态迁移在服务中强制校验。 */
@RestController
@RequestMapping("/api/v1/detection-policies")
public class DetectionPolicyController {
    private final DetectionPolicyService service;
    public DetectionPolicyController(DetectionPolicyService service) { this.service = service; }
    @GetMapping @PreAuthorize("hasAuthority('detection.policy.read')")
    public ApiEnvelope<List<DetectionPolicyMapper.Row>> list(HttpServletRequest r) { return wrap(service.list(), r); }
    @GetMapping("/{id}") @PreAuthorize("hasAuthority('detection.policy.read')")
    public ApiEnvelope<DetectionPolicyMapper.Row> get(@PathVariable long id, HttpServletRequest r) { return wrap(service.get(id), r); }
    @PostMapping @ResponseStatus(HttpStatus.CREATED) @PreAuthorize("hasAuthority('detection.policy.manage')")
    public ApiEnvelope<DetectionPolicyMapper.Row> create(@Valid @RequestBody DraftBody b, @AuthenticationPrincipal IdentityPrincipal a, HttpServletRequest r) {
        return wrap(service.create(null, new DetectionPolicyService.Draft(b.policyType(), b.config(), b.reason()), a, r), r);
    }
    @PostMapping("/{id}/versions") @ResponseStatus(HttpStatus.CREATED) @PreAuthorize("hasAuthority('detection.policy.manage')")
    public ApiEnvelope<DetectionPolicyMapper.Row> version(@PathVariable long id, @Valid @RequestBody DraftBody b, @AuthenticationPrincipal IdentityPrincipal a, HttpServletRequest r) {
        return wrap(service.create(id, new DetectionPolicyService.Draft(b.policyType(), b.config(), b.reason()), a, r), r);
    }
    @PostMapping("/{id}/submit") @PreAuthorize("hasAuthority('detection.policy.manage')")
    public ApiEnvelope<DetectionPolicyMapper.Row> submit(@PathVariable long id, @AuthenticationPrincipal IdentityPrincipal a, HttpServletRequest r) { return wrap(service.submit(id,a,r),r); }
    @PostMapping("/{id}/decision") @PreAuthorize("hasAuthority('detection.policy.approve')")
    public ApiEnvelope<DetectionPolicyMapper.Row> decide(@PathVariable long id, @Valid @RequestBody DecisionBody b, @AuthenticationPrincipal IdentityPrincipal a, HttpServletRequest r) { return wrap(service.decide(id,b.decision(),b.reason(),a,r),r); }
    @PostMapping("/{id}/withdraw") @PreAuthorize("hasAuthority('detection.policy.manage')")
    public ApiEnvelope<DetectionPolicyMapper.Row> withdraw(@PathVariable long id, @Valid @RequestBody ReasonBody b, @AuthenticationPrincipal IdentityPrincipal a, HttpServletRequest r) { return wrap(service.retire(id,b.reason(),true,a,r),r); }
    @PostMapping("/{id}/retire") @PreAuthorize("hasAuthority('detection.policy.approve')")
    public ApiEnvelope<DetectionPolicyMapper.Row> retire(@PathVariable long id, @Valid @RequestBody ReasonBody b, @AuthenticationPrincipal IdentityPrincipal a, HttpServletRequest r) { return wrap(service.retire(id,b.reason(),false,a,r),r); }
    private static <T> ApiEnvelope<T> wrap(T data, HttpServletRequest r) { return ApiEnvelope.success(data,(String)r.getAttribute(REQUEST_ID_ATTRIBUTE)); }
    public record DraftBody(String policyType, @NotNull JsonNode config, @NotBlank @Size(max=1000) String reason) { }
    public record DecisionBody(@NotBlank String decision, @NotBlank @Size(max=1000) String reason) { }
    public record ReasonBody(@NotBlank @Size(max=1000) String reason) { }
}
