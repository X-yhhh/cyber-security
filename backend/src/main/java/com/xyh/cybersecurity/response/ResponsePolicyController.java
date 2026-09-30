package com.xyh.cybersecurity.response;

import com.fasterxml.jackson.databind.JsonNode;
import com.xyh.cybersecurity.common.api.ApiEnvelope;
import com.xyh.cybersecurity.identity.IdentityPrincipal;
import com.xyh.cybersecurity.response.application.ResponsePolicyService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
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

import java.math.BigDecimal;
import java.util.List;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/**
 * 响应策略版本管理（M6）。只做协议适配：权限点由 {@code @PreAuthorize} 粗筛，起草人/审批人分离、
 * 状态迁移、内容校验与审计全部在 {@link ResponsePolicyService} 中复核。本控制器不触发任何响应动作。
 */
@RestController
@RequestMapping("/api/v1/response-policies")
public class ResponsePolicyController {
    private final ResponsePolicyService service;

    public ResponsePolicyController(ResponsePolicyService service) { this.service = service; }

    @GetMapping
    @PreAuthorize("hasAuthority('response.policy.read')")
    public ApiEnvelope<List<ResponsePolicyService.PolicyView>> list(@RequestParam(required = false) String status,
                                                                    @RequestParam(required = false) String policyKey,
                                                                    HttpServletRequest request) {
        return ApiEnvelope.success(service.list(status, policyKey), requestId(request));
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('response.policy.read')")
    public ApiEnvelope<ResponsePolicyService.PolicyView> get(@PathVariable long id, HttpServletRequest request) {
        return ApiEnvelope.success(service.get(id), requestId(request));
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAuthority('response.policy.draft')")
    public ApiEnvelope<ResponsePolicyService.PolicyView> create(@Valid @RequestBody DraftBody body,
                                                                @AuthenticationPrincipal IdentityPrincipal actor,
                                                                HttpServletRequest request) {
        return ApiEnvelope.success(service.createDraft(body.toInput(), actor, request), requestId(request));
    }

    /** 以 {id} 为基础新建下一版本草稿；请求体中省略的字段沿用基础版本。 */
    @PostMapping("/{id}/versions")
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAuthority('response.policy.draft')")
    public ApiEnvelope<ResponsePolicyService.PolicyView> version(@PathVariable long id, @Valid @RequestBody DraftBody body,
                                                                 @AuthenticationPrincipal IdentityPrincipal actor,
                                                                 HttpServletRequest request) {
        return ApiEnvelope.success(service.createVersion(id, body.toInput(), actor, request), requestId(request));
    }

    @PostMapping("/{id}/submit")
    @PreAuthorize("hasAuthority('response.policy.draft')")
    public ApiEnvelope<ResponsePolicyService.PolicyView> submit(@PathVariable long id,
                                                                @AuthenticationPrincipal IdentityPrincipal actor,
                                                                HttpServletRequest request) {
        return ApiEnvelope.success(service.submit(id, actor, request), requestId(request));
    }

    @PostMapping("/{id}/withdraw")
    @PreAuthorize("hasAuthority('response.policy.draft')")
    public ApiEnvelope<ResponsePolicyService.PolicyView> withdraw(@PathVariable long id,
                                                                  @AuthenticationPrincipal IdentityPrincipal actor,
                                                                  HttpServletRequest request) {
        return ApiEnvelope.success(service.withdraw(id, actor, request), requestId(request));
    }

    @PostMapping("/{id}/decision")
    @PreAuthorize("hasAuthority('response.policy.approve')")
    public ApiEnvelope<ResponsePolicyService.PolicyView> decide(@PathVariable long id, @Valid @RequestBody DecisionBody body,
                                                                @AuthenticationPrincipal IdentityPrincipal actor,
                                                                HttpServletRequest request) {
        return ApiEnvelope.success(service.decide(id, body.decision(), body.reason(), actor, request), requestId(request));
    }

    @PostMapping("/{id}/retire")
    @PreAuthorize("hasAuthority('response.policy.approve')")
    public ApiEnvelope<ResponsePolicyService.PolicyView> retire(@PathVariable long id, @Valid @RequestBody ReasonBody body,
                                                                @AuthenticationPrincipal IdentityPrincipal actor,
                                                                HttpServletRequest request) {
        return ApiEnvelope.success(service.retire(id, body.reason(), actor, request), requestId(request));
    }

    private static String requestId(HttpServletRequest request) {
        Object value = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        return value instanceof String id ? id : "unknown";
    }

    /** 不接受状态、审批人、内容哈希等服务端字段；未知 JSON 字段按全局配置处理。 */
    public record DraftBody(@Size(max = 64) String policyKey, @Size(max = 32) String environment, JsonNode match,
                            @Size(max = 48) String actionType, JsonNode actionParams, BigDecimal riskLimit,
                            Boolean autoExecute, Boolean approvalRequired, Integer maxDurationSeconds,
                            @NotBlank @Size(max = 1000) String reason) {
        ResponsePolicyService.DraftInput toInput() {
            return new ResponsePolicyService.DraftInput(policyKey, environment, match, actionType, actionParams,
                    riskLimit, autoExecute, approvalRequired, maxDurationSeconds, reason);
        }
    }

    public record DecisionBody(@NotBlank String decision, @NotBlank @Size(max = 1000) String reason) { }

    public record ReasonBody(@NotBlank @Size(max = 1000) String reason) { }
}
