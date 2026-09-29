package com.xyh.cybersecurity.inference;

import com.xyh.cybersecurity.common.api.ApiEnvelope;
import com.xyh.cybersecurity.identity.IdentityPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Positive;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/** 推理台账只读查询与回放 dry-run；在线推理只由 M2 消费链路触发，不开放任意记录的推理入口。 */
@RestController
@RequestMapping("/api/v1")
public class InferenceController {
    private final InferenceAdminService service;

    public InferenceController(InferenceAdminService service) { this.service = service; }

    @GetMapping("/inference-requests")
    @PreAuthorize("hasAuthority('inference.request.read')")
    public ApiEnvelope<InferenceAdminService.Page> list(@RequestParam(required = false) String dataSourceId,
                                                        @RequestParam(required = false) String assetId,
                                                        @RequestParam(required = false) String status,
                                                        @RequestParam(required = false) String modelVersionId,
                                                        @RequestParam(required = false) String from,
                                                        @RequestParam(required = false) String to,
                                                        @RequestParam(required = false) String page,
                                                        @RequestParam(required = false) String size,
                                                        @AuthenticationPrincipal IdentityPrincipal actor,
                                                        HttpServletRequest request) {
        return ApiEnvelope.success(service.list(actor.id(), new InferenceAdminService.ListQuery(dataSourceId, assetId,
                status, modelVersionId, from, to, page, size)), requestId(request));
    }

    @PostMapping("/inference/dry-run")
    @PreAuthorize("hasAuthority('model.replay.run')")
    public ApiEnvelope<InferenceAdminService.DryRunView> dryRun(@Valid @RequestBody DryRunBody body,
                                                                @AuthenticationPrincipal IdentityPrincipal actor,
                                                                HttpServletRequest request) {
        return ApiEnvelope.success(service.dryRun(body.dataSourceId(), body.batchId(), actor, request),
                requestId(request));
    }

    private static String requestId(HttpServletRequest request) {
        Object value = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        return value instanceof String id ? id : "unknown";
    }

    public record DryRunBody(@Positive long dataSourceId, @Positive long batchId) { }
}
