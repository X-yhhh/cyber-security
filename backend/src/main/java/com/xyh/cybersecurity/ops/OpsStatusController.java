package com.xyh.cybersecurity.ops;

import com.xyh.cybersecurity.common.api.ApiEnvelope;
import com.xyh.cybersecurity.identity.IdentityPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/** 受权限保护的运行摘要；不返回连接串、RabbitMQ 凭据或原始数据。 */
@RestController
@RequestMapping("/api/v1/ops")
public class OpsStatusController {

    private final OpsMetrics metrics;

    public OpsStatusController(OpsMetrics metrics) { this.metrics = metrics; }

    @GetMapping("/status")
    @PreAuthorize("hasAuthority('ops.status.read')")
    public ApiEnvelope<OpsMetrics.Snapshot> status(@AuthenticationPrincipal IdentityPrincipal actor,
                                                   HttpServletRequest request) {
        return ApiEnvelope.success(metrics.snapshot(), requestId(request));
    }

    private static String requestId(HttpServletRequest request) {
        Object value = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        return value instanceof String id ? id : "unknown";
    }
}
