package com.xyh.cybersecurity.query;

import com.xyh.cybersecurity.common.api.ApiEnvelope;
import com.xyh.cybersecurity.identity.IdentityPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/** 控制台态势聚合入口；资产、接入、响应和模型列表按领域拆分到只读控制器。 */
@RestController
@RequestMapping("/api/v1")
public class ConsoleQueryController {

    private final ConsoleQueryService service;

    public ConsoleQueryController(ConsoleQueryService service) { this.service = service; }

    /** 态势汇总，只包含当前身份可见范围内的计数。 */
    @GetMapping("/overview")
    public ApiEnvelope<ConsoleQueryService.OverviewView> overview(
            @AuthenticationPrincipal IdentityPrincipal actor, HttpServletRequest request) {
        return ApiEnvelope.success(service.overview(actor.id(), actor.permissions().contains("alert.read")),
                requestId(request));
    }

    private static String requestId(HttpServletRequest request) {
        Object value = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        return value instanceof String id ? id : "unknown";
    }
}
