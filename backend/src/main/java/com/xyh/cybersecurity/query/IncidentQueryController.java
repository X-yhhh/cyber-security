package com.xyh.cybersecurity.query;

import com.xyh.cybersecurity.common.api.ApiEnvelope;
import com.xyh.cybersecurity.identity.IdentityPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/** 事件响应台账只读查询；不提供状态写入或执行入口。 */
@RestController
@RequestMapping("/api/v1")
public class IncidentQueryController {
    private final ConsoleQueryService service;
    public IncidentQueryController(ConsoleQueryService service) { this.service = service; }

    @GetMapping("/approvals/ledger")
    @PreAuthorize("hasAuthority('approval.read')")
    public ApiEnvelope<List<ConsoleQueryService.LedgerView>> ledger(@AuthenticationPrincipal IdentityPrincipal actor,
                                                                    HttpServletRequest request) {
        return ApiEnvelope.success(service.ledger(actor.id(), "approval.decide", false), requestId(request));
    }

    @GetMapping("/actions/mine")
    @PreAuthorize("hasAuthority('action.request')")
    public ApiEnvelope<List<ConsoleQueryService.LedgerView>> mine(@AuthenticationPrincipal IdentityPrincipal actor,
                                                                  HttpServletRequest request) {
        return ApiEnvelope.success(service.ledger(actor.id(), "action.request", true), requestId(request));
    }

    private static String requestId(HttpServletRequest request) {
        Object value = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        return value instanceof String id ? id : "unknown";
    }
}
