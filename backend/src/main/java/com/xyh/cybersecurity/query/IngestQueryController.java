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

/** 接入批次和隔离回放场景的只读查询控制器。 */
@RestController
@RequestMapping("/api/v1")
public class IngestQueryController {
    private final ConsoleQueryService service;
    public IngestQueryController(ConsoleQueryService service) { this.service = service; }

    @GetMapping("/data-sources/ingest-summary")
    @PreAuthorize("hasAuthority('ingest.batch.read')")
    public ApiEnvelope<List<ConsoleQueryService.IngestSummary>> ingestSummary(
            @AuthenticationPrincipal IdentityPrincipal actor, HttpServletRequest request) {
        return ApiEnvelope.success(service.ingestSummary(actor.id()), requestId(request));
    }

    @GetMapping("/replay-scenarios")
    @PreAuthorize("hasAuthority('source.read')")
    public ApiEnvelope<List<ConsoleQueryService.ReplayScenarioView>> replay(HttpServletRequest request) {
        return ApiEnvelope.success(service.replayScenarios(), requestId(request));
    }

    private static String requestId(HttpServletRequest request) {
        Object value = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        return value instanceof String id ? id : "unknown";
    }
}
