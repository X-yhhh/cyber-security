package com.xyh.cybersecurity.shadow;

import com.xyh.cybersecurity.common.api.ApiEnvelope;
import com.xyh.cybersecurity.identity.IdentityPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/** 影子验证汇总（路线 B §13）只读接口；授权与范围在服务层复核。 */
@RestController
@RequestMapping("/api/v1")
public class ShadowReportController {
    private final ShadowReportService service;

    public ShadowReportController(ShadowReportService service) {
        this.service = service;
    }

    /**
     * 数据源在 [from, to) 内的影子验证汇总与 G3 逐项判定。
     *
     * @param from 可选，ISO-8601 瞬时，缺省 to − 7 天
     * @param to   可选，ISO-8601 瞬时，缺省当前时间；范围不超过 31 天
     * @param zone 可选，划分自然日与工作日的时区（如 Asia/Shanghai），缺省 UTC
     */
    @GetMapping("/data-sources/{id}/shadow-report")
    @PreAuthorize("hasAuthority('shadow.report.read')")
    public ApiEnvelope<ShadowReport> summary(@PathVariable long id, @RequestParam(required = false) String from,
                                             @RequestParam(required = false) String to,
                                             @RequestParam(required = false) String zone,
                                             @AuthenticationPrincipal IdentityPrincipal principal,
                                             HttpServletRequest request) {
        boolean alertReader = principal.getAuthorities().stream().map(GrantedAuthority::getAuthority)
                .anyMatch("alert.read"::equals);
        return ApiEnvelope.success(service.summary(principal.id(), id, from, to, zone, alertReader), requestId(request));
    }

    private String requestId(HttpServletRequest request) {
        Object value = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        return value instanceof String id ? id : "unknown";
    }
}
