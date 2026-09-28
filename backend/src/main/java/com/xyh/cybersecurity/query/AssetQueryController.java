package com.xyh.cybersecurity.query;

import com.xyh.cybersecurity.common.api.ApiEnvelope;
import com.xyh.cybersecurity.identity.IdentityPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/** 资产及传感器只读查询；资源范围由查询服务在 SQL 中再次校验。 */
@RestController
@RequestMapping("/api/v1")
public class AssetQueryController {
    private final ConsoleQueryService service;
    public AssetQueryController(ConsoleQueryService service) { this.service = service; }

    @GetMapping("/sensors")
    @PreAuthorize("hasAuthority('sensor.read')")
    public ApiEnvelope<List<ConsoleQueryService.SensorView>> sensors(@AuthenticationPrincipal IdentityPrincipal actor,
                                                                     HttpServletRequest request) {
        return ApiEnvelope.success(service.sensors(actor.id()), requestId(request));
    }

    @GetMapping("/assets/{id}/authorizations")
    @PreAuthorize("hasAuthority('asset.authorization.read')")
    public ApiEnvelope<List<ConsoleQueryService.AuthorizationView>> authorizations(
            @PathVariable long id, @AuthenticationPrincipal IdentityPrincipal actor, HttpServletRequest request) {
        return ApiEnvelope.success(service.authorizations(actor.id(), id), requestId(request));
    }

    @GetMapping("/users/{id}/roles")
    @PreAuthorize("hasAuthority('iam.user.read')")
    public ApiEnvelope<List<ConsoleQueryService.RoleBindingView>> roles(@PathVariable long id,
                                                                        HttpServletRequest request) {
        return ApiEnvelope.success(service.roleBindings(id), requestId(request));
    }

    private static String requestId(HttpServletRequest request) {
        Object value = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        return value instanceof String id ? id : "unknown";
    }
}
