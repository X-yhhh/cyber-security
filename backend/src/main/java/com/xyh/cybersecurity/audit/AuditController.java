package com.xyh.cybersecurity.audit;

import com.xyh.cybersecurity.authorization.PermissionService;
import com.xyh.cybersecurity.common.api.ApiEnvelope;
import com.xyh.cybersecurity.common.api.ApiRequestException;
import com.xyh.cybersecurity.identity.IdentityPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/** 只追加审计记录的范围过滤只读查询。 */
@RestController
@RequestMapping("/api/v1/audit")
public class AuditController {

    private final AuditMapper auditMapper;
    private final PermissionService permissionService;

    public AuditController(AuditMapper auditMapper, PermissionService permissionService) {
        this.auditMapper = auditMapper;
        this.permissionService = permissionService;
    }

    @GetMapping
    @PreAuthorize("hasAuthority('audit.read')")
    public ApiEnvelope<Page> list(@RequestParam(defaultValue = "0") int page,
                                  @RequestParam(defaultValue = "20") int size,
                                  @AuthenticationPrincipal IdentityPrincipal principal,
                                  HttpServletRequest request) {
        if (page < 0 || size < 1 || size > 100 || (long) page * size > Integer.MAX_VALUE) {
            throw ApiRequestException.badRequest("分页参数超出允许范围");
        }
        permissionService.require(SecurityContextHolder.getContext().getAuthentication(), "audit.read");
        return ApiEnvelope.success(new Page(auditMapper.countVisible(principal.id()), page, size,
                auditMapper.listVisible(principal.id(), page * size, size)), requestId(request));
    }

    private String requestId(HttpServletRequest request) {
        Object value = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        return value instanceof String requestId ? requestId : "unknown";
    }

    public record Page(long totalElements, int page, int size, java.util.List<AuditMapper.AuditView> items) { }
}
