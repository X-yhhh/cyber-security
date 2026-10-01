package com.xyh.cybersecurity.asset;

import com.xyh.cybersecurity.authorization.PermissionService;
import com.xyh.cybersecurity.common.api.ApiEnvelope;
import com.xyh.cybersecurity.common.api.ApiRequestException;
import com.xyh.cybersecurity.identity.IdentityPrincipal;
import com.xyh.cybersecurity.security.SecurityAuditWriter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/** 查询当前人工主体在功能权限与资产范围交集内可见的资产。 */
@RestController
@RequestMapping("/api/v1/assets")
public class AssetController {

    private final AssetMapper assetMapper;
    private final PermissionService permissionService;
    private final SecurityAuditWriter securityAuditWriter;
    private final AssetService assetService;
    private final ObjectMapper objectMapper;

    public AssetController(AssetMapper assetMapper, PermissionService permissionService,
                           SecurityAuditWriter securityAuditWriter, AssetService assetService, ObjectMapper objectMapper) {
        this.assetMapper = assetMapper;
        this.permissionService = permissionService;
        this.securityAuditWriter = securityAuditWriter;
        this.assetService = assetService;
        this.objectMapper = objectMapper;
    }

    @GetMapping
    @PreAuthorize("hasAuthority('asset.read')")
    public ApiEnvelope<Page<AssetMapper.AssetView>> list(
            @RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "20") int size,
            @AuthenticationPrincipal IdentityPrincipal principal, HttpServletRequest request) {
        checkPage(page, size);
        permissionService.require(org.springframework.security.core.context.SecurityContextHolder.getContext()
                .getAuthentication(), "asset.read");
        long total = assetMapper.countVisible(principal.id());
        var items = assetMapper.listVisible(principal.id(), page * size, size);
        return ApiEnvelope.success(new Page<>(total, page, size, items), requestId(request));
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('asset.read')")
    public ApiEnvelope<AssetMapper.AssetView> get(@PathVariable long id,
                                                  @AuthenticationPrincipal IdentityPrincipal principal,
                                                  HttpServletRequest request) {
        permissionService.require(org.springframework.security.core.context.SecurityContextHolder.getContext()
                .getAuthentication(), "asset.read");
        AssetMapper.AssetView asset = assetMapper.findVisible(principal.id(), id);
        if (asset == null) {
            securityAuditWriter.denied(request,
                    org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication(),
                    "authorization.scope.denied", "resource_out_of_scope_or_not_found");
            throw ApiRequestException.notFound();
        }
        return ApiEnvelope.success(asset, requestId(request));
    }

    @PostMapping
    @ResponseStatus(org.springframework.http.HttpStatus.CREATED)
    @PreAuthorize("hasAuthority('asset.manage')")
    public ApiEnvelope<AssetMapper.AssetView> create(@Valid @RequestBody CreateAssetBody body,
                                                     @AuthenticationPrincipal IdentityPrincipal principal,
                                                     HttpServletRequest request) {
        JsonNode labels = parseObject(body.labels() == null ? objectMapper.createObjectNode() : body.labels(),
                "资产标签必须是 JSON 对象");
        return ApiEnvelope.success(assetService.create(new AssetService.CreateAssetRequest(body.assetKey(),
                body.assetType(), body.environment(), body.criticality(), body.owner(), labels.toString()),
                principal, request), requestId(request));
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('asset.manage')")
    public ApiEnvelope<AssetMapper.AssetView> update(@PathVariable long id, @Valid @RequestBody UpdateAssetBody body,
                                                      @AuthenticationPrincipal IdentityPrincipal principal,
                                                      HttpServletRequest request) {
        if (!java.util.Set.of("low", "medium", "high", "critical").contains(body.criticality())
                || !java.util.Set.of("active", "disabled", "retired").contains(body.status())) {
            throw com.xyh.cybersecurity.common.api.ApiRequestException.badRequest("资产关键性或状态无效");
        }
        return ApiEnvelope.success(assetService.update(id, new AssetService.UpdateAssetRequest(
                body.criticality(), body.owner(), body.status()), principal, request), requestId(request));
    }

    @PostMapping("/{id}/authorizations")
    @ResponseStatus(org.springframework.http.HttpStatus.CREATED)
    @PreAuthorize("hasAuthority('asset.authorization.manage')")
    public ApiEnvelope<AssetService.AuthorizationView> requestAuthorization(
            @PathVariable long id, @Valid @RequestBody AuthorizationBody body,
            @AuthenticationPrincipal IdentityPrincipal principal, HttpServletRequest request) {
        return ApiEnvelope.success(assetService.requestAuthorization(id, new AssetService.AuthorizationRequest(
                body.authorizationRef(), parseObject(body.scope(), "授权范围必须是 JSON 对象").toString(),
                body.validFrom(), body.validUntil()),
                principal, request), requestId(request));
    }

    @PostMapping("/{assetId}/authorizations/{authorizationId}/approve")
    @PreAuthorize("hasAuthority('asset.authorization.approve')")
    public ApiEnvelope<AssetService.AuthorizationView> approveAuthorization(
            @PathVariable long assetId, @PathVariable long authorizationId,
            @AuthenticationPrincipal IdentityPrincipal principal, HttpServletRequest request) {
        return ApiEnvelope.success(assetService.approveAuthorization(assetId, authorizationId, principal, request),
                requestId(request));
    }

    /** 撤销待审批或有效的授权；申请或批准权限任一即可（范围内）。 */
    @PostMapping("/{assetId}/authorizations/{authorizationId}/revoke")
    @PreAuthorize("hasAnyAuthority('asset.authorization.manage','asset.authorization.approve')")
    public ApiEnvelope<AssetService.AuthorizationView> revokeAuthorization(
            @PathVariable long assetId, @PathVariable long authorizationId, @Valid @RequestBody ReasonBody body,
            @AuthenticationPrincipal IdentityPrincipal principal, HttpServletRequest request) {
        return ApiEnvelope.success(assetService.revokeAuthorization(assetId, authorizationId, body.reason(), principal,
                request), requestId(request));
    }

    private JsonNode parseObject(JsonNode node, String message) {
        try {
            if (node == null || !node.isObject()) throw new IllegalArgumentException();
            return node;
        } catch (Exception exception) {
            throw com.xyh.cybersecurity.common.api.ApiRequestException.badRequest(message);
        }
    }

    private static void checkPage(int page, int size) {
        if (page < 0 || size < 1 || size > 100 || (long) page * size > Integer.MAX_VALUE) {
            throw ApiRequestException.badRequest("分页参数超出允许范围");
        }
    }

    private String requestId(HttpServletRequest request) {
        Object value = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        return value instanceof String requestId ? requestId : "unknown";
    }

    public record Page<T>(long totalElements, int page, int size, java.util.List<T> items) { }
    public record CreateAssetBody(@NotBlank @Size(max = 128) String assetKey,
                                  @NotBlank @Size(max = 48) String assetType,
                                  @NotBlank @Size(max = 32) String environment,
                                  @NotBlank @Size(max = 24) String criticality,
                                  @Size(max = 128) String owner, JsonNode labels) { }
    public record UpdateAssetBody(@NotBlank String criticality, @Size(max = 128) String owner,
                                  @NotBlank String status) { }
    public record ReasonBody(@NotBlank @Size(max = 1000) String reason) { }
    public record AuthorizationBody(@NotBlank @Size(max = 255) String authorizationRef,
                                    @NotNull JsonNode scope,
                                    @NotNull java.time.Instant validFrom,
                                    @NotNull java.time.Instant validUntil) { }
}
