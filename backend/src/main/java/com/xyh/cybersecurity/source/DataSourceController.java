package com.xyh.cybersecurity.source;

import com.fasterxml.jackson.databind.JsonNode;
import com.xyh.cybersecurity.common.api.ApiEnvelope;
import com.xyh.cybersecurity.identity.IdentityPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
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

import java.util.List;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/** 为有权主体提供范围过滤后的数据源及只追加映射版本管理。 */
@RestController
@RequestMapping("/api/v1/data-sources")
public class DataSourceController {

    private final DataSourceService service;
    private final DataSourceMapper mapper;

    public DataSourceController(DataSourceService service, DataSourceMapper mapper) {
        this.service = service;
        this.mapper = mapper;
    }

    @GetMapping
    @PreAuthorize("hasAuthority('source.read')")
    public ApiEnvelope<DataSourceService.Page> list(@RequestParam(defaultValue = "0") int page,
                                                     @RequestParam(defaultValue = "20") int size,
                                                     @AuthenticationPrincipal IdentityPrincipal principal,
                                                     HttpServletRequest request) {
        return ApiEnvelope.success(service.list(principal.id(), page, size), requestId(request));
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('source.read')")
    public ApiEnvelope<DataSourceMapper.DataSourceView> get(@PathVariable long id,
                                                             @AuthenticationPrincipal IdentityPrincipal principal,
                                                             HttpServletRequest request) {
        DataSourceMapper.DataSourceView view = mapper.findVisible(principal.id(), id);
        if (view == null) throw com.xyh.cybersecurity.common.api.ApiRequestException.notFound();
        return ApiEnvelope.success(view, requestId(request));
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAuthority('source.manage')")
    public ApiEnvelope<DataSourceMapper.DataSourceView> create(@Valid @RequestBody CreateBody body,
                                                                @AuthenticationPrincipal IdentityPrincipal principal,
                                                                HttpServletRequest request) {
        return ApiEnvelope.success(service.create(new DataSourceService.CreateRequest(body.sourceKey(),
                body.sourceType(), body.environment(), body.schemaVersion()), principal, request), requestId(request));
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('source.manage')")
    public ApiEnvelope<DataSourceMapper.DataSourceView> update(@PathVariable long id,
                                                                @Valid @RequestBody UpdateBody body,
                                                                @AuthenticationPrincipal IdentityPrincipal principal,
                                                                HttpServletRequest request) {
        return ApiEnvelope.success(service.update(id, new DataSourceService.UpdateRequest(body.environment(),
                body.schemaVersion(), body.status()), principal, request), requestId(request));
    }

    @GetMapping("/{id}/mappings")
    @PreAuthorize("hasAuthority('source.read')")
    public ApiEnvelope<List<DataSourceMapper.MappingView>> mappings(@PathVariable long id,
                                                                     @AuthenticationPrincipal IdentityPrincipal principal,
                                                                     HttpServletRequest request) {
        if (mapper.findVisible(principal.id(), id) == null) {
            throw com.xyh.cybersecurity.common.api.ApiRequestException.notFound();
        }
        return ApiEnvelope.success(mapper.listMappingsVisible(principal.id(), id), requestId(request));
    }

    @PostMapping("/{id}/mappings")
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAuthority('source.manage')")
    public ApiEnvelope<DataSourceMapper.MappingView> createMapping(@PathVariable long id,
                                                                    @Valid @RequestBody MappingBody body,
                                                                    @AuthenticationPrincipal IdentityPrincipal principal,
                                                                    HttpServletRequest request) {
        return ApiEnvelope.success(service.createMapping(id, new DataSourceService.MappingRequest(body.mappingVersion(),
                body.sourceSchema().toString(), body.mapping().toString(), body.featureContractVersion()), principal, request),
                requestId(request));
    }

    /** 独立批准他人登记的映射版本；登记人自批 403，历史映射缺登记人 409。 */
    @PostMapping("/{id}/mappings/{mappingId}/approve")
    @PreAuthorize("hasAuthority('source.mapping.approve')")
    public ApiEnvelope<DataSourceMapper.MappingView> approveMapping(@PathVariable long id, @PathVariable long mappingId,
                                                                     @AuthenticationPrincipal IdentityPrincipal principal,
                                                                     HttpServletRequest request) {
        return ApiEnvelope.success(service.approveMapping(id, mappingId, principal, request), requestId(request));
    }

    /** 驳回他人登记的待批准映射；登记人本人 403，状态不符 409 {@code MAPPING_STATUS_CONFLICT}。 */
    @PostMapping("/{id}/mappings/{mappingId}/reject")
    @PreAuthorize("hasAuthority('source.mapping.approve')")
    public ApiEnvelope<DataSourceMapper.MappingView> rejectMapping(@PathVariable long id, @PathVariable long mappingId,
                                                                    @Valid @RequestBody ReasonBody body,
                                                                    @AuthenticationPrincipal IdentityPrincipal principal,
                                                                    HttpServletRequest request) {
        return ApiEnvelope.success(service.rejectMapping(id, mappingId, body.reason(), principal, request),
                requestId(request));
    }

    /** 退役已批准映射；退役后该版本的新批次被拒绝。 */
    @PostMapping("/{id}/mappings/{mappingId}/retire")
    @PreAuthorize("hasAuthority('source.mapping.approve')")
    public ApiEnvelope<DataSourceMapper.MappingView> retireMapping(@PathVariable long id, @PathVariable long mappingId,
                                                                    @Valid @RequestBody ReasonBody body,
                                                                    @AuthenticationPrincipal IdentityPrincipal principal,
                                                                    HttpServletRequest request) {
        return ApiEnvelope.success(service.retireMapping(id, mappingId, body.reason(), principal, request),
                requestId(request));
    }

    private String requestId(HttpServletRequest request) {
        Object value = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        return value instanceof String id ? id : "unknown";
    }

    public record CreateBody(@NotBlank @Size(max = 128) String sourceKey,
                             @NotBlank @Size(max = 48) String sourceType,
                             @NotBlank @Size(max = 32) String environment,
                             @NotBlank @Size(max = 64) String schemaVersion) { }
    public record UpdateBody(@NotBlank @Size(max = 32) String environment,
                             @NotBlank @Size(max = 64) String schemaVersion,
                             @NotBlank String status) { }
    public record ReasonBody(@NotBlank @Size(max = 1000) String reason) { }
    /** @param featureContractVersion 可选：映射绑定的特征契约版本（V11） */
    public record MappingBody(@NotBlank @Size(max = 64) String mappingVersion,
                              @NotNull JsonNode sourceSchema, @NotNull JsonNode mapping,
                              @Size(max = 64) String featureContractVersion) { }
}
