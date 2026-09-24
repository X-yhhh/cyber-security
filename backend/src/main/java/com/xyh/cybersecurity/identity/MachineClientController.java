package com.xyh.cybersecurity.identity;

import com.xyh.cybersecurity.common.api.ApiEnvelope;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/** 由平台管理员签发仅可提交批次的连接器机器凭据。 */
@RestController
@RequestMapping("/api/v1/machine-clients")
public class MachineClientController {

    private final MachineClientService service;

    public MachineClientController(MachineClientService service) {
        this.service = service;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAuthority('system.config.update')")
    public ApiEnvelope<MachineClientService.IssuedClient> create(@Valid @RequestBody CreateMachineClientBody body,
                                                                  @AuthenticationPrincipal IdentityPrincipal actor,
                                                                  HttpServletRequest request) {
        return ApiEnvelope.success(service.create(body.clientKey(), body.clientType(), body.scopes(),
                body.sourceAssetBindings(), actor, request, requestId(request)), requestId(request));
    }

    private String requestId(HttpServletRequest request) {
        Object value = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        return value instanceof String id ? id : "unknown";
    }

    public record CreateMachineClientBody(@NotBlank @Pattern(regexp = "[A-Za-z0-9._-]{3,96}") String clientKey,
                                          @NotBlank String clientType,
                                          @NotEmpty @Size(max = 32) List<ScopeBody> scopes,
                                          @NotEmpty @Size(max = 32) List<@Valid SourceAssetBindingBody> sourceAssetBindings) { }
    public record ScopeBody(@NotBlank String scopeType,
                            @NotBlank @Size(max = 128) String scopeId) { }
    public record SourceAssetBindingBody(@jakarta.validation.constraints.Positive long dataSourceId,
                                         @jakarta.validation.constraints.Positive long assetId) { }
}
