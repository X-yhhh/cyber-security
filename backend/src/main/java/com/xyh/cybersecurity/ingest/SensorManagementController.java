package com.xyh.cybersecurity.ingest;

import com.fasterxml.jackson.databind.JsonNode;
import com.xyh.cybersecurity.common.api.ApiEnvelope;
import com.xyh.cybersecurity.identity.IdentityPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/** 管理员登记已授权主机传感器并一次性获得设备凭据；凭据不会再次读取。 */
@RestController
@RequestMapping("/api/v1/sensors")
public class SensorManagementController {
    private final SensorManagementService service;
    public SensorManagementController(SensorManagementService service) { this.service = service; }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAuthority('sensor.manage')")
    public ApiEnvelope<SensorManagementService.IssuedSensor> register(@Valid @RequestBody RegisterBody body,
                                                                        @AuthenticationPrincipal IdentityPrincipal actor,
                                                                        HttpServletRequest request) {
        SensorManagementService.ConfigRequest config = new SensorManagementService.ConfigRequest(body.config().configVersion(),
                body.config().interfaceScope(), body.config().filterPolicy(), body.config().flowWindowSeconds(),
                body.config().featureContractVersion(), body.config().samplingPolicy());
        var result = service.register(new SensorManagementService.RegisterRequest(body.agentKey(), body.assetId(), body.dataSourceId(),
                body.platform(), body.agentVersion(), body.capabilities(), config), actor, request);
        return ApiEnvelope.success(result, requestId(request));
    }

    private String requestId(HttpServletRequest request) { Object value = request.getAttribute(REQUEST_ID_ATTRIBUTE); return value instanceof String s ? s : "unknown"; }

    public record RegisterBody(@NotBlank @Size(max = 128) String agentKey, @Positive long assetId,
                               @Positive long dataSourceId, @NotBlank @Size(max = 32) String platform,
                               @NotBlank @Size(max = 64) String agentVersion, @NotNull JsonNode capabilities,
                               @Valid @NotNull ConfigBody config) { }
    public record ConfigBody(@NotBlank @Size(max = 64) String configVersion, @NotNull JsonNode interfaceScope,
                             @NotNull JsonNode filterPolicy, @Positive int flowWindowSeconds,
                             @NotBlank @Size(max = 64) String featureContractVersion,
                             @NotNull JsonNode samplingPolicy) { }
}
