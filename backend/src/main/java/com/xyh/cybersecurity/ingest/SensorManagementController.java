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
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/**
 * 传感器登记与生命周期管理：登记时一次性签发设备凭据（不会再次读取）；之后的详情、资料修改、配置版本
 * 起草/审批/启用、凭据轮换与吊销、下线均在传感器所属资产范围内二次校验（开发路线 §4.1）。
 */
@RestController
@RequestMapping("/api/v1/sensors")
public class SensorManagementController {
    private final SensorManagementService service;
    private final SensorLifecycleService lifecycle;

    public SensorManagementController(SensorManagementService service, SensorLifecycleService lifecycle) {
        this.service = service;
        this.lifecycle = lifecycle;
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('sensor.read')")
    public ApiEnvelope<SensorLifecycleService.SensorDetail> detail(@PathVariable long id,
                                                                   @AuthenticationPrincipal IdentityPrincipal actor,
                                                                   HttpServletRequest request) {
        return ApiEnvelope.success(lifecycle.detail(id, actor), requestId(request));
    }

    /** 修改平台标识；采集配置变更须走配置版本流程。 */
    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('sensor.manage')")
    public ApiEnvelope<SensorLifecycleService.SensorDetail> update(@PathVariable long id, @Valid @RequestBody UpdateBody body,
                                                                   @AuthenticationPrincipal IdentityPrincipal actor,
                                                                   HttpServletRequest request) {
        return ApiEnvelope.success(lifecycle.updatePlatform(id, body.platform(), actor, request), requestId(request));
    }

    @PostMapping("/{id}/configs")
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAuthority('sensor.manage')")
    public ApiEnvelope<SensorAdminMapper.ConfigRow> draftConfig(@PathVariable long id, @Valid @RequestBody DraftConfigBody body,
                                                                @AuthenticationPrincipal IdentityPrincipal actor,
                                                                HttpServletRequest request) {
        return ApiEnvelope.success(lifecycle.draftConfig(id, new SensorLifecycleService.ConfigDraft(body.configVersion(),
                body.interfaceScope(), body.filterPolicy(), body.flowWindowSeconds(), body.featureContractVersion(),
                body.samplingPolicy(), body.reason()), actor, request), requestId(request));
    }

    /** 他人批准或驳回配置版本；批准不自动生效。 */
    @PostMapping("/{id}/configs/{configId}/decision")
    @PreAuthorize("hasAuthority('sensor.config.approve')")
    public ApiEnvelope<SensorAdminMapper.ConfigRow> decideConfig(@PathVariable long id, @PathVariable long configId,
                                                                 @Valid @RequestBody DecisionBody body,
                                                                 @AuthenticationPrincipal IdentityPrincipal actor,
                                                                 HttpServletRequest request) {
        return ApiEnvelope.success(lifecycle.decideConfig(id, configId, body.decision(), body.reason(), actor, request),
                requestId(request));
    }

    @PostMapping("/{id}/configs/{configId}/activate")
    @PreAuthorize("hasAuthority('sensor.manage')")
    public ApiEnvelope<SensorAdminMapper.ConfigRow> activateConfig(@PathVariable long id, @PathVariable long configId,
                                                                   @AuthenticationPrincipal IdentityPrincipal actor,
                                                                   HttpServletRequest request) {
        return ApiEnvelope.success(lifecycle.activateConfig(id, configId, actor, request), requestId(request));
    }

    /** 轮换凭据；新凭据只返回这一次。 */
    @PostMapping("/{id}/credentials/rotate")
    @PreAuthorize("hasAuthority('sensor.manage')")
    public ApiEnvelope<SensorLifecycleService.RotatedCredential> rotate(@PathVariable long id,
                                                                        @AuthenticationPrincipal IdentityPrincipal actor,
                                                                        HttpServletRequest request) {
        return ApiEnvelope.success(lifecycle.rotateCredential(id, actor, request), requestId(request));
    }

    @PostMapping("/{id}/credentials/revoke")
    @PreAuthorize("hasAuthority('sensor.manage')")
    public ApiEnvelope<SensorLifecycleService.SensorDetail> revoke(@PathVariable long id, @Valid @RequestBody ReasonBody body,
                                                                   @AuthenticationPrincipal IdentityPrincipal actor,
                                                                   HttpServletRequest request) {
        return ApiEnvelope.success(lifecycle.revokeCredential(id, body.reason(), actor, request), requestId(request));
    }

    /** 下线：吊销凭据、退役配置，不可恢复。 */
    @PostMapping("/{id}/decommission")
    @PreAuthorize("hasAuthority('sensor.manage')")
    public ApiEnvelope<SensorLifecycleService.SensorDetail> decommission(@PathVariable long id,
                                                                         @Valid @RequestBody ReasonBody body,
                                                                         @AuthenticationPrincipal IdentityPrincipal actor,
                                                                         HttpServletRequest request) {
        return ApiEnvelope.success(lifecycle.decommission(id, body.reason(), actor, request), requestId(request));
    }

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

    public record UpdateBody(@NotBlank @Size(max = 32) String platform) { }
    public record DraftConfigBody(@NotBlank @Size(max = 64) String configVersion, @NotNull JsonNode interfaceScope,
                                  @NotNull JsonNode filterPolicy, @Positive int flowWindowSeconds,
                                  @NotBlank @Size(max = 64) String featureContractVersion,
                                  @NotNull JsonNode samplingPolicy, @NotBlank @Size(max = 1000) String reason) { }
    public record DecisionBody(@NotBlank String decision, @NotBlank @Size(max = 1000) String reason) { }
    public record ReasonBody(@NotBlank @Size(max = 1000) String reason) { }
    public record RegisterBody(@NotBlank @Size(max = 128) String agentKey, @Positive long assetId,
                               @Positive long dataSourceId, @NotBlank @Size(max = 32) String platform,
                               @NotBlank @Size(max = 64) String agentVersion, @NotNull JsonNode capabilities,
                               @Valid @NotNull ConfigBody config) { }
    public record ConfigBody(@NotBlank @Size(max = 64) String configVersion, @NotNull JsonNode interfaceScope,
                             @NotNull JsonNode filterPolicy, @Positive int flowWindowSeconds,
                             @NotBlank @Size(max = 64) String featureContractVersion,
                             @NotNull JsonNode samplingPolicy) { }
}
