package com.xyh.cybersecurity.ingest;

import com.fasterxml.jackson.databind.JsonNode;
import com.xyh.cybersecurity.common.api.ApiEnvelope;
import com.xyh.cybersecurity.identity.MachinePrincipal;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/** 传感器专用机器路由；不接受浏览器会话、assetId 冒充或任意命令。 */
@RestController
@RequestMapping("/api/v1/machine/sensors")
public class SensorIngestController {
    private final SensorIngestService service;

    public SensorIngestController(SensorIngestService service) { this.service = service; }

    @PostMapping("/{sensorId}/heartbeat")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @PreAuthorize("hasAuthority('machine.sensor.heartbeat')")
    public void heartbeat(@PathVariable long sensorId, @Valid @RequestBody HeartbeatBody body,
                          @AuthenticationPrincipal MachinePrincipal principal, HttpServletRequest request) {
        service.heartbeat(sensorId, principal, new SensorIngestService.HeartbeatRequest(body.observedAt(), body.agentVersion(), body.capabilities()), requestId(request));
    }

    @GetMapping("/{sensorId}/config")
    @PreAuthorize("hasAuthority('machine.sensor.config.read')")
    public ApiEnvelope<SensorIngestService.ConfigView> config(@PathVariable long sensorId,
                                                               @AuthenticationPrincipal MachinePrincipal principal,
                                                               HttpServletRequest request) {
        return ApiEnvelope.success(service.config(sensorId, principal), requestId(request));
    }

    @PostMapping("/{sensorId}/health-windows")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @PreAuthorize("hasAuthority('machine.sensor.heartbeat')")
    public void health(@PathVariable long sensorId, @Valid @RequestBody HealthWindowBody body,
                       @AuthenticationPrincipal MachinePrincipal principal, HttpServletRequest request) {
        service.healthWindow(sensorId, principal, new SensorIngestService.HealthWindowRequest(body.windowStart(), body.windowEnd(),
                body.flowsSeen(), body.flowsEmitted(), body.flowsDropped(), body.queueDepthMax(), body.cpuPercent(),
                body.memoryBytes(), body.errors()), requestId(request));
    }

    @PostMapping("/{sensorId}/flow-batches")
    @PreAuthorize("hasAuthority('machine.sensor.ingest')")
    public org.springframework.http.ResponseEntity<ApiEnvelope<SensorIngestService.BatchReceipt>> flowBatch(
            @PathVariable long sensorId,
            @RequestHeader("Idempotency-Key") @NotBlank @Size(max = 160) String idempotencyKey,
            @Valid @RequestBody FlowBatchBody body,
            @AuthenticationPrincipal MachinePrincipal principal, HttpServletRequest request) {
        SensorIngestService.Submission result = service.submit(sensorId, principal, idempotencyKey,
                new SensorIngestService.SensorBatchRequest(body.dataSourceId(), body.configVersion(), body.sequence(), body.observedAt(),
                        body.sourceMappingVersion(), body.featureContractVersion(), body.records().stream().map(r ->
                                new SensorIngestService.FlowRecordRequest(r.recordKey(), r.flowStartAt(), r.flowEndAt(), r.observedAt(), r.directionBasis(), r.features())).toList()), requestId(request));
        HttpStatus status = result.receipt().acceptedCount() == 0 ? HttpStatus.UNPROCESSABLE_ENTITY
                : (result.created() ? HttpStatus.CREATED : HttpStatus.OK);
        return org.springframework.http.ResponseEntity.status(status)
                .body(ApiEnvelope.success(result.receipt(), requestId(request)));
    }

    private String requestId(HttpServletRequest request) {
        Object value = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        return value instanceof String id ? id : "unknown";
    }

    public record HeartbeatBody(@NotNull Instant observedAt, @NotBlank @Size(max = 64) String agentVersion,
                                @NotNull JsonNode capabilities) { }
    public record HealthWindowBody(@NotNull Instant windowStart, @NotNull Instant windowEnd,
                                   @jakarta.validation.constraints.PositiveOrZero long flowsSeen,
                                   @jakarta.validation.constraints.PositiveOrZero long flowsEmitted,
                                   @jakarta.validation.constraints.PositiveOrZero long flowsDropped,
                                   @jakarta.validation.constraints.PositiveOrZero long queueDepthMax,
                                   Double cpuPercent, @jakarta.validation.constraints.PositiveOrZero Long memoryBytes,
                                   JsonNode errors) { }
    public record FlowBatchBody(@Positive long dataSourceId, @NotBlank @Size(max = 64) String configVersion,
                                @Positive long sequence, @NotNull Instant observedAt,
                                @NotBlank @Size(max = 64) String sourceMappingVersion,
                                @NotBlank @Size(max = 64) String featureContractVersion,
                                @NotEmpty @Size(max = 500) List<@Valid FlowRecordBody> records) { }
    public record FlowRecordBody(@NotBlank @Size(max = 160) String recordKey, @NotNull Instant flowStartAt,
                                 @NotNull Instant flowEndAt, @NotNull Instant observedAt,
                                 @NotBlank @Size(max = 32) String directionBasis,
                                 @NotNull JsonNode features) { }
}
