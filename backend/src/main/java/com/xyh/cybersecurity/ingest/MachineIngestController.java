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
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/** 接收连接器已规范化的有限记录批次；不接收原始包或任意载荷引用。 */
@RestController
@RequestMapping("/api/v1/machine/ingest")
public class MachineIngestController {

    private final MachineIngestService service;

    public MachineIngestController(MachineIngestService service) {
        this.service = service;
    }

    @PostMapping("/batches")
    @PreAuthorize("hasAuthority('machine.ingest.submit')")
    public org.springframework.http.ResponseEntity<ApiEnvelope<MachineIngestService.BatchReceipt>> submit(
            @RequestHeader("Idempotency-Key") @NotBlank @Size(max = 160) String idempotencyKey,
            @Valid @RequestBody BatchBody body,
            @AuthenticationPrincipal MachinePrincipal principal,
            HttpServletRequest request) {
        Object value = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        String requestId = value instanceof String id ? id : "unknown";
        MachineIngestService.Submission submission = service.submit(principal.id(), principal.clientKey(), idempotencyKey,
                new MachineIngestService.BatchRequest(body.dataSourceId(), body.mappingVersion(), body.records().stream()
                        .map(record -> new MachineIngestService.RecordRequest(record.recordKey(), record.eventType(),
                                record.eventTime(), record.assetId(), record.payload())).toList()), requestId);
        HttpStatus status = submission.created() ? HttpStatus.CREATED : HttpStatus.OK;
        return org.springframework.http.ResponseEntity.status(status)
                .body(ApiEnvelope.success(submission.receipt(), requestId));
    }

    public record BatchBody(@Positive long dataSourceId,
                            @NotBlank @Size(max = 64) String mappingVersion,
                            @NotEmpty @Size(max = 500) List<@Valid RecordBody> records) { }
    public record RecordBody(@NotBlank @Size(max = 160) String recordKey,
                             @NotBlank @Size(max = 64) String eventType,
                             @NotNull Instant eventTime,
                             Long assetId,
                             @NotNull JsonNode payload) { }
}
